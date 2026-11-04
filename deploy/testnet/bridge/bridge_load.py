#!/usr/bin/env python3
"""Sustained bridge load on a generation whose bridge is deployed, for the host's measured envelope (TN-B #429, B-TEST #438; BRIDGE-MEASURED.md lists it as not measured).

--workers parallel testers, each with its own faucet-funded key (the driver of rehearse_bridge.py signs with one key, so parallel driver runs would collide on nonces),
loop the tester CLI's whole round trip for --duration: init a fresh wallet, lock, mint, transfer, burn, redeem, claim. --out receives:
  cycles.jsonl   one line per step of every cycle (worker, cycle, step, seconds, ok, error)
  samples.jsonl  one line per --interval: this generation's containers (docker stats) and its file system
  summary.json   round trips completed and failed, worker crashes, step latencies, each service's peak memory and CPU against its limit, the disk growth

A failed cycle is recorded and its wallet is kept in GENERATION/bridge (it may hold a lock); the worker goes on, and stops after --max-failures failures in a row. Wallets and
key files are named per run, so a kept wallet cannot collide with a later run. The exit code is 1 if any cycle failed, any worker crashed, no round trip completed, or the vault
does not hold exactly the locks of the failed cycles. A mismatch after a failed cycle may mean a transaction landed after its step failed: check the kept wallet.

Keys and wallets stay in GENERATION/bridge, never in --out. The key files are deleted when the run ends; init copies the EVM key into the wallet's keys.json (0600), so a kept
wallet still holds its key. It does not check the vault's whole event log: run rehearse_bridge.py --stages custody after it.

What the numbers are: only this generation's containers are sampled. The one-shot tester containers that generate the load share the host and are not in the samples, and the
disk figure is the whole file system's, so it means something only under the host lock.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

from rehearse_bridge import TESTER_LOCK_WEI, BridgeRehearsal

# The lock comes back with the claim, so this only pays gas. A round trip cost about 0.23 test UCT at M=8 on the host and the price rises with load, so 20 minutes at
# about 29 cycles a worker need about 7. What a worker does not spend is stranded with its deleted key, and the faucet starts with 1000: 15 leaves about twice the need,
# and three runs of M=1, 4 and 8 fit one generation. Repeat runs: check the faucet and pass --funds.
WORKER_FUNDS = 15 * 10 ** 18
TRANSFERS = 2
UNITS = {'B': 1, 'KiB': 2 ** 10, 'MiB': 2 ** 20, 'GiB': 2 ** 30, 'TiB': 2 ** 40, 'kB': 10 ** 3, 'MB': 10 ** 6, 'GB': 10 ** 9, 'TB': 10 ** 12}


def size_bytes(text):
    """A size as docker stats prints it (`184.5MiB`)."""
    m = re.fullmatch(r'\s*([0-9.]+)\s*([A-Za-z]+)\s*', text)
    if not m or m[2] not in UNITS:
        raise ValueError(f'not a size: {text!r}')
    return float(m[1]) * UNITS[m[2]]


def parse_stats(line):
    """One line of docker stats --format '{{json .}}' as (name, memory bytes, memory limit bytes, CPU percent)."""
    row = json.loads(line)
    used, limit = row['MemUsage'].split('/')
    return row['Name'], size_bytes(used), size_bytes(limit), float(row['CPUPerc'].rstrip('%'))


def summarize(steps, samples, seconds):
    """The summary of the steps and samples of one run: a pure function of what the files hold."""
    cycles = {(s['worker'], s['cycle']) for s in steps}
    failed = {(s['worker'], s['cycle']) for s in steps if not s['ok']}
    done = [c for c in cycles if c not in failed and any((s['worker'], s['cycle']) == c and s['step'] == 'claim' for s in steps)]
    latency = {}
    for name in dict.fromkeys(s['step'] for s in steps):
        times = sorted(s['seconds'] for s in steps if s['step'] == name and s['ok'])
        if times:
            latency[name] = {'n': len(times), 'p50': round(statistics.median(times), 2), 'p95': round(times[min(len(times) - 1, int(len(times) * 0.95))], 2), 'max': round(times[-1], 2)}
    services = {}
    for sample in samples:
        for name, c in sample['containers'].items():
            s = services.setdefault(name, {'memPeakMiB': 0, 'memLimitMiB': round(c['memLimit'] / 2 ** 20), 'cpuPeakPct': 0})
            s['memPeakMiB'] = max(s['memPeakMiB'], round(c['mem'] / 2 ** 20, 1))
            s['cpuPeakPct'] = max(s['cpuPeakPct'], c['cpuPct'])
    disk = [s['diskUsed'] for s in samples]
    prices = [s['gasPrice'] for s in samples if s.get('gasPrice') is not None]
    growth = disk[-1] - disk[0] if disk else None
    return {'seconds': round(seconds), 'roundTrips': len(done), 'failedCycles': len(failed), 'roundTripsPerMinute': round(len(done) * 60 / seconds, 2) if seconds else 0,
            'workerCrashes': 0, 'gasPriceWei': {'first': prices[0], 'peak': max(prices), 'last': prices[-1]} if prices else None, 'stepSeconds': latency, 'services': services, 'diskGrowthBytes': growth, 'diskGrowthPerRoundTripBytes': round(growth / len(done)) if done and growth is not None else None}


class Load:
    def gas_price(self):
        """What limits a tester's budget. A sample that cannot read it is still a sample."""
        try:
            return int(self.r.call('eth_gasPrice'), 16)
        except Exception:
            return None

    def __init__(self, r, out, duration, interval, max_failures, funds=WORKER_FUNDS):
        self.r, self.out, self.duration, self.interval, self.max_failures, self.funds = r, out, duration, interval, max_failures, funds
        self.lock = threading.Lock()
        self.steps, self.samples = [], []
        self.stop = threading.Event()
        self.stranded = 0
        self.crashes = 0
        self.run_id = secrets.token_hex(3)
        self.cycles_file = (out / 'cycles.jsonl').open('a')
        self.samples_file = (out / 'samples.jsonl').open('a')

    def record(self, row):
        with self.lock:
            self.steps.append(row)
            self.cycles_file.write(json.dumps(row) + '\n')
            self.cycles_file.flush()

    def cycle(self, worker, n, key):
        """One round trip in a fresh wallet. True when the claim is done."""
        work = self.r.gen / 'bridge'
        wallet = f'load-{self.run_id}-w{worker}-c{n}'
        step = 'init'
        locked = False
        start = time.monotonic()
        try:
            (work / wallet).mkdir()
            if os.getuid() == 0:
                os.chown(work / wallet, 10001, 10001)
            for step, args in (('init', ['init', '--config', '/work/public/tester-config.json', '--eth-key-file', '/work/tester.key']), ('lock', ['lock', '--amount', f'{TESTER_LOCK_WEI}wei']),
                               ('mint', ['mint']), ('transfer', ['transfer', '--count', str(TRANSFERS)]), ('burn', ['burn']), ('redeem', ['redeem']), ('claim', ['claim'])):
                start = time.monotonic()
                code, text = self.r.tester(*args, check=False, wallet=wallet, key=key)
                if code != 0:   # the tester's own last line says why: out of funds is the load tool's budget, not the bridge's limit
                    raise RuntimeError(f'the tester failed: {step}: {text.splitlines()[-1] if text else ""}')
                self.record({'worker': worker, 'cycle': n, 'step': step, 'seconds': time.monotonic() - start, 'ok': True})
                locked = locked or step == 'lock'
        except Exception as error:
            self.record({'worker': worker, 'cycle': n, 'step': step, 'seconds': time.monotonic() - start, 'ok': False, 'error': str(error)[:300]})
            if locked:
                with self.lock:
                    self.stranded += 1
            return False
        shutil.rmtree(work / wallet)
        return True

    def worker(self, worker, key, deadline):
        failures, n = 0, 0
        try:
            while time.monotonic() < deadline and failures < self.max_failures:
                n += 1
                failures = 0 if self.cycle(worker, n, key) else failures + 1
        except Exception as error:   # outside any step: it must not leave a smaller run that looks clean
            with self.lock:
                self.crashes += 1
            self.r.say(f'worker {worker} crashed: {type(error).__name__}: {error}')
            return
        if failures >= self.max_failures:
            self.r.say(f'worker {worker} stops after {failures} failures in a row')

    def sample_once(self):
        ids = self.r.bridge_compose('ps', '-q').split()
        out = subprocess.run(['docker', 'stats', '--no-stream', '--format', '{{json .}}', *ids], text=True, capture_output=True).stdout if ids else ''
        containers = {}
        for line in out.splitlines():
            try:
                name, used, limit, cpu = parse_stats(line)
            except (ValueError, KeyError) as error:   # a container starting or stopping prints `--`: only that row is lost
                self.r.say(f'sample row skipped: {error}')
                continue
            containers[name] = {'mem': used, 'memLimit': limit, 'cpuPct': cpu}
        row = {'at': time.time(), 'containers': containers, 'diskUsed': shutil.disk_usage(self.r.gen).used, 'gasPrice': self.gas_price()}
        with self.lock:
            self.samples.append(row)
            self.samples_file.write(json.dumps(row) + '\n')
            self.samples_file.flush()

    def sampler(self):
        while not self.stop.is_set():
            try:
                self.sample_once()
            except Exception as error:   # a lost sample must not end the load; the gap shows in the file
                self.r.say(f'sample failed: {error}')
            self.stop.wait(self.interval)

    def address(self, key):
        """The key's address. cast takes the key on its command line, which a CalledProcessError would print: this failure names no argv."""
        try:
            return self.r.cast_run('wallet', 'address', '--private-key', key)
        except subprocess.CalledProcessError as error:
            raise RuntimeError(f'cast could not derive a worker address (exit {error.returncode})') from None

    def run(self, workers):
        work = self.r.gen / 'bridge'
        keys = []
        try:
            for w in range(1, workers + 1):
                key, name = f'0x{secrets.token_hex(32)}', f'load-{self.run_id}-w{w}.key'
                (work / name).write_text(key + '\n')
                os.chmod(work / name, 0o600)
                if os.getuid() == 0:
                    os.chown(work / name, 10001, 10001)
                keys.append(name)
                self.r.faucet_send(self.address(key), self.funds)
            before = self.r.vault_balance()
            start = time.monotonic()
            sampler = threading.Thread(target=self.sampler)
            sampler.start()
            threads = [threading.Thread(target=self.worker, args=(w + 1, keys[w], start + self.duration)) for w in range(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            seconds = time.monotonic() - start
            self.stop.set()
            sampler.join()
            summary = summarize(self.steps, self.samples, seconds)
            summary['workers'] = workers
            summary['workerCrashes'] = self.crashes
            held = self.r.vault_balance() - before
            summary['vault'] = {'heldAfterRun': held, 'lockedByFailedCycles': self.stranded * TESTER_LOCK_WEI}
            (self.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
            self.r.say(f'round trips {summary["roundTrips"]}, failed cycles {summary["failedCycles"]}, vault held {held}')
            return summary['failedCycles'] == 0 and self.crashes == 0 and summary['roundTrips'] > 0 and held == self.stranded * TESTER_LOCK_WEI
        finally:
            self.stop.set()
            for name in keys:
                (work / name).unlink(missing_ok=True)
            self.cycles_file.close()
            self.samples_file.close()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--generation', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--cast', default='cast')
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--duration', type=float, default=1200, help='seconds; a cycle under way finishes')
    p.add_argument('--interval', type=float, default=5, help='seconds between samples')
    p.add_argument('--max-failures', type=int, default=3)
    p.add_argument('--funds', type=int, default=WORKER_FUNDS, help='wei each worker is funded with: it pays the gas of every cycle')
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    r = BridgeRehearsal(a.generation, a.out, a.cast)
    return 0 if Load(r, a.out, a.duration, a.interval, a.max_failures, a.funds).run(a.workers) else 1


if __name__ == '__main__':
    sys.exit(main())
