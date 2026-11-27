#!/usr/bin/env python3
"""Observation sampler for the testnet package (TN-1 #428/#434/#433): the minute-by-minute sampling the README's "Observation/fault campaign" asks for.

One sample per --interval, for --duration (or --samples): every root's certified head (epoch and round, from the root's own q3/signers through the same read-only
sidecar the handoff wrapper uses), the public gateway's /healthz and block number, the faucet guard's /healthz, every service's state, health and restart count, the
containers' memory and the disk use of the generation's filesystem. Each sample is one line of JSONL; the summary lists every ALERT and the exit code is 1 if there is
any (a failure is recorded as a failure). Alerts follow the README's notification rules: certified heads stopped for --stall seconds (no root's round moved), a
service not running or unhealthy, a restart count that went up, disk above --disk-limit percent, the gateway or faucet not answering 200; and, to see a starving
shard before it stalls (#1018): a container's memory above --mem-limit percent of its limit for --mem-samples samples in a row while its tasks stall on
memory (cgroup memory pressure, full avg60, at least --mem-pressure percent; page cache alone fills a limit without stalling anyone), an OOM kill in a
container, and the chain's block rate over the last --rate-window seconds below --rate-drop of the median of such rates seen after the first --rate-warmup
seconds (a catch-up burst, when sampling starts or later, is not the chain's rate).

It only reads: no key, no credential, no signing method. The faucet's budget and balance are in its /healthz body, kept as text in the sample for the operator to
compare with the reserve; this tool does not interpret them. It measures the package where it runs, nothing about a host unless it runs on that host.
"""
import argparse
import collections
import http.client
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_ops   # noqa: E402

PUBLIC_RPC = '127.0.0.1:8545'
FAUCET = '127.0.0.1:8088'
CLIENT_IP = '203.0.113.200'   # documentation range (RFC 5737)


def get(host, path, body=None, timeout=10, headers=None):
    """(status, text); a refusal is a status, an unreachable server is status 0 with the reason."""
    conn = http.client.HTTPConnection(host, timeout=timeout)
    try:
        conn.request('POST' if body is not None else 'GET', path, body=body, headers=dict({'Content-Type': 'application/json'} if body is not None else {}, **(headers or {})))
        r = conn.getresponse()
        return r.status, r.read().decode(errors='replace')
    except (http.client.HTTPException, OSError) as error:
        return 0, type(error).__name__
    finally:
        conn.close()


def ps_rows(text):
    """The rows of `docker compose ps --format json`: one JSON object per line on some Compose v2 versions, one JSON array on others."""
    text = text.strip()
    if not text:
        return []
    if text.startswith('['):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip().startswith('{')]


def collect(generation, transport, now=time.time, faucet=True):
    """One sample of the running generation."""
    compose = ['docker', 'compose', '-f', str(Path(generation) / 'compose.yaml')]
    sample = {'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now())), 'roots': {}, 'services': {}}
    for i in transport.entities:
        try:
            status, body = transport.post(i, '/api/v1/q3/signers', b'{}')
            head = json.loads(body) if status == 200 else None
            sample['roots'][str(i)] = {'epoch': head['epoch'], 'round': head['round']} if head else {'status': status}
        except (handoff_ops.HandoffError, ValueError, KeyError, subprocess.SubprocessError) as error:
            sample['roots'][str(i)] = {'error': str(error)[:200]}
    ps = subprocess.run(compose + ['ps', '-a', '--format', 'json'], text=True, capture_output=True)
    for row in ps_rows(ps.stdout):
        restarts, _, ident = subprocess.run(['docker', 'inspect', '--format', '{{.RestartCount}} {{.Id}}', row['ID']], text=True, capture_output=True).stdout.strip().partition(' ')
        sample['services'][row['Service']] = {'state': row.get('State'), 'health': row.get('Health') or None, 'restarts': int(restarts) if restarts.isdigit() else None}
        if ident:
            sample.setdefault('cgroup', {})[row.get('Name') or row['Service']] = cgroup_memory(ident)
    config = json.loads((Path(generation) / 'compose.yaml').read_text())
    # the services Compose declares and this sampler expects to run: a missing one is an alert (no container at all would otherwise leave no row to judge)
    sample['missing'] = sorted(set(config['services']) - set(sample['services']) - (set() if faucet else {'signer'}))
    stats = subprocess.run(['docker', 'stats', '--no-stream', '--format', '{{.Name}}\t{{.MemUsage}}'], text=True, capture_output=True)   # host-wide: keep this project's containers
    sample['memory'] = {k: v for k, v in (line.split('\t', 1) for line in stats.stdout.splitlines() if '\t' in line) if k.startswith(config['name'] + '-')}
    usage = shutil.disk_usage(generation)
    sample['disk_percent'] = round(100 * usage.used / usage.total, 1)
    status, text = get(PUBLIC_RPC, '/healthz')
    sample['gateway'] = {'healthz': status}
    # the gateway trusts the client address only from its proxy peer with X-Forwarded-For (nginx sets it in front; here a documentation address stands in, as the rehearsal does)
    status, text = get(PUBLIC_RPC, '/', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_blockNumber', 'params': []}), headers={'X-Forwarded-For': CLIENT_IP})
    try:
        sample['gateway']['block'] = int(json.loads(text)['result'], 16) if status == 200 else None
    except (ValueError, KeyError, TypeError):
        sample['gateway']['block'] = None
    if sample['gateway']['block'] is None:
        sample['gateway']['block_status'] = f'{status} {text[:120]}'
    if faucet:
        status, text = get(FAUCET, '/healthz')
        sample['faucet'] = {'healthz': status, 'body': text[:300]}
    return sample


def cgroup_memory(ident, root='/sys/fs/cgroup'):
    """A container's memory pressure (PSI 'full avg60', percent) and OOM kill count from its cgroup v2 files, None where they cannot be read (another
    cgroup driver or version, or not this host's container)."""
    out = {'pressure_full_avg60': None, 'oom_kill': None}
    for d in (Path(root) / 'system.slice' / f'docker-{ident}.scope', Path(root) / 'docker' / ident):
        try:
            for line in (d / 'memory.pressure').read_text().splitlines():
                if line.startswith('full '):
                    out['pressure_full_avg60'] = float(dict(kv.split('=', 1) for kv in line.split()[1:])['avg60'])
            for line in (d / 'memory.events').read_text().splitlines():
                if line.startswith('oom_kill '):
                    out['oom_kill'] = int(line.split()[1])
            return out
        except (OSError, ValueError, KeyError, IndexError):
            continue
    return out


UNITS = {'B': 1, 'KiB': 1 << 10, 'MiB': 1 << 20, 'GiB': 1 << 30, 'TiB': 1 << 40, 'kB': 10 ** 3, 'KB': 10 ** 3, 'MB': 10 ** 6, 'GB': 10 ** 9, 'TB': 10 ** 12}


def memory_use(text):
    """(used, limit) in bytes from a `docker stats` MemUsage such as '1.5GiB / 2GiB', or None if it does not read as one."""
    sizes = []
    for part in text.split('/'):
        m = re.fullmatch(r'\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)\s*', part)
        if not m or m.group(2) not in UNITS:
            return None
        sizes.append(float(m.group(1)) * UNITS[m.group(2)])
    return tuple(sizes) if len(sizes) == 2 else None


class Watch:
    """The state the alerts compare a sample with: the best round seen and when it last moved, the restart counts, and the gateway's blocks over the
    last rate window with the block rates seen."""

    def __init__(self, stall=120, disk_limit=80, mem_limit=90, rate_window=3600, rate_drop=0.5, mem_samples=5, mem_pressure=1.0, rate_warmup=None):
        self.stall, self.disk_limit, self.mem_limit, self.rate_window, self.rate_drop = stall, disk_limit, mem_limit, rate_window, rate_drop
        self.mem_samples, self.mem_pressure = mem_samples, mem_pressure
        self.rate_warmup = rate_window if rate_warmup is None else rate_warmup
        self.started = None
        self.near = {}   # container -> samples in a row above mem_limit
        self.ooms = {}   # container -> its last OOM kill count
        self.best = None
        self.moved_at = None
        self.best_block = None
        self.block_moved_at = None
        self.restarts = {}
        self.blocks = collections.deque()   # (at, block), from the newest sample at least rate_window old
        self.rates = collections.deque(maxlen=20000)   # the window rates seen after the warm-up, for their median

    def step(self, sample, at):
        """The alerts this sample raises. `at` is the sample's time in seconds (any monotonic origin)."""
        alerts = []
        rounds = [r['round'] for r in sample['roots'].values() if 'round' in r]
        for i, r in sample['roots'].items():
            if 'round' not in r:
                alerts.append(f'root {i} gave no certified head: {json.dumps(r)}')
        if rounds and (self.best is None or max(rounds) > self.best):
            self.best, self.moved_at = max(rounds), at
        elif self.moved_at is None:
            self.moved_at = at
        if at - self.moved_at >= self.stall:
            alerts.append(f'certified heads stopped: no root moved past round {self.best} for {int(at - self.moved_at)} s')
        # the roots keep certifying while a stuck execution shard does not: the README's rule is the roots AND the certified shard heads, here the gateway's block
        block = sample['gateway'].get('block')
        if block is None:
            alerts.append(f'the gateway block is unreadable: {sample["gateway"].get("block_status", "no status")}')
        if block is not None and (self.best_block is None or block > self.best_block):
            self.best_block, self.block_moved_at = block, at
        elif self.block_moved_at is None:
            self.block_moved_at = at
        if at - self.block_moved_at >= self.stall:
            alerts.append(f'the execution chain stopped: no block past {self.best_block} for {int(at - self.block_moved_at)} s')
        # a falling block rate comes hours before a stall (#1018: 2800/h fell to 350/h over four hours of a starving shard)
        if self.started is None:
            self.started = at
        if block is not None:
            self.blocks.append((at, block))
            while len(self.blocks) > 1 and self.blocks[1][0] <= at - self.rate_window:
                self.blocks.popleft()
            since, first = self.blocks[0]
            if at - since >= self.rate_window and since - self.started >= self.rate_warmup:
                rate = (block - first) * 3600 / (at - since)
                usual = sorted(self.rates)[len(self.rates) // 2] if self.rates else None
                if usual and rate < self.rate_drop * usual:
                    alerts.append(f'the block rate fell to {rate:.0f}/h over the last {int(at - since)} s, below {self.rate_drop:.0%} of the usual {usual:.0f}/h')
                self.rates.append(rate)
        cgroups = sample.get('cgroup', {})
        for name, usage in sorted(sample.get('memory', {}).items()):
            use = memory_use(usage)
            near = bool(use and use[1] > 0 and 100 * use[0] / use[1] > self.mem_limit)
            self.near[name] = self.near.get(name, 0) + 1 if near else 0
            pressure = cgroups.get(name, {}).get('pressure_full_avg60')
            # docker's figure counts page cache, which can sit at the limit for a whole run: only a limit its tasks stall on is an alert
            if self.near[name] >= self.mem_samples and (pressure is None or pressure >= self.mem_pressure):
                stalled = 'unknown' if pressure is None else f'{pressure:g}%'
                alerts.append(f'{name} memory {usage.strip()} is above {self.mem_limit:g}% of its limit for {self.near[name]} samples (memory pressure, full avg60: {stalled})')
        for name, c in sorted(cgroups.items()):
            oom = c.get('oom_kill')
            before = self.ooms.get(name)
            if oom is not None and before is not None and oom > before:
                alerts.append(f'{name} had {oom - before} OOM kill(s)')
            if oom is not None:
                self.ooms[name] = oom
        for name in sample.get('missing', []):
            alerts.append(f'{name} has no container')
        for name, s in sorted(sample['services'].items()):
            if s['state'] != 'running':
                alerts.append(f'{name} is {s["state"]}')
            elif s['health'] not in (None, 'healthy'):
                alerts.append(f'{name} is {s["health"]}')
            if s['restarts'] is not None:
                before = self.restarts.get(name)
                if before is not None and s['restarts'] > before:
                    alerts.append(f'{name} restarted ({before} -> {s["restarts"]})')
                self.restarts[name] = s['restarts']
        if sample['disk_percent'] > self.disk_limit:
            alerts.append(f'disk {sample["disk_percent"]}% above {self.disk_limit}%')
        if sample['gateway']['healthz'] != 200:
            alerts.append(f'the gateway /healthz answered {sample["gateway"]["healthz"]}')
        if 'faucet' in sample and sample['faucet']['healthz'] != 200:
            alerts.append(f'the faucet /healthz answered {sample["faucet"]["healthz"]}')
        return alerts


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('generation', type=Path)
    p.add_argument('--out', type=Path, required=True, help='directory for samples.jsonl and summary.json')
    p.add_argument('--interval', type=float, default=60)
    g = p.add_mutually_exclusive_group()
    g.add_argument('--duration', type=float, default=86400, help='seconds (default 24 h)')
    g.add_argument('--samples', type=int)
    p.add_argument('--stall', type=float, default=120, help='seconds without any root moving before the heads count as stopped')
    p.add_argument('--disk-limit', type=float, default=80)
    p.add_argument('--mem-limit', type=float, default=90, help='percent of a container\'s memory limit above which its use is an alert (default 90)')
    p.add_argument('--rate-window', type=float, default=3600, help='seconds over which the block rate is measured (default 3600)')
    p.add_argument('--rate-drop', type=float, default=0.5, help='a block rate below this fraction of the median rate seen is an alert (default 0.5)')
    p.add_argument('--rate-warmup', type=float, default=None, help='seconds from the first sample whose windows are not counted (default: one rate window)')
    p.add_argument('--mem-samples', type=int, default=5, help='samples in a row above --mem-limit before it is an alert (default 5)')
    p.add_argument('--mem-pressure', type=float, default=1.0, help='memory pressure (PSI full avg60, percent) at or above which a container near its limit is starving (default 1.0)')
    p.add_argument('--no-faucet', action='store_true', help='do not sample the faucet guard (its /healthz needs the signer, which a rehearsal does not start)')
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    transport = handoff_ops.DockerTransport(a.generation)
    watch, alerts, start, n = Watch(a.stall, a.disk_limit, a.mem_limit, a.rate_window, a.rate_drop, a.mem_samples, a.mem_pressure, a.rate_warmup), [], time.monotonic(), 0
    with (a.out / 'samples.jsonl').open('a') as out:
        while True:
            at = time.monotonic() - start
            sample = collect(a.generation, transport, faucet=not a.no_faucet)
            raised = watch.step(sample, at)
            sample['alerts'] = raised
            alerts += [f'{sample["time"]} {x}' for x in raised]
            out.write(json.dumps(sample, sort_keys=True) + '\n')
            out.flush()
            n += 1
            for x in raised:
                print(f'ALERT {sample["time"]} {x}', flush=True)
            if (a.samples is not None and n >= a.samples) or (a.samples is None and at + a.interval > a.duration):
                break
            time.sleep(a.interval)
    summary = {'samples': n, 'interval': a.interval, 'alerts': alerts, 'best_round': watch.best}
    (a.out / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(json.dumps(summary))
    raise SystemExit(1 if alerts else 0)


if __name__ == '__main__':
    main()
