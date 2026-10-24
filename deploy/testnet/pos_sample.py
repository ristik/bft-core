#!/usr/bin/env python3
"""The PoS extension of the observation sampler (TN-S #430): the same samples as observe.py plus, for a generation made with generate.py --pos, the contracts' own clock and
books read through the public gateway: the registry's `progress()`, `ucTime()` and `recordCount()`, the custody's `recordCursor()`, the election's `thresholds()`, `openResult()`
and `liveCount()`, and the reward pool's balance, `available()`, `totalCredits()`, `accounted()` and `nextStart()`.

It only reads (eth_call and eth_getBalance; no key, credential or signing method) and reuses observe.collect and observe.Watch unchanged. The alerts it adds, on top of
observe's: the registry progress stopped for --stall seconds; the custody behind the registry's record count for more than --lag seconds; an election result open for more than
--open-limit seconds (a reserved candidate nobody acknowledged: while it is open the reward pool closes the tail only up to the reservation progress, contracts#72); the pool
holding less than it has accounted for; the pool's funded balance at zero (exhausted); a view that cannot be read. Wei amounts are decimal strings in the JSONL (JSON numbers lose
precision in some readers).

Run as `python3 deploy/testnet/pos_sample.py $G --out DIR [--interval 60] [--duration 86400 | --samples N] [--no-faucet]`. A rehearsal runner has no signer: use --no-faucet.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_ops   # noqa: E402
import observe   # noqa: E402

REGISTRY = '0xff00000000000000000000000000000000000002'
# the 4-byte selectors (`cast sig`); test_package pins them against cast when it is installed
SELECTORS = {
    'progress': '0x577bd336', 'ucTime': '0x88fe2650', 'recordCount': '0x900407bc', 'recordCursor': '0xca01c983', 'openResult': '0x5552dcb8',
    'thresholds': '0xcda43b3a', 'liveCount': '0xfc474d62', 'available': '0x48a0d754', 'totalCredits': '0xb5bd3eb9', 'accounted': '0x19f8dcf1', 'nextStart': '0x25ce3eee',
}
ZERO_WORD = '00' * 32


GAP = 0.12        # seconds between two gateway calls: the gateway answers 429 above 10 requests per second per client address (a sample makes a dozen)
RETRIES = 5
_last = [0.0]


def eth(method, params):
    """The result of one JSON-RPC call through the gateway (with the forwarded address it requires), or raises ValueError naming the refusal. Calls are spaced by GAP
    and a 429 is retried after a second, as the rehearsal's own client does (the first live run of the sampler found 429s in a burst)."""
    for attempt in range(RETRIES + 1):
        wait = _last[0] + GAP - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        status, text = observe.get(observe.PUBLIC_RPC, '/', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}), headers={'X-Forwarded-For': observe.CLIENT_IP})
        _last[0] = time.monotonic()
        if status != 429 or attempt == RETRIES:
            break
        time.sleep(1)
    try:
        body = json.loads(text)
    except ValueError:
        raise ValueError(f'{method}: {status} {text[:80]}')
    if status != 200 or 'result' not in body:
        raise ValueError(f'{method}: {status} {json.dumps(body.get("error", body))[:120]}')
    return body['result']


def words(result):
    """The 32-byte words of an eth_call result, as hex strings without the prefix."""
    raw = result[2:] if result.startswith('0x') else result
    if len(raw) == 0 or len(raw) % 64:
        raise ValueError(f'a result of {len(raw) // 2} bytes is not whole words')
    return [raw[i:i + 64] for i in range(0, len(raw), 64)]


def view(to, name, count=1):
    """The `count` words a no-argument view of `to` returns."""
    out = words(eth('eth_call', [{'to': to, 'data': SELECTORS[name]}, 'latest']))
    if len(out) != count:
        raise ValueError(f'{name} returned {len(out)} words, not {count}')
    return out


def number(word):
    return int(word, 16)


def pos_collect(generation):
    """The PoS part of one sample. A view that cannot be read is recorded under `errors`, not raised: an unreadable chain is a finding."""
    deployment = json.loads((Path(generation) / 'network' / 'pos-deployment.json').read_text())
    custody, election, pool = deployment['custody'], deployment['election'], deployment['rewardPool']
    out, errors = {}, []
    def get(key, fn):
        try:
            out[key] = fn()
        except (ValueError, OSError) as error:
            errors.append(f'{key}: {str(error)[:140]}')
    get('progress', lambda: number(view(REGISTRY, 'progress')[0]))
    get('ucTime', lambda: number(view(REGISTRY, 'ucTime')[0]))
    get('recordCount', lambda: number(view(REGISTRY, 'recordCount')[0]))
    get('recordCursor', lambda: number(view(custody, 'recordCursor')[0]))
    get('liveCount', lambda: number(view(election, 'liveCount')[0]))
    get('thresholds', lambda: [str(number(w)) for w in view(election, 'thresholds', 2)])
    def open_result():
        word = view(election, 'openResult')[0]
        return None if word == ZERO_WORD else '0x' + word
    get('openResult', open_result)
    books = {}
    for key in ('available', 'totalCredits', 'accounted', 'nextStart'):
        try:
            books[key] = str(number(view(pool, key)[0]))
        except (ValueError, OSError) as error:
            errors.append(f'pool {key}: {str(error)[:140]}')
    try:
        books['balance'] = str(int(eth('eth_getBalance', [pool, 'latest']), 16))
    except (ValueError, OSError) as error:
        errors.append(f'pool balance: {str(error)[:140]}')
    out['pool'] = books
    out['errors'] = errors
    return out


class PosWatch:
    """The PoS alerts: what a sample's `pos` part says against the same part earlier."""

    def __init__(self, stall=120, lag=300, open_limit=3600):
        self.stall, self.lag, self.open_limit = stall, lag, open_limit
        self.best = None
        self.moved_at = None
        self.behind_since = None
        self.open_since = {}
        self.funded = False   # the pool was seen with a funded balance: only then is 0 an exhaustion, not an unfunded pool

    def step(self, pos, at):
        alerts = [f'unreadable: {e}' for e in pos.get('errors', [])]
        progress = pos.get('progress')
        if progress is not None:
            if self.best is None or progress > self.best:
                self.best, self.moved_at = progress, at
            elif at - self.moved_at >= self.stall:
                alerts.append(f'the registry progress stopped at {self.best} for {int(at - self.moved_at)} s')
        count, cursor = pos.get('recordCount'), pos.get('recordCursor')
        if count is not None and cursor is not None:
            if cursor > count:
                alerts.append(f'the custody cursor {cursor} is past the registry record count {count}')
            if cursor < count:
                if self.behind_since is None:
                    self.behind_since = at
                if at - self.behind_since >= self.lag:
                    alerts.append(f'the custody is behind the registry ({cursor} of {count} records) for {int(at - self.behind_since)} s')
            else:
                self.behind_since = None
        if 'openResult' in pos:
            result = pos['openResult']
            if result is None:
                self.open_since.clear()
            else:
                self.open_since.setdefault(result, at)
                if at - self.open_since[result] >= self.open_limit:
                    alerts.append(f'election result {result[:18]}.. open for {int(at - self.open_since[result])} s')
        books = pos.get('pool', {})
        if 'balance' in books and 'accounted' in books and int(books['balance']) < int(books['accounted']):
            alerts.append(f'the reward pool holds {books["balance"]} wei, less than the {books["accounted"]} it has accounted for')
        if books.get('available') not in (None, '0'):
            self.funded = True
        elif books.get('available') == '0' and self.funded:
            alerts.append('the reward pool has no funded balance left (available 0 after it was funded)')
        return alerts


def pos_observe(r):
    """Rehearsal stage `pos-observe`: the sampler run for two samples against the running PoS package (after pos-smoke), as an operator would start it. It exits 0 (no
    alert) and every sample carries the contracts' views as numbers; the record cursor equals the record count and the pool holds exactly its balance books."""
    out = r.evidence / 'pos-observe'
    run = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(r.gen), '--out', str(out), '--samples', '2', '--interval', '5', '--no-faucet', '--stall', '3600'],
                         text=True, capture_output=True)
    r.say('  pos_sample: exit %d: %s' % (run.returncode, ' | '.join((run.stdout + run.stderr).strip().splitlines()[-4:])))
    r.expect(run.returncode == 0, 'the sampler runs and raises no alert on the running package', (run.stdout + run.stderr).strip()[-400:])
    rows = [json.loads(line) for line in (out / 'samples.jsonl').read_text().splitlines()]
    r.expect(len(rows) == 2, 'two samples were written', str(len(rows)))
    for row in rows:
        pos = row['pos']
        r.expect(not pos['errors'], 'every contract view was readable', str(pos['errors']))
        r.expect(isinstance(pos['progress'], int) and pos['progress'] > 0 and pos['recordCursor'] == pos['recordCount'], 'the sample has the registry clock and a caught-up custody', json.dumps(pos)[:200])
        r.expect(int(pos['pool']['balance']) >= int(pos['pool']['accounted']) > 0, 'the pool holds at least what it has accounted for', json.dumps(pos['pool']))
    r.expect(rows[1]['pos']['progress'] >= rows[0]['pos']['progress'], 'the registry progress did not go backwards', f"{rows[0]['pos']['progress']} -> {rows[1]['pos']['progress']}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('generation', type=Path)
    p.add_argument('--out', type=Path, required=True, help='directory for samples.jsonl and summary.json')
    p.add_argument('--interval', type=float, default=60)
    g = p.add_mutually_exclusive_group()
    g.add_argument('--duration', type=float, default=86400, help='seconds (default 24 h)')
    g.add_argument('--samples', type=int)
    p.add_argument('--stall', type=float, default=120, help='seconds without any root (or the registry progress) moving before it counts as stopped')
    p.add_argument('--lag', type=float, default=300, help='seconds the custody may stay behind the registry record count')
    p.add_argument('--open-limit', type=float, default=3600, help='seconds an election result may stay open')
    p.add_argument('--disk-limit', type=float, default=80)
    p.add_argument('--no-faucet', action='store_true', help='do not sample the faucet guard (its /healthz needs the signer, which a rehearsal does not start)')
    a = p.parse_args()
    if not (a.generation / 'network' / 'pos-deployment.json').exists():
        p.error('the generation has no network/pos-deployment.json: it was not made with generate.py --pos (use observe.py)')
    a.out.mkdir(parents=True, exist_ok=True)
    transport = handoff_ops.DockerTransport(a.generation)
    watch, pos_watch, alerts, start, n = observe.Watch(a.stall, a.disk_limit), PosWatch(a.stall, a.lag, a.open_limit), [], time.monotonic(), 0
    with (a.out / 'samples.jsonl').open('a') as out:
        while True:
            at = time.monotonic() - start
            sample = observe.collect(a.generation, transport, faucet=not a.no_faucet)
            sample['pos'] = pos_collect(a.generation)
            raised = watch.step(sample, at) + pos_watch.step(sample['pos'], at)
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
    summary = {'samples': n, 'interval': a.interval, 'alerts': alerts, 'best_round': watch.best, 'best_progress': pos_watch.best}
    (a.out / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(json.dumps(summary))
    raise SystemExit(1 if alerts else 0)


if __name__ == '__main__':
    main()
