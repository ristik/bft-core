#!/usr/bin/env python3
"""Sustained-load generator for the testnet package (TN-1 #433): signed native transfers through the public RPC gateway at a chosen rate.

Signs all transfers up front (foundry's `cast mktx`, offline: the key never leaves this machine and no signing method is used on the node), then submits them
at --rate per second, spread over --ips client addresses (the X-Forwarded-For a trusted proxy would set; omit --ips for a real client address), and waits for
every accepted transfer's receipt. It FAILS when an accepted transfer is not mined successfully, when a request fails other than by the gateway's documented rate
limit (HTTP 429, counted, never retried), or when fewer than --min-accepted transfers were accepted. It measures the package under that load, nothing about a host
unless it runs on that host. A summary JSON is written with --out.
"""
import argparse, http.client, json, statistics, subprocess, sys, time
from urllib.parse import urlsplit


class Client:
    def __init__(self, url):
        u = urlsplit(url)
        self.host, self.port, self.path = u.hostname, u.port or (443 if u.scheme == 'https' else 80), u.path or '/'
        self.tls = u.scheme == 'https'
        self.conn = None

    def post(self, method, params, xff=None):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
        headers = {'Content-Type': 'application/json'}
        if xff:
            headers['X-Forwarded-For'] = xff
        for attempt in (0, 1):   # a kept-alive connection the server closed is reopened once; a refusal is not retried
            try:
                if self.conn is None:
                    self.conn = (http.client.HTTPSConnection if self.tls else http.client.HTTPConnection)(self.host, self.port, timeout=15)
                self.conn.request('POST', self.path, body, headers)
                r = self.conn.getresponse()
                return r.status, r.read().decode(errors='replace')
            except (http.client.HTTPException, OSError) as e:
                self.conn = None
                if attempt:
                    return 0, type(e).__name__
        return 0, 'unreachable'


def result(client, method, params, xff=None):
    status, text = client.post(method, params, xff)
    if status != 200:
        raise RuntimeError(f'{method}: HTTP {status} {text[:120]}')
    body = json.loads(text)
    if 'error' in body:
        raise RuntimeError(f'{method}: {body["error"]}')
    return body['result']


def cast_signer(cast, keystore, password_file, chain_id):
    def sign(to, nonce, price, value=1):
        return subprocess.run([cast, 'mktx', '--keystore', keystore, '--password-file', password_file, '--legacy', '--nonce', str(nonce), '--gas-price', str(price),
                               '--gas-limit', '21000', '--chain', str(chain_id), '--value', str(value), to], check=True, text=True, capture_output=True).stdout.strip()
    return sign


def run(client, sender, sign, rate, duration, ips, ip_prefix, recipients, receipt_wait, min_accepted, clock=time.monotonic, sleep=time.sleep):
    count = int(rate * duration)
    first = f'{ip_prefix}1' if ips else None
    nonce = int(result(client, 'eth_getTransactionCount', [sender, 'pending'], first), 16)
    price = int(result(client, 'eth_gasPrice', [], first), 16)
    targets = ['0x%040x' % (0xA0000 + i % recipients) for i in range(count)]
    raws = [sign(targets[i], nonce + i, price) for i in range(count)]
    accepted, limited, errors, latency = {}, 0, [], []
    start = clock()
    for i, raw in enumerate(raws):
        due = start + i / rate
        if clock() < due:
            sleep(due - clock())
        xff = f'{ip_prefix}{1 + i % ips}' if ips else None
        t = clock()
        for attempt in range(20):   # a rate-limited submission is counted and resubmitted: a dropped nonce would strand every later transfer
            status, text = client.post('eth_sendRawTransaction', [raw], xff)
            if status != 429:
                break
            limited += 1
            sleep(0.2)
        latency.append(clock() - t)
        if status == 200 and 'error' not in json.loads(text):
            accepted[json.loads(text)['result']] = t - start
        else:
            errors.append(f'tx {i}: HTTP {status} {text[:120]}')
    sent_span = clock() - start
    # the receipts are fetched once each, paced under the per-address limit; first wait (one cheap call a second) until the sender's account has taken them all
    mined, failed, deadline = {}, set(), clock() + receipt_wait
    while int(result(client, 'eth_getTransactionCount', [sender, 'latest'], first), 16) < nonce + len(accepted) and clock() < deadline:
        sleep(1)
    drained = clock() - start - sent_span
    per_second = 8 * max(ips, 1)
    for k, h in enumerate(accepted):
        if clock() >= deadline:
            break
        if k and k % per_second == 0:
            sleep(1)
        r = result(client, 'eth_getTransactionReceipt', [h], f'{ip_prefix}{1 + k % ips}' if ips else None)
        if r and r['status'] == '0x1':
            mined[h] = True
        elif r:
            failed.add(h)
    missing = [h for h in accepted if h not in mined and h not in failed]
    summary = {'rate_requested': rate, 'rate_achieved': round(len(raws) / sent_span, 2) if sent_span else None, 'ips': ips, 'submitted': len(raws),
               'accepted': len(accepted), 'rate_limited_429': limited, 'errors': len(errors), 'mined_ok': len(mined), 'mined_failed': len(failed),
               'not_mined_in_time': len(missing), 'submit_latency_s': {'p50': round(statistics.median(latency), 4), 'max': round(max(latency), 4)} if latency else {},
               'drained_after_last_submit_s': round(drained, 2)}
    problems = [*errors[:5], *([f'{len(failed)} accepted transfers mined with a failed status'] if failed else []),
                *([f'{len(missing)} accepted transfers not mined within {receipt_wait} s'] if missing else []),
                *([f'only {len(accepted)} accepted, wanted at least {min_accepted}'] if len(accepted) < min_accepted else [])]
    return summary, problems


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--rpc', required=True)
    p.add_argument('--chain-id', type=int, required=True)
    p.add_argument('--sender', required=True, help='address of the funded keystore account')
    p.add_argument('--keystore', required=True)
    p.add_argument('--password-file', required=True)
    p.add_argument('--cast', default='cast')
    p.add_argument('--rate', type=float, default=8, help='transfers per second in total (gateway limits: 10/s per client address, 100/s overall)')
    p.add_argument('--duration', type=float, default=30, help='seconds')
    p.add_argument('--ips', type=int, default=0, help='spread over this many client addresses via X-Forwarded-For (only behind a trusted proxy peer)')
    p.add_argument('--ip-prefix', default='203.0.113.')
    p.add_argument('--recipients', type=int, default=16)
    p.add_argument('--receipt-wait', type=int, default=180)
    p.add_argument('--min-accepted', type=int, default=1)
    p.add_argument('--out')
    a = p.parse_args(argv)
    summary, problems = run(Client(a.rpc), a.sender, cast_signer(a.cast, a.keystore, a.password_file, a.chain_id), a.rate, a.duration, a.ips, a.ip_prefix,
                            a.recipients, a.receipt_wait, a.min_accepted)
    summary['problems'] = problems
    print(json.dumps(summary, indent=2))
    if a.out:
        open(a.out, 'w').write(json.dumps(summary, indent=2) + '\n')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
