#!/usr/bin/env python3
"""Interrupt a private four-root handoff after one endorsement, or endorse all.

Thin adapter for the loopback plan/intent/endorse APIs used by `ubft root
handoff propose`. It leaves durable target evidence for `ubft root handoff abort`.
No process management, retries of a different attempt, or state-file edits.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request


def post(url, route, body):
    request = urllib.request.Request(
        url + '/api/v1/handoff/' + route,
        json.dumps(body).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read(1 << 20)
        return json.loads(raw) if raw else None


def write(directory, name, data):
    (directory / name).write_text(json.dumps(data, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--next-trust-base', required=True, type=Path)
    parser.add_argument('--root-rpc', required=True, help='exactly four loopback URLs')
    parser.add_argument('--out', required=True, type=Path, help='new evidence directory')
    parser.add_argument('--endorse-all', action='store_true', help='allow H to commit')
    args = parser.parse_args()
    urls = [url.rstrip('/') for url in args.root_rpc.split(',')]
    if len(set(urls)) != 4:
        parser.error('this fixture requires four distinct root RPC URLs')
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
                or parsed.path or parsed.query or parsed.fragment
                or parsed.username or parsed.password or not parsed.port):
            parser.error('only http://127.0.0.1:PORT URLs are supported')
    next_trust = json.loads(args.next_trust_base.read_text())
    if next_trust['epoch'] != 2 or len(next_trust['rootNodes']) != 4:
        parser.error('this interruption fixture requires four roots and successor epoch 2')
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    print('STEP: record current context and request a same-members epoch-2 plan', flush=True)
    context = post(urls[0], 'evm-assignment/context', {})
    write(args.out, 'context.json', context)
    if context['acknowledgementPending']:
        raise RuntimeError('an assignment acknowledgement is pending')
    plan = post(urls[0], 'plan', {'nextTrustBase': next_trust})
    write(args.out, 'plan.json', plan)
    if plan['Attempt'] != context['attempt']:
        raise RuntimeError('context changed; preserve evidence and inspect current attempt')
    predecessor = bytes.fromhex(context['predecessor'].removeprefix('0x'))
    body = base64.b64decode(plan['Body'], validate=True)
    if len(predecessor) != 32 or not body:
        raise RuntimeError('invalid predecessor or canonical body')
    # evmroot.TrustBaseBodyV2.Identity is SHA-256 of these canonical body bytes.
    target = dict(network=context['network'], oldEpoch=1,
                  predecessorBodyId='0x' + predecessor.hex(),
                  attempt=plan['Attempt'], nextBodyId='0x' + hashlib.sha256(body).hexdigest())
    write(args.out, 'target.json', target)
    wire_target = dict(target)
    for field in ('predecessorBodyId', 'nextBodyId'):
        wire_target[field] = base64.b64encode(bytes.fromhex(target[field][2:])).decode()
    write(args.out, 'target-wire.json', wire_target)
    print('STEP: distribute intent; wait for Prepare and endorse one root', flush=True)
    for url in urls[1:]:
        post(url, 'intent', plan)
    # A single endorsement cannot reach the four-unit-weight root quorum.
    deadline = time.monotonic() + 60
    while True:
        try:
            post(urls[0], 'endorse', plan)
            break
        except urllib.error.HTTPError as error:
            diagnostic = error.read().decode(errors='replace')
            if 'before the handoff is prepared' not in diagnostic or time.monotonic() >= deadline:
                raise RuntimeError(diagnostic) from error
            time.sleep(0.2)
    if args.endorse_all:
        print('STEP: endorse the remaining roots; H may now commit', flush=True)
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(post, url, 'endorse', plan) for url in urls[1:]]
            for future in futures:
                try:
                    future.result()
                    results.append({'accepted': True})
                except urllib.error.HTTPError as error:
                    results.append({'accepted': False, 'error': error.read().decode(errors='replace')})
        write(args.out, 'endorsements.json', results)
        if 1 + sum(result['accepted'] for result in results) < 3:
            raise RuntimeError('fewer than three roots endorsed; inspect the exact saved target')
        expected = 'too_late'
    else:
        expected = 'pending'
    # The status endpoint authenticates all target fields against committed control.
    deadline = time.monotonic() + 60
    while True:
        status = post(urls[0], 'abort/status', wire_target)
        write(args.out, 'status.json', status)
        if status['state'] == expected:
            break
        if time.monotonic() >= deadline or status['state'] not in ('pending', expected):
            raise RuntimeError('unexpected or timed-out control state: ' + status['state'])
        time.sleep(0.2)
    print('PASS: authenticated target is ' + expected + '; evidence: ' + str(args.out), flush=True)
    if not args.endorse_all:
        print('Run the documented Abort immediately; Prepare can lapse after 24 root rounds.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        raise SystemExit('STOP: ' + str(error))
