#!/usr/bin/env python3
"""Interrupt a private root handoff of the Q3 flow after one endorsement, or endorse all.

The fresh-B1 layout has one handoff flow: a V3 candidate, one readiness receipt per successor entity, a V3 plan. A V2 plan is refused by name
(ErrHandoffNeedsV3Plan). This is the thin adapter for the loopback plan/intent/endorse/abort-status APIs `ubft root handoff propose` uses, driven
with the receipts the lane already produced (`root handoff q3-candidate`, then `q3-readiness` per entity). It leaves the durable target
evidence the documented `ubft root handoff abort` takes. No process management, no retries of a different attempt, no state-file edits.

  --dry-run   validates every input, prints the plan request and the steps, contacts nothing.
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


class Stop(Exception):
    pass


def head(major, n):
    """CBOR initial byte(s) in the shortest (canonical) form."""
    if n < 24:
        return bytes([major << 5 | n])
    for width, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | extra]) + n.to_bytes(width, 'big')
    raise Stop('value too large')


def encode_receipts(receipts):
    """q3format.EncodeReceipts: a definite CBOR array of [nodeId text, signature bytes], strictly ordered by node id."""
    ordered = sorted(receipts, key=lambda r: r['nodeId'].encode())
    names = [r['nodeId'] for r in ordered]
    if not ordered or len(set(names)) != len(names):
        raise Stop('need at least one receipt, and exactly one per entity: ' + ','.join(names))
    out = head(4, len(ordered))
    for r in ordered:
        name, sig = r['nodeId'].encode(), bytes.fromhex(r['signature'].removeprefix('0x'))
        out += head(4, 2) + head(3, len(name)) + name + head(2, len(sig)) + sig
    return out


def read_receipts(paths):
    receipts = []
    for path in paths:
        try:
            data = json.loads(Path(path).read_text())
            receipts.append({'nodeId': data['nodeId'], 'signature': data['signature']})
        except (OSError, ValueError, KeyError) as error:
            raise Stop(f'receipt {path}: {error}')
    return receipts


def quorum(total_weight):
    """The weighted threshold of the lanes' committees (W=9 gives 7, four unit-weight roots give 3)."""
    return total_weight * 2 // 3 + 1


def check_loopback(url):
    parsed = urllib.parse.urlparse(url)
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.path or parsed.query or parsed.fragment
            or parsed.username or parsed.password or not parsed.port):
        raise Stop('only http://127.0.0.1:PORT URLs are supported: ' + url)


def post(url, route, body):
    request = urllib.request.Request(url + '/api/v1/handoff/' + route, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read(1 << 20)
        return json.loads(raw) if raw else None


def write(directory, name, data):
    (directory / name).write_text(json.dumps(data, indent=2) + '\n')


def plan_request(next_trust, receipts):
    return {'nextTrustBase': next_trust, 'q3Receipts': '0x' + encode_receipts(receipts).hex()}


def inputs(args):
    """Everything that can be checked without a root."""
    urls = [url.rstrip('/') for url in args.root_rpc.split(',')]
    if len(urls) < 4 or len(set(urls)) != len(urls):
        raise Stop('this fixture requires at least four distinct root RPC URLs')
    for url in urls:
        check_loopback(url)
    next_trust = json.loads(args.next_trust_base.read_text())
    old_trust = json.loads(args.old_trust_base.read_text())
    if next_trust['epoch'] != old_trust['epoch'] + 1 or next_trust['networkId'] != old_trust['networkId']:
        raise Stop('the successor trust base must be the next epoch of the old one on the same network')
    members = {node['nodeId']: node['stake'] for node in old_trust['rootNodes']}
    if len(members) != len(urls):
        raise Stop(f'{len(urls)} root URLs for {len(members)} old members: list one RPC per old member')
    entities = {node['nodeId'] for node in next_trust['rootNodes']}
    receipts = read_receipts(args.receipts.split(','))
    if {r['nodeId'] for r in receipts} != entities:
        raise Stop('exactly one q3-readiness receipt per successor entity is required: have ' + ','.join(sorted(r['nodeId'] for r in receipts)))
    threshold = quorum(sum(members.values()))
    heaviest = max(members.values())
    if not args.endorse_all and heaviest >= threshold:
        raise Stop(f'one endorsement of weight {heaviest} reaches the quorum {threshold}: the rehearsal could not stay pre-H')
    return urls, next_trust, old_trust, receipts, threshold


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--next-trust-base', required=True, type=Path, help='the V3 candidate trust base (epoch+1, same members, the lane weights)')
    parser.add_argument('--old-trust-base', required=True, type=Path, help='the trust base of the current epoch (sets the quorum and the member count)')
    parser.add_argument('--receipts', required=True, help='comma-separated q3-readiness receipt files, one per successor entity')
    parser.add_argument('--v3-body-id', type=Path, help='v3-body-id.txt of the q3-candidate: the plan must carry exactly that body')
    parser.add_argument('--root-rpc', required=True, help='comma-separated loopback URLs, one per old member; the first plans and endorses alone')
    parser.add_argument('--out', required=True, type=Path, help='new evidence directory')
    parser.add_argument('--endorse-all', action='store_true', help='allow H to commit')
    parser.add_argument('--dry-run', action='store_true', help='validate the inputs and print the plan request; contact nothing')
    args = parser.parse_args(argv)
    urls, next_trust, old_trust, receipts, threshold = inputs(args)
    request = plan_request(next_trust, receipts)
    if args.dry_run:
        print('DRY RUN: inputs valid; no root contacted')
        print(f'STEP: context, V3 plan for epoch {next_trust["epoch"]} with {len(receipts)} receipts ({(len(request["q3Receipts"]) - 2) // 2} bytes), '
              f'quorum weight {threshold}, intent to {len(urls) - 1} roots, endorse at the first root'
              + (' and all others' if args.endorse_all else ' only'))
        print('STEP: abort/status of the saved target; expected ' + ('too_late' if args.endorse_all else 'pending'))
        return 0
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    print('STEP: record current context and request a V3 plan', flush=True)
    context = post(urls[0], 'evm-assignment/context', {})
    write(args.out, 'context.json', context)
    if context['acknowledgementPending']:
        raise Stop('an assignment acknowledgement is pending')
    plan = post(urls[0], 'plan', request)
    write(args.out, 'plan.json', plan)
    if plan['Attempt'] != context['attempt']:
        raise Stop('context changed; preserve evidence and inspect current attempt')
    if not plan.get('Receipts'):
        raise Stop('the plan carries no readiness receipts: not a V3 plan')
    predecessor = bytes.fromhex(context['predecessor'].removeprefix('0x'))
    body = base64.b64decode(plan['Body'], validate=True)
    if len(predecessor) != 32 or not body:
        raise Stop('invalid predecessor or canonical body')
    # q3format.BodyV3.Identity is SHA-256 of the canonical body bytes.
    next_body_id = hashlib.sha256(body).hexdigest()
    if args.v3_body_id and args.v3_body_id.read_text().strip().removeprefix('0x') != next_body_id:
        raise Stop('the plan carries another body than the q3-candidate derived')
    target = dict(network=context['network'], oldEpoch=old_trust['epoch'], predecessorBodyId='0x' + predecessor.hex(),
                  attempt=plan['Attempt'], nextBodyId='0x' + next_body_id)
    write(args.out, 'target.json', target)
    wire_target = dict(target)
    for field in ('predecessorBodyId', 'nextBodyId'):
        wire_target[field] = base64.b64encode(bytes.fromhex(target[field][2:])).decode()
    write(args.out, 'target-wire.json', wire_target)
    print('STEP: distribute intent; wait for Prepare and endorse one root', flush=True)
    for url in urls[1:]:
        post(url, 'intent', plan)
    # One endorsement alone cannot reach the old committee's quorum (checked against the old trust base above).
    deadline = time.monotonic() + 60
    while True:
        try:
            post(urls[0], 'endorse', plan)
            break
        except urllib.error.HTTPError as error:
            diagnostic = error.read().decode(errors='replace')
            if 'before the handoff is prepared' not in diagnostic or time.monotonic() >= deadline:
                raise Stop(diagnostic)
            time.sleep(0.2)
    if args.endorse_all:
        print('STEP: endorse the remaining roots; H may now commit', flush=True)
        others = urls[1:]
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(others)) as pool:
            futures = [pool.submit(post, url, 'endorse', plan) for url in others]
            for future in futures:
                try:
                    future.result()
                    results.append({'accepted': True})
                except urllib.error.HTTPError as error:
                    results.append({'accepted': False, 'error': error.read().decode(errors='replace')})
        write(args.out, 'endorsements.json', results)
        if len(urls) * 2 // 3 + 1 > 1 + sum(result['accepted'] for result in results):
            raise Stop('too few roots endorsed; inspect the exact saved target')
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
            raise Stop('unexpected or timed-out control state: ' + status['state'])
        time.sleep(0.2)
    print('PASS: authenticated target is ' + expected + '; evidence: ' + str(args.out), flush=True)
    if not args.endorse_all:
        print('Run the documented Abort immediately; Prepare can lapse after 24 root rounds.', flush=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, Stop) as error:
        raise SystemExit('STOP: ' + str(error))
