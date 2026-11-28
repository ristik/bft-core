#!/usr/bin/env python3
"""Summarize a private ERC20 run, including incomplete runs."""

import argparse
import hashlib
import json
import math
from pathlib import Path


def read(path):
    return json.loads(path.read_text()) if path.is_file() else None


def certified_call(run, name):
    cost = read(run / (name + '.cost.json'))
    locator = read(run / (name + '.locator.json'))
    receipt = read(run / (name + '.receipt.json'))
    proof = run / (name + '.cbor')
    if not (cost and locator and receipt and proof.is_file() and proof.stat().st_size):
        return None
    index = locator['receiptLogIndex']
    if receipt['status'] != '0x1' or not 0 <= index < len(receipt['logs']):
        return None
    log = receipt['logs'][index]
    if (
        cost['tx'] == locator['transactionHash'] == receipt['transactionHash']
        and cost['blockHash'] == locator['blockHash'] == receipt['blockHash']
        and int(cost['transactionIndex']) == int(locator['transactionIndex']) == int(receipt['transactionIndex'], 16)
        and all(log[key].lower() == locator[key].lower() for key in ('address', 'data'))
        and [topic.lower() for topic in log['topics']] == locator['topics']
    ):
        return {**cost, 'locator': locator}
    return None


PAID_TOPIC = '0x606160394df2742a67735645b7e783304d61d2dbc5b550e8c6acfaf27b6291d7'
GAP_TOPIC = '0x8a46311ac4f3c67db8441654400fcf9d7c6eee13cf1b3a9be2f81679131f7dc3'


def paid(call, vault, amount):
    if call:
        log = call['locator']
        return (log['address'] == vault and len(log['topics']) == 3 and log['topics'][0] == PAID_TOPIC
                and len(log['data']) == 66 and int(log['data'], 16) == amount)
    return False


def payout(run, name, q_delta):
    custody = read(run / (name + '.custody.json'))
    call = certified_call(run, name)
    if (custody and call and int(custody['qDelta']) == q_delta
            and (run / (name + '.signed')).is_file()):
        return {'qDelta': q_delta, **call}
    return None


def uct_control(run):
    result = read(run / 'result.json')
    deployment = read(run / 'deployment.json')
    final = read(run / 'recovered.custody.json')
    if not (result and deployment and final):
        return None
    expected = {'deposit': 100, 'ordinary': 40, 'recovered': 60, 'vaultBalance': 0}
    if any(int(result.get(key, -1)) != value for key, value in expected.items()):
        return None
    if int(final['balance']) != 0 or int(final['outstanding']) != 0:
        return None
    calls = {name: certified_call(run, name) for name in ('ordinary', 'recovered')}
    if all(paid(call, deployment['vault'], expected[name]) for name, call in calls.items()):
        return {**expected, 'payouts': calls}
    return None


def gap_input(run, label, predecessor, kind):
    """Read the predecessor and gap count from the pinned cold-call frame."""
    path = run / (label + '.calldata')
    proof = run / (predecessor + '.cbor')
    if not (path.is_file() and proof.is_file()):
        return None
    data = path.read_bytes()
    tag = 68 + 42
    start = tag + 5
    end = start + int.from_bytes(data[tag + 1:start], 'big')
    body_end = 68 + int.from_bytes(data[36:68], 'big')
    if (end + 2 > body_end or body_end > len(data) or data[tag] != kind
            or data[start:end] != proof.read_bytes()):
        return None
    return int.from_bytes(data[end:end + 2], 'big')


def funded_reserve(out, recovered):
    run = out / 'recovered'
    result = read(run / 'offline-result.json')
    observation = read(run / 'reserve-observations.json')
    funding = read(out / 'relayer-funding.json')
    funding_receipt = read(out / 'fund-relayer.receipt.json')
    deployment = read(out / 'deployment.json')
    if not (result and observation and funding and funding_receipt and deployment and recovered):
        return None
    if (funding_receipt['status'] != '0x1' or funding_receipt['transactionHash'] != funding['tx']
            or funding_receipt['to'].lower() != funding['payer']
            or observation['fundedRelayer'] != funding['tx']
            or int(observation['funded']) != int(funding['balance'])
            or int(funding['balance']) <= 0):
        return None

    progress = int(result['progressCalls'])
    if progress < 1:
        return None
    labels = [f'offline-run-{i}' for i in range(1, progress + 1)]
    advances = result['advanceCalls']
    through = 0
    checkpoint_calls = None
    for i, advance in enumerate(advances):
        label = f'offline-advance-{through}'
        gaps = advance['verifiedGaps']
        call = certified_call(run, label)
        if (label != advance['label'] or gaps <= 0 or not call
                or gap_input(run, label, labels[-1], 1 if i == 0 else 2) != gaps):
            return None
        through += gaps
        log = call['locator']
        event = bytes.fromhex(log['data'][2:])
        if (log['address'] != deployment['recovery'] or log['topics'] != [GAP_TOPIC, result['session']]
                or len(event) != 288 or int.from_bytes(event[:32], 'big') != progress + i + 1
                or int.from_bytes(event[224:256], 'big') != through
                or '0x' + event[64:96].hex() != result['eta']
                or int(advance['verifiedThrough']) != through):
            return None
        labels.append(label)
        if through == 64:
            checkpoint_calls = len(labels)
    if (not advances or through != int(result['segment']) or through != result['verifiedGapCount']
            or gap_input(run, 'offline-paid', labels[-1], 2) != 0
            or not paid(recovered, deployment['vault'], 910)
            or recovered['locator']['topics'][1] != result['eta']):
        return None
    labels.append('offline-paid')

    fees, bids = [], []
    for nonce, label in enumerate(labels):
        call = certified_call(run, label)
        bid = read(run / (label + '.submitted.json'))
        if (not (call and bid and (run / (label + '.signed')).is_file())
                or bid['payer'] != funding['payer'] or int(bid['nonce']) != nonce or bid['hash'] != call['tx']):
            return None
        fee = int(call['paidFee'])
        limit = int(bid['gasLimit']) * int(bid['maxFeePerGas'])
        if fee < 0 or fee > limit:
            return None
        fees.append(fee)
        bids.append(limit)

    def totals(count, gaps):
        return {'calls': labels[:count], 'throughGaps': str(gaps),
                'observedFees': str(sum(fees[:count])), 'upperBids': str(sum(bids[:count]))}

    prefix = totals(checkpoint_calls, 64) if checkpoint_calls is not None else None
    complete = totals(len(labels), through)
    if observation['checkpoint64'] != prefix or observation['throughPayout'] != complete:
        return None
    return {**observation, 'passedObservedWindow': bool(prefix and sum(bids) <= int(funding['balance']))}


def throughput(run):
    restored = read(run / 'recovered/offline-result.json')
    archive = read(run / 'offline-load/archive-result.json')
    if not restored or not archive or not restored['advanceCalls']:
        return None
    when = sorted(
        int(read(run / 'offline-load' / f'seal-{i}.locator.json')['blockTimestamp'])
        for i in range(int(archive['segments']))
    )
    peak = max(sum(t <= j < t + 30 for j in when) for t in when) / 30
    calls = restored['advanceCalls']
    samples = sorted(i['proofMs'] for i in calls)
    p99 = samples[math.ceil(.99 * len(samples)) - 1]
    q = min(c['verifiedGaps'] for c in calls)
    shrink = all(int(c['beforeBacklog']) > int(c['afterBacklog']) for c in calls)
    during = sum(int(c['arrivedDuringCall']) for c in calls)
    settled = restored['finalBacklog'] == 0
    pass_window = p99 > 0 and q * 1000 / p99 >= 2 * peak and shrink and during > 0 and settled
    return {'q': q, 'receiptP99Ms': p99, 'peakSealsPerSec30s': peak, 'arrivalsDuringAdvance': during,
            'shrinkingBacklog': shrink, 'initialBacklog': restored['initialBacklog'],
            'finalBacklog': restored['finalBacklog'], 'samples': len(calls), 'passedObservedWindow': pass_window}


def summarize(run, asset):
    out = run / asset
    restored = read(out / 'recovered/restored-predecessor.locator.json')
    rollback = read(out / 'payout-failure.custody.json')
    costs = [(p.relative_to(run).as_posix(), read(p)) for p in out.rglob('*.cost.json')]
    biggest = max(costs, key=lambda row: row[1]['signedBytes'], default=None)
    recovery_calls = [row for row in costs if '/recovered/offline-' in row[0]]
    totals = {key: sum(int(row[1][key]) for row in costs) for key in ('gas', 'paidFee')}
    ordinary = payout(out, 'ordinary-paid', -40)
    recovered = payout(out / 'recovered', 'offline-paid', -910)
    retry = payout(out, 'retry-paid', -50)
    retry_custody = read(out / 'retry-paid.custody.json')
    return {
        'deposit': read(out / 'deposit-custody.json'), 'walletAdmission': read(out / 'wallet-admission.json'),
        'ordinary': ordinary, 'recovered': recovered, 'retry': retry,
        'rollbackAndIndependentRetry': bool(rollback and retry and rollback['certifiedFailedReceipt']
                                            and rollback['qDelta'] == 0 and rollback['payer'] != retry_custody['payer']),
        'alternateRestore': bool(restored and restored['source'] > 0 and recovered),
        'isolated': (out / 'isolation-after.json').is_file(), 'includedCosts': totals,
        'largestObservedSignedTransaction': biggest, 'throughput': throughput(out),
        'largestObservedSignedRecoveryPacket': max(recovery_calls, key=lambda row: row[1]['signedBytes'], default=None),
        'reserveObservation': funded_reserve(out, recovered),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    assets = {asset: summarize(args.run, asset) for asset in ('plain', 'fee')}
    fee_window = assets['fee']['throughput']
    fee_reserve = assets['fee']['reserveObservation']
    both = list(assets.values())
    uct = uct_control(args.run)
    checks = {
        'native UCT alongside two ERC20s': bool(uct and all(a['isolated'] and a['deposit'] for a in both)),
        'nested splits and ordinary and recovered across a seal': all(a['ordinary'] and a['recovered'] for a in both),
        'payout failure and independent retry': all(a['rollbackAndIndependentRetry'] for a in both),
        'restore through alternate archive': all(a['alternateRestore'] for a in both),
        'observed catch-up under continued load': bool(fee_window and fee_window['passedObservedWindow']),
        'observed funded 64-gap schedule': bool(fee_reserve and fee_reserve['passedObservedWindow']),
        'largest legal signed packet and all worst-case indivisible calls': False,
        'full 64-segment funding envelope': False,
        'real-value qualification': False,
    }
    result = {'assets': assets, 'uctControl': uct,
              'checks': {k: 'PASS' if v else 'FAIL' for k, v in checks.items()}, 'files': {}}
    for pattern in ('deployment.json', 'result.json', 'ordinary.*', 'recovered.*'):
        for path in args.run.glob(pattern):
            result['files'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    folders = [args.run / p for p in ('plain', 'fee', 'erc20-graph', 'descriptors')]
    for directory in folders:
        for path in sorted(directory.rglob('*')):
            relative = path.relative_to(args.run)
            if (path.is_file() and all(not part.startswith('.') for part in relative.parts)
                and path.suffix in {'.bin', '.calldata', '.cbor', '.initcode', '.json', '.signed', '.sol', '.state'}):
                result['files'][str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
