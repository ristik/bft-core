#!/usr/bin/env python3
"""Summarize a private ERC20 run, including incomplete runs."""

import argparse
import hashlib
import json
import math
from pathlib import Path


def read(path):
    return json.loads(path.read_text()) if path.is_file() else None


def payout(run, name, q_delta):
    custody = read(run / (name + '.custody.json'))
    cost = read(run / (name + '.cost.json'))
    locator = read(run / (name + '.locator.json'))
    if custody and cost and locator and int(custody['qDelta']) == q_delta:
        if (cost['tx'], cost['blockHash'], cost['transactionIndex']) == (
            locator['transactionHash'], locator['blockHash'], locator['transactionIndex']
        ) and (run / (name + '.signed')).is_file() and (run / (name + '.cbor')).is_file():
            return {'qDelta': q_delta, **cost, 'locator': locator}
    return None


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
        'reserveObservation': read(out / 'recovered/reserve-observations.json'),
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
    checks = {
        'native UCT alongside two ERC20s': all(a['isolated'] and a['deposit'] for a in both),
        'nested splits and ordinary and recovered across a seal': all(a['ordinary'] and a['recovered'] for a in both),
        'payout failure and independent retry': all(a['rollbackAndIndependentRetry'] for a in both),
        'restore through alternate archive': all(a['alternateRestore'] for a in both),
        'observed catch-up under continued load': bool(fee_window and fee_window['passedObservedWindow']),
        'observed funded 64-gap schedule': bool(fee_reserve and int(fee_reserve['coveredGaps']) == 64
                                                and int(fee_reserve['upperBids']) <= int(fee_reserve['funded'])),
        'largest legal signed packet and all worst-case indivisible calls': False,
        'full 64-segment funding envelope': False,
        'real-value qualification': False,
    }
    result = {'assets': assets, 'checks': {k: 'PASS' if v else 'FAIL' for k, v in checks.items()}, 'files': {}}
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
