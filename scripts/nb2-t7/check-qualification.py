#!/usr/bin/env python3
"""Index public test evidence and rederive the generation bindings independently of the driver."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess

DESCRIPTORS = ('cert-batch-v2', 'rsmt-member-v1', 'registry-layout', 'execution', 'build-index', 'primitive-vectors')
CASES = {
    'transfer-600': (44, 390_000_000),
    'transfer-600-split-1': (46, 395_000_000),
    'split-20': (8, 50_000_000),
}
CONTRACTS = {
    'FlatReceipts': 'receipts', 'FlatLineage': 'lineage', 'NativeBridgeVerifier11': 'ordinary',
    'NativeBridgeRecovery11': 'recovery', 'NativeBridgeVault11': 'vault',
}


def read(path):
    return json.loads(path.read_bytes())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return sha(path.read_bytes())


def keccak(data):
    return bytes.fromhex(subprocess.check_output(['cast', 'keccak', '0x' + data.hex()], text=True).strip()[2:])


def labelled(label, *pieces):
    return keccak(keccak(('UNICITY/NB2/CONT/1.1/' + label).encode()) + b''.join(pieces))


def raw(value):
    return bytes.fromhex(value.removeprefix('0x'))


def hex_digest(value):
    return '0x' + value.hex()


def require(actual, expected, label):
    if actual != expected:
        raise SystemExit(f'{label}: expected {expected}, got {actual}')


def source_file(checkout, revision, filename):
    return subprocess.check_output(['git', '-C', str(checkout), 'show', f'{revision}:{filename}'])


def source_map(values, checkout, revision=None):
    for name, expected in values.items():
        content = (checkout / name).read_bytes() if revision is None else source_file(checkout, revision, name)
        require(sha(content), expected, name)


def inspect_graph(run, repo, ureth, artifacts):
    g, pins = (read(run / name) for name in ('deployment.json', 'pins.json'))
    descriptor_dir = run / 'descriptors'
    desc = {name: digest(descriptor_dir / f'{name}.json') for name in (*DESCRIPTORS, 'semantic-profile')}
    for name in ('cert-batch-v2', 'rsmt-member-v1', 'execution'):
        record = read(descriptor_dir / f'{name}.json')
        require(record['ureth'], pins['ureth'], f'{name} source revision')
        source_map(record.get('sources', record.get('rules')), ureth, pins['ureth'])
    registry = read(descriptor_dir / 'registry-layout.json')
    source_map(registry['sources'], repo)
    source_map(registry['native'], ureth, pins['ureth'])
    source_map(read(descriptor_dir / 'primitive-vectors.json')['artifacts'], repo)
    source_map(read(descriptor_dir / 'semantic-profile.json')['specification'], repo)
    require('0x' + desc['semantic-profile'], g['profile'], 'semantic profile')
    gamma = (run / 'gamma.bin').read_bytes()
    require('0x' + sha(gamma), g['domain'], 'Gamma domain')
    release = labelled('RELEASE', *(bytes.fromhex(desc[name]) for name in DESCRIPTORS))
    require(hex_digest(release), g['release'], 'release digest')
    registry_digest = labelled('REGISTRY', raw(g['runtimeHashes']['registry']), bytes.fromhex(desc['registry-layout']))
    require(g['runtimeHashes']['registry'], pins['registryRuntimeKeccak'], 'registry runtime')
    records = b''.join(role.to_bytes(2, 'big') + raw(address) + raw(d) for role, address, d in [
        (1, g['ordinary'], g['runtimeHashes']['ordinary']),
        (2, g['receipts'], g['runtimeHashes']['receipts']),
        (3, '00' * 18 + '0100', desc['cert-batch-v2']),
        (4, '00' * 18 + '0102', desc['rsmt-member-v1']),
        (5, g['registry'], registry_digest.hex()),
        (256, g['lineage'], g['runtimeHashes']['lineage']),
    ])
    require(records, (run / 'pin-records.bin').read_bytes(), 'ordered pin records')
    require(hex_digest(labelled('PINS', release, b'\x00\x06', records)), g['pins'], 'pin digest')

    runtime_path = run / 'validator-graph.json'
    if runtime_path.exists():
        for gateway in read(runtime_path):
            require(gateway['runtimeHashes'], g['runtimeHashes'], 'validator runtime hashes')
            require(gateway['executionGenesis'], g['executionGenesis'], 'validator genesis')
            require(int(gateway['chainId']), int(g['chainId']), 'validator chain id')
    for name in CONTRACTS:
        artifact = read(artifacts / f'{name}.sol' / f'{name}.json')
        creation, deployed = (raw(artifact[key]['object']) for key in ('bytecode', 'deployedBytecode'))
        require([hex_digest(keccak(code)) for code in (creation, deployed)], pins['artifactKeccak'][name], name)
        initcode = (run / f'{name}.initcode').read_bytes()
        if not initcode.startswith(creation):
            raise SystemExit(f'{name} live initcode does not start with the pinned creation bytes')
        require(read(run / f'{name}.receipt.json')['contractAddress'].lower(), g[CONTRACTS[name]], name)
    return {'deployment': g, 'sourcePins': pins, 'descriptorSha256': desc}


def percentile(values, percent):
    return sorted(values)[math.ceil(len(values) * percent / 100) - 1]


def workload(directory, tx_limit, gas_limit):
    result = directory / 'result.json'
    if not result.exists():
        error = directory / 'error.json'
        costs = [read(path) for path in directory.glob('run-*.cost.json')]
        return {'status': 'incomplete', 'txTarget': tx_limit, 'gasTarget': gas_limit,
                'includedBeforeFailure': len(costs), 'gasBeforeFailure': sum(int(row['gas']) for row in costs),
                'failure': read(error) if error.exists() else None}
    names = [*(path.name.removesuffix('.cost.json') for path in directory.glob('run-*.cost.json')), 'recovered']
    cost = [read(directory / f'{n}.cost.json') for n in names]
    locators = [read(directory / f'{n}.locator.json') for n in names]
    waits = [measure['inclusionMs'] + locator['acquisitionMs'] for measure, locator in zip(cost, locators)]
    gas = sum(int(row['gas']) for row in cost)
    peak = max(int(row['gas']) for row in cost)
    shape = [read(directory / f'{n}.shape.json') for n in names if n != 'recovered']
    observed_bids = []
    for name, row in zip(names, cost):
        data = (directory / f'{name}.calldata').read_bytes()
        intrinsic = 21_000 + sum(4 if value == 0 else 16 for value in data)
        execution = int(row['gas']) - intrinsic
        # The floor plus observed execution and 20% margin is an observed
        # lower bound on the release quote. It does not bound larger witnesses.
        observed_bids.append(21_000 + 16 * len(data) + (6 * execution + 4) // 5 +
                             (500_000 if name == 'recovered' else 0))
    return {'status': 'pass' if len(cost) <= tx_limit and gas <= gas_limit else 'fail',
            'transactions': len(cost), 'txTarget': tx_limit, 'txDelta': len(cost) - tx_limit,
            'gas': gas, 'gasTarget': gas_limit, 'gasDelta': gas - gas_limit, 'maxIncludedGas': peak,
            'receiptMs': {str(p): percentile(waits, p) for p in (50, 95, 99)},
            'maxSignedBytes': max(int(row['signedBytes']) for row in cost),
            'maxObservedRunShape': {k: max(row[k] for row in shape)
                                    for k in ('operations', 'calldataBytes', 'pages', 'receiptBytes', 'openingBytes')},
            'actualFeeWei': str(sum(int(row['paidFee']) for row in cost)),
            'largestObservedGasQuoteFloor': max(observed_bids),
            'receiptRetryPolls': sum(row.get('attempts', 1) - 1 for row in locators),
            'custody': read(result), 'lineage': read(directory / 'workload.json')}


def public_files(run):
    allowed = {'.json', '.txt', '.pin', '.cbor', '.bin', '.initcode', '.sha256'}
    for path in run.rglob('*'):
        parts = path.relative_to(run).parts
        if (path.is_file() and path.suffix in allowed and
                not any(part.startswith('.') or '.private.' in part or part in ('mongo', 'paired') for part in parts)):
            yield str(Path(*parts)), digest(path)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, default=Path('.'))
    p.add_argument('--ureth', type=Path, required=True)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('runs', type=Path, nargs='+')
    args = p.parse_args()
    report = {'schema': 'nb2-t7-test-qualification-evidence', 'version': 1, 'realValueAuthorized': False,
              'feeEnvelope': None, 'peakWindowEnvelope': None, 'generations': {},
              'corporaSha256': {name: digest(args.repo / 'testvectors' / name / 'MANIFEST') for name in
                                ('nb2-continuation-v1.1', 'nb2-continuation-v1.1/transcripts', 'nb2-continuation-v1.1-supplement')}}
    for run in args.runs:
        graph = inspect_graph(run, args.repo, args.ureth, args.artifacts)
        graph['costs'] = {name: workload(run / name, *limits) for name, limits in CASES.items()
                          if (run / name).is_dir() and not (run / name / 'offline-checkpoint.json').exists()}
        offline = list(run.glob('*/offline-result.json'))
        if offline:
            graph['offline'] = read(offline[0])
        if (run / 'offline-load/custody-result.json').exists():
            graph['offlineSettlementLoad'] = read(run / 'offline-load/custody-result.json')
        if (run / 'custody-result.json').exists():
            graph['custody'] = read(run / 'custody-result.json')
        for file in ('validator-graph.json', 'public-relay-check.json', 'gateway-checks.json'):
            if (run / file).exists():
                graph[file.removesuffix('.json')] = read(run / file)
        graph['buildEvidence'] = (run / 'builds.txt').read_text().splitlines()[:7]
        graph['evidenceSha256'] = dict(public_files(run))
        report['generations'][run.name] = graph
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
