#!/usr/bin/env python3
"""Deploy and verify the NB2 v1.1 graph on a running testnet generation.

The generation's funder account deploys (never the faucet key: its nonces are the faucet signer's,
bft-core#1287). The release is written only after
readback of the five contracts and the native seal registry. Publish the release
and its trust files together through the authenticated operator channel.
"""
import argparse
import fcntl
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent))
from deploy_bridge import image, record_image, tools   # noqa: E402  (the bridge tools image by its recorded ID, #1092)
import release_nb2   # noqa: E402

ETH = 'http://ureth1:8545'
CONTRACTS = '/opt/bridge/contracts'
NBP = '/opt/bridge/native-bridge-plugins'
REPO = HERE.parents[3]
# The package ships the imported-tip certificate relation. The T7 membership
# and execution descriptor sources still match this ureth pin.
RELEASE_URETH = '0e17a7172f89d8bbfeaf2b3688c16506c566f213'
RELEASE_URETH_LOCK = '99e0b3f3bcae2ded12eecf1d7563a455d05e67d1502137a6ef813a2e0cf075af'
REGISTRY = '0xff00000000000000000000000000000000000002'
NETWORK_ID, EVM_PARTITION, EVM_SHARD, AGG_PARTITION = 3, 8, '0x80', 7
QMAX_DEFAULT = 10 ** 27
DESCRIPTORS = ('cert-batch-v2', 'rsmt-member-v1', 'registry-layout', 'execution', 'build-index', 'primitive-vectors')
CONTRACT_NAMES = ('FlatReceipts', 'FlatLineage', 'NativeBridgeVerifier11', 'NativeBridgeRecovery11', 'NativeBridgeVault11')
ESTIMATE_ATTEMPTS = 6
BOUND_PARENT_REFUSAL = 'error code -32603: bound execution input rejected the block: bound parent hash mismatch'


def cast(gen, *args):
    return tools(gen, 'cast', *args, capture=True).strip()


def keccak(gen, data):
    return cast(gen, 'keccak', '0x' + data.hex()).lower()


def digest(data):
    return '0x' + hashlib.sha256(data).hexdigest()


def hash_fields(gen, label, *fields):
    prefix = keccak(gen, ('UNICITY/NB2/CONT/1.1/' + label).encode())
    return keccak(gen, bytes.fromhex(prefix[2:] + ''.join(field.removeprefix('0x') for field in fields)))


def rpc(gen, target, method, *params):
    return json.loads(cast(gen, 'rpc', '--rpc-url', target, '--raw', method, json.dumps(params)))


def same(name, actual, expected):
    if not isinstance(actual, str) or actual.lower() != expected.lower():
        raise SystemExit(f'{name}: expected {expected}, got {actual}')


def artifact(gen, name, hashes):
    data = json.loads(tools(gen, 'cat', f'{CONTRACTS}/out/{name}.sol/{name}.json', capture=True))
    codes = [('0x' + data[field]['object'].removeprefix('0x')).lower() for field in ('bytecode', 'deployedBytecode')]
    for kind, code, expected in zip(('creation', 'runtime template'), codes, hashes, strict=True):
        same(f'{name} {kind} hash', keccak(gen, bytes.fromhex(code[2:])), expected)
    return codes[0]


def cast_failure_reasons(error):
    """Cast --json reports failures on stdout. Older tools use stderr."""
    try:
        result = json.loads(error.stdout or '')
    except json.JSONDecodeError:
        result = None
    if isinstance(result, dict) and isinstance(result.get('errors'), list):
        reasons = [e['message'] for e in result['errors']
                   if isinstance(e, dict) and isinstance(e.get('message'), str) and e['message']]
        if reasons:
            return list(dict.fromkeys(reasons))
    return [(error.stderr or '').strip() or 'no diagnostic from cast']


def moving_estimate_head(reason):
    reason = reason.removeprefix('Error: ')
    prefix = 'Failed to estimate gas: '
    return (reason.startswith(prefix)
            and reason[len(prefix):].removeprefix('server returned an error response: ') == BOUND_PARENT_REFUSAL)


def create(gen, initcode, label, *, transport=None):
    """One creation from the funder keystore; its receipt."""
    run = tools if transport is None else transport
    for attempt in range(1, ESTIMATE_ATTEMPTS + 1):
        try:
            out = run(gen, 'cast', 'send', '--rpc-url', ETH, '--keystore', '/gen/funder-secrets/keystore.json',
                        '--password-file', '/gen/funder-secrets/password', '--json', '--create', initcode, capture=True)
            break
        except subprocess.CalledProcessError as error:
            reasons = cast_failure_reasons(error)
            # The pending head can advance during estimation (bft-core#1130).
            # This specific failure precedes signing and broadcast.
            if attempt < ESTIMATE_ATTEMPTS and moving_estimate_head(reasons[0]):
                print(f'{label}: gas estimate refused on a moving head (attempt {attempt}/{ESTIMATE_ATTEMPTS}); retrying', flush=True)
                time.sleep(min(attempt * 2, 10))
                continue
            detail = '; '.join(reasons).replace(initcode, '[creation bytecode redacted]')
            raise SystemExit(f'the {label} creation failed: cast exited {error.returncode}: {detail[-2000:]}') from None
    receipt = json.loads(out)
    if receipt.get('status') not in ('0x1', 1, '1'):
        raise SystemExit(f'the {label} creation failed: {out[:400]}')
    print(f'{label}: {receipt["contractAddress"]} in block {int(receipt["blockNumber"], 16)} (tx {receipt["transactionHash"]})')
    return receipt


def write_json(path, doc):
    path.write_text(json.dumps(doc, indent=2) + '\n')


def descriptors(gen, manifest, bridge, work):
    """Bind the reviewed rules and the actual immutable node artifacts into P."""
    corpus = REPO / 'testvectors/nb2-continuation-v1.1-supplement/descriptors'
    dest = work / 'public/descriptors'
    dest.mkdir(exist_ok=True)
    native = manifest['artifacts']
    hashes = {}
    tip_descriptors = {'cert-batch-v2', 'primitive-vectors', 'registry-layout', 'semantic-profile'}
    for name in (*DESCRIPTORS, 'semantic-profile'):
        if name in tip_descriptors:
            data = (HERE / f'{name}-tip.json').read_bytes()
        elif name == 'build-index':
            data = (json.dumps({'sources': native['sources'], 'binarySha256': native['binary_sha256'],
                                'nodeImages': native['images'], 'bridgeImage': bridge}, sort_keys=True) + '\n').encode()
        else:
            data = (corpus / f'{name}.json').read_bytes()
            if name in ('rsmt-member-v1', 'execution'):
                descriptor = json.loads(data)
                descriptor['ureth'] = RELEASE_URETH
                if name == 'execution':
                    descriptor['rules']['Cargo.lock'] = RELEASE_URETH_LOCK
                data = (json.dumps(descriptor, sort_keys=True) + '\n').encode()
        (dest / f'{name}.json').write_bytes(data)
        hashes[name] = digest(data)
    return hashes


def deploy_graph(gen, evidence_bin, manifest, work, bridge, pin, qmax):
    reviewed = json.loads((REPO / 'scripts/nb2-t7/pins.json').read_text())
    templates = reviewed['artifactKeccak']
    code = {name: artifact(gen, name, templates[name]) for name in CONTRACT_NAMES}
    registry_hash = code_hash(gen, ETH, REGISTRY)
    same('native seal registry runtime', registry_hash, reviewed['registryRuntimeKeccak'])
    if int(rpc(gen, ETH, 'eth_chainId'), 16) != manifest['chain_id']:
        raise SystemExit('execution chain ID differs from generation manifest')
    same('execution genesis', rpc(gen, ETH, 'eth_getBlockByNumber', '0x0', False)['hash'], manifest['genesis_hash'])

    descriptor_hashes = descriptors(gen, manifest, bridge, work)
    fields = [descriptor_hashes[name] for name in DESCRIPTORS]
    profile = descriptor_hashes['semantic-profile']
    nodes = {'registry': {'address': REGISTRY, 'runtimeCodeHash': registry_hash}}
    if 'funder_address' not in manifest:
        raise SystemExit('the generation has no funder account (generate.py funder-secrets/): the faucet key is the faucet signer\'s alone')
    deployer = manifest['funder_address']
    # On a partial failure there is no safe implicit retry of a creation.
    (work / '.deployment-started').touch(exist_ok=False)

    def deploy(role, name, signature=None, *args):
        encoded = cast(gen, 'abi-encode', signature, *args)[2:] if signature else ''
        receipt = create(gen, code[name] + encoded, name)
        address = receipt['contractAddress'].lower()
        block_hash = receipt['blockHash']
        nodes[role] = {'contract': name, 'address': address, 'block': int(receipt['blockNumber'], 16),
                       'blockHash': block_hash, 'transaction': receipt['transactionHash'],
                       'runtimeCodeHash': code_hash(gen, ETH, address, canonical_block(block_hash)),
                       'creationCodeHash': templates[name][0], 'runtimeTemplateHash': templates[name][1],
                       'constructorArgs': '0x' + encoded}
        return address, nodes[role]['runtimeCodeHash']

    receipts, receipts_hash = deploy('receipts', 'FlatReceipts')
    same('receipt helper runtime', receipts_hash, templates['FlatReceipts'][1])
    lineage, lineage_hash = deploy('lineage', 'FlatLineage', 'f(address)', receipts)
    ordinary, ordinary_hash = deploy('ordinary', 'NativeBridgeVerifier11',
        'f(address,bytes32,bytes32,bytes32)', lineage, lineage_hash, profile, registry_hash)

    # The recovery creation consumes nonce n and the vault consumes n+1.
    latest = int(rpc(gen, ETH, 'eth_getTransactionCount', deployer, 'latest'), 16)
    pending = int(rpc(gen, ETH, 'eth_getTransactionCount', deployer, 'pending'), 16)
    if latest != pending:
        raise SystemExit('the deployer has pending transactions')
    predicted = cast(gen, 'compute-address', '--nonce', str(latest + 1), deployer).split()[-1].lower()
    config = json.loads(subprocess.check_output([str(evidence_bin), 'gamma', '-flat', '-network', str(NETWORK_ID),
        '-root-genesis', pin, '-execution-genesis', manifest['genesis_hash'], '-chain-id', str(manifest['chain_id']),
        '-evm-partition', str(EVM_PARTITION), '-evm-shard', EVM_SHARD, '-aggregator-partition', str(AGG_PARTITION),
        '-vault', predicted, '-verifier', ordinary, '-verifier-code-hash', ordinary_hash, '-profile-hash', profile,
        '-k', '64', '-b', '16', '-qmax', str(qmax)], text=True))
    gamma, domain = config['gamma'], config['domain']
    same('Go Γ domain', digest(bytes.fromhex(gamma[2:])), domain)

    def pin_record(role, address, identity):
        return f'{role:04x}' + address.removeprefix('0x') + identity[2:]

    records = [
        pin_record(1, ordinary, ordinary_hash), pin_record(2, receipts, receipts_hash),
        pin_record(3, '0000000000000000000000000000000000000100', fields[0]),
        pin_record(4, '0000000000000000000000000000000000000102', fields[1]),
        pin_record(5, REGISTRY, hash_fields(gen, 'REGISTRY', registry_hash, fields[2])),
        pin_record(256, lineage, lineage_hash),
    ]
    release = hash_fields(gen, 'RELEASE', *fields)
    pins = hash_fields(gen, 'PINS', release, f'{len(records):04x}', *records)
    salt = '0x' + secrets.token_hex(32)
    recovery, recovery_hash = deploy('recovery', 'NativeBridgeRecovery11',
        'f(bytes,address,bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32),bytes32)',
        gamma, ordinary, salt, '(' + ','.join(fields) + ')', pins)
    vault, _ = deploy('vault', 'NativeBridgeVault11', 'f(bytes,address,bytes32,bytes32)', gamma, recovery, recovery_hash, profile)
    same('vault predicted from the deployer nonce', vault, predicted)

    return {'build': 'production', 'fields': config, 'gamma': gamma, 'domain': domain, 'deployer': deployer,
            'contracts': nodes, 'release': release, 'pins': pins, 'pinRecords': ['0x' + r for r in records],
            'salt': salt, 'recoveryGeneration': hash_fields(gen, 'GEN', salt, domain),
            'descriptors': descriptor_hashes, 'trustPin': pin, 'firstBlock': nodes['receipts']['block'],
            'compiler': {'solc': '0.8.37', 'evm': 'cancun', 'viaIR': True,
                         'optimizerRuns': {'src/nb2/verifier/**': 1, 'default': 200}}}


def code_hash(gen, target, address, at='latest'):
    code = rpc(gen, target, 'eth_getCode', address, at)
    if code == '0x':
        raise SystemExit(f'{target} has no code at {address}')
    return keccak(gen, bytes.fromhex(code[2:]))


def canonical_block(block_hash):
    return {'blockHash': block_hash, 'requireCanonical': True}


def verify_graph(gen, record, head, target=ETH):
    at = canonical_block(head['hash'])
    finalized = int(head['number'], 16)
    nodes = record['contracts']
    for role, node in nodes.items():
        if 'transaction' in node:
            if node['block'] > finalized:
                raise SystemExit(f'{target} {role} creation is above finalized block {finalized}')
            creation = rpc(gen, target, 'eth_getBlockByNumber', hex(node['block']), False)
            same(f'{target} {role} canonical creation block', (creation or {}).get('hash'), node['blockHash'])
        same(f'{target} {role} runtime', code_hash(gen, target, node['address'], at), node['runtimeCodeHash'])
    address = lambda role: nodes[role]['address']
    runtime = lambda role: nodes[role]['runtimeCodeHash']
    profile = record['descriptors']['semantic-profile']
    hooks = {'LINEAGE()(address)': address('lineage'), 'LINEAGE_HASH()(bytes32)': runtime('lineage'),
             'RECEIPTS()(address)': address('receipts'), 'RECEIPTS_HASH()(bytes32)': runtime('receipts'),
             'REGISTRY_HASH()(bytes32)': runtime('registry')}
    checks = {
        'lineage': {'RECEIPTS()(address)': address('receipts'), 'RECEIPTS_HASH()(bytes32)': runtime('receipts')},
        'ordinary': {**hooks, 'PROFILE_HASH()(bytes32)': profile},
        'recovery': {**hooks, 'ORDINARY()(address)': address('ordinary'), 'ORDINARY_HASH()(bytes32)': runtime('ordinary'),
                     'VAULT()(address)': address('vault'), 'DOMAIN()(bytes32)': record['domain'],
                     'PINS()(bytes32)': record['pins'], 'GENERATION()(bytes32)': record['recoveryGeneration']},
        'vault': {'config()(bytes)': record['gamma'], 'domain()(bytes32)': record['domain'],
                  'RECOVERY()(address)': address('recovery'), 'RECOVERY_RUNTIME()(bytes32)': runtime('recovery'),
                  'RECOVERY_PINS()(bytes32)': record['pins'], 'RECOVERY_GENERATION()(bytes32)': record['recoveryGeneration']},
    }
    for role, getters in checks.items():
        for getter, value in getters.items():
            signature = getter[:getter.index(')') + 1]
            data = cast(gen, 'sig', signature)
            raw = rpc(gen, target, 'eth_call', {'to': address(role), 'data': data}, at)
            same(f'{target} {role} {getter}', cast(gen, 'abi-decode', getter, raw), value)


def run_deployment(gen, evidence_bin, qmax, output):
    manifest = json.loads((gen / 'manifest.json').read_text())
    if not manifest.get('utb'):
        raise SystemExit('NB2 v1.1 requires a UTB generation')
    if manifest['artifacts']['sources']['ureth'] != RELEASE_URETH:
        raise SystemExit('generation ureth is outside the reviewed NB2 native descriptors')
    profile = json.loads((gen / 'network/b1-profile.json').read_bytes())
    if type(profile.get('executionRevision')) is not int or profile['executionRevision'] != 2:
        raise SystemExit('NB2 imported-tip semantics require B1 execution revision 2')
    if not evidence_bin.is_file() or not os.access(evidence_bin, os.X_OK):
        raise SystemExit('nb2-evidence must be an executable file')
    if not 0 < qmax < 2 ** 144:
        raise SystemExit('Qmax must be positive and below 2^144')
    bridge = image(gen)
    services = release_nb2.active_services(gen)
    limits = release_nb2.admission(gen, manifest, bridge, services)
    sources = limits[0]
    pins = json.loads((HERE.parent / 'pins.json').read_text())
    for name in ('contracts', 'native-bridge-plugins'):
        same(f'bridge image {name} pin', sources.get(name), pins[name])
    same('bridge dnb-tool bft pin', sources.get('bft'), manifest['artifacts']['sources']['bft'])
    record_image(gen, bridge)
    tools(gen, 'dnb-tool', 'trust-bundle', '--trust-base', '/gen/network/trust-base.json',
          '--out', '/work/nb2/public/trust-base.bundle.cbor', '--out-pin', '/work/nb2/public/trust-base.genesis.entryid')
    pin = '0x' + (output / 'public/trust-base.genesis.entryid').read_text().strip().removeprefix('0x')
    same('trust bundle genesis', pin, '0x' + manifest['utb']['genesis_id'].removeprefix('0x'))
    record = deploy_graph(gen, evidence_bin, manifest, output, bridge, pin, qmax)
    record_path = output / 'deployment.json'
    write_json(record_path, record)
    checkpoints = []
    for i in range(1, manifest['validators'] + 1):
        target = f'http://ureth{i}:8545'
        genesis = rpc(gen, target, 'eth_getBlockByNumber', '0x0', False)
        same(f'{target} execution genesis', genesis['hash'], manifest['genesis_hash'])
        # Wait for each paired validator to see the vault creation before comparing its graph.
        block = record['contracts']['vault']['block']
        for _ in range(120):
            head = rpc(gen, target, 'eth_getBlockByNumber', 'finalized', False)
            if head and int(head['number'], 16) >= block:
                break
            time.sleep(1)
        else:
            raise SystemExit(f'{target} did not finalize vault deployment block {block}')
        verify_graph(gen, record, head, target)
        checkpoint = {'validator': i, 'blockHash': head['hash'], 'blockNumber': int(head['number'], 16)}
        checkpoints.append(checkpoint)
        print(f'{target}: verified five contracts and native registry at finalized block '
              f'{checkpoint["blockNumber"]} ({checkpoint["blockHash"]})', flush=True)
    record['readbackCheckpoints'] = checkpoints
    write_json(record_path, record)
    doc = release_nb2.build(gen, record, bridge, services, limits=limits)
    path = output / 'public/nb2-release.json'
    temp = path.with_suffix('.tmp')
    write_json(temp, doc)
    temp.replace(path)
    if os.getuid() == 0:
        subprocess.run(['chown', '-R', '10001:10001', str(gen / 'bridge')], check=True)
    print(json.dumps({'release': str(path), 'domain': record['domain'],
                      'contracts': {role: node['address'] for role, node in record['contracts'].items()}}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('generation', type=Path)
    p.add_argument('--nb2-evidence', type=Path, required=True,
                   help='build from this checkout with go build ./scripts/nb2-evidence')
    p.add_argument('--qmax', type=int, default=QMAX_DEFAULT)
    a = p.parse_args()
    gen = a.generation.resolve()
    output = gen / 'bridge/nb2'
    (output / 'public').mkdir(parents=True, exist_ok=True)
    with (output / '.deploy.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('another NB2 deployment is active for this generation') from None
        if (output / '.deployment-started').exists() or (output / 'deployment.json').exists():
            raise SystemExit('this generation already attempted an NB2 deployment; use a fresh generation')
        run_deployment(gen, a.nb2_evidence.resolve(), a.qmax, output)


if __name__ == '__main__':
    main()
