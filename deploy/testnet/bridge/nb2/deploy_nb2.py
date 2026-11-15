#!/usr/bin/env python3
"""Deploy the native bridge v2 (NB2-09, bft-core#1105): NativeBridgeVerifierV2 and NativeBridgeVaultV2 on a running generation, and its release manifest.

    deploy_nb2.py GENERATION --nb2-evidence BIN [--k 4 --b 2] [--qmax WEI] [--no-production]

An operator action on the generation's internal validators network, against validator 1's execution client, signed with the generation's faucet keystore
(the key never leaves its file), in the bridge tools image (deploy_bridge.py's tools(): forge/cast and the contracts' build output at the pin):

  1. the trust-base release bundle and its genesis EntryID (dnb-tool trust-bundle): Γ.rootGenesis32 and the wallets' trust input;
  2. the verifier, as initcode from the image's build output (`cast send --create`, nothing recompiles), of the build that admits K: the test build
     (admitsTestSet, K in {4, 8} x B in {2, 4}) for the lanes' K = 4, the production build for (64, 16). It creates its receipt helper;
  3. Γ (section 4.1) by the Go reference (nb2-evidence gamma, built from this checkout), for the vault's address predicted from the deployer's nonce;
  4. the vault of the same build with exactly those bytes; its constructor checks them (BadConfig otherwise), and config() and domain() are read back;
  5. unless --no-production, the production pair (64, 16) as well: the lane's admission check needs both builds on one chain;
  6. GENERATION/bridge/nb2/: deployment.json (what was deployed), lane.json (the driver's view), public/ (what wallets get: the trust bundle and
     its pin, and the release manifest nb2-release.json with the pinned limits and the operating envelope, release_nb2.py).
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent))
from deploy_bridge import image, record_image, tools   # noqa: E402  (the bridge tools image by its recorded ID, #1092)
import release_nb2   # noqa: E402

ETH = 'http://ureth1:8545'
CONTRACTS = '/opt/bridge/contracts'
NBP = '/opt/bridge/native-bridge-plugins'
NETWORK_ID = 3   # generate.py: the signing authorities' --network-id, the trust base's network (the plug-in's bindTrust checks it)
EVM_PARTITION, EVM_SHARD, AGG_PARTITION = 8, '0x80', 7   # generate.py: the EVM shard; the package's one aggregator (owner decision 40)
QMAX_DEFAULT = 10 ** 27   # the test deployment's liability cap: 10^9 UCT (owner question, briefs/owner-questions.md)
UNIT_WEI = 10 ** 15   # one scenario unit: deposit 100 units = 0.1 UCT
TEST_SET = {4, 8}, {2, 4}


def artifact(gen, contract, source):
    """The creation bytecode of CONTRACT from the image's forge build output (no link references: the verifier's libraries are internal)."""
    art = json.loads(tools(gen, 'cat', f'{CONTRACTS}/out/{source}/{contract}.json', capture=True))
    code = art['bytecode']['object']
    if '__$' in code:
        raise SystemExit(f'{contract} has unlinked library references')
    return code if code.startswith('0x') else '0x' + code


def cast(gen, *args):
    return tools(gen, 'cast', *args, capture=True).strip()


def create(gen, initcode, label):
    """One creation from the faucet keystore; its receipt."""
    out = tools(gen, 'cast', 'send', '--rpc-url', ETH, '--keystore', '/gen/faucet-secrets/keystore.json', '--password-file', '/gen/faucet-secrets/password',
                '--json', '--create', initcode, capture=True)
    receipt = json.loads(out)
    if receipt.get('status') not in ('0x1', 1, '1'):
        raise SystemExit(f'the {label} creation failed: {out[:400]}')
    print(f'{label}: {receipt["contractAddress"]} in block {int(receipt["blockNumber"], 16)} (tx {receipt["transactionHash"]})')
    return receipt


def word(b):
    return ('01' if b else '00').rjust(64, '0')


def abi_bytes(data):
    raw = bytes.fromhex(data[2:])
    return (32).to_bytes(32, 'big').hex() + len(raw).to_bytes(32, 'big').hex() + raw.hex() + '00' * (-len(raw) % 32)


def deploy_pair(gen, evidence_bin, k, b, qmax, fields, deployer, production):
    """The verifier and the vault of one build, Γ in between. Returns the deployment record of the pair."""
    verifier_code = artifact(gen, 'NativeBridgeVerifierV2', 'NativeBridgeVerifierV2.sol') + word(not production)
    v = create(gen, verifier_code, f'{"production" if production else "test"} verifier')
    verifier = v['contractAddress']
    vhash = cast(gen, 'codehash', '--rpc-url', ETH, verifier)
    helper = cast(gen, 'call', '--rpc-url', ETH, verifier, 'RECEIPTS()(address)')
    helper_hash = cast(gen, 'codehash', '--rpc-url', ETH, helper)
    pinned = cast(gen, 'call', '--rpc-url', ETH, verifier, 'RECEIPTS_CODEHASH()(bytes32)')
    if pinned != helper_hash:
        raise SystemExit(f'the verifier pins helper code {pinned}, the helper has {helper_hash}')
    nonce = int(cast(gen, 'nonce', '--rpc-url', ETH, deployer))
    predicted = cast(gen, 'compute-address', '--nonce', str(nonce), deployer).split()[-1]
    g = json.loads(subprocess.check_output([str(evidence_bin), 'gamma', '-network', str(NETWORK_ID), '-root-genesis', fields['rootGenesis'],
                                            '-execution-genesis', fields['executionGenesis'], '-chain-id', str(fields['chainId']), '-evm-partition', str(EVM_PARTITION),
                                            '-evm-shard', EVM_SHARD, '-aggregator-partition', str(AGG_PARTITION), '-vault', predicted, '-verifier', verifier,
                                            '-verifier-code-hash', vhash, '-profile-hash', fields['profileHash'], '-k', str(k), '-b', str(b), '-qmax', str(qmax)], text=True))
    contract = 'NativeBridgeVaultV2' if production else 'NativeBridgeVaultV2Test'
    vault_initcode = artifact(gen, contract, f'{contract}.sol')
    vt = create(gen, vault_initcode + abi_bytes(g['gamma']), f'{"production" if production else "test"} vault')
    vault = vt['contractAddress']
    if vault.lower() != predicted.lower():
        raise SystemExit(f'the vault landed at {vault}, Γ names {predicted}: another transaction used the deployer\'s nonce; deploy again')
    config = cast(gen, 'call', '--rpc-url', ETH, vault, 'config()(bytes)')
    domain = cast(gen, 'call', '--rpc-url', ETH, vault, 'domain()(bytes32)')
    if config.lower() != g['gamma'].lower() or domain.lower() != g['domain'].lower() or domain[2:] != hashlib.sha256(bytes.fromhex(g['gamma'][2:])).hexdigest():
        raise SystemExit(f'the vault reads back another Γ or domain: {config[:80]}.. {domain}')
    vault_hash = cast(gen, 'codehash', '--rpc-url', ETH, vault)
    return {
        'build': 'production' if production else 'test', 'K': k, 'B': b, 'Qmax': str(qmax), 'gamma': g['gamma'], 'domain': g['domain'], 'fields': g,
        'vault': {'contract': contract, 'address': vault, 'transaction': vt['transactionHash'], 'block': int(vt['blockNumber'], 16), 'runtimeCodeHash': vault_hash,
                  'initcodeSha256': hashlib.sha256(bytes.fromhex(vault_initcode[2:])).hexdigest()},
        'verifier': {'contract': 'NativeBridgeVerifierV2', 'admitsTestSet': not production, 'address': verifier, 'transaction': v['transactionHash'],
                     'block': int(v['blockNumber'], 16), 'codeHash': vhash},
        'helper': {'contract': 'Nb2ReceiptVerifier', 'address': helper, 'codeHash': helper_hash},
        '_vaultInitcode': vault_initcode,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('generation', type=Path)
    p.add_argument('--nb2-evidence', required=True, type=Path, help='the nb2-evidence binary built from this checkout (go build ./scripts/nb2-evidence)')
    p.add_argument('--k', type=int, default=4)
    p.add_argument('--b', type=int, default=2)
    p.add_argument('--qmax', type=int, default=QMAX_DEFAULT)
    p.add_argument('--no-production', action='store_true', help='do not deploy the production (64, 16) pair beside the test one')
    p.add_argument('--gateway', default='http://rpc:8545', help='the public gateway as the validators network names it (the driver\'s only RPC)')
    a = p.parse_args()
    gen = a.generation.resolve()
    manifest = json.loads((gen / 'manifest.json').read_text())
    work = gen / 'bridge' / 'nb2'
    (work / 'public').mkdir(parents=True, exist_ok=True)
    if (a.k, a.b) != (64, 16) and not (a.k in TEST_SET[0] and a.b in TEST_SET[1]):
        raise SystemExit(f'(K, B) = ({a.k}, {a.b}) is admitted by neither build')

    tools(gen, 'dnb-tool', 'trust-bundle', '--trust-base', '/gen/network/trust-base.json', '--out', '/work/nb2/public/trust-base.bundle.cbor',
          '--out-pin', '/work/nb2/public/trust-base.genesis.entryid')
    pin = (work / 'public/trust-base.genesis.entryid').read_text().strip()
    pin = pin if pin.startswith('0x') else '0x' + pin
    profile_hash = '0x' + tools(gen, 'sha256sum', f'{NBP}/protocol/profile.json', capture=True).split()[0]
    vectors_digest = tools(gen, 'cat', f'{NBP}/protocol/vectors/nb2/nb2-vectors.json.sha256', capture=True).split()[0]
    fields = {'rootGenesis': pin, 'executionGenesis': manifest['genesis_hash'], 'chainId': manifest['chain_id'], 'profileHash': profile_hash}
    deployer = manifest['faucet_address']

    deployed = {'test' if (a.k, a.b) != (64, 16) else 'production': deploy_pair(gen, a.nb2_evidence.resolve(), a.k, a.b, a.qmax, fields, deployer, (a.k, a.b) == (64, 16))}
    if not a.no_production and (a.k, a.b) != (64, 16):
        deployed['production'] = deploy_pair(gen, a.nb2_evidence.resolve(), 64, 16, a.qmax, fields, deployer, True)
    primary = deployed['test'] if 'test' in deployed else deployed['production']
    initcodes = {}
    for name, d in deployed.items():
        initcodes[name] = d.pop('_vaultInitcode')
        (work / f'vault-initcode-{name}.hex').write_text(initcodes[name] + '\n')
    record = {'primary': primary['build'], 'deployments': deployed, 'deployer': deployer, 'trustPin': pin, 'profileHash': profile_hash, 'vectorsDigest': vectors_digest}
    (work / 'deployment.json').write_text(json.dumps(record, indent=2) + '\n')

    bridge = image(gen)
    record_image(gen, bridge)
    ureth = json.loads((gen / 'compose.yaml').read_text())['services']['ureth1']['entrypoint']
    doc = release_nb2.build(gen, record, bridge, ureth)
    lane = {'rpc': a.gateway, 'agg': a.gateway + '/aggregator', 'direct': ETH, 'release': '/work/nb2/public/nb2-release.json',
            'trustBundle': '/work/nb2/public/trust-base.bundle.cbor', 'trustPin': '/work/nb2/public/trust-base.genesis.entryid', 'unit': str(UNIT_WEI),
            'verifier': primary['verifier']['address'], 'helper': primary['helper']['address'],
            'test': {'gamma': primary['gamma'], 'vaultInitcode': initcodes[primary['build']]}}
    if 'production' in deployed and primary['build'] == 'test':
        prod = deployed['production']
        lane['production'] = {'vault': prod['vault']['address'], 'verifier': prod['verifier']['address'], 'gamma': prod['gamma'], 'vaultInitcode': initcodes['production']}
    (work / 'lane.json').write_text(json.dumps(lane, indent=2) + '\n')
    # the envelope comes from the plug-in's measured gas model, run in the image (driver.ts envelope) over the manifest's pins
    (work / 'public/nb2-release.json').write_text(json.dumps(doc, indent=2) + '\n')
    release_nb2.driver(gen, 'envelope', '/work/nb2/envelope.json')
    doc['envelope'] = json.loads((work / 'envelope.json').read_text())
    (work / 'public/nb2-release.json').write_text(json.dumps(doc, indent=2) + '\n')
    if os.getuid() == 0:
        subprocess.run(['chown', '-R', '10001:10001', str(gen / 'bridge')], check=True)
    print(json.dumps({n: {'vault': d['vault']['address'], 'verifier': d['verifier']['address'], 'domain': d['domain']} for n, d in deployed.items()}))


if __name__ == '__main__':
    main()
