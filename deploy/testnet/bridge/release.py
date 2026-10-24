"""The bridge release manifest (TN-B #429/#438, briefs/tnb-without-host.md): one file that names everything this generation's bridge was built and deployed
from, and its limits. deploy_bridge.py writes it as GENERATION/bridge/public/bridge-release.json (published with the tester files; it holds no secret).

Every value is read from where it is in force, not restated:
  package     the generation's manifest.json: generation, chain, genesis hash, the node images and their source pins (deploy/testnet/pins.json)
  bridge      artifacts/bridge-images.json, checked against the image the deploy ran: the bridge tools image, its source pins (bridge/pins.json: contracts,
              native-bridge-plugins, Node/Go/Foundry) and the dnb-tool digest
  contracts   bridge-broadcast.json and the chain: BridgeVault and TokenVerifier addresses, their deploy transactions and blocks, their code hashes, the CFG
  profile     the bridge profile's vector corpus digest (native-bridge-plugins protocol/vectors/MANIFEST.sha256) and the state-transition SDK in the image;
              the generation's B1 profile (network/b1-profile.json) and its sha256
  limits      D1 the redemption envelope bound, D3 the ordinary block capacity, the block gas limit, the proof window, the gateway's body bound, the lock-proof
              endpoint's rate, the largest lock and the SDK batch bound. Live values come from the generation's files; the constants of a pinned component name
              their definition.
"""
import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARTIFACTS = HERE.parent / 'artifacts'
NBP = '/opt/bridge/native-bridge-plugins'   # the image's native-bridge-plugins checkout (Dockerfile.tools)
CONTRACTS = '/opt/bridge/contracts'   # and its contracts checkout

# Constants of a pinned component: the value and where it is defined, at that component's pin in this manifest.
D1_ENVELOPE_BYTES = 2 << 20   # ureth crates/unicity/bridge/src/lib.rs MAX_ENVELOPE_BYTES
MAX_LOCK_WEI = (1 << 64) - 1   # a token amount is 8 bytes in the bridge profile (native-bridge-plugins tester/core.ts MAX_LOCK_WEI)
LOCKPROOF_RATE = {'perClientPerSecond': 2, 'globalPerSecond': 20, 'concurrent': 4}   # bft-core scripts/dnb-tool/serve.go defaultProofLimits


def gateway_limits():
    """The public gateway's body bounds, read from gateway.py (the one definition): every method, eth_sendRawTransaction, and the /aggregator route."""
    text = (HERE.parent / 'gateway.py').read_text()
    return {k: int(re.search(rf'^{k} = (\d+)', text, re.M).group(1)) for k in ('MAX_BODY', 'MAX_RAW_TX_BODY', 'AGG_MAX_BODY')}


def flag(command, name):
    """The value of NAME in a container command (a list), or None."""
    return command[command.index(name) + 1] if name in command else None


def build(gen, tools, image_id, ureth_command, gateway):
    """The manifest of generation GEN. TOOLS(*args) runs a command in the bridge tools image and returns its output; IMAGE_ID is that image's ID;
    URETH_COMMAND is validator 1's execution client command (compose.yaml); GATEWAY is gateway_limits()."""
    package = json.loads((gen / 'manifest.json').read_text())
    images = json.loads((ARTIFACTS / 'bridge-images.json').read_text())
    if images['images']['bridge'] != image_id:
        raise SystemExit(f'artifacts/bridge-images.json records {images["images"]["bridge"]}, but the deploy ran {image_id}')
    work = gen / 'bridge'
    addr = json.loads((work / 'bridge-addresses.json').read_text())
    broadcast = json.loads((work / 'bridge-broadcast.json').read_text())
    deployed = {}
    for tx in broadcast['transactions']:
        name = tx.get('contractName')
        if name in ('BridgeVault', 'TokenVerifier') and tx.get('transactionType') in ('CREATE', 'CREATE2'):   # not a later call to the contract
            receipt = next(r for r in broadcast['receipts'] if r['transactionHash'] == tx['hash'])
            deployed[name] = {'address': tx['contractAddress'], 'transaction': tx['hash'], 'block': int(receipt['blockNumber'], 16),
                              'codeHash': tools('cast', 'codehash', '--rpc-url', 'http://ureth1:8545', tx['contractAddress']).strip()}
    if {n: d['address'] for n, d in deployed.items()} != {n: addr[n] for n in ('BridgeVault', 'TokenVerifier')}:
        raise SystemExit(f'the broadcast\'s contracts {deployed} are not bridge-addresses.json\'s {addr}')
    corpus = tools('cat', f'{NBP}/protocol/vectors/MANIFEST.sha256').split()
    # the contracts' golden tests are pinned to one corpus; the plug-ins must carry that same corpus
    pinned = json.loads(tools('cat', f'{CONTRACTS}/script/bridge-golden/corpus-pin.json'))['corpus']['manifestSha256']
    if corpus[0] != pinned:
        raise SystemExit(f'the plug-ins\' corpus {corpus[0]} is not the one the contracts are pinned to ({pinned})')
    sdk_dir = f'{NBP}/node_modules/@unicitylabs/state-transition-sdk'
    sdk = json.loads(tools('cat', f'{sdk_dir}/package.json'))
    lock = json.loads(tools('cat', f'{NBP}/package-lock.json'))['packages']['node_modules/@unicitylabs/state-transition-sdk']
    batch = int(re.search(r'BATCH_MAX_STATE_IDS = (\d+)', tools('cat', f'{sdk_dir}/lib/api/IBatchAggregatorClient.js')).group(1))
    profile_bytes = (gen / 'network/b1-profile.json').read_bytes()
    profile = json.loads(profile_bytes)
    return {
        'schema': 1,
        'package': {'generation': package['generation'], 'chainId': package['chain_id'], 'genesisHash': package['genesis_hash'], 'validators': package['validators'],
                    'sources': package['artifacts']['sources'], 'images': package['artifacts']['images']},
        'bridge': {'sources': images['sources'], 'image': image_id, 'dnbToolSha256': images['dnb_tool_sha256']},
        'contracts': {'commit': images['sources']['contracts'], 'cfg': addr['CFG'], **deployed},
        'profile': {'corpusDigest': corpus[0], 'corpusSource': 'native-bridge-plugins protocol/vectors/MANIFEST.sha256, equal to contracts script/bridge-golden/corpus-pin.json',
                    'nativeBridgePlugins': images['sources']['native-bridge-plugins'],
                    'sdk': {'version': sdk['version'], 'resolved': lock['resolved'], 'integrity': lock['integrity']},
                    'b1Profile': {'sha256': hashlib.sha256(profile_bytes).hexdigest(), **profile}},
        'limits': {
            'D1envelopeBytes': {'value': D1_ENVELOPE_BYTES, 'source': 'ureth crates/unicity/bridge/src/lib.rs MAX_ENVELOPE_BYTES, at package.sources.ureth'},
            'D3ordinaryCapacity': {'value': profile['ordinaryCapacity'], 'source': 'network/b1-profile.json ordinaryCapacity (ubft engine-api b1-profile --ordinary-capacity)'},
            'blockGasLimit': {'value': profile['maxGas'], 'source': 'network/b1-profile.json maxGas: the ordinary capacity plus the system reservation (ureth --builder.gaslimit)'},
            'proofWindowBlocks': {'value': int(flag(ureth_command, '--rpc.eth-proof-window')), 'source': 'compose.yaml ureth --rpc.eth-proof-window: a lock\'s proof can be fetched for this many blocks'},
            'gatewayMaxBodyBytes': {'value': gateway['MAX_BODY'], 'source': 'gateway.py MAX_BODY: every public method but eth_sendRawTransaction'},
            'gatewayMaxRawTxBodyBytes': {'value': gateway['MAX_RAW_TX_BODY'], 'source': 'gateway.py MAX_RAW_TX_BODY: eth_sendRawTransaction, so a redemption up to the D1 envelope fits as hex'},
            'gatewayAggregatorMaxBodyBytes': {'value': gateway['AGG_MAX_BODY'], 'source': 'gateway.py AGG_MAX_BODY: the public /aggregator route (its own rate limit)'},
            'lockProofRate': {'value': LOCKPROOF_RATE, 'source': 'bft-core scripts/dnb-tool/serve.go defaultProofLimits, at bridge.sources.bft'},
            'maxLockWei': {'value': str(MAX_LOCK_WEI), 'source': 'the bridge profile\'s 8-byte token amount'},
            'aggregatorBatchStateIds': {'value': batch, 'source': f'state-transition-sdk {sdk["version"]} BATCH_MAX_STATE_IDS: one consolidation holds the mint, the transfers '
                                        f'and the burn, so a token redeemed through one aggregator carries at most {batch - 2} transfers'},
        },
    }
