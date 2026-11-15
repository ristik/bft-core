"""The native bridge v2 release manifest (NB2-09, bft-core#1105; spec docs/design/native-bridge-v2.md section 4.3): GENERATION/bridge/nb2/public/nb2-release.json.

One file that names what the deployment is and the limits it runs with. It holds no secret and is published with the trust bundle. A wallet reads `pins` as
its DeploymentPins (native-bridge-plugins nb2 bridge.ts) and `envelope` for its preflight; every other part says where a value comes from:

  package     the generation's manifest.json: generation, chain, genesis hash, validators, the node images and their source pins
  bridge      the bridge tools image and its source pins (artifacts/bridge-images.json, bridge/pins.json)
  deployment  per build (test, and production when deployed): Γ and D, K, B, Qmax, the vault's, the verifier's and its receipt helper's addresses,
              deploy transactions, blocks and code hashes; deploymentBlock, from which wallets read logs
  profile     the semantic profile hash (SHA-256 of the plug-ins' protocol/profile.json, in Γ) and the vectors digest (nb2-vectors.json.sha256)
  pins        section 4.3: gamma, build, vaultRuntimeCodeHash, maxEncodedTxBytes, userGasLimit, gasReserve, returnReserveSegments, deploymentBlock,
              stateReadOnly
  limits      each pinned limit with its source: L_max and the path's limits (the pools' --txpool.max-tx-input-bytes and --txpool.max-tx-gas from
              the B1 profile's ureth flags, the gateway body), the user gas
              capacity (b1-profile ordinaryCapacity) and the block gas limit, the gateway's bodies, log window and answer cap, retention
  envelope    from the limits by the plug-in's measured gas model (driver.ts envelope): the largest token, the proofs beside it, the return delay
"""
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTNET = HERE.parent.parent
ARTIFACTS = TESTNET / 'artifacts'
NBP = '/opt/bridge/native-bridge-plugins'

# L_max, the wallets' pinned encoded-transaction limit (spec section 4.3; owner-question default 512 KiB, fallback 128 KiB). It must lie within
# every limit of the path: each validator's pool (--txpool.max-tx-input-bytes, set by the B1 profile's ureth flags: 4 MiB at this bft pin, twice
# the protocol 6/7 envelope) and the gateway's eth_sendRawTransaction body (2 L_max + 64 KiB, section 12.7).
L_MAX = 512 << 10
GAS_RESERVE = 500_000   # spec section 12.4, fixed by #1098
RETURN_RESERVE_SEGMENTS = 64   # spec section 12.5 default (PARAM, #1105)
STATE_READ_ONLY = False   # the lanes use seal receipts (section 12.2); a plain state() read is not evidence here
# ureth flags that would stop a gateway node serving the wallet evidence (section 12.7 "Retention"): any of them makes the manifest refuse
NOT_PROOF_SOURCE = ('--unicity.no-proof-source', '--unicity.companion-retention-depth', '--prune.receipts.distance', '--prune.receipts.before',
                    '--prune.receiptslogfilter', '--prune.bodies.distance', '--prune.bodies.pre-merge', '--full')


def flag(command, name):
    """The value of NAME in a container command, as `NAME VALUE` or `NAME=VALUE` (the B1 profile's ureth flags); the last one counts, as clap's."""
    found = None
    for i, w in enumerate(command):
        if w == name and i + 1 < len(command):
            found = command[i + 1]
        elif w.startswith(name + '='):
            found = w.split('=', 1)[1]
    return found


def gateway_limits():
    text = (TESTNET / 'gateway.py').read_text()
    pick = lambda k: int(eval(re.search(rf'^{k} = ([^#\n]+)', text, re.M).group(1), {}))   # noqa: E731 (literal constants and shifts only)
    return {k: pick(k) for k in ('MAX_BODY', 'MAX_RAW_TX_BODY', 'AGG_MAX_BODY', 'LOG_BLOCK_RANGE', 'MAX_RESULT_BYTES', 'LARGE_SLOTS')}


def driver_cmd(gen, *args, env_file=None, extra=()):
    """The docker command of one driver run (driver.ts) in the bridge tools image: GENERATION/bridge at /work, this directory at
    tests/live/nb2lane of the image's plug-in checkout (read-only), on the validators network, as the tools user."""
    from deploy_bridge import image, validators_network
    envs = ['--env-file', str(env_file)] if env_file else []
    return ['docker', 'run', '--rm', '--read-only', '--network', validators_network(gen), '--user', '10001:10001', *envs, '-e', 'HOME=/tmp/home', *extra,
            '--tmpfs', '/tmp', '-v', f'{gen / "bridge"}:/work', '-v', f'{HERE}:{NBP}/tests/live/nb2lane:ro', '-w', NBP, image(gen),
            'npx', '--no-install', 'tsx', 'tests/live/nb2lane/driver.ts', *args]


def driver(gen, *args, env_file=None):
    if os.getuid() == 0:
        subprocess.run(['chown', '-R', '10001:10001', str(gen / 'bridge')], check=True)
    out = subprocess.run(driver_cmd(gen, *args, env_file=env_file), text=True, capture_output=True)
    if out.returncode != 0:
        raise SystemExit(f'driver {args[0]} failed:\n{out.stdout[-3000:]}\n{out.stderr[-3000:]}')
    return out.stdout


def build(gen, record, image_id, ureth_command):
    package = json.loads((gen / 'manifest.json').read_text())
    images = json.loads((ARTIFACTS / 'bridge-images.json').read_text())
    if images['images']['bridge'] != image_id:
        raise SystemExit(f'artifacts/bridge-images.json records {images["images"]["bridge"]}, but the deploy ran {image_id}')
    profile_bytes = (gen / 'network/b1-profile.json').read_bytes()
    b1 = json.loads(profile_bytes)
    pool = flag(ureth_command, '--txpool.max-tx-input-bytes')
    pool_gas = flag(ureth_command, '--txpool.max-tx-gas')
    if pool is None:
        raise SystemExit('compose.yaml runs ureth without --txpool.max-tx-input-bytes: the pool\'s encoded-transaction limit is reth\'s default, not pinned')
    if pool_gas is None or int(pool_gas) != b1['ordinaryCapacity']:
        raise SystemExit(f'ureth --txpool.max-tx-gas {pool_gas} is not the profile\'s ordinary capacity {b1["ordinaryCapacity"]}')
    pool = int(pool)
    if pool < L_MAX:
        raise SystemExit(f'the pool admits {pool} encoded bytes, below L_max {L_MAX}')
    bad = [f for f in NOT_PROOF_SOURCE if f in ureth_command]
    if bad:
        raise SystemExit(f'validator 1\'s ureth is not a full proof source ({bad}): wallets could not fetch their evidence')
    gw = gateway_limits()
    lmax = L_MAX
    if gw['MAX_RAW_TX_BODY'] < 2 * lmax + (64 << 10):
        raise SystemExit(f'the gateway\'s eth_sendRawTransaction body bound {gw["MAX_RAW_TX_BODY"]} is below 2 L_max + 64 KiB (section 12.7)')
    primary = record['deployments'][record['primary']]
    deployment_block = primary['verifier']['block']   # the first block of this deployment: the verifier's creation precedes the vault's
    pins = {
        'gamma': primary['gamma'], 'build': primary['build'], 'vaultRuntimeCodeHash': primary['vault']['runtimeCodeHash'], 'maxEncodedTxBytes': lmax,
        'userGasLimit': str(b1['ordinaryCapacity']), 'gasReserve': str(GAS_RESERVE), 'returnReserveSegments': RETURN_RESERVE_SEGMENTS,
        'deploymentBlock': primary['vault']['block'], 'stateReadOnly': STATE_READ_ONLY,
    }
    return {
        'schema': 'unicity-nb2-release', 'version': 1,
        'status': 'test deployment, fake value: no continuation (NB2-12), mint admission open (#1039); see docs/design/native-bridge-v2.md section 2',
        'package': {'generation': package['generation'], 'chainId': package['chain_id'], 'genesisHash': package['genesis_hash'], 'validators': package['validators'],
                    'sources': package['artifacts']['sources'], 'images': package['artifacts']['images']},
        'bridge': {'image': image_id, 'sources': images['sources']},
        'deployment': {'primary': record['primary'], 'deployer': record['deployer'], 'firstBlock': deployment_block, **record['deployments']},
        'profile': {'semanticProfileHash': record['profileHash'], 'source': 'SHA-256 of native-bridge-plugins protocol/profile.json at bridge.sources',
                    'vectorsDigest': record['vectorsDigest'], 'vectorsSource': 'protocol/vectors/nb2/nb2-vectors.json.sha256', 'protocolVersion': 9,
                    'b1Profile': {'sha256': hashlib.sha256(profile_bytes).hexdigest()}},
        'trust': {'bundle': 'trust-base.bundle.cbor', 'genesisEntryId': record['trustPin'], 'source': 'dnb-tool trust-bundle of network/trust-base.json; Γ.rootGenesis32',
                  'refresh': 'GET /api/v1/trustbases on the gateway (the SDK trust-base path)'},
        'pins': pins,
        'limits': {
            'maxEncodedTxBytes': {'value': lmax, 'source': 'release_nb2.py L_MAX (owner-question default, spec section 15): the wallets\' limit; within the pool and the gateway limits below'},
            'poolMaxTxInputBytes': {'value': pool, 'source': 'compose.yaml ureth --txpool.max-tx-input-bytes, from the B1 profile\'s ureth flags (ubft cli/ubft/cmd/b1_activation.go urethTxInputBytes)'},
            'poolMaxTxGas': {'value': int(pool_gas), 'source': 'compose.yaml ureth --txpool.max-tx-gas: the profile\'s ordinary capacity (a transaction above userGasLimit is refused at admission)'},
            'gatewayMaxRawTxBytes': {'value': (gw['MAX_RAW_TX_BODY'] - (64 << 10)) // 2, 'source': 'gateway.py MAX_RAW_TX_BODY: the largest encoded transaction its body carries as hex with framing (below the pool\'s)'},
            'userGasLimit': {'value': b1['ordinaryCapacity'], 'source': 'network/b1-profile.json ordinaryCapacity: the block gas available to user transactions (max_gas - system_gas)'},
            'blockGasLimit': {'value': b1['maxGas'], 'source': 'network/b1-profile.json maxGas (ureth --builder.gaslimit): ordinary capacity plus the system reservation'},
            'gasReserve': {'value': GAS_RESERVE, 'source': 'spec section 12.4 (#1098)'},
            'returnReserveSegments': {'value': RETURN_RESERVE_SEGMENTS, 'source': 'spec section 12.5 default'},
            'gatewayMaxBodyBytes': {'value': gw['MAX_BODY'], 'source': 'gateway.py MAX_BODY: every public method but eth_call, eth_estimateGas and eth_sendRawTransaction'},
            'gatewayMaxRawTxBodyBytes': {'value': gw['MAX_RAW_TX_BODY'], 'source': 'gateway.py MAX_RAW_TX_BODY: at least 2 L_max + 64 KiB (section 12.7)'},
            'gatewayLargeSlots': {'value': gw['LARGE_SLOTS'], 'source': 'gateway.py LARGE_SLOTS: large bodies read at once (503 busy: retry)'},
            'gatewayLogBlockRange': {'value': gw['LOG_BLOCK_RANGE'], 'source': 'gateway.py LOG_BLOCK_RANGE: blocks per eth_getLogs window'},
            'gatewayMaxResultBytes': {'value': gw['MAX_RESULT_BYTES'], 'source': 'gateway.py MAX_RESULT_BYTES: one relayed answer (413 above: ask for less)'},
            'gatewayAggregatorMaxBodyBytes': {'value': gw['AGG_MAX_BODY'], 'source': 'gateway.py AGG_MAX_BODY: the /aggregator route'},
            'retention': {'value': {'proofSource': True, 'companions': 'life of the deployment', 'receipts': 'life of the deployment', 'logs': 'life of the deployment'},
                          'source': f'compose.yaml ureth: none of {", ".join(NOT_PROOF_SOURCE)} (ureth refuses pruning on a proof source); unicity_sealCompanionHorizonV1 answers null'},
            'p2p': {'value': 'no execution-client transaction gossip in this package (ureth --disable-discovery, no trusted peers): the gateway relays eth_sendRawTransaction to every validator; a block travels between validators on the shard node\'s /unicity/shard-payload/1.0.0 (no frame cap)',
                    'source': 'generate.py, deploy/testnet/gateway.py, shardnode/net_dissemination.go'},
        },
        'envelope': None,
    }
