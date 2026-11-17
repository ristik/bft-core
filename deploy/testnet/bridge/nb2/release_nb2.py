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


def wallet_cmd(gen, cwd, *args, env_file=None):
    """The docker command of one reference-wallet command (native-bridge-plugins wallet/nb2-wallet.ts, bft-core#1107) in the bridge tools image, as
    a wallet developer runs it: from the working directory CWD (a directory of GENERATION/bridge, at /work), on the validators network, as the tools
    user, its key from the environment file. The wallet is the image's own plug-in checkout's: nothing of this directory is mounted."""
    from deploy_bridge import image, validators_network
    envs = ['--env-file', str(env_file)] if env_file else []
    return ['docker', 'run', '--rm', '--read-only', '--network', validators_network(gen), '--user', '10001:10001', *envs, '-e', 'HOME=/tmp/home',
            '--tmpfs', '/tmp', '-v', f'{gen / "bridge"}:/work', '-w', cwd, image(gen),
            'node', f'{NBP}/node_modules/.bin/tsx', f'{NBP}/wallet/nb2-wallet.ts', *args]


def driver(gen, *args, env_file=None):
    if os.getuid() == 0:
        subprocess.run(['chown', '-R', '10001:10001', str(gen / 'bridge')], check=True)
    out = subprocess.run(driver_cmd(gen, *args, env_file=env_file), text=True, capture_output=True)
    if out.returncode != 0:
        raise SystemExit(f'driver {args[0]} failed:\n{out.stdout[-3000:]}\n{out.stderr[-3000:]}')
    return out.stdout


# The exact keys generate.py's topology() writes for an execution client (and joiner.py clones). A ureth service with any other key (extends, command,
# a merge, anything new) is refused: the manifest judges the generated form only and never resolves Compose's inheritance or merging.
URETH_KEYS = frozenset({'cap_drop', 'cpus', 'entrypoint', 'image', 'logging', 'mem_limit', 'networks', 'pids_limit', 'read_only', 'restart', 'security_opt',
                        'stop_grace_period', 'tmpfs', 'volumes'})
URETH_SERVICE = re.compile(r'^ureth\d+$')


# Compose's interpolation (compose-go template): `$$` is an escaped `$`, `$NAME` and `${...}` are substituted (names case-insensitive); any other `$`
# is left as written. A string Compose would render differently from its text is not judged.
COMPOSE_REWRITES = re.compile(r'\$(?:\$|\{|[_A-Za-z])')


def key_preflight():
    """The ureth key preflight wrapper's head exactly as generate.py and joiner.py write it (ureth_key.entrypoint, bft-core#1148): /bin/sh -c PREFLIGHT
    ureth, then ureth's own argv. PREFLIGHT is written unescaped; it is accepted only while Compose leaves it as written (its one `$` is "$@")."""
    import sys
    if str(TESTNET) not in sys.path:
        sys.path.insert(0, str(TESTNET))
    import ureth_key
    head = ureth_key.entrypoint([])
    if COMPOSE_REWRITES.search(ureth_key.PREFLIGHT):
        raise SystemExit('ureth_key.PREFLIGHT holds text Compose would interpolate: the manifest cannot judge the generated entrypoint (refused)')
    return head


def effective_argv(name, service):
    """The arguments SERVICE runs with, in the only form generate.py writes: exactly its keys (URETH_KEYS), `entrypoint` a list of plain strings, behind
    the node key preflight (key_preflight: exactly ureth_key's text, stripped) or bare. Anything else is refused, so Compose is never emulated: no extends
    or command, no string entrypoint, no other argument holding `$`, a backslash or a quote (a `$$` too: Compose would render it `$`)."""
    if not isinstance(service, dict) or set(service) != URETH_KEYS:
        extra = sorted(set(service) - URETH_KEYS) if isinstance(service, dict) else []
        missing = sorted(URETH_KEYS - set(service)) if isinstance(service, dict) else []
        raise SystemExit(f'{name} is not the generated service form (extra keys {extra}, missing {missing}): refused')
    ep = service['entrypoint']
    if not isinstance(ep, list) or not all(isinstance(x, str) for x in ep):
        raise SystemExit(f'{name}\'s entrypoint is not a list of strings ({type(ep).__name__}): refused')
    head = key_preflight()
    if ep[:len(head)] == head:
        ep = ep[len(head):]
        if not ep:
            raise SystemExit(f'{name}\'s entrypoint is the key preflight with no command after it (refused)')
    elif ep[:2] == head[:2]:
        raise SystemExit(f'{name}\'s entrypoint is a shell wrapper other than the generated key preflight (ureth_key.entrypoint): refused')
    odd = [x for x in ep if any(c in x for c in '$\\\'"')]
    if odd:
        raise SystemExit(f'{name}\'s entrypoint has arguments Compose would rewrite (interpolation, escapes or quotes): {odd[:3]} (refused)')
    return list(ep)


def active_services(gen):
    """Every execution-client service of the generation's Compose files: compose.yaml, and every override beside it (compose*.json/yaml: the joiner and
    restore overrides handoff_ops.compose_files selects, the install-epoch ones, the protocol 6/7 bridge overlay). Only the joiner override may add an
    execution client (the joiner's clone of a genesis one, a new name); no override may touch one the base defines, and no other override may define
    one at all: Compose would merge them, and the manifest judges whole generated services only."""
    import sys
    if str(TESTNET) not in sys.path:
        sys.path.insert(0, str(TESTNET))
    import handoff_ops
    gen = Path(gen)
    base = json.loads((gen / 'compose.yaml').read_text()).get('services', {})
    out = {n: s for n, s in base.items() if URETH_SERVICE.match(n)}
    overrides = sorted((p for p in gen.iterdir() if p.is_file() and p.name.startswith('compose') and p.name != 'compose.yaml' and p.suffix in ('.json', '.yaml', '.yml')),
                       key=lambda p: (p.name != handoff_ops.JOINER_OVERRIDE, p.name))   # the joiner override first, as compose_files orders it
    for path in overrides:
        try:
            services = json.loads(path.read_text()).get('services', {})
        except ValueError:
            raise SystemExit(f'{path.name} is not the generated JSON form: the manifest cannot judge it (refused)')
        if not isinstance(services, dict):
            raise SystemExit(f'{path.name}: services is not a mapping')
        for name, svc in services.items():
            if not URETH_SERVICE.match(name):
                continue
            if name in out:
                raise SystemExit(f'{path.name} overrides {name}, which an earlier file defines: an override may not alter an execution client (refused)')
            if path.name != handoff_ops.JOINER_OVERRIDE:
                raise SystemExit(f'{path.name} defines {name}: only the joiner override adds an execution client (refused)')
            out[name] = svc
    return out


def validator_pins(name, command, b1):
    """One validator's execution client as the manifest requires it: a full proof source (none of NOT_PROOF_SOURCE, in either flag form), a pinned pool
    byte limit at or above L_max, and the pool gas cap at the profile's ordinary capacity. Returns (pool bytes, pool gas)."""
    bad = [f for f in NOT_PROOF_SOURCE if any(w == f or w.startswith(f + '=') for w in command)]
    if bad:
        raise SystemExit(f'{name} is not a full proof source ({", ".join(bad)}): wallets could not fetch their evidence from it')
    pool, pool_gas = flag(command, '--txpool.max-tx-input-bytes'), flag(command, '--txpool.max-tx-gas')
    if pool is None:
        raise SystemExit(f'{name} runs without --txpool.max-tx-input-bytes: its pool\'s encoded-transaction limit is reth\'s default, not pinned')
    if int(pool) < L_MAX:
        raise SystemExit(f'{name}\'s pool admits {pool} encoded bytes, below L_max {L_MAX}')
    if pool_gas is None or int(pool_gas) != b1['ordinaryCapacity']:
        raise SystemExit(f'{name} runs --txpool.max-tx-gas {pool_gas}, not the profile\'s ordinary capacity {b1["ordinaryCapacity"]}')
    return int(pool), int(pool_gas)


def build(gen, record, image_id, services):
    """The manifest of generation GEN. SERVICES are compose.yaml's services: every validator's execution client (ureth1..N, N the manifest's validators)
    must be there and pass validator_pins with the same settings, because the gateway relays to all of them."""
    package = json.loads((gen / 'manifest.json').read_text())
    images = json.loads((ARTIFACTS / 'bridge-images.json').read_text())
    if images['images']['bridge'] != image_id:
        raise SystemExit(f'artifacts/bridge-images.json records {images["images"]["bridge"]}, but the deploy ran {image_id}')
    profile_bytes = (gen / 'network/b1-profile.json').read_bytes()
    b1 = json.loads(profile_bytes)
    per = {}
    for i in range(1, package['validators'] + 1):
        if not isinstance(services.get(f'ureth{i}'), dict):
            raise SystemExit(f'compose.yaml has no ureth{i}: the manifest describes every validator\'s pool')
    for name in sorted((n for n in services if URETH_SERVICE.match(n)), key=lambda n: int(n[5:])):   # the genesis validators and any joiner's
        per[name] = validator_pins(name, effective_argv(name, services[name]), b1)
    if len(set(per.values())) != 1:
        raise SystemExit(f'the validators\' pools differ ({per}): one admission policy per deployment')
    pool, pool_gas = next(iter(per.values()))
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
            'poolMaxTxInputBytes': {'value': pool, 'source': f'compose.yaml --txpool.max-tx-input-bytes of every validator ({", ".join(per)}), from the B1 profile\'s ureth flags (ubft cli/ubft/cmd/b1_activation.go urethTxInputBytes)'},
            'poolMaxTxGas': {'value': pool_gas, 'source': 'compose.yaml ureth --txpool.max-tx-gas: the profile\'s ordinary capacity (a transaction above userGasLimit is refused at admission)'},
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
                          'source': f'compose.yaml, every validator ({", ".join(per)}): none of {", ".join(NOT_PROOF_SOURCE)} (ureth refuses pruning on a proof source); unicity_sealCompanionHorizonV1 answers null'},
            'p2p': {'value': 'no execution-client transaction gossip in this package (ureth --disable-discovery, no trusted peers): the gateway relays eth_sendRawTransaction to every validator; a block travels between validators on the shard node\'s /unicity/shard-payload/1.0.0 (no frame cap)',
                    'source': 'generate.py, deploy/testnet/gateway.py, shardnode/net_dissemination.go'},
        },
        'envelope': None,
    }
