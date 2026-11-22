"""Build the wallet release for one checked NB2 v1.1 generation."""
import hashlib
import json
import math
import os
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTNET = HERE.parent.parent
ARTIFACTS = TESTNET / 'artifacts'
T7 = HERE.parents[3] / 'docs/design/nb2-t7-qualification-evidence.json'
PROVISIONAL = 'testnet-provisional'
MAX_CALL_GAS = 24_000_000
CALLDATA_BYTES = 393_216
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


def admission(gen, package, image_id, services):
    images = json.loads((ARTIFACTS / 'bridge-images.json').read_text())
    if images['images']['bridge'] != image_id:
        raise SystemExit(f'artifacts/bridge-images.json records {images["images"]["bridge"]}, but the deploy ran {image_id}')
    profile_bytes = (gen / 'network/b1-profile.json').read_bytes()
    b1 = json.loads(profile_bytes)
    per = {}
    for i in range(1, package['validators'] + 1):
        if not isinstance(services.get(f'ureth{i}'), dict):
            raise SystemExit(f'compose.yaml has no ureth{i}: the manifest describes every validator\'s pool')
    for name in sorted(services, key=lambda n: int(n[5:])):
        per[name] = validator_pins(name, effective_argv(name, services[name]), b1)
    if len(set(per.values())) != 1:
        raise SystemExit(f'the validators\' pools differ ({per}): one admission policy per deployment')
    pool, pool_gas = next(iter(per.values()))
    gw = gateway_limits()
    if gw['MAX_RAW_TX_BODY'] < 2 * L_MAX + (64 << 10):
        raise SystemExit(f'the gateway\'s eth_sendRawTransaction body bound {gw["MAX_RAW_TX_BODY"]} is below 2 L_max + 64 KiB')
    return images['sources'], profile_bytes, b1, pool, pool_gas, gw, ', '.join(per)


def envelopes():
    """Quote disposable test value from the T7 samples, with explicit margins."""
    evidence = T7.read_bytes()
    generations = json.loads(evidence)['generations']
    cases = {
        'transfer-600': generations['qualification-archive-costs']['costs']['transfer-600'],
        'split-20': generations['qualification-costs']['costs']['split-20'],
    }
    workloads = {}
    for name, sample in cases.items():
        workloads[name] = {
            'includedTransactions': sample['transactions'], 'includedGas': str(sample['gas']),
            'maxIncludedCallGas': str(sample['maxIncludedGas']),
            'budgetTransactions': math.ceil(sample['transactions'] * 3 / 2),
            'budgetGas': str(math.ceil(sample['gas'] * 3 / 2)),
        }
    fee = {
        'status': PROVISIONAL, 'sourceSha256': hashlib.sha256(evidence).hexdigest(),
        'source': 'docs/design/nb2-t7-qualification-evidence.json',
        'gasMarginPercent': 50, 'transactionMarginPercent': 50,
        'atMaxFeePerGasWei': '1000000000', 'workloads': workloads,
    }
    for item in workloads.values():
        item['budgetWeiAtReferenceFee'] = str(int(item['budgetGas']) * int(fee['atMaxFeePerGasWei']))

    sample = generations['qualification-loaded']['sealingSample']
    p99 = 2 * max(sample['proofMs']['99'], *(x['receiptMs']['99'] for x in cases.values()))
    progress = max(x['budgetTransactions'] for x in workloads.values()) * p99
    backlog = {
        'duringProgress': str(math.ceil(progress * sample['peakSeals'] / sample['peakWindowMs'])),
        'peakSeals': str(sample['peakSeals']), 'elapsedMs': str(sample['peakWindowMs']),
        'receiptP99Ms': str(p99), 'advancePeakSeals': '1', 'finalInclusionMs': str(p99),
        'finalPeakSeals': '1', 'qualifiedForMs': str(sample['firstToLastSealMs']),
    }
    peak = {'status': PROVISIONAL, 'sourceSha256': fee['sourceSha256'], 'sample': sample,
            'timingMarginPercent': 100, 'arrivalMarginSealsPerCall': 1, 'backlog': backlog}

    execution = str(math.ceil(max(x['maxIncludedGas'] for x in cases.values()) * 3 / 2))
    def range_of(entry, operations, pages, gaps, opening):
        return {'minReceiptBytes': 0, 'max': {'entry': entry, 'calldataBytes': CALLDATA_BYTES,
                'operations': operations, 'pages': pages, 'gaps': gaps, 'receiptBytes': 65536,
                'openingBytes': opening}, 'execution': execution}
    ranges = [range_of('run', n, 32, 0, 131072) for n in range(1, 17)]
    ranges += [range_of('advanceGaps', 0, 0, n, 0) for n in range(1, 129)]
    ranges += [range_of('redeemRecovered', 0, 0, n, 0) for n in range(129)]
    ordinary = [{'maxEvidenceBytes': 65536, 'maxOperations': 16, 'maxGaps': '128', 'execution': execution}]
    return fee, peak, ranges, ordinary


def build(gen, record, image_id, services, origin, *, limits=None):
    package = json.loads((gen / 'manifest.json').read_text())
    sources, profile_bytes, b1, pool, pool_gas, gw, validators = limits or admission(gen, package, image_id, services)
    vault, recovery = (record['contracts'][role] for role in ('vault', 'recovery'))
    gas = min(b1['ordinaryCapacity'], MAX_CALL_GAS)
    fee, peak, ranges, ordinary = envelopes()
    return {
        'schema': 'unicity-nb2-release', 'version': '1.1', 'status': PROVISIONAL, 'realValueAuthorized': False,
        'package': {'generation': package['generation'], 'chainId': package['chain_id'], 'genesisHash': package['genesis_hash'],
                    'validators': package['validators'], 'sources': package['artifacts']['sources'], 'images': package['artifacts']['images']},
        'bridge': {'image': image_id, 'sources': sources},
        'deployment': record,
        'profile': {'semanticProfileHash': record['descriptors']['semantic-profile'], 'b1ProfileSha256': hashlib.sha256(profile_bytes).hexdigest()},
        'trust': {'bundle': 'trust-base.bundle.cbor', 'genesisEntryId': record['trustPin'], 'origin': origin,
                  'refresh': 'GET /api/v1/trustbases on the gateway'},
        'pins': {'gamma': record['gamma'], 'build': record['build'], 'vaultRuntimeCodeHash': vault['runtimeCodeHash'],
                 'maxEncodedTxBytes': L_MAX, 'userGasLimit': str(gas), 'gasReserve': str(GAS_RESERVE),
                 'returnReserveSegments': RETURN_RESERVE_SEGMENTS, 'deploymentBlock': vault['block'], 'stateReadOnly': STATE_READ_ONLY},
        'recovery': {'status': PROVISIONAL, 'salt': record['salt'], 'address': recovery['address'],
                     'runtimeHash': recovery['runtimeCodeHash'], 'pins': record['pins'], 'ranges': ranges,
                     'ordinaryRanges': ordinary, 'backlog': peak['backlog']},
        'feeEnvelope': fee, 'peakWindowEnvelope': peak,
        'limits': {
            'maxEncodedTxBytes': {'value': L_MAX, 'source': 'NB2 v1.1 reference profile'},
            'poolMaxTxInputBytes': {'value': pool, 'source': f'Compose ureth flags of every validator ({validators})'},
            'poolMaxTxGas': {'value': pool_gas, 'source': 'Compose --txpool.max-tx-gas and the B1 ordinary capacity'},
            'gatewayMaxRawTxBytes': {'value': (gw['MAX_RAW_TX_BODY'] - (64 << 10)) // 2, 'source': 'gateway.py MAX_RAW_TX_BODY minus hex framing'},
            'userGasLimit': {'value': gas, 'source': 'minimum of B1 ordinaryCapacity and NB2 v1.1 per-call gas ceiling'},
            'blockGasLimit': {'value': b1['maxGas'], 'source': 'network/b1-profile.json maxGas'},
            'calldataBytes': {'value': CALLDATA_BYTES, 'source': 'NB2 v1.1 cold-call calldata cap'},
            'gasReserve': {'value': GAS_RESERVE, 'source': 'NB2 v1.1 seal reserve'},
            'returnReserveSegments': {'value': RETURN_RESERVE_SEGMENTS, 'source': 'NB2 v1.1 recovery reserve'},
            'gatewayMaxBodyBytes': {'value': gw['MAX_BODY'], 'source': 'gateway.py MAX_BODY'},
            'gatewayMaxRawTxBodyBytes': {'value': gw['MAX_RAW_TX_BODY'], 'source': 'gateway.py MAX_RAW_TX_BODY'},
            'gatewayLargeSlots': {'value': gw['LARGE_SLOTS'], 'source': 'gateway.py LARGE_SLOTS'},
            'gatewayLogBlockRange': {'value': gw['LOG_BLOCK_RANGE'], 'source': 'gateway.py LOG_BLOCK_RANGE'},
            'gatewayMaxResultBytes': {'value': gw['MAX_RESULT_BYTES'], 'source': 'gateway.py MAX_RESULT_BYTES'},
            'gatewayAggregatorMaxBodyBytes': {'value': gw['AGG_MAX_BODY'], 'source': 'gateway.py AGG_MAX_BODY'},
            'retention': {'value': {'proofSource': True, 'companions': 'life of the deployment', 'receipts': 'life of the deployment',
                                    'logs': 'life of the deployment'},
                          'source': f'Compose proof-source configuration on every validator ({validators})'},
        },
    }
