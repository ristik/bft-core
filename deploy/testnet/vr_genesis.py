#!/usr/bin/env python3
"""The genesis plan of a validator-registry (VR) generation (VT-14, ristik/bft-core#1158; design section 2.1 "Genesis consistency").

One command produces every artifact of the generation and refuses any mismatch between them:

  keys              root and EVM node keys of N validators (root-node / shard-node init)
  trust-base.json   the genesis root trust base, signed by every root
  shard-conf        the EVM shard configuration, pinning VR (validator_registry, validator_registry_code_hash) from the measurement
  b1-profile.json   both hooks on VR, priced from the complete-path measurement (engine-api b1-profile --vr-hook-measurement)
  vr/input.json     the contracts genesis input; genesis-identities.json the roots' --genesis-identities (ubft vr-genesis plan)
  vr/alloc.json     VR + facets, PoaElection, PoaComposerEngine (first, checked), FoundationMultisig (contracts script/vr-genesis.sh)
  genesis.json      the EVM genesis with the SealRegistry and the VR accounts; full-shard-conf.json (engine-api genesis)
  vr-deployment.json the roots' --vr-deployment, written by `ubft vr-genesis verify` only when everything agrees
  ureth-flags.txt   the paired ureth's --unicity.* flags (the profile's, plus the genesis commitment)

The recorded measurement (--measurement) is ureth's complete-path measurement the profile is pinned from; its VR and module code hashes are
what the PDR pins before anything is deployed. The fresh measurement is a generation step: with --ureth the plan runs the paired ureth's
measurement (crates/unicity/execution/tests/vr_hook.rs vr_hook_measurement) itself, and `verify` holds it to the final allocation (VR and
module code, H, caps, ceilings) and to the pins; a requirement above them refuses the generation (raise M_H, never keep stale pins). An
externally taken fresh measurement may be passed with --fresh-measurement instead; the recorded file is never taken for it.

This builds a development generation's files only: it starts nothing, and it never touches a running network. A later staging regeneration
uses the same steps (deploy/testnet/generate.py --vr is the follow-up that wires them into the Compose package).

    deploy/testnet/vr_genesis.py --ubft build/ubft --contracts ../unicity-pos-contracts --ureth ../ureth \\
        --measurement deploy/testnet/vr-hook-measurement.json --validators 4 --out /tmp/vr-gen
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
NETWORK_ID, PARTITION, CHAIN_ID = 3, 8, 3
FEE_COLLECTOR = '0x00000000000000000000000000000000000000fe'   # generate.py FEE: the shard nodes' --engine-fee-collector
CONTINUITY = '1/2'                                                # generate.py EVM_CONTINUITY_MAX_DISTANCE
MAX_EPOCHS, DELTA_EV, DELTA_HOLD = 2, 16, 17                      # generate.py
VR = '0xff00000000000000000000000000000000000003'

# The PoS prototype's choices (VT-04; deploy/testnet/pos.py's lane values). The committee ceiling and the identity pool are the contracts'
# measured deployment limit (script/VRPosGenesis.s.sol): nMax 5, an index of 8 identities of one lot each.
POS_BOND_UNIT = 100 * 10**18
POS_TREASURY = '0x00000000000000000000000000000000000000ee'
POS_REWARD_FUNDING = 10_000 * 10**18
POS_REWARD_RATE = 10**18
POS_CADENCE = (400, 300)
POS_LIMITS = '4,5,5'   # nMin,nTarget,nMax: nTarget 5 so the fifth identity (the joiner) is elected


class VRGenesisError(RuntimeError):
    pass


def run(*args, cwd=None, env=None):
    done = subprocess.run([str(a) for a in args], text=True, capture_output=True, cwd=cwd, env=env)
    if done.returncode != 0:
        raise VRGenesisError(' '.join(map(str, args[:4])) + ' failed\n' + done.stdout + done.stderr)
    return done.stdout


# A development generation's premine (--dev-fund): each identity owner and governor signer, whose keys the plan generates, holds this many
# wei, so they can send the transactions an election needs (an owner's proposeBinding, a multisig queue and execute).
DEV_FUND_WEI = 1000 * 10**18


def dev_network_word(generation):
    """The network word of a development generation; `ubft vr-genesis verify --dev-generation` accepts dev funding only under it."""
    return '0x' + hashlib.sha256(('unicity.dev.vr.' + generation).encode()).hexdigest()


def dev_keys(out, n, new_key=None):
    """Fresh keys for n owners and the five governor signers (DEV only), in out/dev-keys/ (vr_dev_keys: keys.json 0600, O_EXCL)."""
    import vr_dev_keys
    return vr_dev_keys.write(out / 'dev-keys', n, **({'new_key': new_key} if new_key else {}))


def network_word(generation):
    return '0x' + hashlib.sha256(('unicity.testnet.vr.' + generation).encode()).hexdigest()


def dev_signers(generation):
    """Five DEV multisig signers nobody holds a key for (a development generation; a real one passes --governor-signers)."""
    return [('0x' + hashlib.sha256(f'unicity.vr.dev-signer/{generation}/{i}'.encode()).hexdigest()[:40]) for i in range(5)]


def partition_params(chain_id, measurement):
    return ','.join([f'proof_type=exec', f'chain_id={chain_id}', f'continuity_max_distance={CONTINUITY}',
                     f'validator_registry={measurement["registry"]}', f'validator_registry_code_hash={measurement["registryCodeHash"]}'])


def funded_base_genesis(chain_id, max_gas, entropy):
    return {'config': {'chainId': chain_id, 'homesteadBlock': 0, 'eip150Block': 0, 'eip155Block': 0, 'eip158Block': 0, 'byzantiumBlock': 0,
        'constantinopleBlock': 0, 'petersburgBlock': 0, 'istanbulBlock': 0, 'berlinBlock': 0, 'londonBlock': 0, 'mergeNetsplitBlock': 0,
        'shanghaiTime': 0, 'cancunTime': 0, 'terminalTotalDifficulty': 0, 'terminalTotalDifficultyPassed': True},
        'nonce': '0x0', 'timestamp': '0x0', 'extraData': '0x' + entropy, 'gasLimit': hex(max_gas), 'difficulty': '0x0',
        'mixHash': '0x' + '00' * 32, 'coinbase': '0x' + '00' * 20, 'baseFeePerGas': '0x3b9aca00', 'alloc': {}}


def merge_alloc(genesis, extra):
    have = {k.lower().removeprefix('0x') for k in genesis['alloc']}
    for address in extra:
        if address.lower().removeprefix('0x') in have:
            raise VRGenesisError(f'the genesis alloc already has {address}')
    genesis['alloc'].update(extra)
    return genesis


def genesis_commitment(genesis):
    slot = run('cast', 'keccak', 'unicity.seal-registry/genesisCommitment').strip().lower()
    alloc = {k.lower().removeprefix('0x'): v for k, v in genesis['alloc'].items()}
    storage = {k.lower(): v for k, v in alloc['ff00000000000000000000000000000000000002']['storage'].items()}
    word = storage.get(slot)
    if not word or int(word, 16) == 0:
        raise VRGenesisError('genesisCommitment is not set in the registry storage of the finalized genesis')
    return '0x' + word.lower().removeprefix('0x').rjust(64, '0')


def git_commit(path):
    """The checkout's commit, or a note that the tree carries no git metadata (a copied tree)."""
    done = subprocess.run(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True, capture_output=True)
    if done.returncode != 0:
        return 'unknown: no git metadata at ' + str(Path(path).resolve())
    dirty = subprocess.run(['git', '-C', str(path), 'status', '--porcelain'], text=True, capture_output=True).stdout.strip()
    return done.stdout.strip() + (' (modified)' if dirty else '')


def fresh_measurement(a, out, module_hash=None):
    """The paired ureth's complete-path measurement, run now (cargo test of the ignored vr_hook_measurement), or an explicit external one."""
    if a.fresh_measurement:
        fresh = Path(a.fresh_measurement).resolve()
        if fresh == Path(a.measurement).resolve():
            raise VRGenesisError('--fresh-measurement is the recorded measurement: a fresh measurement must be taken anew')
        shutil.copy2(fresh, out / 'vr-hook-measurement-fresh.json')
        return out / 'vr-hook-measurement-fresh.json', {'mode': 'external (operator-supplied; its provenance is the operator\'s)', 'path': str(fresh),
                                                        'host': socket.gethostname(),
                                                        'receivedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}
    target = out / 'vr-hook-measurement-fresh.json'
    # a PoS generation (a module hash is given) is measured on the PoS-capable build: its fixture, caps and H (ureth VR_HOOK_BUILD=pos)
    env = dict(os.environ, VR_HOOK_MEASUREMENT=str(target), **({'VR_HOOK_MODULE_CODE_HASH': module_hash, 'VR_HOOK_BUILD': 'pos'} if module_hash else {}))
    command = ['cargo', 'test', '-p', 'reth-unicity-execution', '--features', 'test-utils', '--test', 'vr_hook', '--', '--ignored', '--exact',
               'vr_hook_measurement', '--nocapture']
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    log = run(*command, cwd=Path(a.ureth).resolve(), env=env)
    (out / 'vr-hook-measurement-fresh.log').write_text(log)
    if not target.is_file():
        raise VRGenesisError('the ureth measurement wrote no measurement file')
    return target, {'mode': 'ran', 'command': ' '.join(command), 'cwd': str(Path(a.ureth).resolve()), 'urethCommit': git_commit(a.ureth),
                    'host': socket.gethostname(), 'startedUtc': started, 'log': str(out / 'vr-hook-measurement-fresh.log')}


def check_fixture_copies(contracts, ureth):
    """ureth's testdata/vr-hook*.json are verbatim copies of the contracts checkout's test/vr/fixtures/vr-hook*.json: the measurement is taken over
    ureth's copy, so a copy that differs from the contracts the generation allocates measures other code (VT-04b: a stale copy pinned wrong numbers)."""
    for name in ('vr-hook.json', 'vr-hook-pos.json'):
        c, u = contracts / 'test/vr/fixtures' / name, ureth / 'crates/unicity/execution/testdata' / name
        for f in (c, u):
            if not f.is_file():
                raise VRGenesisError(f'{f} is missing: both fixture files must exist before the copies are compared')
        if c.read_bytes() != u.read_bytes():
            raise VRGenesisError(f'ureth {u} is not the contracts checkout\'s {c}: regenerate and copy the fixture before measuring')


def pos_module_hash(contracts, work):
    """The PosElectionAdapter's runtime code hash at 0xff..07: its immutables (VR, the election and the custody, both CREATE addresses of fixed
    deployers) are constants of the contracts build, so the contracts genesis of the sample plan names the same module as every generation's."""
    sample = json.loads((contracts / 'test/vr/fixtures/vr-genesis-input.json').read_text())
    sample['limits'].update(nMax=5, vMax=8, lMax=1, rMax=4)
    sample['pos'] = {'bondUnit': str(POS_BOND_UNIT), 'treasury': POS_TREASURY, 'rootNetwork': 3, 'rootGenesis': '0x' + '11' * 32,
                     'assignmentId': '0x' + '22' * 32, 'rewardFunding': str(POS_REWARD_FUNDING), 'rewardRate': str(POS_REWARD_RATE),
                     'cadenceRounds': POS_CADENCE[0], 'cadenceSeconds': POS_CADENCE[1]}
    work.mkdir(parents=True)
    (work / 'sample-input.json').write_text(json.dumps(sample))
    run(contracts / 'script/vr-pos-genesis.sh', work / 'sample-input.json', work / 'out', cwd=contracts)
    return json.loads((work / 'out/deployment.json').read_text())['moduleCodeHash']


def pos_measurement(a, out, module_hash, name):
    """ureth's complete-path measurement with the PoS module's code hash (VR_HOOK_MODULE_CODE_HASH; every module path of the measurement is the
    cap-bounded test module, so the numbers are the generation's; VR_HOOK_BUILD=pos selects the PoS-capable VR build's fixture, caps and H = 16).
    Taken twice: the recorded one the profile is pinned from, the fresh one verify holds
    the generation to."""
    target = out / name
    env = dict(os.environ, VR_HOOK_MEASUREMENT=str(target), VR_HOOK_MODULE_CODE_HASH=module_hash, VR_HOOK_BUILD='pos')
    log = run('cargo', 'test', '-p', 'reth-unicity-execution', '--features', 'test-utils', '--test', 'vr_hook', '--', '--ignored', '--exact',
              'vr_hook_measurement', '--nocapture', cwd=Path(a.ureth).resolve(), env=env)
    (out / (name + '.log')).write_text(log)
    return target


# The Compose ceremony already has a trust base and pending authorities. Use
# those exact node keys in the same two-pass plan and verifier as the CLI.
def compose_pos_genesis(a, *, ubft, home, network, generation, roots, evms, funded, flags):
    trust = home / 'trust-base.json'
    conf = home / f'shard-conf-{PARTITION}_0.json'
    profile = home / 'b1-profile.json'
    keys = dev_keys(home, a.validators)
    balances = {addr: hex(int(value['balance'])) for addr, value in funded['alloc'].items()}
    balances.update({key['address']: hex(DEV_FUND_WEI) for key in keys['owners'] + keys['signers']})
    merge_alloc(funded, {addr: {'balance': balances[addr]} for addr in balances if addr not in funded['alloc']})
    bindings = [{'rootNodeId': root, 'evmNodeId': evm} for root, evm in zip(roots, evms, strict=True)]
    (network / 'genesis-bindings.json').write_text(json.dumps(bindings) + '\n')
    (network / 'funded-accounts.json').write_text(json.dumps(balances) + '\n')
    root_genesis = re.search(r'^root genesis id +(0x[0-9a-f]{64})$',
        run(ubft, 'trust-base', 'utb-manifest', '--trust-base', trust, '--out-dir', home / 'utb'), re.M)
    if root_genesis is None:
        raise VRGenesisError('the manifest tool printed no root genesis id')

    def write_plan(assignment):
        run(ubft, 'vr-genesis', 'plan', '--trust-base', trust, '--shard-conf', conf,
            '--bindings', network / 'genesis-bindings.json', '--owners', home / 'dev-keys/owners.json',
            '--b1-profile', profile, '--network-word', dev_network_word(generation),
            '--governor-signers', (home / 'dev-keys/signers.txt').read_text().strip(), '--limits', '4,5,16',
            '--fee-collector', FEE_COLLECTOR, '--out-input', network / 'vr-input.json',
            '--out-identities', home / 'genesis-identities.json', '--utb-genesis', home / 'vr-utb.cbor',
            '--utb-genesis-id', home / 'vr-utb.id', '--pos', '--pos-bond-unit', POS_BOND_UNIT,
            '--pos-treasury', POS_TREASURY, '--pos-root-genesis', root_genesis[1], '--pos-assignment-id', assignment,
            '--pos-reward-funding', POS_REWARD_FUNDING, '--pos-reward-rate', POS_REWARD_RATE,
            '--pos-cadence-rounds', a.pos_cadence_rounds, '--pos-cadence-seconds', a.pos_cadence_seconds)

    def finalize(alloc, prefix=''):
        source = home / (prefix + 'funded.json')
        source.write_text(json.dumps(alloc) + '\n')
        return run(ubft, 'engine-api', 'genesis', '--shard-conf', conf, '--trust-base', trust, '--b1-profile', profile,
            '--alloc-source', source, '--out', home / (prefix + 'genesis.json'),
            '--full-shard-conf', home / (prefix + 'full-shard-conf.json'), '--identities-out', home / (prefix + 'b1-identities.json'))

    write_plan('0x' + '11' * 32)
    finalize(funded, 'reconcile-')
    reconciled = home / 'reconcile-full-shard-conf.json'
    assignment = re.search(r'genesis assignment id (0x[0-9a-f]{64})',
        run(ubft, 'vr-genesis', 'assignment', '--shard-conf', reconciled, '--genesis-identities', home / 'genesis-identities.json'))
    if assignment is None:
        raise VRGenesisError('vr-genesis assignment printed no id')
    write_plan(assignment[1])
    for actual, pinned in (('vr-utb.cbor', 'utb-genesis.cbor'), ('vr-utb.id', 'utb-genesis.id')):
        if (home / actual).read_bytes() != (network / pinned).read_bytes():
            raise VRGenesisError('the VR plan disagrees with the authority ceremony UTB genesis')
    contracts = a.pos_contracts.resolve()
    run(contracts / 'script/vr-pos-genesis.sh', network / 'vr-input.json', home / 'vr-contracts', cwd=contracts)
    shutil.copy2(home / 'vr-contracts/deployment.json', network / 'deployment.json')
    identity = finalize(merge_alloc(funded, json.loads((home / 'vr-contracts/alloc.json').read_text())))
    full = home / 'full-shard-conf.json'
    if full.read_bytes() != reconciled.read_bytes():
        raise VRGenesisError('the contracts allocation changed the full shard configuration')
    fresh, provenance = fresh_measurement(a, network)
    flags = [*flags, '--unicity.genesis-commitment=' + genesis_commitment(json.loads((home / 'genesis.json').read_text()))]
    (network / 'ureth-flags.txt').write_text(' '.join(flags) + f' --unicity.fee-collector={FEE_COLLECTOR}\n')
    (network / 'fee-collector.txt').write_text(FEE_COLLECTOR + '\n')
    print(verify_compose_pos(ubft, network, generation, home))
    deployment = json.loads((network / 'deployment.json').read_text())
    return identity, flags, {'profile': 'vr-pos16', 'registry': VR, 'committee_limits': [4, 5, 16], 'contracts': git_commit(contracts),
        'genesis_assignment': assignment[1], 'custody': deployment['custody'], 'election': deployment['election'],
        'owner_keys': 'vr-owner-keys', 'cadence_rounds': a.pos_cadence_rounds, 'cadence_seconds': a.pos_cadence_seconds,
        'measurement_sha256': hashlib.sha256(fresh.read_bytes()).hexdigest(), 'measurement_provenance': provenance}


def verify_compose_pos(ubft, net, generation, configs=None, *, output=None):
    cfg = configs or net
    return run(ubft, 'vr-genesis', 'verify', '--input', net / 'vr-input.json', '--deployment', net / 'deployment.json',
        '--genesis', cfg / 'genesis.json', '--shard-conf', cfg / 'full-shard-conf.json', '--trust-base', cfg / 'trust-base.json',
        '--b1-profile', cfg / 'b1-profile.json', '--genesis-identities', cfg / 'genesis-identities.json',
        '--vr-hook-measurement', net / 'vr-hook-measurement-fresh.json', '--ureth-flags', (net / 'ureth-flags.txt').read_text().strip(),
        '--fee-collector', FEE_COLLECTOR, '--out-root-deployment', output or net / 'vr-deployment.json',
        '--utb-genesis', net / 'utb-genesis.cbor', '--utb-genesis-id', net / 'utb-genesis.id',
        '--funded-accounts', net / 'funded-accounts.json', '--dev-generation', generation)

def plan(a):
    out = Path(a.out).resolve()
    if out.exists():
        raise VRGenesisError(f'{out} exists: a generation is never regenerated in place')
    ubft, contracts = str(Path(a.ubft).resolve()), Path(a.contracts).resolve()
    pos_hash = None
    if a.ureth:
        check_fixture_copies(contracts, Path(a.ureth).resolve())
    if a.pos:
        if not (contracts / 'script/vr-pos-genesis.sh').is_file():
            raise VRGenesisError(f'{contracts} has no script/vr-pos-genesis.sh: not a PoS-capable contracts checkout')
        if not a.ureth:
            raise VRGenesisError('a PoS generation takes its measurements with --ureth (the module hash is the adapter\'s)')
        pos_hash = pos_module_hash(contracts, out / 'pos-sample')
        measurement_path = pos_measurement(a, out, pos_hash, 'vr-hook-measurement-pos-recorded.json')
    else:
        measurement_path = Path(a.measurement).resolve()
    measurement = json.loads(measurement_path.read_text())
    if measurement.get('registry') != VR:
        raise VRGenesisError(f'the measurement is of a registry at {measurement.get("registry")}, not {VR}')
    if not (contracts / 'script/vr-genesis.sh').is_file():
        raise VRGenesisError(f'{contracts} is not a unicity-pos-contracts checkout with script/vr-genesis.sh')
    generation = a.generation or out.name
    home = out / 'home'
    (out / 'vr').mkdir(parents=True, exist_ok=True)
    home.mkdir()
    shutil.copy2(measurement_path, out / 'vr-hook-measurement.json')

    roots, evms = [], []
    for i in range(1, a.validators + 1):
        run(ubft, 'root-node', 'init', '--home', home / f'root{i}', '--generate')
        run(ubft, 'shard-node', 'init', '--home', home / f'evm{i}', '--generate')
        roots.append(run(ubft, 'node-id', '--home', home / f'root{i}').strip().splitlines()[-1])
        evms.append(run(ubft, 'node-id', '--home', home / f'evm{i}').strip().splitlines()[-1])
    run(ubft, 'trust-base', 'generate', '--home', home, '--epoch', '1', '--epoch-start', '1', '--network-id', NETWORK_ID,
        *sum((['--node-info', home / f'root{i}/node-info.json'] for i in range(1, a.validators + 1)), []))
    for i in range(1, a.validators + 1):
        run(ubft, 'trust-base', 'sign', '--home', home / f'root{i}', '--trust-base', home / 'trust-base.json')
    run(ubft, 'shard-conf', 'generate', '--home', home, '--network-id', NETWORK_ID, '--partition-id', PARTITION, '--partition-type-id', PARTITION,
        '--shard-id', '0x80', '--epoch-start', '1', '--t2-timeout', '5000', '--partition-params', partition_params(a.chain_id, measurement),
        *sum((['--node-info', home / f'evm{i}/node-info.json'] for i in range(1, a.validators + 1)), []))
    trust, conf = home / 'trust-base.json', home / f'shard-conf-{PARTITION}_0.json'

    profile_out = run(ubft, 'engine-api', 'b1-profile', '--shard-conf', conf, '--trust-base', trust, '--max-epochs-per-update', MAX_EPOCHS,
                      '--delta-ev', DELTA_EV, '--delta-hold', DELTA_HOLD, '--out', out / 'b1-profile.json', '--vr-hook-measurement', measurement_path)
    flags = [l.split(':', 1)[1].strip() for l in profile_out.splitlines() if l.startswith('ureth flags:')]
    if len(flags) != 1:
        raise VRGenesisError('b1-profile printed no single "ureth flags:" line')
    profile = json.loads((out / 'b1-profile.json').read_text())

    (out / 'genesis-bindings.json').write_text(json.dumps([{'rootNodeId': roots[i], 'evmNodeId': evms[i]} for i in range(a.validators)], indent=1) + '\n')
    signers = a.governor_signers.split(',') if a.governor_signers else dev_signers(generation)
    owners_file, funded, word = (Path(a.owners).resolve() if a.owners else None), {}, a.network_word or network_word(generation)
    if a.dev_fund:
        keys = dev_keys(out, a.validators)
        # ids follow ascending root node id (vr-genesis plan); owners.json is in id order, one generated key per identity, payee = owner
        owners_file = out / 'dev-keys/owners.json'
        signers = [k['address'] for k in keys['signers']]
        funded = {k['address']: hex(DEV_FUND_WEI) for k in keys['owners'] + keys['signers']}
        word = dev_network_word(generation)
        (out / 'dev-funded-accounts.json').write_text(json.dumps(funded, indent=1) + '\n')
    def plan_cmd(assignment):
        pos_args = []
        if a.pos:
            root_genesis = re.search(r'^root genesis id +(0x[0-9a-f]{64})$', run(ubft, 'trust-base', 'utb-manifest', '--trust-base', trust, '--out-dir', out / 'root-identity'), re.M)
            if not root_genesis:
                raise VRGenesisError('the manifest tool printed no root genesis id')
            pos_args = ['--pos', '--pos-bond-unit', str(POS_BOND_UNIT), '--pos-treasury', POS_TREASURY, '--pos-root-genesis', root_genesis.group(1),
                        '--pos-assignment-id', assignment, '--pos-reward-funding', str(POS_REWARD_FUNDING), '--pos-reward-rate', str(POS_REWARD_RATE),
                        '--pos-cadence-rounds', str(POS_CADENCE[0]), '--pos-cadence-seconds', str(POS_CADENCE[1])]
        run(ubft, 'vr-genesis', 'plan', '--trust-base', trust, '--shard-conf', conf, '--bindings', out / 'genesis-bindings.json',
            '--b1-profile', out / 'b1-profile.json', '--network-word', word, '--governor-signers', ','.join(signers),
            '--limits', a.limits or (POS_LIMITS if a.pos else '4,4,16'), '--fee-collector', FEE_COLLECTOR, '--out-input', out / 'vr/input.json',
            '--out-identities', out / 'genesis-identities.json',
            '--utb-genesis', out / 'utb-genesis.cbor', '--utb-genesis-id', out / 'utb-genesis.id',   # the signed trust-base history's genesis entry and its pin
            *(['--owners', owners_file] if owners_file else []), *pos_args)

    reconciled = None
    if a.pos:
        # The custody genesis names the genesis assignment id of the FULL shard configuration (base + seal_registry_genesis), which the roots
        # close (deploy/testnet/pos.py): a reconciling genesis without the contracts' accounts gives the full configuration, `vr-genesis
        # assignment` the id, and the final genesis must leave the full configuration unchanged.
        plan_cmd('0x' + '11' * 32)
        pre = funded_base_genesis(a.chain_id, int(profile['maxGas']), secrets.token_hex(32))
        merge_alloc(pre, {addr: {'balance': bal} for addr, bal in funded.items()})
        (home / 'reconcile.json').write_text(json.dumps(pre, indent=2) + '\n')
        run(ubft, 'engine-api', 'genesis', '--shard-conf', conf, '--trust-base', trust, '--b1-profile', out / 'b1-profile.json',
            '--alloc-source', home / 'reconcile.json', '--out', home / 'reconcile-genesis.json', '--full-shard-conf', home / 'reconcile-full-shard-conf.json',
            '--identities-out', home / 'reconcile-identities.json')
        said = re.search(r'genesis assignment id (0x[0-9a-f]{64})', run(ubft, 'vr-genesis', 'assignment', '--shard-conf', home / 'reconcile-full-shard-conf.json',
                                                                         '--genesis-identities', out / 'genesis-identities.json'))
        if not said:
            raise VRGenesisError('vr-genesis assignment printed no id')
        reconciled = said.group(1)
        plan_cmd(reconciled)
        genesis_extra = pre['extraData']
    else:
        plan_cmd('')
    run(contracts / ('script/vr-pos-genesis.sh' if a.pos else 'script/vr-genesis.sh'), out / 'vr/input.json', out / 'vr', cwd=contracts)

    funded_genesis = funded_base_genesis(a.chain_id, int(profile['maxGas']), pre['extraData'].removeprefix('0x') if a.pos else secrets.token_hex(32))
    merge_alloc(funded_genesis, json.loads((out / 'vr/alloc.json').read_text()))
    merge_alloc(funded_genesis, {addr: {'balance': bal} for addr, bal in funded.items()})
    (home / 'funded.json').write_text(json.dumps(funded_genesis, indent=2) + '\n')
    print(run(ubft, 'engine-api', 'genesis', '--shard-conf', conf, '--trust-base', trust, '--b1-profile', out / 'b1-profile.json',
              '--alloc-source', home / 'funded.json', '--out', out / 'genesis.json', '--full-shard-conf', out / 'full-shard-conf.json',
              '--identities-out', out / 'b1-identities.json'))
    genesis = json.loads((out / 'genesis.json').read_text())
    if a.pos and (out / 'full-shard-conf.json').read_bytes() != (home / 'reconcile-full-shard-conf.json').read_bytes():
        raise VRGenesisError('the full shard configuration changed after the genesis assignment was fixed (the contracts accounts moved seal_registry_genesis?)')
    fresh, provenance = fresh_measurement(a, out, pos_hash)
    provenance['sha256'] = hashlib.sha256(fresh.read_bytes()).hexdigest()
    ureth = flags[0] + f' --unicity.genesis-commitment={genesis_commitment(genesis)} --unicity.fee-collector={FEE_COLLECTOR}'
    (out / 'ureth-flags.txt').write_text(ureth + '\n')
    shutil.copy2(trust, out / 'trust-base.json')

    verified = run(ubft, 'vr-genesis', 'verify', '--input', out / 'vr/input.json', '--deployment', out / 'vr/deployment.json', '--genesis', out / 'genesis.json',
                   '--shard-conf', out / 'full-shard-conf.json', '--trust-base', trust, '--b1-profile', out / 'b1-profile.json',
                   '--genesis-identities', out / 'genesis-identities.json', '--vr-hook-measurement', fresh,
                   '--ureth-flags', ureth, '--fee-collector', FEE_COLLECTOR, '--out-root-deployment', out / 'vr-deployment.json',
                   '--utb-genesis', out / 'utb-genesis.cbor', '--utb-genesis-id', out / 'utb-genesis.id',
                   *(['--funded-accounts', out / 'dev-funded-accounts.json', '--dev-generation', generation] if a.dev_fund else []))
    print(verified.strip())
    summary = {'generation': generation, 'validators': a.validators, 'chainId': a.chain_id, 'networkId': NETWORK_ID,
               'deployment': json.loads((out / 'vr/deployment.json').read_text()), 'profile': {k: profile[k] for k in ('hRecords', 'hookRecordGas', 'electGas', 'systemGas', 'maxGas')},
               'utbGenesisId': (out / 'utb-genesis.id').read_text().strip(), 'ureth': ureth, 'roots': roots, 'evms': evms, 'freshMeasurement': provenance, 'devFunded': funded}
    (out / 'vr-genesis-summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--ubft', default=str(HERE.parents[1] / 'build/ubft'))
    p.add_argument('--contracts', required=True, help='a unicity-pos-contracts checkout with script/vr-genesis.sh (forge, cast and python3 on PATH)')
    p.add_argument('--measurement', help='the complete-path VR hook measurement the profile is pinned from (not with --pos: a PoS generation takes it with --ureth)')
    p.add_argument('--pos', action='store_true', help='the PoS-prototype generation (VT-04): the module is the PosElectionAdapter, the P85 stack its holder; default limits 4,5,5')
    p.add_argument('--ureth', help='a ureth checkout at the pin (cargo on PATH): the plan runs its complete-path measurement as the fresh one')
    p.add_argument('--fresh-measurement', help='instead of --ureth: an externally taken fresh measurement (never the recorded file)')
    p.add_argument('--validators', type=int, default=4)
    p.add_argument('--chain-id', type=int, default=CHAIN_ID)
    p.add_argument('--generation', help='the generation name (default: the output directory name)')
    p.add_argument('--network-word', help="VR's network word (default: sha256('unicity.testnet.vr.' + generation))")
    p.add_argument('--governor-signers', help='the FoundationMultisig signers, five comma-separated addresses (default: DEV keyless signers)')
    p.add_argument('--owners', help='JSON [{owner, payee}] per identity in ascending root node id (default: DEV keyless addresses)')
    p.add_argument('--limits', help='CommitteeLimits nMin,nTarget,nMax')
    p.add_argument('--dev-fund', action='store_true', help='DEVELOPMENT ONLY: generate keys for every owner and governor signer, fund them in the genesis '
                   '(the premine verify checks), and use the dev network word; refused with --network-word, --owners or --governor-signers')
    p.add_argument('--out', required=True)
    a = p.parse_args()
    if not 1 <= a.validators <= 16:
        p.error('--validators must be 1..16')
    if a.dev_fund and (a.network_word or a.owners or a.governor_signers):
        p.error('--dev-fund generates the owners and signers and uses the dev network word: it excludes --network-word, --owners and --governor-signers')
    if a.pos == bool(a.measurement):
        p.error('exactly one of --measurement (a PoA generation) and --pos (which measures itself, with --ureth)')
    if a.pos and a.fresh_measurement:
        p.error('--pos takes both measurements with --ureth')
    if bool(a.ureth) == bool(a.fresh_measurement):
        p.error('the fresh measurement is a generation step: pass --ureth (run it now) or --fresh-measurement (an external one), exactly one')
    try:
        summary = plan(a)
    except VRGenesisError as e:
        sys.exit(f'vr-genesis: {e}')
    print(json.dumps({k: summary[k] for k in ('generation', 'validators', 'profile')}, indent=1))


if __name__ == '__main__':
    main()
