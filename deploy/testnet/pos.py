"""The proof-of-stake profile of the testnet package (#437 groundwork).

The contracts' genesis state (custody, election, evidence, ...) is allocated into the EVM genesis exactly as the P85 lane does it
(scripts/lib/p85-lib.sh), with one rule that the lane learned in runs 25 and 26: the custody genesis names the genesis assignment id of the FULL shard
configuration (the base plus seal_registry_genesis, which `ubft engine-api genesis --full-shard-conf` writes), never of the base one. The order is
therefore: a first pass on the base configuration (provisional), a reconciling finalization without the PoS accounts to obtain the full configuration, the
contracts genesis again when the id differs, the PoS accounts merged into the alloc, the real finalization, and `ubft pos-relayer verify-genesis` on the
final configuration. Nothing here starts a process but the pinned tools.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

# The lane's values (scripts/lib/p85-lib.sh). The cadence is a rehearsal value: an election is due this many ordinary root rounds and UC seconds after the
# last acknowledged rotation. #437 sets the testnet's own (--pos-cadence-rounds / --pos-cadence-seconds).
# manifest limits.vMax, limits.lMax, election nMax: the election price AND the records hook's per-record reservation are measured at exactly these. (16, 1, 6) is what
# the 3,000,000 per record covers with the 1.25 margin (the RecoveryAck of 8 members in 2 lots costs 3,629,888 cold, contracts docs/p85/HOOK_GAS.md); until the owner
# decides between a higher limit and lower caps (Q12) the package declares caps the limit covers, and `b1-profile --hook-measurement` refuses any pair it does not.
CAPS = (16, 1, 6)
BOND_UNIT = 100 * 10**18               # 100 UCT in base units: one weight unit
GENESIS_UNITS = 1                      # bond units per genesis identity (unit weights)
HOOK_RECORDS = ('ack', 'stage', 'closure', 'recovery')   # the records of script/measure-hook-gas.sh: the hook's worst record is the largest of them
H_RECORDS = 2
HOOK_RECORD_GAS = 3_000_000
CADENCE_ROUNDS = 400
CADENCE_SECONDS = 300
REGISTRY = '0xff00000000000000000000000000000000000002'
TREASURY = '0x00000000000000000000000000000000000000ee'

ASSIGNMENT = re.compile(r'genesis assignment id (0x[0-9a-f]{64})')
AGREE = re.compile(r'genesis assignment (0x[0-9a-f]{64}) is the full shard configuration\'s')


class PosError(RuntimeError):
    pass


def code_hash(genesis, address):
    """keccak-256 of the runtime code the genesis alloc carries at `address` (`cast keccak`: the Python standard library has no keccak)."""
    want = address.lower().removeprefix('0x')
    found = [v for k, v in genesis['alloc'].items() if k.lower().removeprefix('0x') == want]
    if len(found) != 1 or len(found[0].get('code', '0x')) <= 2:
        raise PosError(f'no code at {address} in the genesis alloc')
    done = subprocess.run(['cast', 'keccak', found[0]['code']], text=True, capture_output=True)
    if done.returncode != 0:
        raise PosError('cast keccak failed: ' + done.stderr)
    return done.stdout.strip().lower()


def assignment_id(stderr):
    """The id `ubft pos-relayer genesis` prints on stderr."""
    found = ASSIGNMENT.findall(stderr)
    if len(found) != 1:
        raise PosError('pos-relayer genesis printed no single genesis assignment id: ' + stderr)
    return found[0]


def genesis_weights(n, spec=None):
    """The genesis weight of each of `n` identities, in the trust base's order: `spec` is None (all 1) or a list of positive integers, one per identity.

    The same number is the bond units in the contracts genesis, the root member's weight in the trust base and the EVM validator's weight in the shard configuration
    (the coupling checks equal weights), and today's genesis rules fix the last at 1: go-base refuses a shard configuration whose validator has another stake ("node must
    have stake == 1"; `shard-conf generate`), while the root trust base alone would take `--root-weights`. So a genesis other than all 1 cannot be built and is refused here
    with that reason, before any key is generated; unequal weights enter by a handoff whose candidate carries them (Q3 weight activation), not by the genesis."""
    weights = [1] * n if spec is None else [int(w) for w in spec]
    if len(weights) != n:
        raise PosError(f'{len(weights)} genesis weights for {n} identities: one per identity, in the trust base\'s order')
    if any(w < 1 for w in weights):
        raise PosError(f'genesis weights must be positive integers: {weights}')
    if any(w != 1 for w in weights):
        raise PosError(f'genesis weights {weights}: the genesis shard configuration takes unit-stake validators only (go-base: "node must have stake == 1") and the coupling needs the '
                       'root member, the EVM validator and the bonded identity to weigh the same, so every genesis weight is 1; an unequal committee is elected by a handoff (the candidate carries the weights)')
    return weights


def network_word(generation):
    return '0x' + hashlib.sha256(('unicity.testnet.pos.' + generation).encode()).hexdigest()


def profile_args(deployment, measurements):
    """The b1-profile flags that pin the hooks and the election to the deployed contracts."""
    return ['--records-custody', deployment['custody'], '--h-records', str(H_RECORDS), '--hook-record-gas', str(HOOK_RECORD_GAS),
            '--election', deployment['election'], '--elect-measurement', str(measurements['election']), '--hook-measurement', str(measurements['hook']),
            '--elect-caps', ','.join(map(str, CAPS))]


def deployment_of(deployment, profile):
    """The roots' --pos-deployment file: the contracts' addresses and code hashes, and the registry's code hash from the profile."""
    return {'networkWord': deployment['networkWord'], 'chainId': str(deployment['chainId']), 'custody': deployment['custody'],
            'custodyCodeHash': deployment['custodyCodeHash'], 'registry': REGISTRY, 'registryCodeHash': profile['runtimeHash'],
            'election': deployment['election'], 'electionCodeHash': deployment['electionCodeHash']}


def merge_alloc(genesis, extra):
    """The PoS accounts added to a genesis source's alloc; an address that is already there is refused, not overwritten."""
    have = {k.lower().removeprefix('0x') for k in genesis['alloc']}
    for address in extra:
        if address.lower().removeprefix('0x') in have:
            raise PosError(f'the genesis alloc already has {address}')
    genesis['alloc'].update(extra)
    return genesis


def root_flags(i, ureth_rpc_host='ureth'):
    """The flags of a root of the PoS profile, as p85_root_flags: the P85 control executor with the election pinned, and the genesis committee's records as K.
    They replace --genesis-identities (the PoS records carry the bonded identities)."""
    return ['--pos-deployment', '/network/pos-deployment.json', '--pos-genesis-identities', '/network/pos-genesis-identities.json',
            '--pos-evm-rpc', f'http://{ureth_rpc_host}{i}:8545']


class Genesis:
    """The contracts genesis of one generation. `ubft` is the pinned tool; `contracts` a clean unicity-pos-contracts checkout at the pin."""

    def __init__(self, work, ubft, contracts, repo, generation, chain_id, dist, cadence=(CADENCE_ROUNDS, CADENCE_SECONDS)):
        self.work, self.ubft, self.contracts, self.repo = Path(work), str(ubft), Path(contracts), Path(repo)
        self.generation, self.chain_id, self.dist, self.cadence = generation, chain_id, dist, cadence
        self.dir = self.work / 'pos'
        self.dir.mkdir(parents=True, exist_ok=False)
        self.assignment = self.first = None

    def _run(self, *args, env=None, cwd=None):
        done = subprocess.run([str(x) for x in args], text=True, capture_output=True, env=env, cwd=cwd)
        if done.returncode != 0:
            raise PosError(' '.join(map(str, args[:3])) + ' failed\n' + done.stdout + done.stderr)
        return done

    def check_tools(self, pinned):
        for tool in ('forge', 'cast'):
            if shutil.which(tool) is None:
                raise PosError(f'{tool} is not on PATH (foundry, pinned v1.8.1: forge builds the contracts genesis, cast hashes the deployed code)')
        if not (self.contracts / 'script/p85-genesis.sh').is_file():
            raise PosError(f'{self.contracts} is not a unicity-pos-contracts checkout (no script/p85-genesis.sh)')
        head = self._run('git', '-C', self.contracts, 'rev-parse', 'HEAD').stdout.strip()
        dirty = self._run('git', '-C', self.contracts, 'status', '--porcelain').stdout.strip()
        if head != pinned or dirty:
            raise PosError(f'the contracts checkout must be clean at the pinned commit {pinned} (it is at {head}{"; modified" if dirty else ""})')

    def plan(self, trust_base, conf, owners=None, weights=None):
        """One bonded identity per root/EVM pair, in the order the trust base and the shard configuration list their nodes.

        The lane's script derives the owner, withdrawal and payee addresses from the root node id by hash: addresses nobody holds the key of. `owners` (the output of
        `tn-keygen owners`: one record of the three addresses per staking id) replaces them with addresses whose keys the ceremony generated, so that top-up, exit,
        withdrawal and a reward claim can be rehearsed. The ids do not depend on them (verify-genesis recomputes from this plan).

        `weights` are the genesis bond units of the identities (genesis_weights: all 1 by default)."""
        n = len(json.loads(Path(trust_base).read_text())['rootNodes'])
        units = ','.join(map(str, genesis_weights(n, weights)))
        out = subprocess.check_output([sys.executable, str(self.repo / 'scripts/p85-genesis-plan.py'), str(trust_base), str(conf), str(BOND_UNIT), units], text=True)
        if owners is not None:
            document = json.loads(out)
            by_id = {row['stakingId']: row for row in owners}
            if sorted(by_id) != [row['stakingId'] for row in document['identities']]:
                raise PosError('the owner keys do not cover the genesis identities one to one')
            for row in document['identities']:
                for role in ('owner', 'withdrawal', 'payee'):
                    row[role] = by_id[row['stakingId']][role]
            out = json.dumps(document, indent=1) + '\n'
        (self.dir / 'plan.json').write_text(out)
        self.trust_base = Path(trust_base)

    def prepare(self, conf, provisional):
        """The contracts genesis input and the contracts' genesis state from the given shard configuration. The base configuration is a first pass only."""
        args = ['pos-relayer', 'genesis'] + (['--provisional'] if provisional else []) + ['--plan', self.dir / 'plan.json', '--trust-base', self.trust_base,
            '--shard-conf', conf, '--out-identities', self.dir / 'genesis-identities.json', '--out-contracts', self.dir / 'contracts-genesis.json']
        self.assignment = assignment_id(self._run(self.ubft, *args).stderr)
        if provisional:
            self.first = self.assignment
        env = dict(os.environ, P85_NETWORK_WORD=network_word(self.generation), P85_CHAIN_ID=str(self.chain_id), P85_ROOTS=REGISTRY, P85_TREASURY=TREASURY,
                   P85_V_MAX=str(CAPS[0]), P85_L_MAX=str(CAPS[1]), P85_N_MAX=str(CAPS[2]), P85_CADENCE_ROUNDS=str(self.cadence[0]),
                   P85_CADENCE_SECONDS=str(self.cadence[1]), P85_DIST_NUM=str(self.dist[0]), P85_DIST_DEN=str(self.dist[1]))
        self._run(self.contracts / 'script/p85-genesis.sh', self.dir / 'contracts-genesis.json', self.dir / 'genesis', env=env)
        measured = self._run(self.contracts / 'script/measure-elect.sh', *map(str, CAPS), env=env, cwd=self.contracts)
        (self.dir / 'elect-measurement.json').write_text(measured.stdout)
        (self.dir / 'hook-measurement.jsonl').write_text(self.measure_hooks(env))
        deployment = json.loads((self.dir / 'genesis/deployment.json').read_text())
        # The b1-profile and the roots' deployment file are built from the FIRST pass: a second pass that deployed anything elsewhere would pin the hooks to one
        # custody and the genesis to another. Everything but the fields that carry the assignment id (the id itself and the manifest hash over it) must be identical.
        if getattr(self, 'deployment', None) is not None:
            moved = sorted(k for k in set(deployment) | set(self.deployment) if 'ssignment' not in k and k != 'manifestHash' and deployment.get(k) != self.deployment.get(k))
            if moved:
                raise PosError('the second contracts genesis differs from the first in ' + ', '.join(moved) + ': the profile and the roots would pin another deployment')
        self.deployment = deployment
        return self.assignment

    def measure_hooks(self, env):
        """The cold measurement of the records hook's records at the deployment's caps (contracts script/measure-hook-gas.sh): JSON lines."""
        return self._run(self.contracts / 'script/measure-hook-gas.sh', *map(str, CAPS), *HOOK_RECORDS, env=env, cwd=self.contracts).stdout

    def check_hook_gas(self, profile):
        """The profile's per-record reservation against a FRESH cold measurement at the caps: refused when the contracts grew past the margin
        (the same rule `b1-profile --hook-measurement` applies at generation, taken from a second measurement)."""
        fresh = self.dir / 'hook-measurement-fresh.jsonl'
        fresh.write_text(self.measure_hooks(dict(os.environ)))
        done = self._run(self.ubft, 'engine-api', 'check-hook-gas', '--b1-profile', profile, '--measurement', fresh)
        return done.stdout + done.stderr

    def alloc_code_hashes(self, genesis):
        """The custody and election code hashes the deployment file records must be those of the code the genesis carries (the keccak of the runtime code)."""
        for module in ('custody', 'election'):
            want = self.deployment[module + 'CodeHash']
            have = code_hash(genesis, self.deployment[module])
            if want.lower() != have:
                raise PosError(f'{module} code in the genesis hashes to {have}, the deployment records {want}')

    def reconcile(self, full_conf):
        """The id the roots will close is the full configuration's: when the first pass (base configuration) differs, prepare again from the full one."""
        want = assignment_id(self._run(self.ubft, 'pos-relayer', 'genesis', '--plan', self.dir / 'plan.json', '--trust-base', self.trust_base, '--shard-conf', full_conf,
                                       '--out-identities', self.dir / 'reconcile-identities.json', '--out-contracts', self.dir / 'reconcile-contracts.json').stderr)
        if self.assignment is None:
            raise PosError('reconcile before prepare')
        if want != self.assignment:
            print(f'pos: the genesis assignment of the base configuration ({self.assignment}) is not the full configuration\'s ({want}): preparing the contracts genesis again')
            self.prepare(full_conf, provisional=False)
            if self.assignment != want:
                raise PosError(f'the prepared genesis carries {self.assignment}, not {want}')
        return want

    def verify(self, full_conf, reconciled_conf):
        """The final full configuration the genesis wrote is the one the id was taken from, and the contracts genesis agrees with it."""
        done = self._run(self.ubft, 'pos-relayer', 'verify-genesis', '--plan', self.dir / 'plan.json', '--trust-base', self.trust_base, '--shard-conf', full_conf,
                         '--contracts-genesis', self.dir / 'contracts-genesis.json')
        agreed = AGREE.findall(done.stderr)
        if agreed != [self.assignment]:
            raise PosError(f'verify-genesis did not confirm {self.assignment}: {done.stderr}')
        if Path(full_conf).read_bytes() != Path(reconciled_conf).read_bytes():
            raise PosError('the full shard configuration changed after the genesis assignment was fixed (the PoS accounts moved seal_registry_genesis?)')
        return agreed[0]
