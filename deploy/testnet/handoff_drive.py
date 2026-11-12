#!/usr/bin/env python3
"""One host command for a proof-of-stake handoff of a running package generation (owner decision 2026-11-12: an operator runs it when an election result is
reserved; no daemon yet, this is the core a later daemon calls).

    handoff_drive.py <generation> [<resultID>] --ubft UBFT [--cast CAST] [--restore-pin H4PIN] [--plan] [--min-window-rounds N] [--joiner STAKINGID=ENTITY ...]

It drives OPERATOR.md 5b for the election's reserved result, the same sequence the rehearsal's pos-proposal, pos-propose, pos-install and pos-advance stages run
(and the lane's p85 steps before them), as resumable steps:

  preflight    every entity service running, the roots of the committee being left at one epoch E (or the successor epoch, on a resume), the result Reserved, the
               reservation window (16,384 registry progress rounds, storage.ResultReservationLifetimeProgress) not about to lapse, the membership change classified
  trust-base   the root trust base of epoch E+1 over the elected members (unit weights), signed in each member's root home; its epoch start is above the root's
               current round, with the rehearsal's 200000*(N-1) for epoch N as the floor (a numbering floor in the file: the install does not wait for that round)
  proposal     the EVM context, the election's proposal, each member's EVM possession proof made in its own signing authority, the candidate, each authority's
               sign-pop, assemble, submit-pops and finalize (skipped when the election already holds the publication), the published assignment
  propose      the roots' candidate, every successor entity's readiness receipt made by its own root, then `handoff_ops.py propose` (plan, intent, endorse) to the
               committee being left
  install      root by root: stop, keep its stores as root.pre-epoch-N, recreate it with the install override (handoff.install_override); then the activation record
  advance      the shard configuration of the activated shard epoch published to network/handoff/, then per entity: shard stopped, authority advance-epoch and
               replace-session (a joiner: complete-enrollment and the restore of its shard node), shard started. The authority is NEVER restarted or recreated
  lockproof    with the bridge overlay: the lock-proof endpoint rescans network/handoff (#996, --shard-conf-dir) and is only checked; without that flag it is
               recreated (the pre-#996 procedure)
  verify       every root at E+1, the result Acknowledged and the EVM block that acknowledged it, the served /api/v1/trustbases history verifying to E+1 (with
               --utb), blocks still produced, recordCursor == recordCount

Every step and sub-step is a row of <generation>/handoff/log.jsonl (event "drive", with the result and the target epoch; handoff_ops.py writes its plan/intent/
endorse rows to the same file). A second run continues after the last completed one. Nothing here reads a key: keys stay in the root homes (`ubft trust-base sign
--home`), the authorities (sockets) and the relayer's staged key copy (rehearse.Rehearsal.relayer).

Membership: the elected identities (frozenMembers of the result) map to entities by the genesis plan (identity k is entity k) and by --joiner STAKINGID=ENTITY
(or <generation>/handoff/joiners.json, {"<stakingId>": entity}). A joiner must have been prepared and started as a follower before the election (pos_join.py
part 1-3); its trust base of epoch E+1 then already exists and is reused when it names exactly the elected roots. A retirement (an incumbent not elected) has
never been rehearsed on the package: the drive refuses it unless --allow-unrehearsed-retirement.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

import handoff
import handoff_ops
import operator_rpc
import rehearse
import remote_entity

LIFETIME = 16384            # storage.ResultReservationLifetimeProgress: a result not prepared within this many registry progress rounds is rejected by the roots
MIN_WINDOW_ROUNDS = 1800    # default margin: the steps up to the Prepare take ~10 min; at ~2 rounds/s this is ~15 min
ZERO = '0x' + '00' * 32
STEPS = ('preflight', 'trust-base', 'proposal', 'propose', 'install', 'advance', 'lockproof', 'verify')
WINDOW_STEPS = frozenset(('trust-base', 'proposal', 'propose'))   # the steps before the Prepare: the window must still be open for them
BRIDGE_OVERRIDE = 'compose.bridge.yaml'
OPERATOR = ('--operator-socket', '/authority/operator.sock', '--operator-credential', '/authority/operator.cred')


class Refused(RuntimeError):
    """The drive will not continue: the reason is for the operator (a lapsing window, an unrehearsed change, a state it cannot explain)."""


# --- pure helpers (unit tested) --------------------------------------------------------------------------------------------------
def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def epoch_start(target, root_round, previous_start=0):
    """The trust base's epoch start: the rehearsal's 200000*(target-1) on a young network, else the next 100000 boundary at least 100000 above the root's round,
    and always above the previous trust base's start (research note gap (c): a running network is past the hard-coded value)."""
    start = max(200000 * (target - 1), (root_round // 100000 + 2) * 100000)
    while start <= previous_start:
        start += 100000
    return start


def window(reserved_at, progress, rate=None):
    """(rounds left before the roots reject the result, seconds left at `rate` rounds/s or None)."""
    left = reserved_at + LIFETIME - progress
    return left, (left / rate if rate and rate > 0 else None)


def classify(current, successor):
    """'no-change' | 'join' | 'retire' | 'mixed' for the sets of entities of the committee being left and of the elected one."""
    current, successor = set(current), set(successor)
    if current == successor:
        return 'no-change'
    if current < successor:
        return 'join'
    if successor < current:
        return 'retire'
    return 'mixed'


def frozen_ids(text):
    """The staking ids of `cast abi-decode frozenMembers(bytes32)((uint64,...)[])` output: the first field of each tuple."""
    return sorted(int(x) for x in re.findall(r'\((\d+),', text.replace('((', '(')))


def identity_entities(plan, joiners):
    """{stakingId: entity}: identity k of the genesis plan is entity k (generate.py writes them in order), joiners as given."""
    found = {int(ident['stakingId']): k for k, ident in enumerate(plan['identities'], 1)}
    for ident, entity in joiners.items():
        found[int(ident)] = int(entity)
    return found


class Journal:
    """The drive's rows in handoff/log.jsonl for one (result, target): which steps and sub-steps are done. Rows of other drives and of handoff_ops are ignored."""

    def __init__(self, path, result=None, target=None, echo=lambda line: print(f'{now()} {line}', flush=True)):
        self.path, self.result, self.target, self.echo = Path(path), result, target, echo

    def rows(self):
        if not self.path.is_file():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get('event') == 'drive':
                out.append(row)
        return out

    def mine(self):
        return [r for r in self.rows() if r.get('result') == self.result and r.get('target') == self.target]

    def last_drive(self):
        """(result, target) of the newest drive row that is not a finished drive, or None: a resume picks it up even once the election has moved on."""
        rows = self.rows()
        finished = {(r['result'], r['target']) for r in rows if (r.get('step') == 'verify' and r.get('status') == 'done' and not r.get('sub')) or r.get('status') == 'abandoned'}
        for row in reversed(rows):
            key = (row.get('result'), row.get('target'))
            if key not in finished:
                return key
        return None

    def done(self, step, sub=None):
        return any(r.get('step') == step and r.get('sub') == sub and r.get('status') == 'done' for r in self.mine())

    def value(self, step, key, sub=None):
        for r in reversed(self.mine()):
            if r.get('step') == step and r.get('sub') == sub and key in r:
                return r[key]
        return None

    def write(self, step, status, sub=None, **detail):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        row = {'event': 'drive', 'time': now(), 'result': self.result, 'target': self.target, 'step': step, 'status': status, **({'sub': sub} if sub else {}), **detail}
        with self.path.open('a') as f:
            f.write(json.dumps(row, sort_keys=True) + '\n')
        return row

    def run(self, step, fn, sub=None):
        """Run `fn` once for (step, sub): skipped when the journal has it done; timed; a failure is recorded and raised. Returns fn's detail dict (or the recorded one)."""
        label = step + (f' {sub}' if sub else '')
        if self.done(step, sub):
            self.echo(f'skip  {label} (done in an earlier run)')
            return None
        self.write(step, 'start', sub)
        self.echo(f'start {label}')
        started = time.monotonic()
        try:
            detail = fn() or {}
        except Exception as error:
            seconds = round(time.monotonic() - started, 1)
            self.write(step, 'fail', sub, seconds=seconds, error=str(error)[-800:])
            self.echo(f'FAIL  {label} after {seconds} s: {error}')
            raise
        seconds = round(time.monotonic() - started, 1)
        self.write(step, 'done', sub, seconds=seconds, **detail)
        self.echo(f'done  {label} in {seconds} s' + (f' {json.dumps(detail, sort_keys=True)}' if detail else ''))
        return detail


# --- the drive -------------------------------------------------------------------------------------------------------------------
class Drive(rehearse.Rehearsal):
    """The rehearsal's primitives (gateway calls, exec in a service, one-shot node containers, the relayer, the scrubbed log) on a generation in service."""
    remote, require, allow_excluding = {}, frozenset(), False   # set by __init__ (remote_entity.load): defaults for a Drive made without it

    def __init__(self, generation, cast, ubft, restore_pin=None, joiners=None, require=(), allow_excluding=False):
        generation = Path(generation).resolve()
        super().__init__(generation, generation / 'handoff' / 'drive', cast)
        self.ubft, self.restore_pin = Path(ubft).resolve(), (Path(restore_pin).resolve() if restore_pin else None)
        # entities on another machine (remote_entity.py register): their per-entity steps run through the laptop's agent
        self.remote = remote_entity.load(self.gen)
        docker = handoff_ops.DockerTransport(self.gen)
        self.n = max(docker.entities + list(self.remote))   # every entity of the generation, a prepared joiner's (local or remote) included
        self.joiner_map = dict(joiners or {})
        saved = self.gen / 'handoff' / 'joiners.json'
        if saved.is_file():
            self.joiner_map = {**json.loads(saved.read_text()), **self.joiner_map}
        self.transport = remote_entity.EntityTransport(docker, self.remote)
        self.require, self.allow_excluding = set(require or ()), allow_excluding
        self.net, self.work = self.gen / 'network', self.gen / 'network' / 'handoff'
        self.deployment = json.loads((self.net / 'pos-deployment.json').read_text())
        self.election, self.custody = self.deployment['election'], self.deployment['custody']
        self.root_rpc, self.shard_rpc = operator_rpc.common_urls(handoff_ops.load_compose(self.gen))
        self.old, self.new = [], []   # entities of the committee being left / elected

    def evh(self):
        path = self.evidence / f'epoch{self.target}'
        path.mkdir(parents=True, exist_ok=True)
        return path

    def restore_body_ids(self):
        """`<epoch>=<V3 body id>` of every activated epoch 2..target: the drive's own activation records, and for an epoch a drive did not install (an earlier
        rehearse run, a manual handoff) the record read from root 1 (`q3-activation`)."""
        found = {}
        for path in sorted(self.evidence.glob('epoch*/activation-record-*.json')):
            record = json.loads(path.read_text())
            found[record['epoch']] = record['v3BodyId']
        for epoch in range(2, self.target + 1):
            if epoch not in found:
                self.exec_in('root1', 'ubft', 'root', 'handoff', 'q3-activation', '--root-rpc', self.root_rpc, '--epoch', str(epoch), '--out', '/tmp/drive-activation.json')
                found[epoch] = json.loads(self.exec_in('root1', 'cat', '/tmp/drive-activation.json'))['v3BodyId']
        return ','.join(f'{e}={found[e]}' for e in sorted(found))

    def scrub(self, text, patterns=False):
        """rehearse's scrub, with the secret scan retried: on a live generation the shard's archive renames its `.writing-*` files while the scan walks it, and
        a vanished file fails the scan (fail-closed: the line is withheld)."""
        for _ in range(5):
            out = super().scrub(text, patterns)
            if not out.startswith('[output withheld: the secret scan failed'):
                return out
            self.rescan()
            time.sleep(0.2)
        return out

    def host_ubft(self, *args):
        """rehearse's host_ubft without its per-call 'ok' line (the drive calls it dozens of times)."""
        run = subprocess.run([str(self.ubft), *map(str, args)], text=True, capture_output=True)
        if run.returncode:
            raise rehearse.Failure(f'ubft {" ".join(map(str, args[:4]))}: exit {run.returncode}: {run.stderr.strip()[-500:]}')
        return run.stdout

    # --- reads ---
    def running(self):
        """The running services of the generation's Compose project, and those of every remote entity whose agent answers."""
        out = set(self.compose('ps', '--services', '--status', 'running').split())
        for remote in self.remote.values():
            try:
                out |= remote.running()
            except remote_entity.AgentError as error:
                self.say(f'  remote entity {remote.entity}: {error}')
        return out

    def pending_remote(self):
        """Remote entities prepared for a join (their delegation admitted, their authority at the successor scope) but not yet members."""
        return {i for i, r in self.remote.items() if r.state == 'prepared'}

    def root_info(self, i):
        status, body = self.transport.post(i, '/api/v1/q3/signers', b'{}')
        if status != 200:
            raise Refused(f'root {i} /api/v1/q3/signers: {status} {body[:200]!r}')
        return json.loads(body)

    def root_node_id(self, i):
        if i in self.remote:
            return self.remote[i].root_node_id
        return self.host_ubft('node-id', '--home', self.gen / f'validator{i}' / 'root').strip().splitlines()[-1]

    def evm_node_id(self, i):
        if i in self.remote:
            return self.remote[i].evm_node_id
        command = handoff_ops.load_compose(self.gen)['services'][f'authority{i}']['entrypoint']
        return command[command.index('--node-id') + 1]

    def node_info(self, i):
        return self.remote[i].node_info_path() if i in self.remote else self.gen / f'validator{i}' / 'root' / 'node-info.json'

    def progress(self):
        return self.view(self.REGISTRY, 'progress()(uint64)')[0]

    def result_words(self, result):
        return rehearse.pos_reject.words(self.call('eth_call', [{'to': self.election, 'data': self.cast_run('calldata', 'result(bytes32)', result)}, 'latest']))

    def published(self, result):
        raw = self.call('eth_call', [{'to': self.election, 'data': self.cast_run('calldata', 'publication(bytes32)', result)}, 'latest'])
        return int(raw[2 + 64 * 10:2 + 64 * 11], 16) == 1

    def open_result(self):
        out = self.view_text(self.election, 'openResult()(bytes32)').strip()
        return None if out == ZERO else out

    def trust_base_file(self, epoch):
        return self.net / ('trust-base.json' if epoch == 1 else f'handoff/trust-base-epoch{epoch}.json')

    def committee_of(self, trust_base):
        """The entities whose root node id the trust base names."""
        named = {node['nodeId'] for node in json.loads(trust_base.read_text())['rootNodes']}
        return sorted(i for i in range(1, self.n + 1) if self.root_node_id(i) in named)

    def rate(self, seconds=6):
        first, t0 = self.progress(), time.monotonic()
        time.sleep(seconds)
        return (self.progress() - first) / (time.monotonic() - t0)

    def check_window(self, result, minimum):
        state, _, attempt, reserved_at = self.result_words(result)[:4]
        progress, rate = self.progress(), self.rate()
        left, seconds = window(reserved_at, progress, rate)
        eta = f'~{seconds / 60:.0f} min' if seconds is not None else 'unknown time'
        self.say(f'  window: reserved at progress {reserved_at}, now {progress} ({rate:.2f} rounds/s): {left} rounds left, {eta}')
        if state != rehearse.RESULT_RESERVED:
            raise Refused(f'result {result} is not Reserved (state {state}): it was acknowledged or closed; nothing to drive')
        if left < minimum:
            raise Refused(f'the reservation window is about to lapse: {left} rounds left (< {minimum}, {eta}); the roots reject the result at progress '
                          f'{reserved_at + LIFETIME}. Let it be rejected and drive the next result')
        return {'reservedAt': reserved_at, 'progress': progress, 'roundsLeft': left, 'rate': round(rate, 2), 'electionAttempt': attempt}

    # --- the plan ---
    def plan(self, result_arg, journal):
        """Target epoch, result, committees and the kind of change, from the chain and the roots (and the journal on a resume)."""
        running = self.running()
        epochs = {}
        pending = {i for i, r in self.remote.items() if r.state != 'member'}   # a remote follower's root is at no epoch of the committee
        for i in range(1, self.n + 1):
            if f'root{i}' in running and i not in pending:
                try:
                    epochs[i] = self.root_info(i).get('epoch')
                except (Refused, handoff_ops.HandoffError, ValueError):
                    epochs[i] = None
        resume = journal.last_drive()
        if resume and (result_arg is None or resume[0] == result_arg):
            result, target = resume
            journal.result, journal.target = resume
            if not journal.done('propose') and self.result_words(result)[0] != rehearse.RESULT_RESERVED:
                # the window lapsed (or the result was closed) before the Prepare: that drive is over, the next result is a new one
                journal.write('drive', 'abandoned', state=self.result_words(result)[0])
                self.say(f'  the unfinished drive of {result} to epoch {target} is abandoned: the result is no longer Reserved')
                return self.plan(result_arg if result_arg != result else None, journal)
            self.say(f'  resuming the drive of {result} to epoch {target} (handoff/log.jsonl)')
        else:
            result, target = result_arg or self.open_result(), None
            if result_arg and self.open_result() not in (result_arg, None):
                raise Refused(f'the open result is {self.open_result()}, not {result_arg}')
        if result is None:
            raise Refused('the election has no open result, and handoff/log.jsonl has no unfinished drive')
        known = sorted(e for e in epochs.values() if e is not None)
        if not known:
            raise Refused('no root answers /api/v1/q3/signers')
        if target is None:
            if len(set(known)) != 1:
                raise Refused(f'the roots are at different epochs {epochs} and the journal has no drive to resume')
            target = known[0] + 1
        self.target = target
        old_tb = self.trust_base_file(target - 1)
        if not old_tb.is_file():
            raise Refused(f'{old_tb} is missing: the epoch-{target - 1} trust base is not where the package keeps it')
        self.old = self.committee_of(old_tb)
        members = self.view_text(self.election, 'frozenMembers(bytes32)((uint64,uint64,uint64,uint64,bytes32)[])', result)
        ids = frozen_ids(members)
        mapping = identity_entities(json.loads((self.net / 'pos-plan.json').read_text()), self.joiner_map)
        unknown = [x for x in ids if x not in mapping]
        if unknown:
            raise Refused(f'elected identities {unknown} map to no entity: pass --joiner STAKINGID=ENTITY for a joiner prepared with pos_join/joiner.py')
        self.new = sorted(mapping[x] for x in ids)
        kind = classify(self.old, self.new)
        self.joiners = set(self.new) - set(self.old)
        left_out = sorted((self.require | (self.pending_remote() if not self.allow_excluding else set())) - set(self.new))
        if left_out:
            raise Refused(f'the result {result} elects {self.new} and leaves out entity {left_out}, '
                          + ('which --require-member names' if set(left_out) <= self.require else 'a remote joiner prepared for this join (its authority is at the scope of '
                             'the next epoch: driving this result moves the epoch past it, briefs/handoff-drive-2026-11-12.md gaps 2-3)')
                          + '. Let it lapse, or rerun with --allow-excluding-joiner if the join is abandoned')
        return {'result': result, 'target': target, 'epochs': epochs, 'old': self.old, 'new': self.new, 'kind': kind, 'electedIds': ids}

    # --- steps ---
    def step_preflight(self, info, minimum, allow_retire):
        if info['kind'] == 'mixed':
            raise Refused(f'the election replaces members ({info["old"]} -> {info["new"]}): a join and a retirement in one handoff were never rehearsed')
        if info['kind'] == 'retire' and not allow_retire:
            raise Refused(f'retirement {sorted(set(info["old"]) - set(info["new"]))}: a handoff without an incumbent was never rehearsed on the package '
                          '(research note section 3, retirement 3); rerun with --allow-unrehearsed-retirement to drive it anyway')
        running = self.running()
        # once proposed, a root or shard may be down mid-install or mid-advance (the steps start them again); an authority never is (its key is only in memory)
        roles = ('pod', 'authority', 'ureth') if info['proposed'] else ('pod', 'root', 'shard', 'authority', 'ureth')
        needed = {f'{role}{i}' for i in set(info['old']) | set(info['new']) for role in roles}
        if not needed <= running:
            raise Refused(f'entity services not running: {sorted(needed - running)}')
        for i in self.joiners:
            status, body = self.transport.post(i, '/api/v1/q3/status', b'{}')
            if status != 200 or json.loads(body).get('follower') is not True:
                raise Refused(f'joiner entity {i}: its root is not a follower ({status} {body[:200]!r}); start it as pos_join.py part 3 does')
        detail = {'kind': info['kind'], 'old': info['old'], 'new': info['new'], 'electedIds': info['electedIds']}
        if not info['proposed']:
            detail |= self.check_window(info['result'], minimum)
        return detail

    def step_trust_base(self, result):
        detail = self.ensure_trust_base()
        (self.work / f'result-epoch-{self.target}.txt').write_text(result + '\n')
        return detail

    def ensure_trust_base(self):
        """handoff/trust-base-epoch<target>.json over self.new, signed by every member in its own root home (a remote member on its machine). A file that names the
        elected roots and carries every signature is reused: a remote joiner's was made when it was prepared, and its authority started at that scope."""
        self.work.mkdir(parents=True, exist_ok=True)
        path = self.work / f'trust-base-epoch{self.target}.json'
        want = {self.root_node_id(i) for i in self.new}
        if path.is_file():
            named = {node['nodeId'] for node in json.loads(path.read_text())['rootNodes']}
            if named != want:
                raise Refused(f'{path} exists and names other roots than the elected ones; move it aside to regenerate')
            signed = json.loads(path.read_text()).get('signatures') or {}
            if len(signed) >= len(want):
                return {'reused': str(path), 'epochStartRound': json.loads(path.read_text()).get('epochStartRound')}
        else:
            previous = json.loads(self.trust_base_file(self.target - 1).read_text())
            start = epoch_start(self.target, self.root_info(self.old[0])['round'], previous.get('epochStartRound', 0))
            self.host_ubft('trust-base', 'generate', '--home', self.work, '--network-id', str(previous['networkId']), '--epoch', str(self.target), '--epoch-start', str(start),
                           '--previous-trust-base', self.trust_base_file(self.target - 1), '--root-weights', ','.join(['1'] * len(self.new)),
                           '--output-file-name', path.name, *[x for i in self.new for x in ('--node-info', self.node_info(i))])
        signed = set((json.loads(path.read_text()).get('signatures') or {}))
        for i in sorted(self.new, key=lambda i: i in self.remote):   # the host's roots first: the laptop gets the file once, signs last
            if self.root_node_id(i) in signed:
                continue
            if i in self.remote:
                self.remote[i].sign_trust_base(path)
            else:
                self.host_ubft('trust-base', 'sign', '--home', self.gen / f'validator{i}' / 'root', '--trust-base', path)
        tb = json.loads(path.read_text())
        return {'file': str(path), 'epochStartRound': tb.get('epochStartRound'), 'signatures': len(tb.get('signatures') or {})}

    def assignment(self, tag, result, reserved, evm_pops=None):
        """rehearse.build_assignment over the elected entities (it numbers the entities 1..n)."""
        work = self.work
        self.exec_in('root1', 'ubft', 'root', 'handoff', 'evm-context', '--root-rpc', self.root_rpc, '--out', '/tmp/context.json')
        context = work / f'{tag}-context.json'
        context.write_text(self.exec_in('root1', 'cat', '/tmp/context.json'))
        ids = {i: (self.root_node_id(i), self.evm_node_id(i)) for i in self.new}
        subprocess.run(['chown', '-R', '10001:10001', str(work)], check=True)
        args = ['pos-relayer', 'proposal', *(['--reserved'] if reserved else []), '--eth-rpc', 'http://ureth1:8545', '--pos-deployment', '/deployment.json',
                '--context', f'/work/{tag}-context.json', '--result-id', result, '--node-ids', ','.join(f'{r},{e}' for r, e in ids.values()),
                '--trust-base', '/trust-base.json', '--out-dir', f'/work/{tag}-proposal']
        if evm_pops:
            args += ['--evm-pops', f'/work/{evm_pops}']
        run = self.node_run(args, [f'{work}:/work', f'{self.net / "pos-deployment.json"}:/deployment.json:ro', f'{self.trust_base_file(self.target - 1)}:/trust-base.json:ro'])
        self.expect(run.returncode == 0, f'{tag}: pos-relayer proposal', run.stderr.strip()[-500:])
        proposal = work / f'{tag}-proposal'
        pops = []
        for i, (_, evm) in ids.items():
            if i in self.remote:
                (work / f'{tag}-pop-{i}.json').write_text(self.remote[i].evm_pop(context, proposal / 'validators.json', proposal / 'identities.json'))
                pops.append(str(work / f'{tag}-pop-{i}.json'))
                continue
            auth = self.gen / f'validator{i}' / 'auth'
            for name, source in (('context.json', context), ('validators.json', proposal / 'validators.json'), ('identities.json', proposal / 'identities.json')):
                shutil.copy(source, auth / name)
                os.chown(auth / name, 10001, 10001)
            out = self.exec_in(f'authority{i}', 'ubft', 'root', 'handoff', 'evm-pop', '--context', '/authority/context.json', '--validators', '/authority/validators.json',
                               '--identities', '/authority/identities.json', '--node-id', evm, '--authority-socket', '/authority/operator.sock',
                               '--authority-credential', '/authority/operator.cred')
            (work / f'{tag}-pop-{i}.json').write_text(out)
            pops.append(str(work / f'{tag}-pop-{i}.json'))
        assignment = work / f'{tag}-assignment.json'
        self.host_ubft('root', 'handoff', 'evm-assemble', '--context', context, '--validators', proposal / 'validators.json', '--identities', proposal / 'identities.json',
                       '--authorization', proposal / 'authorization.json', '--pops', ','.join(pops), '--bindings', proposal / 'bindings.json',
                       *(['--evm-pops', proposal / 'evm-pops.json'] if evm_pops else []), '--out', assignment)
        return assignment, proposal, context

    def step_proposal(self, result):
        """rehearse.pos_proposal steps 2-4 over the elected entities; the submission is skipped when the election already holds the publication (a resume, or the
        next attempt after a lapse: the proofs bind the attempt, so they are made again, the publication stays)."""
        tb = self.work / f'trust-base-epoch{self.target}.json'
        assignment, proposal, context = self.assignment('reserved', result, True)
        attempt = (proposal / 'attempt.txt').read_text().strip()
        self.host_ubft('pos-relayer', 'candidate', '--context', context, '--assignment', assignment, '--next-trust-base', tb, '--out', self.work / 'candidate.hex')
        collected = []
        for i in self.new:
            if i in self.remote:
                (self.work / f'evmpop-{i}.json').write_text(self.remote[i].sign_pop(self.work / 'candidate.hex', attempt))
                collected += ['--pop', self.work / f'evmpop-{i}.json']
                continue
            auth = self.gen / f'validator{i}' / 'auth'
            for name, source in (('candidate.hex', self.work / 'candidate.hex'), ('pos-deployment.json', self.net / 'pos-deployment.json')):
                shutil.copy(source, auth / name)
                os.chown(auth / name, 10001, 10001)
            self.exec_in(f'authority{i}', 'ubft', 'pos-relayer', 'sign-pop', '--candidate', '/authority/candidate.hex', '--pos-deployment', '/authority/pos-deployment.json',
                         '--attempt', attempt, '--authority-socket', '/authority/operator.sock', '--authority-credential', '/authority/operator.cred', '--out', '/authority/evmpop.json')
            shutil.copy(auth / 'evmpop.json', self.work / f'evmpop-{i}.json')
            collected += ['--pop', self.work / f'evmpop-{i}.json']
        self.host_ubft('pos-relayer', 'assemble', '--candidate', self.work / 'candidate.hex', '--pos-deployment', self.net / 'pos-deployment.json', '--attempt', attempt,
                       *collected, '--out', self.work / 'evm-pops-collected.json')
        submitted = False
        if not self.published(result):
            identity = json.loads((self.net / 'pos-plan.json').read_text())['identities'][0]
            if self.balance(identity['owner']) < 10 ** 17:
                self.say(f'  funding the owner of identity {identity["stakingId"]} with 1 UCT for gas (faucet account)')
                self.faucet_send(identity['owner'], 10 ** 18)
            owner_key = self.gen / self.manifest['pos']['owner_keys'] / f'identity-{identity["stakingId"]}' / 'owner.key'
            subprocess.run(['chown', '-R', '10001:10001', str(self.work)], check=True)
            for step, extra in (('submit-pops', ['--evm-pops', '/work/evm-pops-collected.json']), ('finalize', [])):
                status, out = self.relayer(owner_key, step, '--result-id', result, *extra, mounts=[f'{self.work}:/work:ro'])
                self.expect(status == 0, f'pos-relayer tx {step}', out.strip()[-500:])
            self.expect(self.published(result), 'the result is published (the election holds the proofs)')
            submitted = True
        published, _, _ = self.assignment('published', result, False, 'evm-pops-collected.json')
        self.expect(published.stat().st_size > 0, 'the published assignment is written', str(published))
        lines = [f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(self.work)}' for p in sorted(self.work.rglob('*'))
                 if p.is_file() and p.suffix in ('.json', '.hex', '.txt')]
        (self.evh() / 'sha256.txt').write_text('\n'.join(lines) + '\n')
        # the election's attempt (attempt.txt) and the root's handoff attempt are different counters: the root's is what the proofs bind (popContext)
        return {'electionAttempt': int(attempt), 'rootAttempt': self.context_attempt(), 'submitted': submitted}

    def context_attempt(self):
        self.exec_in('root1', 'ubft', 'root', 'handoff', 'evm-context', '--root-rpc', self.root_rpc, '--out', '/tmp/drive-context.json')
        return json.loads(self.exec_in('root1', 'cat', '/tmp/drive-context.json'))['attempt']

    def candidate(self):
        """rehearse.pos_candidate over the successor entities: the candidate from root 1, a readiness receipt from each elected entity's own root."""
        work = self.work
        subprocess.run(['chmod', '-R', 'a+rX', str(work)], check=True)
        self.exec_in('root1', 'rm', '-rf', '/tmp/candidate')
        self.exec_in('root1', 'ubft', 'root', 'handoff', 'q3-candidate', '--next-trust-base', f'/network/handoff/trust-base-epoch{self.target}.json',
                     '--next-evm-assignment', '/network/handoff/published-assignment.json', '--root-rpc', self.root_rpc, '--out-dir', '/tmp/candidate')
        for name in ('candidate.cbor', 'config.json', 'v3-body-id.txt', 'root-weights.json', 'evm-weights.json'):
            (work / name).write_bytes(self.exec_in('root1', 'cat', f'/tmp/candidate/{name}', binary=True))
        subprocess.run(['chmod', '-R', 'a+rX', str(work)], check=True)
        config = json.loads((work / 'config.json').read_text())
        self.expect(config.get('signingScheme') == 2, 'the candidate selects signing scheme 2', str(config)[:200])
        genesis = self.call('eth_getBlockByNumber', ['0x0', False])['hash']
        spec = json.loads((self.net / 'genesis.json').read_text())['alloc']
        code = {k.lower().removeprefix('0x'): v for k, v in spec.items()}[self.REGISTRY.lower().removeprefix('0x')]['code']
        code_hash = hashlib.sha256(bytes.fromhex(code.removeprefix('0x'))).hexdigest()
        receipts = []
        for i in sorted(self.joiners & set(self.remote)):
            self.catch_up_remote(i)
        for i in self.new:
            if i in self.remote:
                (work / f'receipt-{i}.json').write_text(self.remote[i].readiness(work / 'candidate.cbor', genesis, code_hash))
                receipts.append(str(work / f'receipt-{i}.json'))
                continue
            self.exec_in(f'root{i}', 'ubft', 'root', 'handoff', 'q3-readiness', '--candidate', '/network/handoff/candidate.cbor', '--key-conf', '/state/keys.json',
                         '--root-rpc', self.root_rpc, '--shard-rpc', self.shard_rpc, '--eth-url', f'http://ureth{i}:8545', '--engine-url', f'http://ureth{i}:8551',
                         '--jwt-secret', '/jwt/jwt.hex', '--execution-genesis-hash', genesis, '--execution-code-hash', code_hash, '--out', '/tmp/receipt.json')
            (work / f'receipt-{i}.json').write_text(self.exec_in(f'root{i}', 'cat', '/tmp/receipt.json'))
            receipts.append(str(work / f'receipt-{i}.json'))
        return receipts

    def catch_up_remote(self, i):
        """A remote joiner's root started at the genesis trust base and, as a non-member, receives no consensus traffic: on a network past its first handoff it
        stays at epoch 1, and its readiness is refused ("the candidate is not the next epoch of this chain"). Its install restart to the CURRENT epoch makes it
        fetch and verify every activation bundle from the incumbents (installQ3Epochs; it stays a follower), so that the candidate is its next epoch."""
        current = self.target - 1
        epoch = self.follower_epoch(i)
        if epoch is not None and epoch > current:
            raise Refused(f'the joiner\'s root {i} is at epoch {epoch}, past the epoch {current} being left')
        if epoch != current:
            self.say(f'  remote joiner {i}: its root is at epoch {epoch}; install restart to epoch {current} (activation bundles from the incumbents)')
            self.remote[i].install_root(current)
            self.wait(f'the joiner\'s root {i} installed epoch {current}', lambda: self.follower_epoch(i) == current, 300)
        if current >= 3 and self.remote[i].info.get('shardCaughtUp') != current:
            # the shard node's own follower installs epoch 2 and then needs the terminal records of the previous EVM configuration, which a staging-only node
            # has in neither journal nor archive: its verified history stays at epoch 2 and its stage of the candidate is refused. Restored from a survivor's
            # pin of the CURRENT epoch, its history tip is that epoch (the restore after its enrollment repeats this at the new epoch).
            self.say(f'  remote joiner {i}: its shard node is restored at epoch {current} before its readiness (a staging-only node cannot follow past epoch 2)')
            target, self.target = self.target, current
            try:
                self.restore_remote(i, follow=False)
            finally:
                self.target = target
            self.remote[i].info['shardCaughtUp'] = current
            self.remote[i].save()

    def follower_epoch(self, i):
        """The installed epoch of a root that holds no quorum certificate (a follower: q3/signers answers 422), from q3/status."""
        try:
            status, body = self.transport.post(i, '/api/v1/q3/status', b'{}')
            return json.loads(body).get('activeEpoch') if status == 200 else None
        except (handoff_ops.HandoffError, ValueError):
            return None

    def step_propose(self, result, journal):
        recorded = journal.value('proposal', 'rootAttempt')
        current = self.context_attempt()
        if recorded is not None and current != recorded:
            # the possession proofs bind the attempt: a lapsed or aborted attempt needs them made again (rehearse.pos_abort's resubmit=False path)
            self.say(f'  the roots plan attempt {current}, the proofs were made for {recorded}: making them again')
            journal.write('proposal', 'redo', rootAttemptWas=recorded, rootAttemptNow=current)
            journal.write('proposal', 'done', **self.step_proposal(result))
        receipts = self.candidate()
        log = self.gen / 'handoff' / 'log.jsonl'
        run = subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'handoff_ops.py'), 'propose', str(self.gen), '--ubft', str(self.ubft),
                              '--next-trust-base', str(self.work / f'trust-base-epoch{self.target}.json'), '--next-evm-assignment', str(self.work / 'published-assignment.json'),
                              '--readiness-receipts', ','.join(receipts), '--committee', ','.join(map(str, self.old))], text=True, capture_output=True)
        self.keep_redacted(self.evh() / 'propose.log', run.stdout + run.stderr)
        if run.returncode:
            raise rehearse.Failure('handoff_ops.py propose: ' + (run.stdout + run.stderr).strip()[-600:])
        accepted = int(run.stdout.strip().splitlines()[-1].split()[1])
        quorum = len(self.old) * 2 // 3 + 1
        self.expect(accepted >= quorum, f'a quorum of the {len(self.old)} roots endorsed the one plan', run.stdout.strip().splitlines()[-1])
        for path in sorted(self.work.glob('receipt-*.json')) + [self.work / 'candidate.cbor', self.work / 'config.json', self.work / 'v3-body-id.txt']:
            shutil.copy(path, self.evh() / path.name)
        shutil.copy(log, self.evh() / 'log.jsonl')
        return {'endorsed': accepted, 'of': len(self.old), 'v3BodyId': (self.work / 'v3-body-id.txt').read_text().strip()}

    def install_root(self, i, files, base):
        """rehearse.pos_install for one root: stop, keep the stores (once), recreate with the install flag, wait for its listener."""
        if self.root_epoch(i, self.transport) == self.target:
            return {'already': True}
        subprocess.run(['docker', 'compose', *base, 'stop', f'root{i}'], check=True, capture_output=True)
        state, backup = self.gen / f'validator{i}' / 'root', self.gen / f'validator{i}' / f'root.pre-epoch-{self.target}'
        if not backup.exists():
            # copied under a temporary name and renamed when complete: an interrupted copy is never taken for the rollback copy
            partial = backup.with_name(backup.name + '.partial')
            if partial.exists():
                shutil.rmtree(partial)
            subprocess.run(['cp', '-a', str(state), str(partial)], check=True)
            os.rename(partial, backup)
        run = subprocess.run(['docker', 'compose', *files, 'up', '-d', '--no-deps', '--force-recreate', f'root{i}'], text=True, capture_output=True)
        self.expect(run.returncode == 0, f'root {i} recreated with the install flag', run.stderr.strip()[-400:])
        self.wait(f'root {i} listens again', lambda: self.root_listens(i, self.transport), 120)
        return {'backup': str(backup)}

    def step_install(self, journal):
        override = self.gen / f'compose.install-epoch-{self.target}.json'
        if not override.exists():
            override.write_text(json.dumps(handoff.install_override(handoff_ops.load_compose(self.gen), self.target), indent=1) + '\n')
        base = handoff_ops.compose_files(self.gen)
        files = base + ['-f', str(override)]
        roots = sorted(set(self.old) | set(self.new))
        for i in roots:
            if i in self.remote:
                journal.run('install', lambda i=i: self.remote[i].install_root(self.target), sub=f'root{i}')
                continue
            journal.run('install', lambda i=i: self.install_root(i, files, base), sub=f'root{i}')
        for i in roots:
            self.wait(f'root {i} certifies at epoch {self.target}', lambda i=i: self.root_epoch(i, self.transport) == self.target, 300)
        self.exec_in('root1', 'ubft', 'root', 'handoff', 'q3-activation', '--root-rpc', self.root_rpc, '--epoch', str(self.target), '--out', '/tmp/activation.json')
        record = json.loads(self.exec_in('root1', 'cat', '/tmp/activation.json'))
        (self.evh() / f'activation-record-{self.target}.json').write_text(json.dumps(record, indent=1) + '\n')
        self.expect(record.get('epoch') == self.target and record.get('signingScheme') == 2, f'the activation record is epoch {self.target} under scheme 2', str(record)[:200])
        self.expect(record.get('v3BodyId') == (self.work / 'v3-body-id.txt').read_text().strip(), 'the activation record names the candidate\'s V3 body id')
        for i in sorted(set(self.old) & set(self.new)):
            def activated(i=i):
                logs = self.remote[i].logs(f'shard{i}') if i in self.remote else self.compose('logs', '--no-color', '--since', '30m', f'shard{i}', check=False)
                return any('"message":"handoff activated"' in line and f'"rootEpoch":{self.target},' in line for line in logs.splitlines())
            self.wait(f'shard {i} logs the activation of root epoch {self.target}', activated, 120)
        return {'activationRound': record['activationRound'], 'v3BodyId': record['v3BodyId']}

    def authority_status(self, i):
        """`signing-authority status` of entity i (its enrollment: rootEpoch, shardEpoch, enrollmentComplete, generation, faulted, keyLost)."""
        return json.loads(self.exec_in(f'authority{i}', 'ubft', 'signing-authority', 'status', *OPERATOR))

    def keep_credential(self, i):
        """The entity's client credential before the switch, kept once as client.cred.pre-epoch-N (never overwritten: a rerun after the replace-session would
        otherwise keep the NEW session's credential under the old name)."""
        auth = self.gen / f'validator{i}' / 'auth'
        kept = auth / f'client.cred.pre-epoch-{self.target}'
        if kept.exists():
            return
        tmp = auth / f'.client.cred.pre-epoch-{self.target}.tmp'
        shutil.copy(auth / 'client.cred', tmp)
        os.chmod(tmp, 0o600)
        os.chown(tmp, 10001, 10001)
        os.rename(tmp, kept)

    def advance_entity(self, i, shard_epoch, journal):
        """Entity i's switch as sub-steps (advance/entity<i>/...), each resumable. The authority refuses a repeated advance (signingauthority/advance.go), so its
        status is read first and an advance it already holds is not sent again; replace-session may be repeated (the newest session wins: the shard is stopped
        until the credential it starts with is written); the shard is started last. The shard is stopped inside each authority sub-step, so a rerun that finds
        them all done leaves it running."""
        unit = f'entity{i}'
        if i in self.remote:
            return self.advance_remote(i, shard_epoch, journal)
        def stop():
            self.compose('stop', f'shard{i}')
        def advanced(status):
            return status.get('rootEpoch') == self.target and status.get('shardEpoch') == shard_epoch
        def healthy(status):
            if status.get('faulted') or status.get('keyLost'):
                raise Refused(f'authority {i} reports faulted={status.get("faulted")} keyLost={status.get("keyLost")}: stop and inspect it; the drive will not continue')
            return status
        if i in self.joiners:
            def enroll():
                status = healthy(self.authority_status(i))
                if status.get('enrollmentComplete') and status.get('shardEpoch') == shard_epoch:
                    return {'already': True, 'generation': status.get('generation')}
                stop()
                self.exec_in(f'authority{i}', 'ubft', 'signing-authority', 'complete-enrollment', *OPERATOR, '--shard-conf', f'/network/handoff/shard-conf-{shard_epoch}.json')
                return {'generation': self.authority_status(i).get('generation')}
            journal.run('advance', enroll, sub=f'{unit}/complete-enrollment')
            def session():
                stop()
                self.exec_in(f'authority{i}', 'ubft', 'signing-authority', 'replace-session', *OPERATOR, '--out', '/authority/client.cred')
                return {'generation': self.authority_status(i).get('generation')}
            journal.run('advance', session, sub=f'{unit}/replace-session')
            journal.run('advance', lambda: self.restore_joiner(i) or {}, sub=f'{unit}/restore')   # empties and restores its shard node, then runs it (rehearse)
            return {'joiner': True}
        def advance():
            status = healthy(self.authority_status(i))
            if advanced(status):
                return {'already': True, 'generation': status.get('generation')}
            stop()
            self.keep_credential(i)
            self.exec_in(f'authority{i}', 'ubft', 'signing-authority', 'advance-epoch', *OPERATOR, '--trust-base', f'/network/handoff/trust-base-epoch{self.target}.json',
                         '--shard-conf', f'/network/handoff/shard-conf-{shard_epoch}.json')
            return {'generation': self.authority_status(i).get('generation')}
        journal.run('advance', advance, sub=f'{unit}/advance-epoch')
        def session():
            status = healthy(self.authority_status(i))
            self.expect(advanced(status), f'authority {i} holds root epoch {self.target} and shard epoch {shard_epoch} before its new session', str(status)[:200])
            stop()
            self.exec_in(f'authority{i}', 'ubft', 'signing-authority', 'replace-session', *OPERATOR, '--out', '/authority/client.cred')
            return {'generation': self.authority_status(i).get('generation')}
        journal.run('advance', session, sub=f'{unit}/replace-session')
        journal.run('advance', lambda: self.compose('start', f'shard{i}') and {}, sub=f'{unit}/shard-start')
        return {}

    def advance_remote(self, i, shard_epoch, journal):
        """advance_entity for an entity on another machine: the same sub-steps and status checks, each order run there by its agent (remote_joiner.py)."""
        remote, unit = self.remote[i], f'entity{i}'
        conf = self.work / f'shard-conf-{shard_epoch}.json'
        remote.put({f'handoff/{conf.name}': conf, f'handoff/trust-base-epoch{self.target}.json': self.work / f'trust-base-epoch{self.target}.json'})
        def healthy(status):
            if status.get('faulted') or status.get('keyLost'):
                raise Refused(f'authority {i} (laptop) reports faulted={status.get("faulted")} keyLost={status.get("keyLost")}: stop and inspect it')
            return status
        def advanced(status):
            return status.get('rootEpoch') == self.target and status.get('shardEpoch') == shard_epoch
        if i in self.joiners:
            def enroll():
                status = healthy(remote.authority_status())
                if status.get('enrollmentComplete') and status.get('shardEpoch') == shard_epoch:
                    return {'already': True, 'generation': status.get('generation')}
                remote.authority_step('complete-enrollment', self.target, shard_epoch)
                return {'generation': remote.authority_status().get('generation')}
            journal.run('advance', enroll, sub=f'{unit}/complete-enrollment')
            def session():
                remote.authority_step('replace-session', self.target, shard_epoch)
                return {'generation': remote.authority_status().get('generation')}
            journal.run('advance', session, sub=f'{unit}/replace-session')
            journal.run('advance', lambda: self.restore_remote(i) or {}, sub=f'{unit}/restore')
            return {'joiner': True, 'remote': True}
        def advance():
            status = healthy(remote.authority_status())
            if advanced(status):
                return {'already': True, 'generation': status.get('generation')}
            remote.authority_step('advance-epoch', self.target, shard_epoch)   # the laptop keeps client.cred.pre-epoch-N once, then advances
            return {'generation': remote.authority_status().get('generation')}
        journal.run('advance', advance, sub=f'{unit}/advance-epoch')
        def session():
            status = healthy(remote.authority_status())
            self.expect(advanced(status), f'authority {i} (laptop) holds root epoch {self.target} and shard epoch {shard_epoch} before its new session', str(status)[:200])
            remote.authority_step('replace-session', self.target, shard_epoch)
            return {'generation': remote.authority_status().get('generation')}
        journal.run('advance', session, sub=f'{unit}/replace-session')
        journal.run('advance', lambda: remote.authority_step('shard-start', self.target, shard_epoch) and {}, sub=f'{unit}/shard-start')
        return {'remote': True}

    def step_advance(self, journal):
        transport = self.transport
        self.expect(all(self.root_epoch(i, transport) == self.target for i in self.new), f'every elected root certifies at epoch {self.target}')
        shard_epoch = journal.value('advance', 'shardEpoch', sub='shard-conf') or self.successor_shard_epoch()
        def publish():
            self.exec_in('root1', 'ubft', 'q3', 'shard-conf', '--root-rpc', self.root_rpc, '--epoch', str(shard_epoch), '--out', '/tmp/shard-conf.json')
            conf = json.loads(self.exec_in('root1', 'cat', '/tmp/shard-conf.json'))
            self.expect(conf.get('epoch') == shard_epoch and conf.get('partitionId') == 8, f'a root holds the EVM shard configuration of epoch {shard_epoch}', str(conf)[:200])
            tmp = self.work / f'.shard-conf-{shard_epoch}.json.tmp'   # atomic: the lock-proof endpoint's scanner does not match the temporary name (#996)
            tmp.write_text(json.dumps(conf, indent=1) + '\n')
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.work / f'shard-conf-{shard_epoch}.json')
            subprocess.run(['chmod', '-R', 'a+rX', str(self.work)], check=True)
            return {'shardEpoch': shard_epoch}
        journal.run('advance', publish, sub='shard-conf')
        for i in self.new:
            journal.run('advance', lambda i=i: self.advance_entity(i, shard_epoch, journal), sub=f'entity{i}')
        return {'shardEpoch': shard_epoch}

    def restore_remote(self, i, follow=True):
        """rehearse.restore_joiner for an entity on another machine: the pin (the latest certified record of the new epoch, its technical record, the trust
        history's body id) is read HERE from a survivor's archive and shipped; the laptop empties its shard node's and execution client's state, restores, catches up."""
        self.expect(bool(self.restore_pin), 'the joiner\'s restore needs --restore-pin (scripts/h4-restore-pin of the pinned source)')
        if follow:
            status = self.remote[i].status()
            head, chain = status.get('urethHead'), int(self.ureth(1, 'eth_blockNumber'), 16)
            if not status.get('restoring') and status.get('services', {}).get(f'shard{i}') == 'running' and head and head + 5 >= chain:
                self.say(f'  remote entity {i}: its shard node already runs at the head ({head} of {chain}): restored earlier')   # a resumed drive does not wipe it
                return
        bodies = self.restore_body_ids()
        self.expect(bool(bodies), 'an activation record names the V3 body id the restore is anchored to')
        env = dict(os.environ, H4_RESTORE_BODY_IDS=bodies)
        newest = bodies.split(',')[-1].split('=')[1]
        out = Path(tempfile.mkdtemp(prefix='drive-pin-'))
        attempts = []
        try:
            def pinned():
                for j in sorted(set(self.new) - set(self.remote)):
                    run = subprocess.run([str(self.restore_pin), str(self.gen / f'validator{j}' / 'archive'), str(self.net / 'trust-base.json'), str(out / 'tip')],
                                         text=True, capture_output=True, env=env)
                    attempts.append(f'validator {j} archive: exit {run.returncode}: {(run.stdout + run.stderr).strip()[-300:]}')
                    if run.returncode == 0 and f'bodyID=0x{newest}' in run.stdout:
                        return run
                return None
            pin = self.wait('a survivor\'s archive yields a certified record of the new epoch to pin', pinned, 180)
            (self.evh() / f'joiner-restore-pin-{i}.txt').write_text('\n'.join(attempts) + '\n')
            body = re.search(r'bodyID=(0x[0-9a-fA-F]+)', pin.stdout)
            self.expect(bool(body), 'the pin names the trust history\'s body id', pin.stdout.strip()[-300:])
            started = self.remote[i].restore_start((out / 'tip.uc.cbor').read_bytes(), (out / 'tip.tr.cbor').read_bytes(), body.group(1))
            self.say(f'  remote entity {i}: restore started: {started}')
        finally:
            shutil.rmtree(out, ignore_errors=True)
        seen = []
        def replayed():
            head = self.remote[i].status().get('urethHead')
            seen.append(head)
            self.say(f'  remote entity {i}: execution client at {head} (replaying to the pin)')
            return head and len(seen) >= 5 and len(set(seen[-5:])) == 1
        if not follow:
            # before its Commit the node is no member: it gets no certificate and never follows the head. Its replay to the pin is all it can do, and enough:
            # the pin's record is its verified history's tip (what its readiness needs)
            self.wait(f'the laptop\'s execution client {i} replays to the pin', replayed, 7200)
            return
        # restore mode stops at the pin (it asks its archive for nothing later): once replayed, it runs as an ordinary node, which walks its seeded archive
        # and follows the certificates it now receives as a member
        self.wait(f'the laptop\'s execution client {i} replays to the pin', replayed, 7200)
        self.remote[i].seed_archive()   # the records certified during the replay
        finished = self.remote[i].restore_finish()
        self.expect(finished.get('running') is True, f'the laptop\'s shard node {i} runs as an ordinary node', str(finished)[:300])
        def caught_up():
            head = self.remote[i].status().get('urethHead')
            target = int(self.ureth(1, 'eth_blockNumber'), 16)
            self.say(f'  remote entity {i}: execution client at {head}, validator 1 at {target}')
            return head is not None and head + 5 >= target
        self.wait(f'the laptop\'s execution client {i} catches up with validator 1', caught_up, 3600)

    def step_lockproof(self, mode):
        overlay = self.gen / BRIDGE_OVERRIDE
        if not overlay.is_file():
            return {'bridge': False}
        files = handoff_ops.compose_files(self.gen) + ['-f', str(overlay)]
        bridge = json.loads(overlay.read_text())['services']['lockproof']
        command = bridge.get('entrypoint') or bridge.get('command') or []
        rescans = '--shard-conf-dir' in command
        restart = mode == 'always' or (mode == 'auto' and not rescans)
        if restart:
            run = subprocess.run(['docker', 'compose', *files, 'up', '-d', '--no-deps', '--force-recreate', 'lockproof'], text=True, capture_output=True)
            self.expect(run.returncode == 0, 'the lock-proof endpoint recreated', run.stderr.strip()[-300:])
        healthy = self.wait('the lock-proof endpoint answers /healthz', lambda: self.http('127.0.0.1:8090', 'GET', '/healthz')[0] == 200, 120)
        return {'bridge': True, 'restarted': restart, 'rescansHandoffDir': rescans, 'healthy': bool(healthy)}

    def ack_block(self, result, head):
        """(the first block whose state has the result Acknowledged, None) by bisection on eth_call at a block; (None, why) when the client keeps no state that
        far back or the lookup failed (a transport error is reported, not hidden)."""
        data = self.cast_run('calldata', 'result(bytes32)', result)
        def acked(block):
            raw = self.ureth(1, 'eth_call', [{'to': self.election, 'data': data}, hex(block)])
            if not raw or raw == '0x':
                raise ValueError(f'no state at block {block}')
            return int(raw[2:66], 16) == rehearse.RESULT_ACKNOWLEDGED
        lo, hi = max(0, head - 20000), head
        try:
            if acked(lo):
                return None, f'already acknowledged at block {lo}, the oldest one looked at'
            while hi - lo > 1:
                mid = (lo + hi) // 2
                lo, hi = (lo, mid) if acked(mid) else (mid, hi)
            return hi, None
        except Exception as error:   # no state at a block, or the RPC failed: the step still passes (the result IS acknowledged), the reason is recorded
            return None, f'{type(error).__name__}: {error}'[:300]

    def step_verify(self, result, journal):
        transport = self.transport
        epochs = {i: self.root_epoch(i, transport) for i in self.new}
        self.expect(all(e == self.target for e in epochs.values()), f'every elected root certifies at epoch {self.target}', str(epochs))
        state = self.wait(f'the election records {result[:10]}.. Acknowledged', lambda: self.result_words(result)[0] == rehearse.RESULT_ACKNOWLEDGED, 600)
        head = int(self.call('eth_blockNumber'), 16)
        block, why = self.ack_block(result, head)
        self.expect(bool(state), 'the result is Acknowledged', str(self.result_words(result)[0]))
        self.say(f'  acknowledged by block {block} (head {head})' + (f'; the block is unknown: {why}' if why else ''))
        detail = {'epochs': epochs, 'acknowledged': True, 'ackBlock': block, **({'ackBlockUnknown': why} if why else {})}
        utb = self.manifest.get('utb')
        if utb:
            def reached():
                status, body = self.utb_page(f'from={self.utb_genesis_epoch()}&maxEntries=64')
                if status != 200 or not body:
                    return None
                path = self.evh() / 'utb-history.cbor'
                path.write_bytes(body)
                ok, first, tip, tip_id, _ = self.utb_verify(path, utb['genesis_id'])
                return (tip, tip_id) if ok and tip >= self.target else None
            tip, tip_id = self.wait(f'/api/v1/trustbases serves a verifying history reaching epoch {self.target}', reached, 300)
            detail |= {'utbTip': tip, 'utbTipEntryId': tip_id}
        first = int(self.call('eth_blockNumber'), 16)
        later = self.wait('the chain keeps producing blocks', lambda: (lambda b: b if b > first + 2 else None)(int(self.call('eth_blockNumber'), 16)), 120)
        def applied():
            count = self.view(self.REGISTRY, 'recordCount()(uint64)')[0]
            return count if count == self.view(self.custody, 'recordCursor()(uint64)')[0] else None
        records = self.wait('the custody has applied every root record', applied, 300)
        return detail | {'blocks': [first, later], 'records': records}


def parse_joiners(values):
    out = {}
    for value in values or ():
        ident, _, entity = value.partition('=')
        if not ident.isdigit() or not entity.isdigit():
            raise argparse.ArgumentTypeError(f'--joiner wants STAKINGID=ENTITY, got {value!r}')
        out[ident] = int(entity)
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('generation', type=Path)
    p.add_argument('result', nargs='?', help='the election result to drive (default: the open one, or the unfinished drive in handoff/log.jsonl)')
    p.add_argument('--ubft', type=Path, required=True, help='the pinned ubft binary of the generation')
    p.add_argument('--cast', default='cast')
    p.add_argument('--restore-pin', type=Path, help='h4-restore-pin (scripts/h4-restore-pin built from the pinned source): needed for a joiner')
    p.add_argument('--joiner', action='append', help='STAKINGID=ENTITY of a prepared joiner (also read from handoff/joiners.json)')
    p.add_argument('--min-window-rounds', type=int, default=MIN_WINDOW_ROUNDS, help='refuse the steps before the Prepare with fewer progress rounds left')
    p.add_argument('--lockproof-restart', choices=('auto', 'always', 'never'), default='auto',
                   help='auto: recreate the lock-proof endpoint only when it does not rescan network/handoff (pre-#996)')
    p.add_argument('--allow-unrehearsed-retirement', action='store_true')
    p.add_argument('--require-member', type=int, action='append', default=[], metavar='ENTITY',
                   help='refuse a result that does not elect this entity (a joiner being prepared); repeatable')
    p.add_argument('--allow-excluding-joiner', action='store_true',
                   help='drive a result that leaves out a remote joiner prepared for this join (handoff/remote-joiners/*.json, state prepared): abandons that join')
    p.add_argument('--plan', action='store_true', help='print what the drive would do and the window, change nothing')
    a = p.parse_args(argv)
    if os.geteuid() != 0:
        p.error('run as root (sudo -E env PATH=$PATH ...): the generation directory is uid 10001, mode 0700')
    d = Drive(a.generation, a.cast, a.ubft, a.restore_pin, parse_joiners(a.joiner), a.require_member, a.allow_excluding_joiner)
    journal = Journal(d.gen / 'handoff' / 'log.jsonl', echo=d.say)
    started = time.monotonic()
    try:
        info = d.plan(a.result, journal)
        journal.result, journal.target = info['result'], info['target']
        info['proposed'] = journal.done('propose')
        d.say(f'== handoff-drive {info["result"]} -> root epoch {info["target"]}: {info["kind"]}, committee {info["old"]} -> {info["new"]}, roots {info["epochs"]}')
        d.say('   steps done earlier: ' + (', '.join(s for s in STEPS if journal.done(s)) or 'none'))
        if a.plan:
            if not info['proposed']:
                d.check_window(info['result'], a.min_window_rounds)
            return 0
        result = info['result']
        steps = (('preflight', lambda: d.step_preflight(info, a.min_window_rounds, a.allow_unrehearsed_retirement)),
                 ('trust-base', lambda: d.step_trust_base(result)),
                 ('proposal', lambda: d.step_proposal(result)),
                 ('propose', lambda: d.step_propose(result, journal)),
                 ('install', lambda: d.step_install(journal)),
                 ('advance', lambda: d.step_advance(journal)),
                 ('lockproof', lambda: d.step_lockproof(a.lockproof_restart)),
                 ('verify', lambda: d.step_verify(result, journal)))
        for name, fn in steps:
            if name in WINDOW_STEPS and not journal.done(name) and not journal.done('propose'):
                d.check_window(result, a.min_window_rounds)
            if name == 'preflight':   # re-checked on every run: the state may have changed since
                journal.write('preflight', 'checked', **fn())
                continue
            journal.run(name, fn)
        d.say(f'== handoff-drive DONE: root epoch {info["target"]} active, {result[:10]}.. acknowledged, {time.monotonic() - started:.0f} s this run')
        return 0
    except Refused as refusal:
        d.say(f'REFUSED: {refusal}')
        return 3
    except Exception as error:
        d.say(f'STOPPED: {d.scrub(str(error))}. Rerun the same command to continue from handoff/log.jsonl')
        return 1


if __name__ == '__main__':
    sys.exit(main())
