"""Unit tests of handoff_drive.py: the pure rules (window, epoch start, membership) and the journal that makes a drive resumable. No Docker, no network."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import unittest.mock

import handoff
import handoff_drive as hd


class Rules(unittest.TestCase):
    def test_the_window_is_the_reservation_lifetime_from_the_reservation(self):
        self.assertEqual(hd.window(402, 2554, 2.0), (402 + 16384 - 2554, (402 + 16384 - 2554) / 2.0))
        self.assertEqual(hd.window(0, 16384)[0], 0)
        self.assertIsNone(hd.window(0, 10, 0)[1], 'no rate, no time estimate')

    def test_the_epoch_start_is_above_the_root_round_and_the_previous_start(self):
        self.assertEqual(hd.epoch_start(2, 3000), 200000, 'a young network keeps the rehearsal\'s value')
        self.assertEqual(hd.epoch_start(2, 149000), 300000, 'a running network: the next boundary 100000 above its round (gap (c))')
        self.assertGreater(hd.epoch_start(3, 10, previous_start=400000), 400000)
        for root_round in (0, 99999, 100000, 1234567):
            self.assertGreater(hd.epoch_start(2, root_round), root_round + 99999)

    def test_membership_changes_are_classified(self):
        self.assertEqual(hd.classify([1, 2, 3, 4], [4, 3, 2, 1]), 'no-change')
        self.assertEqual(hd.classify([1, 2, 3, 4], [1, 2, 3, 4, 5]), 'join')
        self.assertEqual(hd.classify([1, 2, 3, 4, 5], [1, 2, 3, 5]), 'retire')
        self.assertEqual(hd.classify([1, 2, 3, 4], [1, 2, 3, 5]), 'mixed')

    def test_frozen_members_and_their_entities(self):
        text = '[(1, 1, 0, 1, 0xab), (2, 1, 0, 1, 0xcd), (7, 1, 0, 1, 0xef)]'
        self.assertEqual(hd.frozen_ids(text), [1, 2, 7])
        plan = {'identities': [{'stakingId': 1}, {'stakingId': 2}]}
        self.assertEqual(hd.identity_entities(plan, {'7': 5}), {1: 1, 2: 2, 7: 5})

    def test_joiner_arguments(self):
        self.assertEqual(hd.parse_joiners(['5=5', '9=6']), {'5': 5, '9': 6})
        with self.assertRaises(Exception):
            hd.parse_joiners(['five=5'])


class InProcessSwitch(unittest.TestCase):
    """bft-core#1086: a staying root that switched in process is not restarted; anything else is installed by the restart."""
    def answers(self, *views):
        views, asked = list(views), []
        def status():
            asked.append(1)
            return views.pop(0) if len(views) > 1 else views[0]
        clock = iter(range(0, 1000)).__next__
        return status, asked, clock

    def test_a_switched_root_is_not_restarted(self):
        status, asked, clock = self.answers({'activeEpoch': 2, 'switch': {'phase': 'switching', 'epoch': 1, 'target': 3}},
                                            {'activeEpoch': 3, 'switch': {'phase': 'running', 'epoch': 3, 'target': 3, 'tookMs': 40}})
        self.assertEqual(handoff.switched_in_process(status, 3, wait=10, sleep=lambda s: None, clock=clock)['tookMs'], 40)
        self.assertEqual(len(asked), 2)

    def test_a_leaver_that_switched_is_following(self):
        status, _, clock = self.answers({'activeEpoch': 3, 'follower': True, 'switch': {'phase': 'following', 'epoch': 3, 'target': 3}})
        self.assertIsNotNone(handoff.switched_in_process(status, 3, wait=10, sleep=lambda s: None, clock=clock))

    def test_an_older_image_or_a_disabled_switch_is_restarted_at_once(self):
        status, asked, clock = self.answers({'activeEpoch': 2})
        self.assertIsNone(handoff.switched_in_process(status, 3, wait=10, sleep=lambda s: None, clock=clock))
        self.assertEqual(len(asked), 1)

    def test_a_faulted_switch_is_restarted_at_once(self):
        status, asked, clock = self.answers({'activeEpoch': 3, 'switch': {'phase': 'faulted', 'epoch': 2, 'target': 3}})
        self.assertIsNone(handoff.switched_in_process(status, 3, wait=10, sleep=lambda s: None, clock=clock))
        self.assertEqual(len(asked), 1)

    def test_a_declined_switch_is_restarted_at_once(self):
        status, asked, clock = self.answers({'activeEpoch': 2, 'switch': {'phase': 'running', 'epoch': 2, 'declined': 3, 'declinedReason': 'joiners'}})
        self.assertIsNone(handoff.switched_in_process(status, 3, wait=10, sleep=lambda s: None, clock=clock))
        self.assertEqual(len(asked), 1, 'a successor with joiners: the drive restarts the root after the joiners, without waiting')

    def test_a_root_that_does_not_switch_in_time_is_restarted(self):
        status, asked, clock = self.answers({'activeEpoch': 2, 'switch': {'phase': 'running', 'epoch': 2}})
        self.assertIsNone(handoff.switched_in_process(status, 3, wait=5, sleep=lambda s: None, clock=clock))
        self.assertGreater(len(asked), 1)

    def test_a_root_that_does_not_answer_is_asked_again(self):
        status, asked, clock = self.answers(None, {'activeEpoch': 3, 'switch': {'phase': 'running', 'epoch': 3}})
        self.assertIsNotNone(handoff.switched_in_process(status, 3, wait=10, sleep=lambda s: None, clock=clock), 'an unavailable status is no evidence: asked again')
        self.assertEqual(len(asked), 2)

    def test_a_root_that_never_answers_is_restarted_after_the_wait(self):
        status, asked, clock = self.answers(None)
        self.assertIsNone(handoff.switched_in_process(status, 3, wait=5, sleep=lambda s: None, clock=clock))
        self.assertGreater(len(asked), 1)

    def test_the_status_epoch_of_a_switching_root_is_its_published_one(self):
        self.assertEqual(handoff.status_epoch({'activeEpoch': 3}), 3, 'an older image: its activeEpoch')
        self.assertEqual(handoff.status_epoch({'activeEpoch': 3, 'switch': {'phase': 'running', 'epoch': 3}}), 3)
        self.assertEqual(handoff.status_epoch({'activeEpoch': 3, 'switch': {'phase': 'following', 'epoch': 3}}), 3)
        for phase in ('switching', 'faulted'):
            self.assertIsNone(handoff.status_epoch({'activeEpoch': 3, 'switch': {'phase': phase, 'epoch': 2, 'target': 3}}), phase)


class InProcessSwitchInstall(unittest.TestCase):
    def drive(self, status):
        d = object.__new__(hd.Drive)
        d.gen, d.target, d.old, d.new = Path('/nonexistent'), 3, [1, 2], [1, 3]
        d.root_epoch = lambda i, transport=None: 2
        d.transport = None
        d.q3_status = status
        return d

    def test_a_staying_root_that_switched_is_not_restarted(self):
        d = self.drive(lambda i: {'activeEpoch': 3, 'switch': {'phase': 'running', 'epoch': 3, 'target': 3, 'tookMs': 35}})
        with unittest.mock.patch('subprocess.run', side_effect=AssertionError('restarted')):
            self.assertEqual(d.install_root(1, [], []), {'already': True, 'inProcess': True, 'switchMs': 35})

    def test_a_joiner_is_never_waited_for(self):
        asked = []
        d = self.drive(lambda i: asked.append(i) or {'activeEpoch': 2, 'follower': True, 'switch': {'phase': 'running', 'epoch': 2}})
        with unittest.mock.patch('subprocess.run', side_effect=RuntimeError('restart')):
            with self.assertRaisesRegex(RuntimeError, 'restart'):
                d.install_root(3, [], [])
        self.assertEqual(asked, [3], 'a joiner (not in the old committee) is asked once and installed by the restart without waiting')

    def test_switching_or_faulted_with_the_target_epoch_is_restarted(self):
        for phase in ('switching', 'faulted'):
            d = self.drive(lambda i: {'activeEpoch': 3, 'switch': {'phase': phase, 'epoch': 2, 'target': 3}})
            d.root_epoch = lambda i, transport=None: 3
            with unittest.mock.patch('subprocess.run', side_effect=RuntimeError('restart')), unittest.mock.patch.object(handoff, 'SWITCH_WAIT_SECONDS', 0):
                with self.assertRaisesRegex(RuntimeError, 'restart', msg=phase):
                    d.install_root(1, [], [])


class JournalResume(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / 'handoff' / 'log.jsonl'
        self.lines = []
        self.journal = hd.Journal(self.path, '0xr1', 2, echo=self.lines.append)

    def tearDown(self):
        self.dir.cleanup()

    def test_a_step_runs_once_and_a_rerun_skips_it(self):
        calls = []
        self.journal.run('trust-base', lambda: calls.append(1) or {'epochStartRound': 200000})
        self.journal.run('trust-base', lambda: calls.append(2))
        self.assertEqual(calls, [1])
        self.assertEqual(self.journal.value('trust-base', 'epochStartRound'), 200000)
        self.assertTrue(any(line.startswith('skip  trust-base') for line in self.lines))
        self.assertTrue(any('done  trust-base in' in line for line in self.lines), 'every step prints its timing')

    def test_a_failed_step_is_recorded_and_runs_again(self):
        def boom():
            raise RuntimeError('root 3 refused')
        with self.assertRaises(RuntimeError):
            self.journal.run('propose', boom)
        rows = self.journal.mine()
        self.assertEqual([r['status'] for r in rows], ['start', 'fail'])
        self.assertIn('root 3 refused', rows[-1]['error'])
        self.assertFalse(self.journal.done('propose'))
        self.journal.run('propose', lambda: {'endorsed': 4})
        self.assertTrue(self.journal.done('propose'))

    def test_sub_steps_resume_inside_a_step(self):
        self.journal.run('install', lambda: {}, sub='root1')
        self.journal.run('install', lambda: {}, sub='root2')
        ran = []
        for i in (1, 2, 3, 4):
            self.journal.run('install', lambda i=i: ran.append(i), sub=f'root{i}')
        self.assertEqual(ran, [3, 4], 'a root installed before the crash is not stopped and recreated again')
        self.assertFalse(self.journal.done('install'), 'the step is done only when it says so')

    def test_the_unfinished_drive_is_found_and_other_rows_are_ignored(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({'event': 'plan', 'attempt': 1}) + '\nnot json\n')
        self.assertIsNone(self.journal.last_drive())
        self.journal.run('trust-base', lambda: {})
        self.assertEqual(self.journal.last_drive(), ('0xr1', 2))
        self.journal.run('verify', lambda: {})
        self.assertIsNone(self.journal.last_drive(), 'a verified drive is finished')
        other = hd.Journal(self.path, '0xr2', 3, echo=self.lines.append)
        other.run('trust-base', lambda: {})
        self.assertEqual(other.last_drive(), ('0xr2', 3))
        other.write('drive', 'abandoned')
        self.assertIsNone(other.last_drive(), 'an abandoned drive (its window lapsed before the Prepare) is not resumed')
        self.assertFalse(other.done('verify'))

    def test_rows_carry_result_target_and_time(self):
        row = self.journal.write('install', 'done', sub='root1', backup='/x')
        self.assertEqual((row['event'], row['result'], row['target'], row['sub'], row['backup']), ('drive', '0xr1', 2, 'root1', '/x'))
        self.assertRegex(row['time'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')


class Source(unittest.TestCase):
    """What the drive must never do, checked on its source."""
    text = (Path(__file__).parent / 'handoff_drive.py').read_text()

    def test_no_authority_is_restarted_or_recreated(self):
        for line in self.text.splitlines():
            if 'authority' in line and any(verb in line for verb in ("'stop'", "'restart'", "'up'", "'rm'", "'down'", "'kill'")):
                self.fail(f'an authority lifecycle command: {line.strip()}')
        self.assertNotIn("'down'", self.text)
        self.assertNotIn('prune', self.text)

    def test_force_recreate_is_only_for_roots_and_the_lock_proof_endpoint(self):
        for line in self.text.splitlines():
            if '--force-recreate' in line and 'subprocess.run' in line:
                self.assertTrue("f'root{i}'" in line or "'lockproof'" in line, line.strip())

    def test_the_steps_are_the_documented_sequence(self):
        self.assertEqual(hd.STEPS, ('preflight', 'trust-base', 'proposal', 'propose', 'install', 'advance', 'lockproof', 'verify'))
        self.assertEqual(hd.WINDOW_STEPS, {'trust-base', 'proposal', 'propose'})


class FakeAuthority:
    """One entity's signing authority as the drive sees it through `docker compose exec`: status, advance-epoch (refused when repeated, as
    signingauthority/advance.go refuses it), replace-session; a failure can be injected once per command."""

    def __init__(self, auth):
        self.auth, self.root_epoch, self.shard_epoch, self.generation = auth, 2, 1, 1
        self.fail_once, self.calls = set(), []

    def exec_in(self, service, *command, binary=False):
        verb = command[2]
        self.calls.append((service, verb))
        if verb in self.fail_once:
            self.fail_once.discard(verb)
            raise hd.rehearse.Failure(f'{service}: {verb}: exit 1: injected')
        if verb == 'status':
            return json.dumps({'rootEpoch': self.root_epoch, 'shardEpoch': self.shard_epoch, 'generation': self.generation, 'enrollmentComplete': True,
                               'faulted': False, 'keyLost': False})
        if verb == 'advance-epoch':
            if self.root_epoch == 3:
                raise hd.rehearse.Failure(f'{service}: advance-epoch: exit 1: context mismatch (a repeated advance)')
            self.root_epoch, self.shard_epoch, self.generation = 3, 2, self.generation + 1
            return ''
        if verb == 'replace-session':
            self.generation += 1
            (self.auth / 'client.cred').write_text(f'session {self.generation}')
            return ''
        raise AssertionError(command)


class AdvanceResume(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.gen = Path(self.dir.name)
        self.auth = self.gen / 'validator1' / 'auth'
        self.auth.mkdir(parents=True)
        (self.auth / 'client.cred').write_text('session 1')
        self.fake = FakeAuthority(self.auth)
        d = object.__new__(hd.Drive)
        d.gen, d.target, d.joiners = self.gen, 3, set()
        d.exec_in = self.fake.exec_in
        self.shard = []
        d.compose = lambda *args, check=True: self.shard.append(args[0]) or ''
        d.say = lambda text: None
        self.drive = d
        self.journal = hd.Journal(self.gen / 'handoff' / 'log.jsonl', '0xr', 3, echo=lambda line: None)
        patcher = unittest.mock.patch('os.chown')
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.dir.cleanup()

    def run_entity(self):
        return self.journal.run('advance', lambda: self.drive.advance_entity(1, 2, self.journal), sub='entity1')

    def test_a_rerun_after_the_advance_does_not_advance_again(self):
        self.fake.fail_once.add('replace-session')
        with self.assertRaises(hd.rehearse.Failure):
            self.run_entity()
        self.assertEqual(self.shard, [], 'phase 2: the shard keeps running through the authority sub-steps, and after the failure')
        self.assertTrue(self.journal.done('advance', 'entity1/advance-epoch'))
        self.run_entity()
        self.assertEqual([v for _, v in self.fake.calls].count('advance-epoch'), 1, 'the advance is sent once')
        self.assertEqual(self.shard, ['start'], 'never stopped for the new session (it reloads its credential in-process); the last step starts it if needed')
        self.assertEqual((self.auth / 'client.cred').read_text(), 'session 3')
        self.assertEqual((self.auth / 'client.cred.pre-epoch-3').read_text(), 'session 1', 'the kept credential is the one before the switch')
        self.assertTrue(self.journal.done('advance', 'entity1'))

    def test_an_advance_the_journal_missed_is_found_in_the_status(self):
        # the drive died while advance-epoch ran: the authority holds the advance, the journal has only its start
        self.fake.root_epoch, self.fake.shard_epoch = 3, 2
        self.journal.write('advance', 'start', sub='entity1/advance-epoch')
        (self.auth / 'client.cred.pre-epoch-3').write_text('session 1')
        (self.auth / 'client.cred').write_text('session 1')
        self.run_entity()
        self.assertNotIn('advance-epoch', [v for _, v in self.fake.calls], 'a repeated advance would be refused for good')
        self.assertEqual(self.journal.value('advance', 'already', sub='entity1/advance-epoch'), True)
        self.assertEqual((self.auth / 'client.cred.pre-epoch-3').read_text(), 'session 1')
        self.assertEqual(self.shard[-1], 'start')

    def test_a_rerun_after_the_new_session_never_overwrites_the_kept_credential(self):
        self.run_entity()
        self.assertEqual((self.auth / 'client.cred').read_text(), 'session 3')
        self.drive.keep_credential(1)   # what a rerun of the advance sub-step would do before sending the advance
        self.assertEqual((self.auth / 'client.cred.pre-epoch-3').read_text(), 'session 1', 'kept once, never replaced by the new session')
        self.run_entity()
        self.assertEqual([v for _, v in self.fake.calls].count('advance-epoch'), 1)
        self.assertEqual(self.shard.count('start'), 1, 'a rerun of a finished entity does not stop its shard')

    def test_a_faulted_authority_stops_the_drive(self):
        real = self.fake.exec_in
        self.drive.exec_in = lambda service, *c, binary=False: json.dumps({'faulted': True, 'keyLost': False}) if c[2] == 'status' else real(service, *c)
        with self.assertRaises(hd.Refused):
            self.run_entity()
        self.assertNotIn('advance-epoch', [v for _, v in self.fake.calls])


class ProofAuthority(FakeAuthority):
    """An authority with a lineage pin (bft-core#1085): it answers lineagePinned, and advance-with-proof verifies (here: accepts) the bundles and
    issues the next session in one order."""

    def __init__(self, auth, retire=False):
        super().__init__(auth)
        self.retire, self.lineage = retire, 1

    def exec_in(self, service, *command, binary=False):
        verb = command[2]
        if verb == 'status':
            self.calls.append((service, verb))
            return json.dumps({'rootEpoch': self.root_epoch, 'shardEpoch': self.shard_epoch, 'generation': self.generation, 'enrollmentComplete': True,
                               'faulted': False, 'keyLost': False, 'lineagePinned': True, 'lineageEpoch': self.lineage})
        if verb == 'advance-with-proof':
            proofs = tuple(a for a in command if a.startswith('/network/handoff/q3-bundle-'))
            self.calls.append((service, verb, proofs))
            for flag in ('--proof', '--out', '--client-socket'):   # the real command's required flags (TestTheAdvanceWithProofCommandRequires...)
                if flag not in command:
                    raise hd.rehearse.Failure(f'{service}: advance-with-proof: exit 1: required flag(s) "{flag[2:]}" not set')
            if self.retire:
                return json.dumps({'steps': [{}], 'retired': True})
            if self.root_epoch != 3:
                self.root_epoch, self.shard_epoch, self.generation, self.lineage = 3, 2, self.generation + 2, 3
                (self.auth / 'client.cred').write_text(f'session {self.generation}')
            return json.dumps({'steps': [{}], 'advanced': True, 'sessionIssued': True})
        return super().exec_in(service, *command, binary=binary)


class AdvanceWithProof(unittest.TestCase):
    run_entity, tearDown = AdvanceResume.run_entity, AdvanceResume.tearDown

    def setUp(self):
        AdvanceResume.setUp(self)
        self.fake = ProofAuthority(self.auth)
        self.drive.exec_in = self.fake.exec_in
        self.drive.activation_bundles = lambda after: [Path(f'/x/q3-bundle-{e}.cbor') for e in range(after + 1, 4)]
        self.drive.expect = lambda condition, what, detail='': (_ for _ in ()).throw(hd.rehearse.Failure(what)) if not condition else None

    def test_a_pinned_authority_is_advanced_by_proof_in_one_order(self):
        self.run_entity()
        proofs = [c for c in self.fake.calls if c[1] == 'advance-with-proof']
        self.assertEqual(proofs, [('authority1', 'advance-with-proof', ('/network/handoff/q3-bundle-2.cbor', '/network/handoff/q3-bundle-3.cbor'))],
                         'every bundle after its lineage tip, in epoch order')
        verbs = [c[1] for c in self.fake.calls]
        self.assertNotIn('advance-epoch', verbs, 'the operator-trusted advance is not used')
        self.assertNotIn('replace-session', verbs, 'the session comes with the proof advance')
        self.assertEqual(self.shard, ['start'])
        self.assertEqual((self.auth / 'client.cred.pre-epoch-3').read_text(), 'session 1')
        self.run_entity()
        self.assertEqual(len([c for c in self.fake.calls if c[1] == 'advance-with-proof']), 1, 'a finished entity is not advanced again')

    def test_a_resume_after_the_authority_accepted_the_target_replays_it(self):
        # the drive died after the authority published the advance (and maybe the session and credential), before the journal row: the
        # authority's lineage tip is already the target, and the rerun still passes the target's bundle (an empty --proof list is refused)
        self.fake.root_epoch, self.fake.shard_epoch, self.fake.lineage = 3, 2, 3
        self.journal.write('advance', 'start', sub='entity1/advance-with-proof')
        self.run_entity()
        proofs = [c for c in self.fake.calls if c[1] == 'advance-with-proof']
        self.assertEqual(proofs, [('authority1', 'advance-with-proof', ('/network/handoff/q3-bundle-3.cbor',))])
        self.assertTrue(self.journal.done('advance', 'entity1/advance-with-proof'))

    def test_an_elected_entity_that_the_authority_retires_stops_the_drive(self):
        self.fake.retire = True
        with self.assertRaises(hd.rehearse.Failure):
            self.run_entity()
        self.assertEqual(self.shard, [])


class Parallel(unittest.TestCase):
    def test_every_job_runs_at_once_and_a_failure_is_raised_after_all_finished(self):
        barrier, finished = threading.Barrier(3, timeout=5), []
        def job(name, fail=False):
            barrier.wait()   # a sequential run would break the barrier
            time.sleep(0.05 if fail else 0.2)
            finished.append(name)
            if fail:
                raise hd.rehearse.Failure(f'{name} failed')
        with self.assertRaisesRegex(hd.rehearse.Failure, 'b failed'):
            hd.parallel({'a': lambda: job('a'), 'b': lambda: job('b', True), 'c': lambda: job('c')})
        self.assertEqual(sorted(finished), ['a', 'b', 'c'], 'no job is left running behind the failure')
        self.assertEqual(hd.parallel({1: lambda: 'x', 2: lambda: 'y'}), {1: 'x', 2: 'y'})
        self.assertEqual(hd.parallel({}), {})


class FakeRemote:
    def __init__(self, install):
        self.install = install

    def install_root(self, target):
        return self.install(5)


class InstallAtOnce(unittest.TestCase):
    """step_install (bft-core#1080; astra on #1084): a root is stopped only with verified evidence to install from (its own commit, or a root that has
    already installed the epoch), the roots are installed at once, and without evidence nothing is stopped."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        gen = Path(self.dir.name)
        (gen / 'work').mkdir()
        (gen / 'work' / 'v3-body-id.txt').write_text('ab' * 32)
        self.events, self.lock = [], threading.Lock()
        self.commits_at = {1: 1, 2: 3, 3: 1, 4: 1}   # the probe at which each old root first serves its own commit (root 2: its third; 0: never)
        self.probes = {i: 0 for i in (1, 2, 3, 4, 5)}
        self.installed, self.running, self.overlap, self.completed = set(), 0, 0, []
        d = object.__new__(hd.Drive)
        d.gen, d.target, d.work, d.root_rpc = gen, 3, gen / 'work', 'http://root'
        d.old, d.new, d.joiners = [1, 2, 3, 4], [1, 2, 3, 4, 5], {5}
        d.remote = {5: FakeRemote(self.install)}
        d.say = lambda text: None
        d.evh = lambda: gen
        d.install_root = lambda i, files, base: self.install(i)
        d.serves_own_activation = self.serves
        record = {'epoch': 3, 'signingScheme': 2, 'v3BodyId': 'ab' * 32, 'activationRound': 99}
        d.exec_in = lambda service, *command, binary=False: json.dumps(record) if command[0] == 'cat' else ''
        self.drive = d
        self.journal = hd.Journal(gen / 'handoff' / 'log.jsonl', '0xr', 3, echo=lambda line: None)
        for target, value in (('handoff_ops.load_compose', {}), ('handoff_ops.compose_files', []), ('handoff.install_override', {})):
            patcher = unittest.mock.patch(f'handoff_drive.{target}', return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = unittest.mock.patch.object(hd, 'INSTALL_GATE_SECONDS', 2)
        patcher.start()
        self.addCleanup(patcher.stop)

    def serves(self, i):
        """q3/bundle of root i: an installed root serves its staged activation; an old root serves its own commit from its commits_at-th probe."""
        with self.lock:
            self.probes[i] += 1
            self.events.append(('probe', i))
            if i in self.installed:
                return True
            return i in self.commits_at and self.probes[i] >= self.commits_at[i] > 0

    def install(self, i):
        with self.lock:
            self.events.append(('install', i))
            self.running += 1
            self.overlap = max(self.overlap, self.running)
        time.sleep(0.2)
        with self.lock:
            self.running -= 1
            self.installed.add(i)
            self.completed.append(i)
            self.events.append(('done', i))
        return {}

    def test_each_root_is_stopped_only_with_evidence_and_they_install_at_once(self):
        self.assertEqual(self.drive.step_install(self.journal), {'activationRound': 99, 'v3BodyId': 'ab' * 32})
        self.assertEqual(sorted(i for kind, i in self.events if kind == 'install'), [1, 2, 3, 4, 5])
        for i in (1, 3, 4):
            self.assertEqual(self.journal.value('install', 'evidence', sub=f'root{i}'), 'own', f'root {i} installs from its own commit')
        two = self.events.index(('install', 2))
        self.assertGreaterEqual(self.events[:two].count(('probe', 2)), 2, 'root 2 was not stopped while it lacked the commit and no root had installed')
        self.assertIn(self.journal.value('install', 'evidence', sub='root2'), {'own', 'root1', 'root3', 'root4', 'root5'})
        self.assertGreaterEqual(self.overlap, 3, 'the roots with the commit are installed at the same time, not one by one')
        joiner = self.events.index(('install', 5))
        self.assertFalse(any(kind == 'install' and i != 5 for kind, i in self.events[:joiner]),
                         'bft-core#1082: the joiner installs before any incumbent is stopped')
        self.assertIn(self.journal.value('install', 'evidence', sub='root5'), {f'root{i} (running)' for i in (1, 2, 3, 4)},
                      'from an old root that holds the commit and keeps running until the joiner is done')
        first_old = min(self.events.index(('install', i)) for i in (1, 2, 3, 4))
        self.assertIn(5, self.installed_at(first_old), 'the incumbents restart only once the joiner has installed')

    def installed_at(self, index):
        """The roots whose install completed before event `index` (install() records the start, installed is the completion)."""
        return set(self.completed[:len([e for e in self.events[:index] if e[0] == 'done'])])

    def test_no_commit_anywhere_stops_no_root(self):
        self.commits_at = {1: 0, 2: 0, 3: 0, 4: 0}   # no old root ever serves the target: the handoff is not committed
        with self.assertRaisesRegex(hd.rehearse.Failure, 'left running'):
            self.drive.step_install(self.journal)
        self.assertEqual([e for e in self.events if e[0] == 'install'], [], 'the old committee is not dismantled')
        for i in (1, 2, 3, 4, 5):
            self.assertFalse(self.journal.done('install', f'root{i}'))

    def test_a_root_without_the_commit_waits_for_an_installed_source(self):
        self.commits_at[3] = 0   # root 3 never commits it itself
        self.drive.step_install(self.journal)
        three = self.events.index(('install', 3))
        self.assertTrue(any(kind == 'install' and i in (1, 2, 4) for kind, i in self.events[:three]), 'after another root has installed')
        self.assertIn(self.journal.value('install', 'evidence', sub='root3'), {'root1', 'root2', 'root4', 'root5'})

    def test_a_failed_joiner_install_leaves_every_incumbent_running(self):
        real = self.drive.remote[5].install
        def failing(i):
            if i == 5:
                raise hd.rehearse.Failure('the joiner root did not come up')
            return real(i)
        self.drive.remote[5].install = failing
        self.drive.install_root = lambda i, files, base: failing(i)
        with self.assertRaisesRegex(hd.rehearse.Failure, 'did not come up|left running'):
            self.drive.step_install(self.journal)
        self.assertEqual([e for e in self.events if e[0] == 'install'], [], 'astra on #1088: no incumbent restarts after a failed joiner install')

    def test_a_slow_joiner_install_leaves_every_incumbent_running(self):
        def slow(i):
            if i == 5:
                time.sleep(1.0)
                return {}
            return self.install(i)
        self.drive.remote[5].install = slow
        self.drive.install_root = lambda i, files, base: slow(i)
        with unittest.mock.patch.object(hd, 'JOINER_FIRST_SECONDS', 0.3):
            with self.assertRaisesRegex(hd.rehearse.Failure, 'left running'):
                self.drive.step_install(self.journal)
        self.assertEqual([e for e in self.events if e[0] == 'install'], [], 'no incumbent restarts while the joiner is still installing')
        self.assertTrue(self.journal.done('install', 'root5'), 'the joiner itself completed')

    def test_a_resumed_install_skips_the_installed_roots(self):
        for i in (1, 2, 3, 4, 5):
            self.journal.write('install', 'done', sub=f'root{i}')
        self.drive.step_install(self.journal)
        self.assertEqual(self.events, [], 'nothing is probed or installed again')


class CommitteeReadiness(unittest.TestCase):
    """bft-core#1082: a member is ready when it reports the target epoch, membership and no member missing (POST /api/v1/committee)."""

    def drive(self, answer, status=200):
        d = object.__new__(hd.Drive)
        d.target = 9
        d.transport = unittest.mock.Mock(post=lambda i, path, body: (status, json.dumps(answer).encode()))
        return d

    def test_only_a_member_of_the_target_with_nothing_missing_is_ready(self):
        ready = {'epoch': 9, 'member': True, 'connected': ['a', 'b'], 'missing': []}
        self.assertEqual(self.drive(ready).committee_connected(5), ready)
        self.assertIsNone(self.drive({**ready, 'missing': ['b']}).committee_connected(5), 'a member it cannot reach')
        self.assertIsNone(self.drive({**ready, 'epoch': 8}).committee_connected(5), 'the old epoch')
        self.assertIsNone(self.drive({**ready, 'member': False}).committee_connected(5), 'not a member')
        self.assertIsNone(self.drive(ready, status=404).committee_connected(5), 'a root without the endpoint')


class AdvanceAtOnce(unittest.TestCase):
    def test_every_entity_advances_at_once_without_waiting_for_the_new_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = Path(tmp)
            (gen / 'work').mkdir()
            d = object.__new__(hd.Drive)
            d.gen, d.target, d.work, d.new, d.root_rpc = gen, 3, gen / 'work', [1, 2, 3, 4], 'http://root'
            d.say = lambda text: None
            d.root_epoch = lambda i, transport=None: self.fail('the advance does not wait for the new epoch\'s certificate')
            d.transport = None
            conf = {'epoch': 2, 'partitionId': 8}
            d.exec_in = lambda service, *command, binary=False: json.dumps(conf) if command[0] == 'cat' else ''
            journal = hd.Journal(gen / 'handoff' / 'log.jsonl', '0xr', 3, echo=lambda line: None)
            journal.write('install', 'done')
            journal.write('advance', 'done', sub='shard-conf', shardEpoch=2)
            barrier, advanced = threading.Barrier(4, timeout=5), []
            d.advance_entity = lambda i, shard_epoch, journal: barrier.wait() is not None and advanced.append((i, shard_epoch)) or {}
            self.assertEqual(d.step_advance(journal), {'shardEpoch': 2})
            self.assertEqual(sorted(advanced), [(1, 2), (2, 2), (3, 2), (4, 2)])
            self.assertTrue(all(journal.done('advance', f'entity{i}') for i in (1, 2, 3, 4)))


class BackupAndAckBlock(unittest.TestCase):
    def test_a_partial_root_backup_is_not_the_rollback_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = Path(tmp)
            state = gen / 'validator1' / 'root'
            state.mkdir(parents=True)
            (state / 'rootchain.db').write_text('db')
            partial = gen / 'validator1' / 'root.pre-epoch-3.partial'
            partial.mkdir()
            (partial / 'half').write_text('x')
            d = object.__new__(hd.Drive)
            d.gen, d.target = gen, 3
            d.root_epoch = lambda i, transport=None: 2
            d.transport = None
            d.expect = lambda *a, **k: None
            d.wait = lambda *a, **k: True
            d.root_listens = lambda *a: True
            d.old, d.new = [1], [1]
            d.q3_status = lambda i: {'activeEpoch': 2}   # an image that does not switch in process (bft-core#1086): restarted
            with unittest.mock.patch('subprocess.run', side_effect=lambda cmd, **k: (__import__('shutil').copytree(cmd[2], cmd[3], symlinks=True) if cmd[0] == 'cp' else None)
                                     or unittest.mock.Mock(returncode=0, stderr='')):
                d.install_root(1, [], [])
            backup = gen / 'validator1' / 'root.pre-epoch-3'
            self.assertEqual(sorted(p.name for p in backup.iterdir()), ['rootchain.db'], 'the leftover partial copy was discarded, the backup is complete')
            self.assertFalse(partial.exists())

    def test_the_ack_block_lookup_reports_why_it_is_unknown(self):
        d = object.__new__(hd.Drive)
        d.election = '0xe'
        d.cast_run = lambda *a: '0xdata'
        def broken(i, method, params):
            raise ConnectionError('ureth1 refused')
        d.ureth = broken
        block, why = d.ack_block('0xr', 100)
        self.assertIsNone(block)
        self.assertIn('ureth1 refused', why)
        acked_from = 60
        d.ureth = lambda i, m, p: '0x' + format(3 if int(p[1], 16) >= acked_from else 1, '064x')
        self.assertEqual(d.ack_block('0xr', 100), (60, None))



class Unattended(unittest.TestCase):
    """--only-if-members, the drive lock and --funder (Q35: a timer drives only the host committee's results, one drive at a time, never from the faucet
    account), and handoff_auto.py's pass."""
    def test_members_are_parsed(self):
        self.assertEqual(hd.parse_members('4,1,3,2'), [1, 2, 3, 4])
        for bad in ('', '1,,2', 'a', '0,1', '1,1', '-1'):
            with self.assertRaises(Exception, msg=bad):
                hd.parse_members(bad)

    def test_one_drive_holds_the_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = hd.hold_lock(tmp)
            self.assertIsNotNone(first)
            self.assertIsNone(hd.hold_lock(tmp), 'a second drive is refused while the first runs')
            first.close()
            again = hd.hold_lock(tmp)
            self.assertIsNotNone(again, 'free again after the first ends')
            again.close()

    def test_the_funder_is_a_keystore_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'keystore.json').write_text(json.dumps({'address': 'ab' * 20}))
            with self.assertRaises(hd.Refused):
                hd.funder_address(d)   # no password file
            (d / 'password').write_text('x')
            self.assertEqual(hd.funder_address(d), '0x' + 'ab' * 20)
            (d / 'keystore.json').write_text(json.dumps({'address': 'nope'}))
            with self.assertRaises(hd.Refused):
                hd.funder_address(d)

    def run_main(self, tmp, new, *extra):
        gen = Path(tmp) / 'tn-x'
        (gen / 'handoff').mkdir(parents=True)
        drive = unittest.mock.MagicMock()
        drive.gen = gen
        drive.funder = None
        drive.plan.return_value = {'result': '0x' + '11' * 32, 'target': 3, 'epochs': {1: 2}, 'old': [1, 2, 3, 4], 'new': new, 'kind': 'x', 'electedIds': new}
        with unittest.mock.patch.object(hd.os, 'geteuid', return_value=0), unittest.mock.patch.object(hd, 'Drive', return_value=drive), \
                unittest.mock.patch('builtins.print'):
            code = hd.main([str(gen), '--ubft', '/x', *extra])
        return code, drive

    def test_another_committee_is_skipped_before_any_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, drive = self.run_main(tmp, [1, 2, 3, 4, 5], '--only-if-members', '1,2,3,4')
        self.assertEqual(code, 4)
        for step in ('step_preflight', 'step_trust_base', 'step_proposal', 'step_propose', 'step_install', 'step_advance'):
            getattr(drive, step).assert_not_called()
        self.assertIn('SKIPPED', ' '.join(str(c) for c in drive.say.call_args_list))

    def test_the_expected_committee_is_driven(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, drive = self.run_main(tmp, [1, 2, 3, 4], '--only-if-members', '1,2,3,4', '--plan')
        self.assertEqual(code, 0)
        drive.check_window.assert_called()

    def test_a_busy_lock_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'tn-x' / 'handoff').mkdir(parents=True)
            held = hd.hold_lock(Path(tmp) / 'tn-x')
            try:
                with unittest.mock.patch.object(hd.os, 'geteuid', return_value=0), unittest.mock.patch.object(hd, 'Drive') as drive, \
                        unittest.mock.patch('builtins.print'):
                    code = hd.main([str(Path(tmp) / 'tn-x'), '--ubft', '/x'])
            finally:
                held.close()
        self.assertEqual(code, 5)
        drive.assert_not_called()

    def test_the_auto_pass_logs_and_maps_exit_codes(self):
        import handoff_auto as ha
        self.assertEqual(ha.outcome(3, 'x\nREFUSED: the election has no open result, and handoff/log.jsonl has no unfinished drive\n'), ('idle: no open result', True))
        self.assertTrue(ha.outcome(5, 'BUSY')[1])
        self.assertTrue(ha.outcome(4, 'SKIPPED: x')[1])
        self.assertFalse(ha.outcome(3, 'REFUSED: the reservation window is about to lapse')[1])
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'log'
            for code, out in ((3, 'REFUSED: the election has no open result, and'), (0, '== handoff-drive DONE: root epoch 3 active'), (4, 'SKIPPED: the elected committee')):
                done = unittest.mock.Mock(returncode=code, stdout=out)
                with unittest.mock.patch.object(ha.subprocess, 'run', return_value=done) as run:
                    self.assertEqual(ha.main([str(Path(tmp) / 'tn-x'), '--members', '1,2,3,4', '--log', str(log), '--', '--ubft', '/u']), 0 if code in (3, 4) else code)
                cmd = run.call_args.args[0]
                self.assertEqual(cmd[cmd.index('--only-if-members') + 1], '1,2,3,4')
                self.assertIn('--ubft', cmd)
            lines = (log / 'auto.log').read_text().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertIn('idle', lines[0]); self.assertIn('driven', lines[1]); self.assertIn('skipped', lines[2])
            self.assertEqual(len(list(log.glob('drive-*.log'))) >= 1, True, 'a pass that did something keeps its output')
            with self.assertRaises(SystemExit), unittest.mock.patch('sys.stderr'):
                ha.main([str(Path(tmp) / 'tn-x'), '--members', '1,2,3,4', '--log', str(log), '--', '--ubft', '/u', '--joiner', '5=5'])


    def test_the_auto_pass_stands_down_for_a_remote_joiner(self):
        import handoff_auto as ha
        with tempfile.TemporaryDirectory() as tmp:
            gen, log = Path(tmp) / 'tn-x', Path(tmp) / 'log'
            joiners = gen / 'handoff' / 'remote-joiners'
            joiners.mkdir(parents=True)
            (joiners / '5.json').write_text(json.dumps({'state': 'member'}))
            (joiners / 'notes.json').write_text('{}')   # not an entity file
            self.assertEqual(ha.joining(gen), [])
            for state in ('registered', 'bonded', 'prepared', 'retiring'):
                (joiners / '5.json').write_text(json.dumps({'state': state}))
                self.assertEqual(ha.joining(gen), [(5, state)])
            (joiners / '6.json').write_text('not json')
            self.assertEqual(ha.joining(gen), [(5, 'retiring'), (6, 'unreadable')])
            (joiners / '6.json').unlink()
            (joiners / '5.json').write_text(json.dumps({'state': 'prepared'}))
            with unittest.mock.patch.object(ha.subprocess, 'run') as run:
                for _ in range(3):
                    self.assertEqual(ha.main([str(gen), '--members', '1,2,3,4', '--log', str(log), '--', '--ubft', '/u']), 0)
            run.assert_not_called()   # no drive while the joiner is prepared
            lines = (log / 'auto.log').read_text().splitlines()
            self.assertEqual(len(lines), 1, 'a repeated stand-down is logged once an hour')
            self.assertIn('stand down: remote joiner(s) 5 prepared', lines[0])

    def test_a_skipped_pass_is_idle_and_logged_hourly(self):
        import handoff_auto as ha
        result = '0x' + 'ab' * 32
        out = f'== handoff-drive {result} -> root epoch 6\nSKIPPED: the elected committee [1, 2, 3, 4, 5] is not [1, 2, 3, 4] (--only-if-members); drive {result} by hand\n'
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'log'
            done = unittest.mock.Mock(returncode=4, stdout=out)
            with unittest.mock.patch.object(ha.subprocess, 'run', return_value=done):
                codes = [ha.main([str(Path(tmp) / 'tn-x'), '--members', '1,2,3,4', '--log', str(log), '--', '--ubft', '/u']) for _ in range(5)]
            self.assertEqual(codes, [0] * 5, 'a skip never fails the unit')
            lines = (log / 'auto.log').read_text().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn('skipped', lines[0]); self.assertIn('hourly', lines[0])
            self.assertEqual(list(log.glob('drive-*.log')), [], 'no full log for a skip')
            other = unittest.mock.Mock(returncode=4, stdout=out.replace('ab', 'cd'))
            with unittest.mock.patch.object(ha.subprocess, 'run', return_value=other):
                ha.main([str(Path(tmp) / 'tn-x'), '--members', '1,2,3,4', '--log', str(log), '--', '--ubft', '/u'])
            self.assertEqual(len((log / 'auto.log').read_text().splitlines()), 2, 'another result gets its own line')


if __name__ == '__main__':
    unittest.main()
