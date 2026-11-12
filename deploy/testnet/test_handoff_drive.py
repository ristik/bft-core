"""Unit tests of handoff_drive.py: the pure rules (window, epoch start, membership) and the journal that makes a drive resumable. No Docker, no network."""
import json
from pathlib import Path
import tempfile
import unittest
import unittest.mock

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
        self.assertEqual(self.shard, ['stop', 'stop'], 'the shard is stopped (by each authority sub-step) and stays stopped after the failure')
        self.assertTrue(self.journal.done('advance', 'entity1/advance-epoch'))
        self.run_entity()
        self.assertEqual([v for _, v in self.fake.calls].count('advance-epoch'), 1, 'the advance is sent once')
        self.assertEqual(self.shard, ['stop', 'stop', 'stop', 'start'], 'stopped again for the new session, started last')
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


if __name__ == '__main__':
    unittest.main()
