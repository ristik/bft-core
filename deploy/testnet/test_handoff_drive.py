"""Unit tests of handoff_drive.py: the pure rules (window, epoch start, membership) and the journal that makes a drive resumable. No Docker, no network."""
import json
from pathlib import Path
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
