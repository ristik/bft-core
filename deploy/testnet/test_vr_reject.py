#!/usr/bin/env python3
"""Unit tests of vr_reject.py's pure parts (bft-core#1311, #1303)."""
import unittest

import rehearse
import vr_reject


def word(v):
    return '%064x' % v


class DecodeOutput(unittest.TestCase):
    def test_reads_the_state_the_clock_and_the_member_ids(self):
        # the ABI encoding of one dynamic tuple: its offset, 16 static head words, the members and changes offsets, then the arrays
        head = [2, 9, 100, 100 + vr_reject.LIFETIME] + [0] * 12
        members_at = 18 * 32
        changes_at = members_at + 32 + 2 * 10 * 32
        tail = [2] + [5] + [0] * 9 + [7] + [0] * 9 + [0]
        raw = '0x' + ''.join(word(v) for v in [32, *head, members_at, changes_at, *tail])
        o = vr_reject.decode_output(raw)
        self.assertEqual((o['state'], o['attempt'], o['reserved'], o['expires']), (2, 9, 100, 100 + vr_reject.LIFETIME))
        self.assertEqual(o['members'], [5, 7])


def record_raw(index, kind, progress, data):
    """The ABI encoding of SealRegistry.recordAt's one dynamic tuple: its offset, six static words, the data offset, then the bytes."""
    head = [index, 0xaa, 0xbb, kind, progress, 1234, 7 * 32]
    return '0x' + ''.join(word(v) for v in [32, *head, 32 * len(data), *data])


class Records(unittest.TestCase):
    RID = '0x' + '11' * 32

    def test_decodes_the_kind_progress_and_data_words(self):
        rec = vr_reject.decode_record(record_raw(9, 7, 5000, [int(self.RID, 16), 1, 0, 0x0f]))
        self.assertEqual((rec['index'], rec['kind'], rec['progress']), (9, 7, 5000))
        self.assertEqual(rec['data'], [int(self.RID, 16), 1, 0, 0x0f])

    def test_finds_the_newest_rejection_of_the_result(self):
        other = int('22' * 32, 16)
        recs = {0: (7, 100, [other, 1, 0, 0]), 1: (7, 200, [int(self.RID, 16), 1, 0, 0x0f]), 2: (1, 210, [int(self.RID, 16)]),
                3: (6, 220, [other] + [0] * 6)}
        at = lambda i: vr_reject.decode_record(record_raw(i, recs[i][0], recs[i][1], recs[i][2]))
        self.assertEqual(vr_reject.find_rejection(at, 4, self.RID), {'index': 1, 'reason': 1, 'bitmap': 0x0f, 'progress': 200})
        self.assertIsNone(vr_reject.find_rejection(at, 4, '0x' + '33' * 32))
        self.assertIsNone(vr_reject.find_rejection(at, 4, self.RID, back=2), 'outside the window')

    def test_frozen_ids_reads_cast_output(self):
        text = '[(1, 1, 250 [2.5e2], 1000000000000 [1e12], 0xab), (5, 1, 2, 1000 [1e3], 0xcd)]'
        self.assertEqual(vr_reject.frozen_ids(text), [1, 5])

    def test_the_park_period_is_two_lifetimes(self):
        self.assertEqual(vr_reject.PARK_PERIOD, 2 * vr_reject.LIFETIME)


class StageOrder(unittest.TestCase):
    def test_vr_reject_is_a_vr_stage(self):
        self.assertIn(('vr-reject', 'vr_reject'), rehearse.VR_STAGES)
        self.assertTrue(callable(rehearse.Rehearsal.vr_reject))


if __name__ == '__main__':
    unittest.main()
