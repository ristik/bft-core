#!/usr/bin/env python3
"""Unit tests of vr_reject.py's pure parts (bft-core#1311)."""
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


class StageOrder(unittest.TestCase):
    def test_vr_reject_is_a_vr_stage(self):
        self.assertIn(('vr-reject', 'vr_reject'), rehearse.VR_STAGES)
        self.assertTrue(callable(rehearse.Rehearsal.vr_reject))


if __name__ == '__main__':
    unittest.main()
