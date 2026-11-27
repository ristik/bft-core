#!/usr/bin/env python3
"""Unit tests of vr_pop_miss.py's pure parts (bft-core#1319)."""
import unittest

import vr_pop_miss
import vr_reject


def record_raw(index, kind, progress, data):
    head = [32, index, 0xaa, 0xbb, kind, progress, 1000, 7 * 32]
    body = [len(data) * 32] + data
    return '0x' + ''.join(f'{w:064x}' for w in head + body)


class PopMiss(unittest.TestCase):
    RID = '0x' + '11' * 32

    def test_find_miss_follows_the_rejection(self):
        recs = {3: (7, 200, [int(self.RID, 16), 1, 0, 0x0f]), 4: (9, 200, [int(self.RID, 16), 4106, 0x10]), 5: (1, 200, [int(self.RID, 16)])}
        at = lambda i: vr_reject.decode_record(record_raw(i, *recs[i]))
        self.assertEqual(vr_pop_miss.find_miss(at, 3, self.RID), {'index': 4, 'deadline': 4106, 'bitmap': 0x10, 'progress': 200})
        self.assertIsNone(vr_pop_miss.find_miss(at, 4, self.RID), 'a SessionClosed is no miss')
        self.assertIsNone(vr_pop_miss.find_miss(at, 3, '0x' + '22' * 32), 'another result')

    def test_stated_reads_text_and_json_logs(self):
        text = ('2026-11-27T10:00:00Z time=x level=INFO msg="VR handoff: PoP misses stated at the request\'s cutoff" request=ab result=cd '
                'deadline=4106 progress=4107 missing="[5]"')
        js = '2026-11-27T10:00:00Z {"msg":"VR handoff: PoP misses stated at the request\'s cutoff","deadline":4106,"missing":"[3 5]"}'
        self.assertEqual(vr_pop_miss.stated(text + '\nother line'), [(4106, [5])])
        self.assertEqual(vr_pop_miss.stated(js), [(4106, [3, 5])])
        self.assertEqual(vr_pop_miss.stated('nothing'), [])

    def test_window(self):
        self.assertEqual(vr_pop_miss.POP_WINDOW, 4096)


if __name__ == '__main__':
    unittest.main()
