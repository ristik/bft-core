#!/usr/bin/env python3
"""The recomputation of rewards_check.py against the numbers the contracts' own tests (test/p85/Rewards.t.sol) pin."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rewards_check as rc  # noqa: E402

UCT = 10**18
G = ["0xg%d" % i for i in range(4)]  # four genesis payees, weight 10 each
MEMBERS = {"G": [(10, p) for p in G], "J": [(10, p) for p in G[:3]], "K": [(10, p) for p in G]}


class Model(unittest.TestCase):
    def run_model(self, segments, progress, tail_open=False, rate=UCT, available=10_000 * UCT):
        return rc.model(segments, progress, tail_open, 0, rate, available, lambda a: MEMBERS[a])

    def test_a_single_owner_closes_whole_grid_intervals_only(self):
        credits, nxt, avail, n = self.run_model([("G", 0, None)], 4_321)
        self.assertEqual((nxt, n), (4_000, 4))
        self.assertEqual(credits[G[0]], UCT // 4 * 4)
        self.assertEqual(avail, 10_000 * UCT - 4 * UCT)

    def test_j_owns_the_interval_between_the_two_offsets(self):
        credits, nxt, _, n = self.run_model([("G", 0, 300), ("J", 300, 700), ("K", 700, None)], 2_000)
        self.assertEqual((nxt, n), (2_000, 4))
        j = (4 * UCT // 10) // 3
        self.assertEqual(credits[G[0]], 3 * UCT // 10 // 4 + j + 13 * UCT // 10 // 4)
        self.assertEqual(credits[G[3]], 3 * UCT // 10 // 4 + 13 * UCT // 10 // 4)

    def test_a_zero_length_j_earns_nothing(self):
        credits, nxt, _, n = self.run_model([("G", 0, 500), ("J", 500, 500), ("K", 500, None)], 1_000)
        self.assertEqual((nxt, n), (1_000, 2))
        self.assertTrue(all(v == UCT // 2 // 4 * 2 for v in credits.values()))

    def test_j_straddles_a_grid_point(self):
        credits, nxt, _, n = self.run_model([("G", 0, 300), ("J", 300, 1_700), ("K", 1_700, None)], 3_000)
        self.assertEqual((nxt, n), (3_000, 5))
        self.assertEqual(credits[G[1]], 3 * UCT // 10 // 4 + (7 * UCT // 10 // 3) * 2 + 13 * UCT // 10 // 4)

    def test_an_open_election_result_keeps_the_tail_open(self):
        _, nxt, _, n = self.run_model([("G", 0, 300), ("K", 300, None)], 5_000, tail_open=True)
        self.assertEqual((nxt, n), (300, 1), "only the finished owner's interval closes")

    def test_dust_and_exhaustion_with_a_tiny_pool(self):
        credits, _, avail, _ = self.run_model([("G", 0, None)], 3_000, rate=7, available=20)
        self.assertEqual(sum(credits.values()), 4 + 4 + 4)
        self.assertEqual(avail, 20 - 12)
        credits, _, avail, _ = self.run_model([("G", 0, None)], 5_000, rate=7, available=10)
        self.assertEqual(avail, 10 - sum(credits.values()))

    def test_a_gap_is_refused(self):
        with self.assertRaises(AssertionError):
            self.run_model([("G", 100, None)], 1_000)


if __name__ == "__main__":
    unittest.main()
