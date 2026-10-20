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


class Replay(unittest.TestCase):
    """X4 B3: the pool's life replayed event by event: exhaustion, zero-budget intervals, refill, no backfill, dust, claims."""
    SNAPS = [(0, UCT), (0, UCT)]   # policy 1 in force from progress 0 at 1 UCT per 1,000 progress units

    def close(self, seg, start, end, budget, distributed=None):
        return {"kind": "close", "segment": seg, "start": start, "end": end, "rate": UCT, "budget": budget, "distributed": budget if distributed is None else distributed}

    def go(self, events, funding=2 * UCT, segments=None):
        return rc.replay(events, segments or [("G", 0, None)], lambda a: MEMBERS[a], 0, self.SNAPS, funding)

    def scenario(self):
        return [self.close(0, 0, 1000, UCT), self.close(0, 1000, 2000, UCT),          # the 2 UCT allocation pays two intervals
                self.close(0, 2000, 3000, 0),                                            # dry: a zero-budget interval, closed and finished
                {"kind": "fund", "amount": 3 * UCT // 2},                                # refill (1.5 UCT)
                self.close(0, 3000, 4000, UCT), self.close(0, 4000, 5000, UCT // 2)]     # paid after the refill; the closed empty interval is not backfilled

    def test_exhaustion_a_zero_budget_interval_and_a_refill_are_replayed_exactly(self):
        s = self.go(self.scenario())
        self.assertEqual((s["stats"]["intervals"], s["stats"]["paid"], s["stats"]["zeroBudget"], s["stats"]["exhaustedAt"], s["stats"]["refilledAfterExhaustion"]),
                        (5, 4, 1, 3000, True))
        self.assertEqual((s["available"], s["totalCredits"], s["nextStart"]), (0, 7 * UCT // 2, 5000))
        self.assertEqual(sum(s["credits"].values()), s["totalCredits"])

    def test_a_backfill_of_the_empty_interval_is_refused(self):
        ev = self.scenario()
        ev[4] = self.close(0, 3000, 4000, UCT)
        ev.insert(5, self.close(0, 2000, 3000, UCT))   # paying interval 3 after the refill, out of order
        with self.assertRaises(rc.ReplayError):
            self.go(ev)

    def test_every_field_of_a_close_is_checked(self):
        for field, value in (("start", 1), ("end", 1500), ("rate", 2 * UCT), ("budget", UCT - 1), ("distributed", UCT - 1), ("segment", 1)):
            ev = self.scenario()
            ev[0] = dict(ev[0], **{field: value})
            with self.subTest(field=field), self.assertRaises(rc.ReplayError):
                self.go(ev)

    def test_a_budget_from_funds_that_were_not_there_is_refused(self):
        ev = self.scenario()
        del ev[3]   # no refill event, yet the interval after it was paid in full
        with self.assertRaises(rc.ReplayError):
            self.go(ev)

    def test_dust_returns_to_available_in_the_same_call(self):
        members = {"X": [(1, "p1"), (1, "p2"), (1, "p3")]}
        s = rc.replay([dict(self.close(0, 0, 1000, 10, 9), rate=10)], [("X", 0, None)], lambda a: members[a], 0, [(0, 10), (0, 10)], 10)
        # rate 10 per 1,000 units: nominal 10; budget min(10, 10) = 10 over three equal weights: 3 each, dust 1 back to available
        self.assertEqual((s["available"], s["totalCredits"], s["stats"]["dust"]), (1, 9, 1))

    def test_claims_cannot_exceed_credit_and_reduce_the_total(self):
        ev = self.scenario()[:2] + [{"kind": "claim", "payee": G[0], "amount": UCT // 8}]
        s = self.go(ev)
        self.assertEqual(s["totalCredits"], 2 * UCT - UCT // 8)
        with self.assertRaises(rc.ReplayError):
            self.go(self.scenario()[:2] + [{"kind": "claim", "payee": G[0], "amount": UCT}])

    def test_a_segment_boundary_splits_the_interval_and_the_new_owner_is_paid(self):
        segs = [("G", 0, 1500), ("K", 1500, None)]
        ev = [self.close(0, 0, 1000, UCT), self.close(0, 1000, 1500, UCT // 2), self.close(1, 1500, 2000, UCT // 2)]
        s = self.go(ev, funding=10 * UCT, segments=segs)
        self.assertEqual(s["nextStart"], 2000)
        with self.assertRaises(rc.ReplayError):   # the interval did not stop at the owner's end
            self.go([self.close(0, 0, 1000, UCT), self.close(0, 1000, 2000, UCT)], funding=10 * UCT, segments=segs)

    def test_a_rate_change_ends_the_interval_at_its_effective_progress(self):
        snaps = [(0, UCT), (0, UCT), (1500, 2 * UCT)]
        ev = [self.close(0, 0, 1000, UCT), dict(self.close(0, 1000, 1500, UCT // 2)), dict(self.close(0, 1500, 2000, UCT), rate=2 * UCT)]
        s = rc.replay(ev, [("G", 0, None)], lambda a: MEMBERS[a], 0, snaps, 10 * UCT)
        self.assertEqual(s["nextStart"], 2000)


if __name__ == "__main__":
    unittest.main()
