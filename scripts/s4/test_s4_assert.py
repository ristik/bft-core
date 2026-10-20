import unittest
import s4_assert as m

POL = dict(penaltyBps=100, lifetimeCapBps=500, bountyBps=1000, bountyCap=10**18)
E = 10**18


class Rules(unittest.TestCase):
    def test_single_lot(self):
        r = m.expected_settlement(POL, [dict(initial=100 * E, remaining=100 * E, penalized=0, capBps=500)])
        self.assertEqual(r["debit"], E)
        self.assertEqual(r["bounty"], E // 10)
        self.assertEqual(r["treasury"], E - E // 10)
        self.assertEqual(r["rows"][0]["remaining"], 99 * E)

    def test_bounty_cap(self):
        r = m.expected_settlement(dict(POL, penaltyBps=1000), [dict(initial=1000 * E, remaining=1000 * E, penalized=0, capBps=5000)])
        self.assertEqual(r["debit"], 100 * E)
        self.assertEqual(r["bounty"], E)  # capped at 1 ether, not 10
        self.assertEqual(r["treasury"], 99 * E)

    def test_cap_room_binds_and_budget_spills(self):
        lots = [dict(initial=100 * E, remaining=100 * E, penalized=4 * E + E // 2, capBps=500),
                dict(initial=100 * E, remaining=100 * E, penalized=0, capBps=500)]
        r = m.expected_settlement(POL, lots)  # budget 2 ether: lot 1 has 0.5 room, lot 2 takes 1.5
        self.assertEqual([x["debit"] for x in r["rows"]], [E // 2, E + E // 2])
        self.assertEqual(r["bounty"], 2 * E // 10)

    def test_stats(self):
        s = m.parse_stats('INF msg="evidence observer stats" kept=3 rejected=1 dropped=0 failed=0 healthy=true')
        self.assertEqual(s, dict(kept=3, rejected=1, dropped=0, failed=0, healthy=True))
        with self.assertRaises(ValueError):
            m.parse_stats("nothing")

    def test_mutant_wrong_cap(self):  # a bounty not capped must differ
        r = m.expected_settlement(dict(POL, penaltyBps=1000, bountyCap=10**30), [dict(initial=1000 * E, remaining=1000 * E, penalized=0, capBps=5000)])
        self.assertNotEqual(r["bounty"], E)


if __name__ == "__main__":
    unittest.main()
