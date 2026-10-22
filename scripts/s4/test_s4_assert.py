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


class OffenderPairs(unittest.TestCase):
    A, B = {"Key": "0xAA11", "Epoch": 2, "Round": 7}, {"Key": "bb22", "Epoch": 2, "Round": 9}

    def test_no_key_keeps_every_pair(self):
        self.assertEqual(m.offender_pairs({"Pairs": [self.A, self.B]}, ""), [self.A, self.B])
        self.assertEqual(m.offender_pairs({"Pairs": None}, ""), [])

    def test_a_key_selects_only_its_offence_whatever_the_prefix_and_case(self):
        self.assertEqual(m.offender_pairs({"Pairs": [self.A, self.B]}, "aa11"), [self.A])
        self.assertEqual(m.offender_pairs({"Pairs": [self.A, self.B]}, "0xBB22"), [self.B])
        self.assertEqual(m.offender_pairs({"Pairs": [self.A]}, "cc33"), [])

    def test_mutant_unfiltered_would_count_two(self):  # the second offence in the same journals must not make the first one "two offences"
        self.assertEqual(len(m.offender_pairs({"Pairs": [self.A, self.B]}, "")), 2)
        self.assertEqual(len(m.offender_pairs({"Pairs": [self.A, self.B]}, "aa11")), 1)


if __name__ == "__main__":
    unittest.main()


class Core(unittest.TestCase):
    LOT = dict(initial=1, remaining=1, penalized=0, category=2, capBps=500, holds=0, pendingHolds=0, retirementImported=False, refCount=1)

    def test_reference_count_is_not_a_case_effect(self):
        self.assertEqual(m.core(self.LOT), m.core(dict(self.LOT, refCount=2)))

    def test_hold_and_debit_are_case_effects(self):
        self.assertNotEqual(m.core(self.LOT), m.core(dict(self.LOT, holds=1)))
        self.assertNotEqual(m.core(self.LOT), m.core(dict(self.LOT, remaining=0, penalized=1)))
