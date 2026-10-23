#!/usr/bin/env python3
"""accounting.py: each invariant has a mutation of a good series that fails on exactly that invariant (and the good series passes)."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import accounting  # noqa: E402

S0 = {"t": 0, "block": 10, "cursors": {"records": 0, "rewards": 0},
      "pool": {"funded": 100, "paid": 0, "balance": 100}, "custody": {"deposited": 50, "withdrawn": 0, "slashed": 0, "held": 50}, "payments": []}
S1 = {"t": 600, "block": 40, "cursors": {"records": 3, "rewards": 1},
      "pool": {"funded": 100, "paid": 30, "balance": 70}, "custody": {"deposited": 50, "withdrawn": 0, "slashed": 5, "held": 50}, "payments": [["1", "0xa", 20], ["1", "0xb", 10]]}
S2 = {"t": 1200, "block": 90, "cursors": {"records": 3, "rewards": 2},
      "pool": {"funded": 150, "paid": 50, "balance": 100}, "custody": {"deposited": 50, "withdrawn": 50, "slashed": 5, "held": 0}, "payments": [["1", "0xa", 20], ["1", "0xb", 10], ["2", "0xa", 20]]}
GOOD = [S0, S1, S2]


def run(snaps):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "s.jsonl"
        p.write_text("\n".join(json.dumps(s) for s in snaps) + "\n")
        return accounting.run(p)


def mutate(i, fn):
    s = copy.deepcopy(GOOD)
    fn(s[i])
    return s


class Accounting(unittest.TestCase):
    def fails(self, snaps, invariant, index):
        r = run(snaps)
        self.assertEqual(r["status"], "FAIL", r)
        self.assertEqual((r["firstFailure"]["invariant"], r["firstFailure"]["snapshot"]), (invariant, index), r)

    def test_a_good_series_passes(self):
        r = run(GOOD)
        self.assertEqual((r["status"], r["snapshots"], r["payments"], r["spanSeconds"]), ("PASS", 3, 3, 1200))

    def test_fewer_than_two_snapshots_is_incomplete_not_pass(self):
        self.assertEqual(run(GOOD[:1])["status"], "INCOMPLETE")
        self.assertEqual(run([])["status"], "INCOMPLETE")

    def test_pool_conservation(self):
        self.fails(mutate(1, lambda s: s["pool"].update(balance=71)), "pool", 1)

    def test_slashed_is_inside_held_or_withdrawn_not_added_again(self):
        # the old identity deposited == withdrawn + slashed + held double counted a slash that sits in a credit: it must not be satisfiable by adding slashed
        self.fails(mutate(1, lambda s: s["custody"].update(held=45)), "custody", 1)
        self.fails(mutate(1, lambda s: s["custody"].update(slashed=51)), "custody", 1)

    def test_a_custody_balance_below_what_it_holds_fails(self):
        self.assertEqual(run(mutate(1, lambda s: s["custody"].update(balance=50)))["status"], "PASS")
        self.fails(mutate(1, lambda s: s["custody"].update(balance=49)), "custody", 1)

    def test_custody_conservation(self):
        self.fails(mutate(2, lambda s: s["custody"].update(withdrawn=44)), "custody", 2)

    def test_a_cursor_going_back_or_disappearing(self):
        self.fails(mutate(2, lambda s: s["cursors"].update(records=2)), "cursor", 2)
        self.fails(mutate(1, lambda s: s["cursors"].pop("rewards")), "cursor", 1)

    def test_a_cumulative_total_going_back_while_every_snapshot_balances(self):
        def with_pool(funded, paid, balance, payments):
            s = copy.deepcopy(S2); s["pool"] = {"funded": funded, "paid": paid, "balance": balance}; s["payments"] = payments
            return s
        # funded 100 -> 90 (90 = 50 paid + 40 held: this snapshot balances on its own)
        self.fails([S0, S1, with_pool(90, 50, 40, S2["payments"])], "cumulative", 2)
        # paid 30 -> 20 (the payments are a prefix of the earlier ones: this snapshot balances and the sums agree)
        self.fails([S0, S1, with_pool(100, 20, 80, S1["payments"][:1])], "cumulative", 2)

    def test_each_custody_total_going_back_is_its_own_failure(self):
        def run_custody(c1, c2):
            a, b = copy.deepcopy(S1), copy.deepcopy(S2)
            a["custody"], b["custody"] = c1, c2
            return run([S0, a, b])
        for name, c1, c2 in (("deposited", dict(deposited=60, withdrawn=0, slashed=5, held=60), dict(deposited=50, withdrawn=0, slashed=5, held=50)),
                             ("withdrawn", dict(deposited=50, withdrawn=10, slashed=5, held=40), dict(deposited=50, withdrawn=9, slashed=5, held=41)),
                             ("slashed", dict(deposited=50, withdrawn=0, slashed=6, held=50), dict(deposited=50, withdrawn=0, slashed=5, held=50))):
            with self.subTest(name):
                r = run_custody(c1, c2)
                self.assertEqual((r["status"], r["firstFailure"]["invariant"], r["firstFailure"]["snapshot"]), ("FAIL", "cumulative", 2), r)
                self.assertIn(f"custody.{name}", r["firstFailure"]["detail"])

    def test_balance_and_held_may_go_down_and_a_new_cursor_may_appear(self):
        s = copy.deepcopy(GOOD)
        s[2]["cursors"]["evidence"] = 1
        self.assertEqual(run(s)["status"], "PASS")

    def test_time_and_block_order(self):
        self.fails(mutate(1, lambda s: s.update(t=0)), "order", 1)
        self.fails(mutate(2, lambda s: s.update(block=39)), "order", 2)

    def test_duplicate_payment(self):
        def dup(s):
            s["payments"].append(["1", "0xa", 5]); s["pool"].update(paid=35, balance=65)
        self.fails(mutate(1, dup), "payments", 1)

    def test_payment_sum_must_match_the_pool(self):
        self.fails(mutate(1, lambda s: s["payments"].__setitem__(0, ["1", "0xa", 19])), "payments", 1)

    def test_earlier_payments_rewritten(self):
        def rewrite(s):
            s["payments"][0] = ["1", "0xc", 20]
        self.fails(mutate(2, rewrite), "payments", 2)

    def test_schema(self):
        self.fails(mutate(0, lambda s: s["pool"].update(paid=-1)), "schema", 0)
        self.fails(mutate(1, lambda s: s.pop("custody")), "schema", 1)
        self.fails(mutate(1, lambda s: s.update(t=True)), "schema", 1)

    def test_the_first_failure_wins(self):
        s = mutate(1, lambda s: s["pool"].update(balance=1))
        s[2]["custody"]["held"] = 1
        self.fails(s, "pool", 1)

    def test_a_line_that_is_not_json_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.jsonl"
            p.write_text(json.dumps(S0) + "\n{not json\n")
            self.assertEqual(accounting.run(p)["firstFailure"]["invariant"], "schema")


if __name__ == "__main__":
    unittest.main()
