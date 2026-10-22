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
      "pool": {"funded": 100, "paid": 30, "balance": 70}, "custody": {"deposited": 50, "withdrawn": 0, "slashed": 5, "held": 45}, "payments": [["1", "0xa", 20], ["1", "0xb", 10]]}
S2 = {"t": 1200, "block": 90, "cursors": {"records": 3, "rewards": 2},
      "pool": {"funded": 150, "paid": 50, "balance": 100}, "custody": {"deposited": 50, "withdrawn": 45, "slashed": 5, "held": 0}, "payments": [["1", "0xa", 20], ["1", "0xb", 10], ["2", "0xa", 20]]}
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

    def test_custody_conservation(self):
        self.fails(mutate(2, lambda s: s["custody"].update(withdrawn=44)), "custody", 2)

    def test_a_cursor_going_back_or_disappearing(self):
        self.fails(mutate(2, lambda s: s["cursors"].update(records=2)), "cursor", 2)
        self.fails(mutate(1, lambda s: s["cursors"].pop("rewards")), "cursor", 1)

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
