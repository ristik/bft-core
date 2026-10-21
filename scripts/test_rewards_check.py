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
    SNAPS = [(0, 0), (0, UCT)]   # policy 1 in force from progress 0 at 1 UCT per 1,000 progress units

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
        s = rc.replay([dict(self.close(0, 0, 1000, 10, 9), rate=10)], [("X", 0, None)], lambda a: members[a], 0, [(0, 0), (0, 10)], 10)
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
        snaps = [(0, 0), (0, UCT), (1500, 2 * UCT)]
        ev = [self.close(0, 0, 1000, UCT), dict(self.close(0, 1000, 1500, UCT // 2)), dict(self.close(0, 1500, 2000, UCT), rate=2 * UCT)]
        s = rc.replay(ev, [("G", 0, None)], lambda a: MEMBERS[a], 0, snaps, 10 * UCT)
        self.assertEqual(s["nextStart"], 2000)


SHIM = r'''#!/usr/bin/env python3
import json, os, sys
W = json.load(open(os.environ["WORLD"]))
a = sys.argv[1:]
def word(n): return format(n, "064x")
def out(ws): print("0x" + "".join(word(w) for w in ws))
if a[0] == "keccak":
    sys.path.insert(0, os.environ["SHADOW"])
    from keccak import keccak256
    print("0x" + keccak256(a[1].encode()).hex())
elif a[0] == "block-number": print(W["block"])
elif a[0] == "balance": print(W["balance"])
elif a[0] == "logs": print(json.dumps(W["logs"]))
elif a[0] == "call":
    args = a[1:]
    i = 0
    while args[i].startswith("--"): i += 2   # the --rpc-url and --block option pairs
    to, sig, params = args[i], args[i + 1], args[i + 2:]
    if sig.startswith("segmentCount"): out([len(W["segments"])])
    elif sig.startswith("segmentAt"): s = W["segments"][int(params[0])]; out([int(s[0], 16), s[1], s[2] or 0, 1 if s[2] is not None else 0])
    elif sig.startswith("assignmentExposures"): out([32, len(W["members"])] + [100 + k for k in range(len(W["members"]))])
    elif sig.startswith("exposures"): k = int(params[0], 16) - 100; m = W["members"][k]; out([0, 0, 0, m[0], 0, 0, 0, int(m[1], 16)])
    elif sig.startswith("currentPolicyID"): out([len(W["snapshots"]) - 1])
    elif sig.startswith("snapshotAt"): s = W["snapshots"][int(params[0])]; out([0] * 10 + [s[1], 0, s[0], 0])
    elif sig.startswith("START"): out([W["start"]])
    elif sig.startswith("available"): out([W["final"]["available"]])
    elif sig.startswith("totalCredits"): out([W["final"]["totalCredits"]])
    elif sig.startswith("nextStart"): out([W["final"]["nextStart"]])
    elif sig.startswith("credits"): out([W["final"]["credits"].get(params[0].lower(), 0)])
    else: sys.exit("shim: " + sig)
'''


class ReplayAgainstTheChain(unittest.TestCase):
    """The glue of `rewards_check.py replay`: logs fetched with cast, decoded, replayed and compared with the chain's own views (a shim stands in for cast)."""
    PAYEES = ["0x%040x" % (0xA0 + i) for i in range(4)]

    def world(self, tamper=None):
        sys.path.insert(0, str(Path(__file__).resolve().parent / "shadow"))
        from keccak import keccak256

        def topic(sig): return "0x" + keccak256(sig.encode()).hex()
        def w(*ns): return "0x" + "".join(format(n, "064x") for n in ns)
        sc = Replay()
        events = sc.scenario()
        members = [(10, p) for p in self.PAYEES]
        state = rc.replay(events, [("0x" + "ab" * 32, 0, None)], lambda a: members, 0, [(0, 0), (0, UCT)], 2 * UCT)
        logs, idx = [], 0
        for n, e in enumerate(events):
            idx += 1
            base = {"blockNumber": hex(10 + n), "logIndex": hex(idx)}
            if e["kind"] == "fund":
                logs.append(dict(base, topics=[topic("Funded(address,uint256)"), w(0xF0)], data=w(e["amount"])))
            else:
                logs.append(dict(base, topics=[topic("IntervalClosed(uint256,uint64,uint64,uint128,uint256,uint256)"), w(e["segment"])],
                                 data=w(e["start"], e["end"], e["rate"], e["budget"], e["distributed"])))
        world = {"block": 99, "balance": state["available"] + state["totalCredits"], "start": 0, "snapshots": [[0, 0], [0, UCT]], "logs": logs,
                 "segments": [["0x" + "ab" * 32, 0, None]], "members": members, "final": {"available": state["available"], "totalCredits": state["totalCredits"],
                                                                                          "nextStart": state["nextStart"], "credits": {k.lower(): v for k, v in state["credits"].items()}}}
        if tamper:
            tamper(world)
        return world

    def run_cli(self, world, *flags, python_flags=()):
        import json
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            shim = Path(d) / "cast"
            shim.write_text(SHIM.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
            shim.chmod(0o755)
            wf = Path(d) / "world.json"
            wf.write_text(json.dumps(world))
            env = {"PATH": "/usr/bin:/bin", "WORLD": str(wf), "SHADOW": str(Path(__file__).resolve().parent / "shadow")}
            return subprocess.run([sys.executable, *python_flags, str(Path(__file__).resolve().parent / "rewards_check.py"), "replay", "--rpc", "x", "--cast", str(shim), "--pool", "0xp",
                                   "--custody", "0xc", "--registry", "0xr", "--election", "0xe", "--policy", "0xq", "--genesis-assignment", "0x" + "ab" * 32,
                                   "--initial-funding", str(2 * UCT), *flags], capture_output=True, text=True, env=env)

    def test_the_chain_agrees_with_the_replay_of_its_logs(self):
        r = self.run_cli(self.world(), "--min-paid", "4", "--require-exhaustion", "--require-refill")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("REWARDS-REPLAY ok", r.stdout)
        self.assertIn('"zeroBudget": 1', r.stdout)

    def test_a_chain_state_that_differs_from_the_logs_is_refused(self):
        for name, tamper in (("available", lambda w: w["final"].update(available=w["final"]["available"] + 1)),
                             ("total credits", lambda w: w["final"].update(totalCredits=w["final"]["totalCredits"] - 1)),
                             ("next start", lambda w: w["final"].update(nextStart=1)),
                             ("a payee's credit", lambda w: w["final"]["credits"].update({self.PAYEES[0]: 1}))):
            with self.subTest(name):
                r = self.run_cli(self.world(tamper))
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("REWARDS-REPLAY FAILED", r.stderr)

    def test_the_checks_survive_python_optimize(self):
        """`python -O` strips assert statements: a tool built on them prints ok having checked nothing. The checks are explicit raises."""
        import ast
        tree = ast.parse((Path(__file__).resolve().parent / "rewards_check.py").read_text())
        self.assertEqual([n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)], [], "no assert statement may carry a check")
        for name, tamper in (("available", lambda w: w["final"].update(available=w["final"]["available"] + 1)),
                             ("a payee's credit", lambda w: w["final"]["credits"].update({self.PAYEES[0]: 1}))):
            with self.subTest(name):
                r = self.run_cli(self.world(tamper), python_flags=("-O",))
                self.assertNotEqual(r.returncode, 0, "python -O printed ok: " + r.stdout)
                self.assertIn("REWARDS-REPLAY FAILED", r.stderr)
        ok = self.run_cli(self.world(), "--require-exhaustion", "--require-refill", python_flags=("-O",))
        self.assertEqual(ok.returncode, 0, ok.stderr)
        for flags in (("--min-paid", "9"),):
            self.assertNotEqual(self.run_cli(self.world(), *flags, python_flags=("-O",)).returncode, 0)

    def test_the_required_facts_are_required(self):
        def no_dry(w):   # drop the zero-budget close and the refill: a pool that never ran dry
            w["logs"] = [l for i, l in enumerate(w["logs"]) if i != 3]   # no refill event
        r = self.run_cli(self.world(no_dry), "--require-refill")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("REWARDS-REPLAY FAILED", r.stderr)
        self.assertNotEqual(self.run_cli(self.world(), "--min-paid", "5").returncode, 0)


if __name__ == "__main__":
    unittest.main()
