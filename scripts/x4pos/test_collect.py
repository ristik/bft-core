#!/usr/bin/env python3
"""collect.py against a stub `cast` that answers custody's and the pool's reads from a JSON world, then accounting.py on what it wrote: the collector's schema is the checker's,
and a wrong event shape or a broken identity is a failure, not a quiet pass."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import accounting  # noqa: E402

SHIM = r'''#!PY
import json, os, sys
W = json.load(open(os.environ["WORLD"]))
a = sys.argv[1:]
if a[0] == "block-number": print(W["block"]); sys.exit(0)
if a[0] == "balance": print(W["balances"][a[-1]]); sys.exit(0)
if a[0] == "call":
    i = a.index("--block") + 2
    to, sig, params = a[i], a[i + 1], a[i + 2:]
    if sig.startswith("nextLotID"): print(W["nextLotID"])
    elif sig.startswith("lots("):
        l = [x for x in W["lots"] if x["id"] == int(params[0])]
        if not l: print("\n".join(["0"] * 13))
        else:
            l = l[0]; print("\n".join(str(x) for x in [l["id"], 1, l["initial"], l["remaining"], l["penalized"], l["category"], 500, 0, 2000, 3600, 0, 0, 0]))
    elif sig.split("(")[0] in W["totals"]: print(W["totals"][sig.split("(")[0]])
    else: sys.exit("shim: " + sig)
    sys.exit(0)
if a[0] == "logs":
    addr = a[a.index("--address") + 1]; sig = a[-1]
    print(json.dumps(W["logs"].get(addr + "|" + sig, []))); sys.exit(0)
sys.exit("shim: " + a[0])
'''

CUST, POOL = "0xCUST", "0xPOOL"


def word(n):
    return "0x" + format(n, "064x")


def addr(h):
    return "0x" + "00" * 12 + h


def log(tx, idx, payee, amount, to=True):
    return {"transactionHash": tx, "logIndex": hex(idx), "topics": ["0xsig", addr(payee)] + ([addr("bb" * 20)] if to else []), "data": word(amount)}


def world(**over):
    # lot 1: released (category 4), initial 100, penalized 10, so 90 went to a credit; lot 2: free 50. The credit of 90 + bounty/treasury 10 = 100 credited in all, 60 claimed, 40 still owed.
    w = {"block": 900, "nextLotID": 2, "balances": {CUST: 190, POOL: 70},
         "lots": [{"id": 1, "initial": 100, "remaining": 0, "penalized": 10, "category": 4}, {"id": 2, "initial": 50, "remaining": 50, "penalized": 0, "category": 1}],
         "totals": {"totalFree": 50, "totalEncumbered": 0, "totalDraining": 0, "totalCredits": 40},
         "logs": {CUST + "|CreditClaimed(address,address,uint256)": [log("0xt1", 1, "aa" * 20, 60)],
                  POOL + "|Funded(address,uint256)": [{"transactionHash": "0xf", "logIndex": "0x0", "topics": ["0xsig"], "data": word(100)}],
                  POOL + "|Claimed(address,address,uint256)": [log("0xt2", 3, "cc" * 20, 30)]}}
    w.update(over)
    return w


class Collect(unittest.TestCase):
    def run_collect(self, w, out=None, t=0, extra=()):
        d = tempfile.mkdtemp()
        d = Path(d)
        shim = d / "cast"
        shim.write_text(SHIM.replace("#!PY", "#!" + sys.executable))
        shim.chmod(0o755)
        (d / "w.json").write_text(json.dumps(w))
        out = out or d / "s.jsonl"
        env = {"PATH": "/usr/bin:/bin", "WORLD": str(d / "w.json")}
        r = subprocess.run([sys.executable, str(HERE / "collect.py"), "snapshot", "--rpc", "x", "--cast", str(shim), "--custody", CUST, "--pool", POOL, "--from-block", "1", "--t", str(t), "--out", str(out), *extra],
                           capture_output=True, text=True, env=env)
        return r, Path(out)

    def test_a_consistent_chain_is_written_in_the_checkers_schema_and_passes_it(self):
        r, out = self.run_collect(world())
        self.assertEqual(r.returncode, 0, r.stderr)
        s = json.loads(out.read_text())
        self.assertEqual(s["custody"], {"deposited": 150, "withdrawn": 60, "slashed": 10, "held": 90, "balance": 190})
        self.assertEqual((s["pool"], s["cursors"], len(s["payments"])), ({"funded": 100, "paid": 30, "balance": 70}, {"nextLotID": 2}, 1))
        self.assertEqual(s["payments"][0], ["0xt2:3", "0x" + "cc" * 20, 30])
        r2, _ = self.run_collect(world(block=901), out=out, t=60)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(accounting.run(out)["status"], "PASS")

    def test_a_genesis_funded_pool_has_no_funded_log_and_needs_the_explicit_amount(self):
        w = world(balances={CUST: 190, POOL: 1000 - 30})
        w["logs"][POOL + "|Funded(address,uint256)"] = []
        r, out = self.run_collect(w, extra=("--genesis-funding", "1000"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(out.read_text())["pool"], {"funded": 1000, "paid": 30, "balance": 970})
        self.run_collect(w, out=out, t=60, extra=("--genesis-funding", "1000"))
        self.assertEqual(accounting.run(out)["status"], "PASS")
        r2, out2 = self.run_collect(w)   # without it the pool looks unfunded: funded 0 against a balance of 970 is the false FAIL the flag exists to prevent
        self.run_collect(w, out=out2, t=60)
        self.assertEqual(accounting.run(out2)["firstFailure"]["invariant"], "pool")

    def test_funded_logs_add_to_the_genesis_amount(self):
        r, out = self.run_collect(world(balances={CUST: 190, POOL: 570}), extra=("--genesis-funding", "500"))
        self.assertEqual(json.loads(out.read_text())["pool"]["funded"], 600)

    def test_the_genesis_lots_count_although_no_event_made_them(self):
        r, out = self.run_collect(world())
        self.assertEqual(json.loads(out.read_text())["custody"]["deposited"], 150)

    def test_a_withdrawn_sum_that_disagrees_with_the_lots_is_a_failure(self):
        w = world()
        w["logs"][CUST + "|CreditClaimed(address,address,uint256)"] = [log("0xt1", 1, "aa" * 20, 59)]
        r, out = self.run_collect(w)
        self.assertEqual(r.returncode, 1)
        self.assertIn("CreditClaimed events 59", r.stderr)
        self.assertIn("collectorNotes", out.read_text())

    def test_nextlotid_is_the_last_assigned_id_and_a_disagreement_either_way_is_refused(self):
        r, out = self.run_collect(world(nextLotID=2))
        self.assertEqual(r.returncode, 0, r.stderr)
        for n, msg in ((5, "nextLotID is 5 but 2 lots exist"), (1, "nextLotID is 1 but 2 lots exist")):
            r, _ = self.run_collect(world(nextLotID=n))
            self.assertEqual(r.returncode, 1)
            self.assertIn(msg, r.stderr)

    def test_a_pool_that_paid_more_than_it_funded_fails_the_checker(self):
        w = world()
        w["logs"][POOL + "|Claimed(address,address,uint256)"] = [log("0xt2", 3, "cc" * 20, 130)]
        r, out = self.run_collect(w)
        self.assertEqual(r.returncode, 0, r.stderr)   # the collector reports what it read; the checker judges it
        r2, _ = self.run_collect(world(block=901), out=out, t=60)
        self.assertEqual(accounting.run(out)["firstFailure"]["invariant"], "pool")


if __name__ == "__main__":
    unittest.main()
