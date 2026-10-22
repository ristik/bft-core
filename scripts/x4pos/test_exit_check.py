#!/usr/bin/env python3
"""exit_check.py against a stub `cast` that answers custody's getters from a JSON world: the exit assertions of the PoS campaign (refusal reasons told apart, exact credit
and balance amounts), including under python -O."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shadow"))
from keccak import keccak256  # noqa: E402

SHIM = r'''#!PY
import json, os, sys
W = json.load(open(os.environ["WORLD"]))
a = sys.argv[1:]
if a[0] == "sig":
    sys.path.insert(0, os.environ["SHADOW"])
    from keccak import keccak256
    print("0x" + keccak256(a[1].encode()).hex()[:8]); sys.exit(0)
if a[0] == "balance":
    print(W["balances"][a[-1]]); sys.exit(0)
assert a[0] == "call"
args = a[1:]
i = 0
frm = None
while args[i].startswith("--"):
    if args[i] == "--from": frm = args[i + 1]
    i += 2
to, sig, params = args[i], args[i + 1], args[i + 2:]
if sig.startswith("positions"):
    p = W["position"]; print("\n".join([p["owner"], p["withdrawal"], "0x" + "00" * 32, "0x" + "00" * 32, str(p["generation"]), "0", "1", "1", "true" if p["requested"] else "false"]))
elif sig.startswith("retirements"):
    r = W["retirement"]; print("\n".join(["true" if r["imported"] else "false", str(r["pRet"]), str(r["tRet"])]))
elif sig.startswith("generationLots"): print("[" + ", ".join(str(l["id"]) for l in W["lots"]) + "]")
elif sig.startswith("lots"):
    l = [x for x in W["lots"] if x["id"] == int(params[0])][0]
    print("\n".join(str(x) for x in [l["id"], 1, l["initial"], l["remaining"], l["penalized"], l["category"], 500, l["refCount"], 2000, 3600, l["holdUntil"], l["evidenceUntil"], l["timeUntil"]]))
elif sig.startswith("liveExposures"): print(W["liveExposures"])
elif sig.startswith("credit"): print(W["credit"])
elif sig.startswith("mature"):
    if W["mature"] == "ok": print("0x"); sys.exit(0)
    sys.stderr.write("Error: server returned an error response: execution reverted, data: \"" + W["mature"] + "\"\n"); sys.exit(1)
else: sys.exit("shim: " + sig)
'''

W0 = {"position": {"owner": "0xOWN", "withdrawal": "0xWD", "generation": 3, "requested": True}, "retirement": {"imported": True, "pRet": 100, "tRet": 7000},
      "lots": [{"id": 4, "initial": 10, "remaining": 10, "penalized": 0, "category": 3, "refCount": 0, "holdUntil": 0, "evidenceUntil": 0, "timeUntil": 0},
               {"id": 9, "initial": 5, "remaining": 4, "penalized": 1, "category": 3, "refCount": 0, "holdUntil": 0, "evidenceUntil": 0, "timeUntil": 0}],
      "liveExposures": 0, "credit": 0, "mature": "ok", "balances": {"0xRCPT": 1000}}


def sel(name):
    return "0x" + keccak256(f"{name}()".encode()).hex()[:8]


class ExitCheck(unittest.TestCase):
    def run_cli(self, world, *argv, flags=()):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            shim = d / "cast"
            shim.write_text(SHIM.replace("#!PY", "#!" + sys.executable))
            shim.chmod(0o755)
            (d / "w.json").write_text(json.dumps(world))
            env = {"PATH": "/usr/bin:/bin", "WORLD": str(d / "w.json"), "SHADOW": str(HERE.parent / "shadow")}
            common = ["--rpc", "x", "--cast", str(shim), "--custody", "0xC", "--id", "5"]
            cmd = argv[0]
            return subprocess.run([sys.executable, *flags, str(HERE / "exit_check.py"), cmd, *common, *argv[1:]], capture_output=True, text=True, env=env, cwd=d)

    def world(self, **over):
        w = json.loads(json.dumps(W0))
        w.update(over)
        return w

    def test_state_reads_the_position_retirement_lots_and_credit(self):
        r = self.run_cli(self.world(credit=77), "state")
        self.assertEqual(r.returncode, 0, r.stderr)
        s = json.loads(r.stdout)
        self.assertEqual((s["generation"], s["retirementRequested"], s["imported"], s["pRet"], s["tRet"], s["liveExposures"], s["credit"]), (3, True, True, 100, 7000, 0, 77))
        self.assertEqual([(l["id"], l["remaining"], l["category"]) for l in s["lots"]], [(4, 10, 3), (9, 4, 3)])

    def test_the_lawful_early_refusals_are_named_and_a_missing_retirement_is_not_one(self):
        for name in ("RoundGateNotMet", "TimeGateNotMet", "EvidenceGateNotMet", "EvidenceHoldPending"):
            with self.subTest(name):
                r = self.run_cli(self.world(mature=sel(name)), "refusal")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(json.loads(r.stdout), {"lawfulEarly": True, "outcome": "refused", "reason": name})
        r = self.run_cli(self.world(mature=sel("RetirementNotImported")), "refusal")
        self.assertEqual(r.returncode, 1)
        self.assertIn("RetirementNotImported", r.stdout)
        self.assertIn("not a lawful early-claim reason", r.stderr)
        self.assertEqual(self.run_cli(self.world(mature=sel("RecordsPending")), "refusal").returncode, 1)
        r = self.run_cli(self.world(mature="0xdeadbeef"), "refusal")
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not know", r.stderr)

    def test_a_matured_exit_is_not_a_refusal_unless_allowed(self):
        self.assertEqual(self.run_cli(self.world(), "refusal").returncode, 1)
        self.assertEqual(self.run_cli(self.world(), "refusal", "--allow-success").returncode, 0)

    def test_matured_asserts_the_exact_credit_and_released_lots(self):
        before = self.world(credit=3)
        after = self.world(credit=3 + 14, lots=[dict(l, category=4, remaining=0) for l in W0["lots"]])
        with tempfile.TemporaryDirectory() as d:
            b = Path(d) / "before.json"
            b.write_text(json.dumps(self.run_state(before)))
            self.assertEqual(self.run_cli(after, "matured", "--before", str(b)).returncode, 0)
            self.assertEqual(self.run_cli(dict(after, credit=3 + 13), "matured", "--before", str(b)).returncode, 1)
            partly = dict(after, lots=[dict(after["lots"][0]), dict(W0["lots"][1])])
            self.assertEqual(self.run_cli(partly, "matured", "--before", str(b)).returncode, 1)

    def run_state(self, world):
        return json.loads(self.run_cli(world, "state").stdout)

    def test_claimed_asserts_the_recipient_balance_and_a_drained_credit(self):
        ok = self.world(credit=0, balances={"0xRCPT": 1014})
        args = ("claimed", "--recipient", "0xRCPT", "--recipient-before", "1000", "--credit", "14")
        self.assertEqual(self.run_cli(ok, *args).returncode, 0)
        self.assertEqual(self.run_cli(self.world(credit=0, balances={"0xRCPT": 1013}), *args).returncode, 1)
        self.assertEqual(self.run_cli(self.world(credit=1, balances={"0xRCPT": 1014}), *args).returncode, 1)

    def test_the_checks_survive_python_optimize(self):
        import ast
        self.assertEqual([n.lineno for n in ast.walk(ast.parse((HERE / "exit_check.py").read_text())) if isinstance(n, ast.Assert)], [])
        r = self.run_cli(self.world(mature=sel("RetirementNotImported")), "refusal", flags=("-O",))
        self.assertEqual(r.returncode, 1)
        r = self.run_cli(self.world(credit=0, balances={"0xRCPT": 1013}), "claimed", "--recipient", "0xRCPT", "--recipient-before", "1000", "--credit", "14", flags=("-O",))
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
