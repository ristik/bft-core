#!/usr/bin/env python3
"""scripts/p85-genesis-plan.py: the default plan is unchanged (derived addresses nobody holds a key for); with P85_PLAN_OWNER_KEYS the owners and withdrawal addresses are keys
the lane holds (X4 #58 step B2: an incumbent must be able to request retirement and claim)."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PLAN = Path(__file__).resolve().parent / "p85-genesis-plan.py"
FAKE_CAST = "#!" + sys.executable + "\nimport hashlib, sys\nkey = sys.argv[-1]\nprint('0x' + hashlib.sha256(key.encode()).hexdigest()[:40])\n"


def addr(tag, node):
    return "0x" + hashlib.sha256(f"p85-lane/{tag}/{node}".encode()).digest()[:20].hex()


class Plan(unittest.TestCase):
    def run_plan(self, **env):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "tb.json").write_text(json.dumps({"rootNodes": [{"nodeId": f"r{i}", "sigKey": "0x02"} for i in range(4)]}))
            (d / "conf.json").write_text(json.dumps({"validators": [{"nodeId": f"e{i}", "sigKey": "0x03"} for i in range(4)]}))
            cast = d / "cast"
            cast.write_text(FAKE_CAST)
            cast.chmod(0o755)
            e = dict(os.environ, P85_CAST=str(cast), **{k: str(d / v) for k, v in env.items()})
            for k in ("P85_PLAN_OWNER_KEYS", "P85_PLAN_PAYEE_KEYS"):
                if k not in env:
                    e.pop(k, None)
            out = subprocess.run([sys.executable, str(PLAN), str(d / "tb.json"), str(d / "conf.json"), "100", "1"], capture_output=True, text=True, env=e)
            self.assertEqual(out.returncode, 0, out.stderr)
            keys = {p.name: (p.read_text().strip(), stat.S_IMODE(p.stat().st_mode)) for p in d.glob("*/*.key")}
            return json.loads(out.stdout), keys

    def test_the_default_plan_derives_addresses_nobody_holds_a_key_for(self):
        plan, keys = self.run_plan()
        self.assertEqual(keys, {})
        for i, ident in enumerate(plan["identities"]):
            self.assertEqual((ident["owner"], ident["withdrawal"], ident["payee"]), (addr("owner", f"r{i}"), addr("withdrawal", f"r{i}"), addr("payee", f"r{i}")))

    def test_held_owner_keys_give_every_identity_its_own_owner_and_withdrawal_key(self):
        plan, keys = self.run_plan(P85_PLAN_OWNER_KEYS="owner-keys")
        self.assertEqual(sorted(keys), sorted(f"{r}-{i}.key" for r in ("owner", "withdrawal") for i in range(1, 5)))
        self.assertTrue(all(mode == 0o600 for _, mode in keys.values()), "key files must be private")
        seen = set()
        for i, ident in enumerate(plan["identities"], start=1):
            for role in ("owner", "withdrawal"):
                key = keys[f"{role}-{i}.key"][0]
                self.assertEqual(ident[role], "0x" + hashlib.sha256(key.encode()).hexdigest()[:40], f"{role} {i} is the address of its key")
                self.assertNotEqual(ident[role], addr(role, f"r{i - 1}"))
                seen.add(ident[role])
            self.assertEqual(ident["payee"], addr("payee", f"r{i - 1}"), "the payee stays derived unless P85_PLAN_PAYEE_KEYS")
        self.assertEqual(len(seen), 8, "owners and withdrawal addresses are all distinct")

    def test_the_two_key_options_are_independent(self):
        plan, keys = self.run_plan(P85_PLAN_OWNER_KEYS="o", P85_PLAN_PAYEE_KEYS="p")
        self.assertEqual(len(keys), 12)
        self.assertEqual(len({i["payee"] for i in plan["identities"]}), 4)


if __name__ == "__main__":
    unittest.main()
