#!/usr/bin/env python3
"""lib.sh x4p_exit_anchor (#1297/#1298) with stubbed chain helpers: it sends anchorTerm for exactly the terms `exit_check.py terms` lists as ready, with their
Closure words; nothing is sent when nothing is ready; a send that loses the race to another anchor is accepted once the term is no longer listed, and refused
otherwise. Stdlib only."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
A, B = "0x" + "a1" * 32, "0x" + "b2" * 32
H, T = "0x" + "d4" * 32, "0x" + "e5" * 32


def run(first, after, send_ok=True):
    """first: what `terms` prints the first time; after: every later time. Returns (rc, sends, stderr)."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "cursor").mkdir()
        (d / "first.json").write_text(json.dumps(first))
        (d / "after.json").write_text(json.dumps(after))
        stubs = f'''
x4p_exit() {{ if [ -e {d}/seen ]; then cat {d}/after.json; else touch {d}/seen; cat {d}/first.json; fi; }}
x4p_address_of() {{ echo 0xSENDER; }}
x4p_ensure_gas() {{ echo gas >>{d}/sends; }}
p85_custody() {{ echo 0xCUSTODY; }}
x4p_send_call() {{ echo "$*" >>{d}/sends; {"true" if send_ok else "false"}; }}
'''
        script = (f'set -uo pipefail; cd {ROOT}; X4_CURSOR_DIR={d}/cursor; X4_STEP_DIR={d}/step; P85_DIR={d}; P85_DEPLOY={d}/none.json; '
                  f'source scripts/x4pos/lib.sh; {stubs} x4p_exit_anchor 5 {d}/key')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        sends = (d / "sends").read_text().splitlines() if (d / "sends").exists() else []
        return r.returncode, sends, r.stderr


def term(aid, ready=True, reason=None):
    return {"assignmentID": aid, "hRecordID": H, "terminalRoot": T, "ready": ready, "reason": reason}


class ExitAnchor(unittest.TestCase):
    def test_anchors_every_ready_term_with_its_closure_words(self):
        rc, sends, err = run({"supported": True, "blockedLots": [4], "terms": [term(A), term(B, False, "SuccessorNotInstalled")]}, {"terms": []})
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(sends), 2, sends)
        self.assertEqual(sends[0], "gas")
        self.assertTrue(sends[1].endswith(f"/key 0xCUSTODY anchorTerm(bytes32,bytes32,bytes32) {A} {H} {T}"), sends)

    def test_nothing_ready_sends_nothing(self):
        for first in ({"supported": False, "blockedLots": [], "terms": []}, {"supported": True, "blockedLots": [4], "terms": [term(A, False, "SuccessorNotInstalled")]}):
            rc, sends, err = run(first, first)
            self.assertEqual((rc, sends), (0, []), err)

    def test_a_lost_race_is_fine_and_a_failed_send_is_not(self):
        first = {"supported": True, "blockedLots": [4], "terms": [term(A)]}
        rc, _, err = run(first, {"supported": True, "blockedLots": [], "terms": []}, send_ok=False)
        self.assertEqual(rc, 0, err)
        rc, _, err = run(first, first, send_ok=False)
        self.assertNotEqual(rc, 0)
        self.assertIn("was not mined", err)


if __name__ == "__main__":
    unittest.main()
