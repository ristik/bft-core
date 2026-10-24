#!/usr/bin/env python3
"""fault-lib.sh, the parts that need no chain: sourcing only defines; x4f_wait (unknown step refused, a step past its time runs at once and records how late); x4f_log_ordered (contiguous, ordered
registry log accepted; a gap or a record that goes back refused); x4f_write (the `stable` verdict is computed, not passed in). Stdlib only."""
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LIB = HERE / "fault-lib.sh"


def sh(script, h3):
    pre = f'set -uo pipefail; cd {ROOT}; H3_DIR={h3}; X4A_DIR=$H3_DIR/x4pos; source {LIB}; '
    return subprocess.run(["bash", "-c", pre + script], capture_output=True, text=True)


class FaultLib(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.h3 = self.tmp.name
        Path(self.h3, "x4pos").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_sourcing_defines_only(self):
        r = sh("declare -F x4f_root_restart x4f_delayed_episode x4_report >/dev/null && echo defined", self.h3)
        self.assertEqual(r.stdout.strip(), "defined", r.stderr)
        self.assertEqual(list(Path(self.h3, "x4pos").iterdir()), [])

    def test_wait_refuses_an_unknown_step_and_a_missing_start(self):
        self.assertNotEqual(sh("x4f_wait nope", self.h3).returncode, 0)
        r = sh("x4f_wait fault-root-restart", self.h3)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no campaign start", r.stderr)

    def test_wait_runs_at_once_when_past_and_records_the_lateness(self):
        Path(self.h3, "x4pos", "t0").write_text(str(int(time.time()) - 100000))
        r = sh("x4f_wait fault-root-restart", self.h3)
        self.assertEqual(r.returncode, 0, r.stderr)
        late = int(Path(self.h3, "x4pos/steps/faults/fault-root-restart.late").read_text())
        self.assertGreater(late, 90000)

    def log_ordered(self, rows):
        body = "\n".join(rows)
        r = sh(f"p85_log_dump() {{ printf '%s\\n' '{body}'; }}; x4f_log_ordered", self.h3)
        return r

    def test_log_ordered(self):
        ok = self.log_ordered(["0 2 10 100 a b", "1 1 20 200 a b", "2 3 20 250 a b"])
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "3"), ok.stderr)
        gap = self.log_ordered(["0 2 10 100 a b", "2 1 20 200 a b"])
        self.assertNotEqual(gap.returncode, 0)
        back = self.log_ordered(["0 2 10 100 a b", "1 1 9 200 a b"])
        self.assertNotEqual(back.returncode, 0)
        self.assertNotEqual(self.log_ordered([""]).returncode, 0)

    def test_write_computes_stable(self):
        b = json.dumps({"lastAcked": "0xa", "openResult": "0xb", "lots": 5, "credits": 7, "cursor": 3, "count": 3, "head": 10})
        a_ok = json.dumps({"lastAcked": "0xa", "openResult": "0xb", "lots": 5, "credits": 7, "cursor": 4, "count": 4, "head": 12})
        a_bad = json.dumps({"lastAcked": "0xa", "openResult": "0xc", "lots": 5, "credits": 7, "cursor": 4, "count": 4, "head": 12})
        for after, want in ((a_ok, True), (a_bad, False)):
            r = sh(f"x4f_write t '{b}' '{after}' '{{}}' && cat $X4F_DIR/t.json", self.h3)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIs(json.loads(r.stdout)["stable"], want)


if __name__ == "__main__":
    unittest.main()
