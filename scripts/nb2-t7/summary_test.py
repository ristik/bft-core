"""Replay an archived slot-3 qualification run with corrupted evidence."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SUMMARY = Path(__file__).with_name('summarize-erc20.py')
UCT = 'native UCT alongside two ERC20s'
RESERVE = 'observed funded 64-gap schedule'


class SummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp:
            cls.baseline = cls.checks(cls.archive, Path(tmp) / 'baseline.json')
        if cls.baseline[UCT] != 'PASS' or cls.baseline[RESERVE] != 'PASS':
            raise AssertionError(f'fixture did not pass both checks: {cls.baseline}')

    @classmethod
    def checks(cls, run, output):
        result = subprocess.run([sys.executable, SUMMARY, run, output, '--plugin', cls.plugin],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(output.read_text())['checks']

    def corrupt(self, relative, data):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / 'run'
            shutil.copytree(self.archive, run, copy_function=os.symlink, symlinks=True)
            artifact = run / relative
            artifact.unlink()
            artifact.write_bytes(data)
            return self.checks(run, Path(tmp) / 'summary.json')

    def test_tampered_receipt_proof_fails_uct_control(self):
        proof = bytearray((self.archive / 'ordinary.cbor').read_bytes())
        proof[-1] ^= 1
        checks = self.corrupt('ordinary.cbor', proof)
        self.assertEqual(checks, {**self.baseline, UCT: 'FAIL'})

    def test_empty_signed_advance_fails_funded_schedule(self):
        checks = self.corrupt('fee/recovered/offline-advance-64.signed', b'')
        self.assertEqual(checks, {**self.baseline, RESERVE: 'FAIL'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=lambda value: Path(value).resolve())
    parser.add_argument('--plugin', type=Path, required=True)
    args, unittest_args = parser.parse_known_args()
    SummaryTests.archive = args.archive
    SummaryTests.plugin = args.plugin
    unittest.main(argv=[sys.argv[0], *unittest_args])
