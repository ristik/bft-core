"""Tests of the VR generation tooling's dev path (VT-14): the shared dev-key generator, vr_genesis.py --dev-fund's argument rules, and the
paired devnet's VR_LANE guard (which must refuse before setup touches test-nodes)."""
import itertools
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import vr_dev_keys  # noqa: E402


def fake_keys():
    counter = itertools.count(1)
    return lambda: (lambda i: {'address': '0x%040x' % (0x1000 - i), 'privateKey': '0x%064x' % i})(next(counter))


class DevKeys(unittest.TestCase):
    def test_the_keys_are_written_atomically_private_and_in_the_plans_shapes(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'dev-keys'
            keys = vr_dev_keys.write(out, 4, new_key=fake_keys())
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((out / 'keys.json').stat().st_mode), 0o600)
            self.assertEqual(json.loads((out / 'keys.json').read_text()), keys)
            owners = json.loads((out / 'owners.json').read_text())
            self.assertEqual(owners, [{'owner': k['address'], 'payee': k['address']} for k in keys['owners']])
            signers = (out / 'signers.txt').read_text().strip().split(',')
            self.assertEqual(len(signers), 5)
            self.assertEqual(signers, sorted(signers), 'the multisig takes its signers ascending')
            self.assertNotIn('privateKey', (out / 'owners.json').read_text() + (out / 'signers.txt').read_text())

    def test_an_existing_directory_or_key_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'dev-keys'
            vr_dev_keys.write(out, 1, new_key=fake_keys())
            with self.assertRaises(FileExistsError):
                vr_dev_keys.write(out, 1, new_key=fake_keys())
            with self.assertRaises(FileExistsError):
                vr_dev_keys.write_exclusive(out / 'keys.json', 'x', 0o600)

    def test_a_repeated_address_is_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            vr_dev_keys.write(Path(d) / 'k', 2, new_key=lambda: {'address': '0x' + '11' * 20, 'privateKey': '0x01'})


class DevFundArguments(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(HERE / 'vr_genesis.py'), '--contracts', '/nonexistent', '--measurement', '/nonexistent',
                               '--out', '/nonexistent/out', *args], text=True, capture_output=True)

    def test_dev_fund_excludes_the_choices_it_makes_itself(self):
        for extra in (['--network-word', '0x' + '11' * 32], ['--owners', 'o.json'], ['--governor-signers', 'a,b,c,d,e']):
            done = self.run_tool('--fresh-measurement', '/x', '--dev-fund', *extra)
            self.assertEqual(done.returncode, 2, done.stderr)
            self.assertIn('--dev-fund generates the owners and signers', done.stderr)

    def test_the_fresh_measurement_is_exactly_one_explicit_source(self):
        for extra in ([], ['--ureth', '/u', '--fresh-measurement', '/x']):
            done = self.run_tool(*extra)
            self.assertEqual(done.returncode, 2, done.stderr)
            self.assertIn('the fresh measurement is a generation step', done.stderr)


class VRLaneGuard(unittest.TestCase):
    """VR_LANE=1 refuses every lane and probe whose steps would not run on a VR generation, before setup-evm-nodes.sh wipes test-nodes."""

    def lane(self, **env):
        with tempfile.TemporaryDirectory() as d:
            e = dict(os.environ, VR_LANE='1', Q3_B1='1', M2_PROFILE2='1', M2_RUN_LOG_DIR=d, VR_CONTRACTS=d, VR_FRESH_MEASUREMENT='/nonexistent', **env)
            marker = REPO / 'test-nodes' / 'vr-guard-marker'
            existed = marker.parent.exists()
            if existed:
                marker.write_text('x')
            done = subprocess.run(['bash', 'scripts/reth-paired-devnet.sh', '4', '1'], cwd=REPO, env=e, text=True, capture_output=True, timeout=60)
            if existed:
                self.assertTrue(marker.exists(), 'the guard ran after test-nodes was touched')
                marker.unlink()
            else:
                self.assertFalse((REPO / 'test-nodes').exists(), 'the guard ran after test-nodes was created')
            return done

    def test_every_conflicting_lane_is_refused_before_setup(self):
        for flag in ('P85_LANE', 'P85_SHADOW', 'Q4_LIVE_LANE', 'H3_ASSIGNMENT_LANE', 'Q3_WEIGHT_LANE', 'H6_ABORT_LANE', 'F8_MIXED_LANE', 'ANYAGE_LANE',
                     'UTB_LANE', 'D2C_RESTART_PROBE', 'H4_RESTORE_PROBE', 'M2A_FINAL_RESTORE', 'FAUCET_PROBE', 'POST_M2A_SKIP_HANDOFF'):
            with self.subTest(flag=flag):
                done = self.lane(**{flag: '1'})
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertTrue('VR_LANE=1 refuses' in done.stderr or 'requires' in done.stderr, done.stderr)

    def test_the_manifest_genesis_modes_are_refused(self):
        for mode in ('t1', 't4', 't6', 'f7'):
            with self.subTest(mode=mode):
                done = self.lane(POST_M2A_MODE=mode)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)

    def test_the_inputs_are_checked_before_setup(self):
        done = self.lane()
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('vr:', done.stderr)


if __name__ == '__main__':
    unittest.main()
