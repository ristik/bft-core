import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('vr_utb_committee', Path(__file__).resolve().parents[2] / 'scripts/vr-utb-committee.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

fake = lambda b: '0x' + bytes(b).hex()   # a stand-in for keccak: the comparison logic only needs equal inputs to hash equal


def member(i, weight, raw):
    return dict(id=i, weight=weight, raw=raw, node=fake(('n%d' % i).encode()), key=fake(bytes([i])))


class CommitteeCheck(unittest.TestCase):
    def entry(self, weights):
        return [('n%d' % (i + 1), w, bytes([i + 1])) for i, w in enumerate(weights)]

    def test_effective_weights_and_threshold_pass_where_raw_differs(self):
        vr = [member(1, 6, 100), member(2, 1, 10), member(3, 1, 10), member(4, 1, 10)]
        self.assertIn('exactly the committee VR installed', mod.compare(self.entry([6, 1, 1, 1]), 7, vr, fake))

    def test_a_raw_weight_match_is_refused(self):
        vr = [member(1, 6, 100), member(2, 1, 10), member(3, 1, 10), member(4, 1, 10)]
        with self.assertRaises(SystemExit):
            mod.compare(self.entry([100, 10, 10, 10]), 111, vr, fake)

    def test_a_wrong_threshold_is_refused(self):
        vr = [member(i, 1, 1) for i in (1, 2, 3, 4)]
        with self.assertRaises(SystemExit):
            mod.compare(self.entry([1, 1, 1, 1]), 4, vr, fake)

    def test_a_missing_or_extra_member_is_refused(self):
        vr = [member(i, 1, 1) for i in (1, 2, 3)]
        with self.assertRaises(SystemExit):
            mod.compare(self.entry([1, 1, 1, 1]), 3, vr, fake)


if __name__ == '__main__':
    unittest.main()
