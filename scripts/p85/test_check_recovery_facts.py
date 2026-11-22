import copy
import unittest

from check_recovery_facts import check_actual, expected, keccak, word


class RecoveryFactsTest(unittest.TestCase):
    def test_recovery_checks_independent_anchors_digests_and_lot_references(self):
        incumbent, reserved, recovered, result = ["0x" + word(n) for n in range(1, 5)]
        network, registry = "0x" + word(6), "0x" + "ff" * 20
        domains = [keccak(label.encode().hex()) for label in ("unicity.p85.exposure", "unicity.p85.exposure-chain")]
        old = "0x" + word(42)
        snapshot = {
            "result": result, "incumbent": incumbent, "reserved": reserved,
            "incumbent_range": [100, 10], "incumbent_seats": {"1": [1, 10], "2": [1, 20]},
            "reserved_seats": {"2": [1, 20]}, "network": network, "chain": 31337, "registry": registry,
            "facts": {
                "1": {"requested": 1, "live": 1, "references": 1, "anchor": 101, "digest": old},
                "2": {"requested": 0, "live": 2, "references": 2, "anchor": 105, "digest": old},
            },
        }
        records = [
            {"index": 0, "kind": 4, "progress": 105, "data": [incumbent, word(21)]},
            {"index": 1, "kind": 4, "progress": 210, "data": [reserved, word(32)]},
            {"index": 2, "kind": 3, "data": [result, recovered, word(200), word(30)]},
            {"index": 3, "kind": 6, "data": [result, word(0), word(0), word(0), word(0), word(1)]},
        ]
        want = expected(snapshot, records, recovered, *domains)
        self.assertEqual([want[str(i)]["anchor"] for i in (1, 2)], [111, 210])
        self.assertEqual(want["1"]["live"], 1)
        self.assertEqual(want["2"]["references"], 1)
        self.assertNotEqual(want["1"]["digest"], old, "K-only has net-zero references but still appends")
        seats = snapshot["incumbent_seats"]
        certified = {id: entry | {"lot_references": 1} for id, entry in want.items()}
        check_actual(want, certified, seats, seats)

        for id, field, value in [
            ("1", "digest", old), ("2", "references", 2), ("1", "anchor", 101),
            ("2", "live", 2), ("2", "lot_references", 2), ("1", "requested", 0),
        ]:
            with self.subTest(id=id, field=field):
                altered = copy.deepcopy(certified)
                altered[id][field] = value
                with self.assertRaises(ValueError):
                    check_actual(want, altered, seats, seats)

        with self.assertRaisesRegex(ValueError, "historical lot"):
            check_actual(want, certified, seats | {"1": [1, 999]}, seats)
        with self.assertRaisesRegex(ValueError, "closures"):
            expected(snapshot, records[1:], recovered, *domains)


if __name__ == "__main__":
    unittest.main()
