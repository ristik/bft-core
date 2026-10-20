#!/usr/bin/env python3
"""Self-tests of the X4 shadow adapter (stdlib unittest; run in CI by .github/workflows/x4-shadow-selftest.yml). They show that the comparator and the
coverage rule catch every kind of divergence and gap they are meant to, that the independent reference reproduces the xrepo-shared selection and
continuity vectors (and that a mutated vector fails: the canary), that the fork refuses every unsafe endpoint, and that a recorded real snapshot replays."""
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import adapter  # noqa: E402
import chain  # noqa: E402
import compare  # noqa: E402
import fork  # noqa: E402
import reference as ref  # noqa: E402
import report  # noqa: E402
from keccak import keccak256  # noqa: E402

ROOT = HERE.parent.parent
SELECTION_VECTORS = ROOT / "continuity/testdata/selection-vectors.json"
CONTINUITY_VECTORS = ROOT / "continuity/testdata/continuity-vectors.json"
RECORDED = HERE / "testdata"
Z = b"\0" * 32
UCT = 10**18


def jload(path):
    with open(path) as fh:
        return json.load(fh)


def b32(n):
    return n.to_bytes(32, "big")


def make_inputs(spares=(), incumbents=(1, 2, 3, 4), retired=(), excluded=(), ref_count=0, progress=100_000, uc_time=604_800, open_result=Z, bonds=None):
    """A synthetic raw-input snapshot: bonded identities 1..N, each with one lot (1000 UCT by default: weight 10 at a 100 UCT unit; `bonds` overrides per id), the
    incumbents committed with weight 10. A spare of full weight is refused by the distance bound (it shifts a quarter of the weight); a light spare is accepted."""
    ids = sorted(set(incumbents) | set(spares))
    bonds = bonds or {}
    identities, lot_table = [], {}
    for i in ids:
        lot_id = 1000 + i
        lot_table[lot_id] = {"id": lot_id, "generation": 1, "remaining": bonds.get(i, 1000) * UCT, "category": 1, "refCount": ref_count if i in incumbents else 0}
        identities.append({"id": i, "indexed": True,
                           "position": {"owner": 0xA0 + i, "withdrawal": 0xB0 + i, "rootKeyHash": b32(0x1000 + i), "stagedRootKeyHash": Z, "generation": 1, "roleNonce": 0,
                                        "openLots": 1, "lotCount": 1, "retirementRequested": i in retired},
                           "excluded": i in excluded,
                           "staged": {"bindingHash": b32(0x3000 + i), "rootKeyHash": b32(0x1000 + i), "evmKeyHash": b32(0x2000 + i), "payee": "0x" + format(0xC0 + i, "040x")},
                           "keyOwner": (i, 2), "lots": [lot_table[lot_id]]})
    exposures = [{"id": i, "generation": 1, "weight": 10, "rawWeight": 10, "rootKeyHash": b32(0x1000 + i), "evmKeyHash": b32(0x2000 + i),
                  "payee": "0x" + format(0xC0 + i, "040x"), "lots": [1000 + i]} for i in incumbents]
    return {"format": "UNICITY_X4_SHADOW_INPUTS/v1", "chainId": 31337, "block": {"number": 77, "hash": "0x" + "ab" * 32, "stateRoot": "0x" + "cd" * 32, "timestamp": 1},
            "modules": {}, "origin": b32(0x5151),
            "election": {"address": "0x" + format(0xE1, "040x"), "initialized": True, "network": b32(0x7e7), "anchorProgress": 0, "anchorTime": 0, "attemptProgress": 0,
                         "attemptTime": 0, "attemptCursor": 0, "openResult": open_result,
                         "params": {"nMin": 4, "nTarget": 10, "nMax": 16, "maxM": 4, "distNum": 1, "distDen": 4, "cadenceRounds": 100_000, "cadenceSeconds": 604_800}},
            "clock": {"recordCount": 3, "custodyCursor": 3, "progress": progress, "ucTime": uc_time},
            "custody": {"bondUnit": 100 * UCT, "minBond": 100 * UCT, "nextStakingID": max(ids), "lastAckedAssignment": b32(0x6a6a),
                        "limits": {"vMax": 128, "lMax": 8, "rMax": 4, "maxBatch": 32}},
            "policy": {"currentPolicyID": 1}, "identities": identities,
            "incumbent": {"assignmentID": b32(0x6a6a), "lineage": b32(0x11), "rootEpoch": 1, "evmEpoch": 1, "exposureDigest": b32(0x21), "keyDigest": b32(0x22), "policyID": 1,
                          "exposures": exposures, "policyTerms": list(range(10))},
            "lotTable": lot_table,
            "moduleDigestInputs": ["0x" + format(a, "040x") if i % 2 == 0 else b32(a) for i, a in enumerate((1, 2, 3, 4, 5, 6, 7, 8, 9, 10))] + ["0x" + format(11, "040x")]}


def contract_like(expected):
    """A contract output identical to the reference's (what an agreeing contract returns)."""
    return json.loads(json.dumps(expected))


class Keccak(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        self.assertEqual(keccak256(b"a" * 200).hex(), "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d")  # a message of two blocks (rate 136), value from cast keccak

    def test_a_multi_block_message_differs_from_sha3(self):
        import hashlib
        self.assertNotEqual(keccak256(b"abc"), hashlib.sha3_256(b"abc").digest())


class ReferenceVectors(unittest.TestCase):
    """The reference replays the xrepo-shared vectors (the Go reference's output, replayed by the Solidity port)."""

    def run_selection(self, cases):
        bad = []
        for c in cases:
            o = [{"id": m["id"], "binding": m["binding"], "weight": m["weight"]} for m in c["old"]]
            e = [{"id": m["id"], "binding": m["binding"], "weight": m["weight"]} for m in c["eligible"]]
            reason, chosen = ref.select(o, e, c["config"])
            if reason != c["reason"] or [m["id"] for m in chosen] != c["chosen"] or [m["weight"] for m in chosen] != c["chosenWeights"]:
                bad.append(c["name"])
        return bad

    def test_selection_vectors(self):
        cases = jload(SELECTION_VECTORS)["cases"]
        self.assertGreater(len(cases), 500)
        self.assertEqual(self.run_selection(cases), [])

    def test_continuity_vectors(self):
        cases = jload(CONTINUITY_VECTORS)["cases"]
        self.assertGreater(len(cases), 400)
        for c in cases:
            p = {"maxM": c["maxM"], "distNum": c["distNum"], "distDen": c["distDen"]}
            try:
                failed, m = ref.check(c["old"], c["new"], p)
            except ValueError:
                self.assertTrue(c["invalid"], c["name"])
                continue
            self.assertFalse(c["invalid"], c["name"])
            want = c["result"]
            got = {k: m[k] for k in ("replaced", "removed", "added", "m", "unchangedOld", "unchangedNew", "totalOld", "totalNew")}
            got.update(distanceNumerator=str(m["distanceNumerator"]), failed=failed)
            self.assertEqual(got, want, c["name"])

    def test_canary_a_mutated_selection_vector_fails(self):
        cases = copy.deepcopy(jload(SELECTION_VECTORS)["cases"])
        victims = [c for c in cases if c["chosen"]][:1]
        victims[0]["chosen"] = victims[0]["chosen"][:-1]
        self.assertEqual(self.run_selection(victims), [victims[0]["name"]])
        weights = copy.deepcopy(next(c for c in cases if c["chosenWeights"]))
        weights["chosenWeights"][0] += 1
        self.assertEqual(self.run_selection([weights]), [weights["name"]])
        reason = copy.deepcopy(cases[0])
        reason["reason"] = (reason["reason"] + 1) % 5
        self.assertEqual(self.run_selection([reason]), [reason["name"]])

    def test_canary_a_mutated_continuity_vector_fails(self):
        c = copy.deepcopy(next(x for x in jload(CONTINUITY_VECTORS)["cases"] if not x["invalid"]))
        p = {"maxM": c["maxM"], "distNum": c["distNum"], "distDen": c["distDen"]}
        _, m = ref.check(c["old"], c["new"], p)
        self.assertEqual(str(m["distanceNumerator"]), c["result"]["distanceNumerator"])
        c["result"]["distanceNumerator"] = str(int(c["result"]["distanceNumerator"]) + 1)
        self.assertNotEqual(str(m["distanceNumerator"]), c["result"]["distanceNumerator"])


class ReferenceElection(unittest.TestCase):
    def test_unchanged_committee_is_reserved(self):
        out = ref.expected(make_inputs())
        self.assertEqual((out["outcome"], out["reason"]), ("Reserved", "None"))
        self.assertEqual([f["id"] for f in out["frozen"]], [1, 2, 3, 4])
        self.assertEqual(compare.case_of(out, make_inputs()["incumbent"]["exposures"]), "unchanged")
        self.assertEqual(out["openResultAfter"], out["resultID"])

    def test_a_valid_changed_candidate(self):
        inp = make_inputs(spares=(5,), bonds={5: 100})
        out = ref.expected(inp)
        self.assertEqual([f["id"] for f in out["frozen"]], [1, 2, 3, 4, 5])
        heavy = ref.expected(make_inputs(spares=(5,)))
        self.assertEqual((heavy["outcome"], heavy["reason"]), ("NoCandidateRecorded", "WeightChurn"), "a spare of full weight breaks the distance bound")
        self.assertEqual(compare.case_of(out, inp["incumbent"]["exposures"]), "changed")

    def test_refusals(self):
        self.assertEqual(ref.expected(make_inputs(retired=(2, 3, 4)))["reason"], "Cardinality")
        over = ref.expected(make_inputs(spares=(5, 6, 7, 8, 9)))
        self.assertEqual((over["outcome"], over["reason"]), ("NoCandidateRecorded", "MembershipChurn"))
        self.assertEqual(ref.expected(make_inputs(ref_count=4))["reason"], "ReferenceCapacity")

    def test_idle_outcomes(self):
        self.assertEqual(ref.expected(make_inputs(progress=99_999))["outcome"], "NotDue")
        self.assertEqual(ref.expected(make_inputs(uc_time=604_799))["outcome"], "NotDue")
        self.assertEqual(ref.expected(make_inputs(open_result=b32(9)))["outcome"], "Disabled")
        inp = make_inputs()
        inp["clock"]["custodyCursor"] = 2
        self.assertEqual(ref.expected(inp)["outcome"], "Disabled")

    def test_eligibility_rules(self):
        eligible_ids = lambda inp: [c["id"] for c in ref.eligible(inp, Z)[0]]  # noqa: E731
        self.assertEqual(eligible_ids(make_inputs(spares=(5,))), [1, 2, 3, 4, 5])
        self.assertEqual(eligible_ids(make_inputs(spares=(5,), excluded=(5,))), [1, 2, 3, 4])
        self.assertEqual(eligible_ids(make_inputs(spares=(5,), retired=(5,))), [1, 2, 3, 4])
        low = make_inputs(spares=(5,))
        low["identities"][-1]["lots"][0]["remaining"] = 99 * UCT
        self.assertEqual(eligible_ids(low), [1, 2, 3, 4], "principal below B_min")
        wrong_key = make_inputs(spares=(5,))
        wrong_key["identities"][-1]["keyOwner"] = (6, 2)
        self.assertEqual(eligible_ids(wrong_key), [1, 2, 3, 4], "EVM key registered to another identity")
        released = make_inputs(spares=(5,))
        released["identities"][-1]["lots"][0]["category"] = 4
        self.assertEqual(eligible_ids(released), [1, 2, 3, 4], "no unreleased lot")

    def test_the_snapshot_digest_folds_every_eligible_identity_in_order(self):
        a = ref.eligible(make_inputs(), Z)[1]
        b = ref.eligible(make_inputs(spares=(5,)), Z)[1]
        self.assertNotEqual(a, b)
        self.assertEqual(ref.eligible(make_inputs(retired=(1, 2, 3, 4)), b32(5))[1], b32(5), "an empty snapshot is the seed")


class Comparator(unittest.TestCase):
    """Every compared field, mutated on either side, is a FAIL with the mismatch located; equal outputs compare equal."""

    def setUp(self):
        self.inp = make_inputs(spares=(5,), bonds={5: 100})
        self.ref = ref.expected(self.inp)
        self.assertEqual(self.ref["outcome"], "Reserved")

    def mutate(self, out, path):
        out = copy.deepcopy(out)
        if path in compare.SCALARS:
            out[path] = "mutated" if isinstance(out.get(path), str) else (out.get(path) or 0) + 1
        elif path in ("frozen.length", "members.length"):
            out[path.split(".")[0]].pop()
        elif path.endswith(".present"):
            out[path.split(".")[0]] = None
        else:
            head, key = path.split(".")
            if head.endswith("[]"):
                item = out[head[:-2]][0]
                v = item[key]
                item[key] = v + [99] if isinstance(v, list) else ("mutated" if isinstance(v, str) else v + 1)
            else:
                v = out[head][key]
                out[head][key] = "mutated" if isinstance(v, str) else v + 1
        return out

    def test_equal_outputs_agree(self):
        self.assertEqual(compare.compare(contract_like(self.ref), self.ref), [])

    def test_every_field_is_checked_on_both_sides(self):
        tested = 0
        for path in compare.paths():
            for side in ("contract", "reference"):
                a, b = contract_like(self.ref), copy.deepcopy(self.ref)
                if side == "contract":
                    a = self.mutate(a, path)
                else:
                    b = self.mutate(b, path)
                mism = compare.compare(a, b)
                self.assertTrue(mism, f"{path} mutated on the {side} side went unnoticed")
                key = path.replace("[]", "[0]")
                self.assertTrue(any(m["field"].startswith(key.split(".")[0]) for m in mism), f"{path}: {mism}")
                tested += 1
        self.assertGreater(tested, 60)

    def test_the_mismatch_names_the_field_and_both_values(self):
        c = contract_like(self.ref)
        c["frozen"][2]["weight"] += 7
        (m,) = compare.compare(c, self.ref)
        self.assertEqual((m["field"], m["contract"] - 7, m["reference"]), ("frozen[2].weight", self.ref["frozen"][2]["weight"], self.ref["frozen"][2]["weight"]))

    def test_the_compared_paths_cover_every_key_of_a_reserved_output(self):
        covered = {p for p, _ in compare.leaves(self.ref)}
        for k in self.ref:
            self.assertTrue(any(c == k or c.startswith(k + ".") or c.startswith(k + "[") for c in covered), f"{k} is not compared")


def row(case, verdict="MATCH", digest="d"):
    return {"verdict": verdict, "case": case, "inputDigest": digest}


def good_rows(n_due=24):
    rows = [row("changed", digest=str(i)) for i in range(8)] + [row("unchanged", digest=str(8 + i)) for i in range(8)]
    rows += [row("refusal:MembershipChurn", digest=str(16 + i)) for i in range(4)] + [row("refusal:Cardinality", digest=str(20 + i)) for i in range(4)]
    return rows + [row("NotDue")] * 3


class Coverage(unittest.TestCase):
    def test_pass(self):
        rows = good_rows()
        cov = report.coverage(rows, len(rows))
        self.assertEqual((cov["status"], cov["dueComparisons"]), ("PASS", 24), cov["reasons"])

    def test_a_mismatch_is_fail(self):
        rows = good_rows()
        rows[3] = row("changed", "MISMATCH", "x")
        self.assertEqual(report.coverage(rows, len(rows))["status"], "FAIL")

    def test_a_skipped_sample_is_incomplete(self):
        rows = good_rows()
        cov = report.coverage(rows[:-1], len(rows))
        self.assertEqual(cov["status"], "INCOMPLETE")
        self.assertTrue(any("accounted" in r for r in cov["reasons"]))

    def test_a_gap_is_incomplete_never_equality(self):
        rows = good_rows() + [{"verdict": "GAP", "case": "gap", "inputDigest": ""}]
        cov = report.coverage(rows, len(rows))
        self.assertEqual(cov["status"], "INCOMPLETE")
        self.assertEqual(cov["dueComparisons"], 24)

    def test_a_vacuous_repeated_answer_is_incomplete(self):
        rows = [row("changed")] * 8 + [row("unchanged")] * 8 + [row("refusal:MembershipChurn")] * 8
        cov = report.coverage(rows, len(rows))
        self.assertEqual(cov["status"], "INCOMPLETE")
        self.assertTrue(any("vacuous" in r for r in cov["reasons"]))

    def test_idle_observations_are_not_due_coverage(self):
        rows = good_rows()[:23] + [row("NotDue")] * 40
        cov = report.coverage(rows, len(rows))
        self.assertEqual((cov["status"], cov["dueComparisons"]), ("INCOMPLETE", 23))

    def test_each_case_needs_two_and_an_over_bound_refusal(self):
        for drop in ("changed", "unchanged"):
            rows = [r for r in good_rows() if r["case"] != drop] + [row(drop, digest="z")] + [row("refusal:Cardinality", digest=f"c{i}") for i in range(8)]
            cov = report.coverage(rows, len(rows))
            self.assertEqual(cov["status"], "INCOMPLETE", drop)
        no_over_bound = [r for r in good_rows() if r["case"] != "refusal:MembershipChurn"] + [row("refusal:Cardinality", digest=f"q{i}") for i in range(4)]
        cov = report.coverage(no_over_bound, len(no_over_bound))
        self.assertEqual(cov["status"], "INCOMPLETE")
        self.assertTrue(any("over-bound" in r for r in cov["reasons"]))


class ForkSafety(unittest.TestCase):
    PIN = {"number": 77, "hash": "0x" + "ab" * 32, "chainId": 31337}

    def make(self, **over):
        f = fork.Fork("http://node.example:8545", self.PIN, command=["true"])
        f.proc = mock.Mock(**{"poll.return_value": None, "pid": 4242})
        f.rpc.chain_id = lambda: over.get("chain", 31337)
        f.rpc.block = lambda n: {"hash": over.get("hash", self.PIN["hash"])}
        return f

    def test_the_verified_loopback_fork_accepts_writes(self):
        f = self.make()
        ev = f.verify()
        self.assertEqual((ev["port"], ev["chainId"]), (f.port, 31337))
        self.assertTrue(f.rpc.verified)

    def test_every_unsafe_endpoint_is_refused(self):
        cases = {"a non-loopback host": lambda f: setattr(f.rpc, "url", f"http://10.0.0.5:{f.port}"),
                 "another port": lambda f: setattr(f.rpc, "url", f"http://127.0.0.1:{f.port + 1}"),
                 "the source node's own URL": lambda f: (setattr(f, "source_url", f.url)),
                 "a dead child": lambda f: setattr(f.proc, "poll", lambda: 1)}
        for name, breaker in cases.items():
            f = self.make()
            breaker(f)
            with self.assertRaises(fork.ForkRefused, msg=name):
                f.verify()
            self.assertFalse(f.rpc.verified, name)

    def test_a_wrong_chain_or_block_is_refused(self):
        with self.assertRaises(fork.ForkRefused):
            self.make(chain=1).verify()
        with self.assertRaises(fork.ForkRefused):
            self.make(hash="0x" + "00" * 32).verify()

    def test_writes_are_refused_before_verification(self):
        f = fork.Fork("http://node.example:8545", self.PIN, command=["true"])
        with self.assertRaises(chain.RpcError):
            f.rpc.send(fork.SYSTEM_CALLER, "0x" + "11" * 20, b"")

    def test_a_receipt_that_arrives_late_is_waited_for_and_one_that_never_does_is_an_error(self):
        f = fork.Fork("http://node.example:8545", self.PIN, command=["true"])
        f.rpc.verified = True
        answers = iter(["0xabc", None, None, {"status": "0x1"}])
        f.rpc.request = lambda m, p: next(answers)
        self.assertEqual(f.rpc.send(fork.SYSTEM_CALLER, "0x" + "11" * 20, b""), 1)
        g = fork.Fork("http://node.example:8545", self.PIN, command=["true"])
        g.rpc.verified = True
        g.rpc.request = lambda m, p: "0xabc" if m == "eth_sendTransaction" else None
        with self.assertRaises(chain.RpcError):
            g.rpc.send(fork.SYSTEM_CALLER, "0x" + "11" * 20, b"", wait=0.5)

    def test_the_authoritative_endpoint_has_no_write_method(self):
        rpc = chain.ReadOnlyRpc("http://node.example:8545")
        for m in ("eth_sendTransaction", "eth_sendRawTransaction", "evm_mine", "anvil_impersonateAccount"):
            with self.assertRaises(chain.RpcError):
                rpc.request(m, [])
        self.assertFalse(hasattr(rpc, "send"))


class RecordedReplay(unittest.TestCase):
    """A recorded real snapshot (testdata/recorded/*): the reference recomputed offline equals the contract output recorded from the real election on the fork."""

    def test_recorded_snapshots_replay(self):
        dirs = sorted(RECORDED.glob("recorded/raw/*")) if RECORDED.exists() else []
        if not dirs:
            self.skipTest("no recorded snapshot checked in yet")
        for d in dirs:
            inp = adapter.load_inputs(d / "inputs.json")
            contract = jload(d / "contract.json")
            self.assertEqual(compare.compare(contract, ref.expected(inp)), [], d.name)
            bad = copy.deepcopy(contract)
            bad["attempt"] = bad.get("attempt", 0) + 1
            self.assertTrue(compare.compare(bad, ref.expected(inp)), "a mutated recorded output must fail")


if __name__ == "__main__":
    unittest.main()
