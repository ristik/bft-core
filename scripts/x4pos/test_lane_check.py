#!/usr/bin/env python3
"""lane-check.sh against a fixture of the files a passing lane leaves (the shapes the publisher's gates read): every phase passes on the full fixture, and each phase is refused when its step is
not recorded or its artifact no longer shows the effect. Stdlib only, no chain."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "lane-check.sh"
ZERO = "0x" + "00" * 32
STEPS = ("p85_baseline x4a_snapshot p85_joiner_nodes p85_joiner_onboard p85_election_reserved p85_proofs p85_handoff p85_install_activation s4_equivocate p85_j_stalls p85_recovery p85_resolved "
         "s4_collect_after_rotation x4e_request s4_submit_settle s4_check x4o_second p85_restarts p85_epoch_switches x4r_intervals x4r_dry_refill x4r_claim x4o_claim x4e_claim x4g_queue x4g_execute x4g_check x4f_root_restart x4f_evm_restart x4f_pair_restart x4f_delayed_episode x4f_soak x4f_reconcile x4a_final").split()
PHASES = {"baseline": "p85_baseline", "rewards": "x4r_claim", "replacement": "p85_handoff", "recovery": "p85_resolved", "epoch-switches": "p85_epoch_switches", "offence-1": "s4_check", "offence-2": "x4o_second",
          "exit-request": "x4e_request", "exit-claim": "x4e_claim", "governance-queue": "x4g_queue", "governance": "x4g_check", "fault-root-restart": "x4f_root_restart", "fault-evm-restart": "x4f_evm_restart", "fault-pair-restart": "x4f_pair_restart",
          "fault-delayed-episode": "x4f_delayed_episode", "soak": "x4f_soak", "reconcile": "x4f_reconcile", "accounting": "x4a_final"}
REPLAY = {"intervals": 2, "zeroBudget": 1, "paid": 1, "fundings": 1, "claims": 0, "refilledAfterExhaustion": True}


def put(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc))


def fixture(root):
    d, s4b = root / "x4pos", root / "s4b"
    put(d / "lane-steps.log", "\n".join(STEPS) + "\n")
    put(d / "snapshots.jsonl", json.dumps({"t": 1, "payments": [["tx:0", "0xa", 5]]}) + "\n")
    put(d / "accounting.txt", {"status": "PASS", "snapshots": 5})
    put(d / "steps/xr/replay-after.txt", "REWARDS-REPLAY ok " + json.dumps(REPLAY) + "\n")
    put(s4b / "post-settle.json", {"epoch": 3, "roundAfterSettle": 5, "roundAfterPaidTx": 9, "lastAckedUnchanged": True, "paidTxOk": True, "openResultUnchanged": True, "lostAfterSettlement": 1, "laterResultStateAfter": 1})
    put(s4b / "pre-submit.json", {"epoch": 3, "openResult": "0x" + "11" * 32, "state": 1, "predecessorIsK": True, "lostBefore": 0})
    put(s4b / "lost-after-admission.txt", "1\n")
    put(d / "steps/exit-request/request.json", {"imported": True, "pRet": 4, "tRet": 7})
    put(d / "steps/exit-request/hold-probe.json", {"outcome": "refused", "reason": "EvidenceHoldPending"})
    put(d / "steps/exit-claim/refusal.json", {"outcome": "refused", "lawfulEarly": True})
    put(d / "steps/exit-claim/matured.json", {"creditDelta": 3})
    put(d / "steps/exit-claim/claimed.json", {"received": 3})
    for n in ("root-restart", "evm-restart"):
        put(d / f"steps/faults/{n}.json", {"fault": n, "stable": True, "paidTxOk": True})
    put(d / "steps/faults/pair-restart.json", {"fault": "pair-restart", "stable": True, "paidTxOk": True, "byteIdentical": True, "blockHash": "0x" + "ab" * 32, "pool": {"unchanged": True}})
    put(d / "steps/faults/delayed-episode.json", {"fault": "delayed-episode", "stable": True, "paidTxOk": True, "shardFrozenDuringOutage": True, "rootsExtendedDuringOutage": True, "logOrdered": True,
                                                  "before": {"rootRound": 10, "evmRound": 5}, "during": {"rootRound": 120, "evmRound": 5}, "after": {"cursor": 9, "count": 9}})
    put(d / "steps/faults/soak.json", {"snapshots": 8})
    put(d / "steps/faults/reconcile-cursors.json", {"converged": True})
    put(d / "steps/reconcile/reconcile.json", {"conserved": True, "intervals": 2, "zeroBudget": 1, "fundings": 1, "refilledAfterExhaustion": True})
    put(d / "steps/gov/queued.json", {"nonce": 1, "rateBefore": "1000", "rateProposed": "500", "policyIdBefore": 1})
    put(d / "steps/gov/outcome.json", {"policyIdBefore": 1, "policyIdAfter": 1, "activated": False, "waitedSeconds": 1800})
    return d, s4b


def run(d, s4b, phase):
    env = dict(os.environ, X4_LANE_DIR=str(d), X4_S4B_DIR=str(s4b))
    return subprocess.run(["bash", str(SCRIPT), phase], env=env, capture_output=True, text=True)


class LaneCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d, self.s4b = fixture(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_phase_passes_on_the_full_fixture(self):
        for ph in PHASES:
            with self.subTest(ph):
                r = run(self.d, self.s4b, ph)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_phase_whose_step_is_not_recorded_is_refused(self):
        for ph, step in PHASES.items():
            with self.subTest(ph):
                put(self.d / "lane-steps.log", "\n".join(s for s in STEPS if s != step) + "\n")
                r = run(self.d, self.s4b, ph)
                self.assertEqual(r.returncode, 1)
                self.assertIn(f"step {step} is not recorded", r.stderr)
                put(self.d / "lane-steps.log", "\n".join(STEPS) + "\n")

    def test_an_artifact_that_no_longer_shows_the_effect_is_refused(self):
        cases = [("rewards", self.d / "steps/xr/replay-after.txt", "REWARDS-REPLAY ok " + json.dumps(dict(REPLAY, zeroBudget=0)) + "\n", "dry, refilled"),
                 ("rewards", self.d / "snapshots.jsonl", json.dumps({"t": 1, "payments": []}) + "\n", "no pool payment"),
                 ("offence-2", self.s4b / "post-settle.json", {"epoch": 3, "roundAfterSettle": 5, "roundAfterPaidTx": 5, "lastAckedUnchanged": True, "paidTxOk": True, "openResultUnchanged": True, "lostAfterSettlement": 1, "laterResultStateAfter": 1}, "post-settle"),
                 ("offence-2", self.s4b / "pre-submit.json", {"epoch": 3, "state": 1, "predecessorIsK": True, "lostBefore": 0}, "pre-submit"),   # no openResult key (null != zero in jq)
                 ("offence-2", self.s4b / "pre-submit.json", {"epoch": 3, "openResult": ZERO, "state": 1, "predecessorIsK": True, "lostBefore": 0}, "pre-submit"),
                 ("offence-2", self.s4b / "lost-after-admission.txt", "0\n", "lost-after-admission"),
                 ("exit-request", self.d / "steps/exit-request/hold-probe.json", {"outcome": "refused", "reason": "RoundGateNotMet"}, "hold-probe"),
                 ("exit-claim", self.d / "steps/exit-claim/claimed.json", {"received": 0}, "claimed.json"),
                 ("governance-queue", self.d / "steps/gov/queued.json", {"nonce": 1, "rateBefore": "1000", "rateProposed": "1000", "policyIdBefore": 1}, "queued.json"),
                 ("governance", self.d / "steps/gov/outcome.json", {"policyIdBefore": 1, "policyIdAfter": 1, "activated": "no", "waitedSeconds": 1800}, "outcome.json"),
                 ("fault-root-restart", self.d / "steps/faults/root-restart.json", {"fault": "root-restart", "stable": False, "paidTxOk": True}, "root-restart.json"),
                 ("fault-evm-restart", self.d / "steps/faults/evm-restart.json", {"fault": "evm-restart", "stable": True, "paidTxOk": False}, "evm-restart.json"),
                 ("fault-pair-restart", self.d / "steps/faults/pair-restart.json", {"fault": "pair-restart", "stable": True, "paidTxOk": True, "byteIdentical": True, "blockHash": "0x" + "ab" * 32, "pool": {"unchanged": False}}, "pair-restart.json"),
                 ("fault-delayed-episode", self.d / "steps/faults/delayed-episode.json", {"fault": "delayed-episode", "stable": True, "paidTxOk": True, "shardFrozenDuringOutage": True, "rootsExtendedDuringOutage": True, "logOrdered": True,
                                                                                           "before": {"rootRound": 10, "evmRound": 5}, "during": {"rootRound": 10, "evmRound": 5}, "after": {"cursor": 9, "count": 9}}, "delayed-episode.json"),
                 ("fault-delayed-episode", self.d / "steps/faults/delayed-episode.json", {"fault": "delayed-episode", "stable": True, "paidTxOk": True, "shardFrozenDuringOutage": False, "rootsExtendedDuringOutage": True, "logOrdered": True,
                                                                                           "before": {"rootRound": 10, "evmRound": 5}, "during": {"rootRound": 120, "evmRound": 5}, "after": {"cursor": 9, "count": 9}}, "delayed-episode.json"),
                 ("fault-pair-restart", self.d / "steps/faults/pair-restart.json", {"fault": "pair-restart", "stable": True, "paidTxOk": True, "byteIdentical": False, "blockHash": "0x" + "ab" * 32, "pool": {"unchanged": True}}, "pair-restart.json"),
                 ("reconcile", self.d / "steps/reconcile/reconcile.json", {"conserved": False, "intervals": 2, "zeroBudget": 1, "fundings": 1, "refilledAfterExhaustion": True}, "reconcile.json"),
                 ("soak", self.d / "steps/faults/soak.json", {"snapshots": 1}, "soak.json"),
                 ("reconcile", self.d / "steps/faults/reconcile-cursors.json", {"converged": False}, "reconcile-cursors.json"),
                 ("reconcile", self.d / "steps/reconcile/reconcile.json", {"conserved": True, "intervals": 2, "zeroBudget": 0, "fundings": 1, "refilledAfterExhaustion": True}, "reconcile.json"),
                 ("accounting", self.d / "accounting.txt", {"status": "PASS", "snapshots": 3}, "at least 4")]
        for ph, path, doc, msg in cases:
            with self.subTest(ph + " " + path.name + " " + msg):
                good = path.read_text()
                put(path, doc)
                r = run(self.d, self.s4b, ph)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn(msg, r.stderr)
                path.write_text(good)

    def test_missing_environment_and_unknown_phase_are_refused(self):
        self.assertEqual(subprocess.run(["bash", str(SCRIPT), "baseline"], env={"PATH": os.environ["PATH"]}, capture_output=True, text=True).returncode, 1)
        self.assertEqual(run(self.d, self.s4b, "nope").returncode, 1)


if __name__ == "__main__":
    unittest.main()
