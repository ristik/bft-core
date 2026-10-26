#!/usr/bin/env python3
"""scripts/x4pos/handoff-lib.sh (x4h_second) and the new parts of gov-lib.sh / offence-lib.sh against stub chain functions: no chain, no node. Each test sources the library under a
bash that defines the lane's functions as recorders, runs the step, and reads what it called (in order, with the environment each call saw) and what it wrote. Stdlib only."""
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ZERO = "0x" + "00" * 32
R2, K, K2, G, J = ("0x" + c * 64 for c in "2abcd")

STUBS = r'''
set -u
calls=$OUT/calls.log; : >"$calls"
rec() { printf '%s' "$1" >>"$calls"; shift; for v in "$@"; do printf ' %s' "$v" >>"$calls"; done; printf '\n' >>"$calls"; }
export H3_DIR=$OUT/h3 P85_DIR=$OUT/p85; mkdir -p "$H3_DIR" "$P85_DIR"
rethEthBase=8545; h3_slot_shard=s; h3_slot_root=r
P85_K=$K P85_J=$J P85_G=$G
cat >"$OUT/cast" <<'EOS'
#!/bin/sh
echo 100
EOS
chmod +x "$OUT/cast"; P85_CAST=$OUT/cast
sleep() { :; }
p85_root_epoch() { if [ -f "$OUT/installed" ]; then echo 4; else cat "$OUT/epoch"; fi; }
p85_log_dump() { echo "0 4 10 10 $G -"; echo "5 2 90 90 $R2 $K2"; }
p85_scenario_ids() { :; }
p85_last_acked() { if [ -f "$OUT/ackdone" ]; then cat "$OUT/after"; else cat "$OUT/acked"; fi; }
p85_open_result() { cat "$OUT/open"; }
p85_election() { echo ELECTION; }
p85_call() { case "$2" in 'result(bytes32)') echo RESULT ;; frozenMembers*) cat "$OUT/frozen" ;; esac; }
p85_dec() { cat >/dev/null; case "$1" in result) cat "$OUT/result.json" ;; esac; }
x4o_lost() { cat "$OUT/lost"; }
q3_trust_base_v3() { rec trust_base "$1" "w=$Q3_WEIGHTS"; }
p85_proofs() { rec proofs "tag=$P85_PROOF_TAG" "ents=$P85_PROOF_ENTITIES" "tb=$P85_PROOF_TB_EPOCH" "roots=$P85_PROOF_ROOTS" "result=$(cat "$H3_DIR/result-id.txt")"; }
q3_handoff_n() { rec handoff "$@" "ents=$Q3_ENTITIES" "pents=$P85_PROOF_ENTITIES" "total=$Q3_TOTAL_WEIGHT" "rq=$Q3_ROOT_QUORUM" "eq=$Q3_EVM_QUORUM" "propose=$Q3_PROPOSE_ROOTS"; }
q3_install_n() { rec install "$1" "roots=$H3_ROOTS"; touch "$OUT/installed"; }
q3_activation_n() { rec activation "$@" "total=$Q3_TOTAL_WEIGHT" "rq=$Q3_ROOT_QUORUM" "roots=$H3_ROOTS"; }
h3_advance_authorities() { rec advance "$@" "norep=$M2_ADVANCE_NO_REPLICA_WAIT"; }
h3_registry_is() { [ "$(cat "$OUT/registry")" = "$1 $2" ]; }
h3_slot() { echo "?"; }
p85_paid() { rec paid "$1"; [ ! -f "$OUT/ack" ] || touch "$OUT/ackdone"; }
p85_result_state() { cat "$OUT/state"; }
p85_stuck_report() { echo STUCK >&2; }
p85_assignment() { if [ "$1" = "$K" ]; then cat "$OUT/k.json"; else cat "$OUT/k2.json"; fi; }
p85_cursor() { echo 7; }
p85_log_count() { echo 7; }
p85_log_target() { echo 7; }
'''


def result_json(**kw):
    return dict({"state": 1, "predecessor": K, "assignmentID": K2, "attempt": 3}, **kw)


def scenario(**over):
    s = {"epoch": "3", "acked": K, "open": R2, "lost": "0", "frozen": "[(1, 1, 1, 1, 0xaa), (2, 1, 1, 1, 0xbb), (3, 1, 1, 1, 0xcc), (4, 1, 1, 1, 0xdd)]", "result": result_json(), "state": "3",
         "registry": "3 4", "ack": True, "after": K2, "k": {"closed": 1, "state": 2}, "k2": {"state": 2, "closed": 0, "offsetSet": 1}}
    s.update(over)
    return s


def run_step(sc, step="x4h_second", extra=""):
    with tempfile.TemporaryDirectory() as out:
        o = Path(out)
        (o / "epoch").write_text(sc["epoch"]); (o / "acked").write_text(sc["acked"]); (o / "open").write_text(sc["open"]); (o / "lost").write_text(sc["lost"])
        (o / "frozen").write_text(sc["frozen"]); (o / "result.json").write_text(json.dumps(sc["result"])); (o / "state").write_text(sc["state"]); (o / "registry").write_text(sc["registry"])
        (o / "after").write_text(sc["after"])
        if sc["ack"]:
            (o / "ack").write_text("1")
        (o / "k.json").write_text(json.dumps(sc["k"])); (o / "k2.json").write_text(json.dumps(sc["k2"]))
        script = f'{STUBS}\nsource {ROOT}/scripts/x4pos/handoff-lib.sh\n{extra}\n{step}\n'
        env = dict(os.environ, OUT=out, K=K, J=J, G=G, R2=R2, K2=K2, PATH=os.environ["PATH"])
        r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=120, cwd=ROOT)
        calls = (o / "calls.log").read_text().splitlines()
        rec = json.loads((o / "h3/x4pos/steps/handoff2/second-handoff.json").read_text()) if (o / "h3/x4pos/steps/handoff2/second-handoff.json").exists() else None
        rid = (o / "h3/result-id.txt").read_text().strip() if (o / "h3/result-id.txt").exists() else None
        return r, calls, rec, rid


class SecondHandoff(unittest.TestCase):
    def test_the_whole_flow_in_order_with_the_arguments_the_handoff_needs(self):
        r, calls, rec, rid = run_step(scenario())
        self.assertEqual(r.returncode, 0, r.stderr)
        names = [c.split()[0] for c in calls]
        self.assertEqual(names, ["trust_base", "proofs", "handoff", "install", "activation", "advance", "paid"])
        by = {c.split()[0]: c for c in calls}
        self.assertIn("trust_base 4 w=1 1 1 1", by["trust_base"])
        # the proofs name the second handoff's own files, the four members, the epoch-4 trust base, the old committee, and the result that was open
        self.assertIn("tag=sign2 ents=1 2 3 4 tb=4 roots=1 2 3 4 result=" + R2, by["proofs"])
        # handoff n=3 into epoch 4 with the four unit weights; the successor entities, proofs entities, weights, quorums (W=4: root 3, EVM 3), planning roots
        self.assertIn("handoff 3 4 1 1 1 1 0 ", by["handoff"])
        for part in ("ents=1 2 3 4", "pents=1 2 3 4", "total=4", "rq=3", "eq=3", "propose=1 2 3 4"):
            self.assertIn(part, by["handoff"])
        self.assertEqual(by["install"], "install 4 roots=1 2 3 4")
        self.assertEqual(by["activation"], "activation 3 4 total=4 rq=3 roots=1 2 3 4")   # n=3 (candidate 3), epoch 4, the Commit is K's (W=4, quorum 3)
        self.assertEqual(by["advance"], "advance 4 3 1 2 3 4 norep=1")
        self.assertEqual(by["paid"], "paid 4")
        self.assertEqual(rid, R2)
        self.assertEqual((rec["rootEpochBefore"], rec["rootEpochAfter"], rec["lastAckedBefore"], rec["lastAckedAfter"], rec["resultState"]), (3, 4, K, K2, 3))
        self.assertEqual((rec["entities"], rec["kClosed"], rec["k2Open"], rec["cursor"], rec["count"], rec["target"]), ([1, 2, 3, 4], True, True, 7, 7, 7))
        self.assertIn("PASS: x4h", r.stdout)

    def refused_after_work(self, needle, **over):
        r, calls, rec, _ = run_step(scenario(**over))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(needle, r.stderr)
        self.assertIsNone(rec, "a handoff that did not land is not recorded")
        return calls

    def test_a_handoff_that_does_not_land_is_not_recorded(self):
        self.refused_after_work("is not the result's new assignment", ack=False)   # custody's last acknowledged assignment never moved
        self.refused_after_work("not Acknowledged", state="1")
        # the acknowledged assignment is the result's, but it is K itself again (the same assignment, not a new one)
        self.refused_after_work("is not the result's new assignment", result=result_json(assignmentID=K), after=K)
        self.refused_after_work("is not the result's new assignment", after=J)   # an acknowledged assignment other than the result's
        self.refused_after_work("did not reach shard epoch 3 / root epoch 4", registry="3 3")
        self.refused_after_work("K is not closed", k={"closed": 0, "state": 2})
        self.refused_after_work("K' is not Active and open", k2={"state": 2, "closed": 1, "offsetSet": 1})
        self.refused_after_work("K' is not Active and open", k2={"state": 1, "closed": 0, "offsetSet": 1})

    def refused_before_any_work(self, needle, **over):
        r, calls, rec, _ = run_step(scenario(**over))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(needle, r.stderr)
        self.assertEqual(calls, [], "nothing may be built, restarted or advanced before the preconditions hold")

    def test_the_preconditions(self):
        self.refused_before_any_work("starts from the recovery's epoch 3", epoch="2")
        self.refused_before_any_work("is not the recovery's K", acked="0x" + "ee" * 32)
        self.refused_before_any_work("not a Reserved result from K", result=result_json(state=5))
        self.refused_before_any_work("not a Reserved result from K", result=result_json(predecessor="0x" + "ee" * 32))
        self.refused_before_any_work("already marked lost", lost="1")
        self.refused_before_any_work("names members '1 2 3'", frozen="[(1, 1, 1, 1, 0xaa), (2, 1, 1, 1, 0xbb), (3, 1, 1, 1, 0xcc)]")
        self.refused_before_any_work("names members '1 2 3 5'", frozen="[(1, 1, 1, 1, 0xaa), (2, 1, 1, 1, 0xbb), (3, 1, 1, 1, 0xcc), (5, 1, 1, 1, 0xee)]")


LANE = r'''
set -u
cd "$ROOT"
export P85_LANE_DEFINE_ONLY=1
source scripts/p85-recovery-steps.sh >/dev/null 2>&1
calls=$OUT/calls.log; : >"$calls"
rec() { printf '%s' "$1" >>"$calls"; shift; for v in "$@"; do printf ' %s' "$v" >>"$calls"; done; printf '\n' >>"$calls"; }
export H3_DIR=$OUT/h3 Q3_DIR=$OUT/h3; mkdir -p "$H3_DIR"; echo 0xaa >"$H3_DIR/result-id.txt"
sleep() { :; }
stop_one_evm_validator() { rec stop_node "$1"; }
stop_pidfile() { rec stop_pidfile "$1"; }
h3_advance_authorities() { rec advance "$@" "norep=$M2_ADVANCE_NO_REPLICA_WAIT"; }
h3_pdr_file() { echo "$OUT/pdr-$1.json"; }
p85_eth_block() { echo 5; }
p85_last_acked() { echo 0xgg; }
p85_genesis_assignment() { echo 0xgg; }
p85_result_state() { echo 1; }
h3_retry_handoff() { :; }
q3_install_n() { :; }
q3_activation_n() { :; }
h3_registry_is() { return 0; }
p85_paid() { rec paid "$1"; }
h3_slot() { echo ?; }
cp() { :; }
build/ubft() { rec ubft "$@"; }
'''


def run_lane(fn, h2):
    with tempfile.TemporaryDirectory() as out:
        env = dict(os.environ, OUT=out, ROOT=str(ROOT), X4_H2_LANE="1" if h2 else "0")
        r = subprocess.run(["bash", "-c", f'{LANE}\n{fn}\necho "ONLINE=$H3_ONLINE" >>"$OUT/calls.log"\n'], env=env, capture_output=True, text=True, timeout=120, cwd=ROOT)
        return r, (Path(out) / "calls.log").read_text().splitlines()


class EntityFourSurvivesTheStall(unittest.TestCase):
    """X4_H2_LANE keeps entity 4's authority and execution client through the J stall and brings its node back into K's scope; without it nothing changes."""

    def test_the_default_lane_stops_entity_4_completely_and_advances_only_entity_3_by_hand(self):
        r, calls = run_lane("p85_j_stalls", False)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("stop_pidfile test-nodes/reth4/pid", calls); self.assertIn("stop_pidfile test-nodes/auth4/pid", calls)
        self.assertIn("stop_pidfile test-nodes/reth5/pid", calls); self.assertIn("stop_pidfile test-nodes/auth5/pid", calls)
        adv = [c for c in calls if c.startswith("ubft signing-authority advance-epoch")]
        self.assertEqual(len(adv), 1); self.assertIn("test-nodes/auth3/operator.sock", adv[0])
        self.assertIn("advance 2 1 1 2 norep=1", calls)
        self.assertIn("ONLINE=1 2", calls)

    def test_the_handoff_lane_keeps_entity_4s_authority_and_execution_client_and_advances_it_like_entity_3(self):
        r, calls = run_lane("p85_j_stalls", True)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("stop_node 4", calls)   # its node is down: J has 2 of 5 and cannot certify
        self.assertNotIn("stop_pidfile test-nodes/reth4/pid", calls); self.assertNotIn("stop_pidfile test-nodes/auth4/pid", calls)
        self.assertIn("stop_pidfile test-nodes/reth5/pid", calls); self.assertIn("stop_pidfile test-nodes/auth5/pid", calls)   # the joiner loses everything as before
        adv = [c for c in calls if c.startswith("ubft signing-authority advance-epoch")]
        self.assertEqual(sorted(re.search(r"test-nodes/auth(\d)/", a).group(1) for a in adv), ["3", "4"])
        self.assertIn("ONLINE=1 2", calls)   # only the retained members' nodes are up in J

    def test_the_recovery_returns_entity_4_into_ks_scope_only_in_the_handoff_lane(self):
        for h2, want, online in ((False, "advance 3 2 1 2 3 norep=1", "ONLINE=1 2 3"), (True, "advance 3 2 1 2 3 4 norep=1", "ONLINE=1 2 3 4")):
            with self.subTest(h2=h2):
                r, calls = run_lane("p85_recovery_attempt_loop", h2)
                self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
                self.assertIn(want, calls)
                self.assertEqual(calls[-1], online)


class GovernanceActivation(unittest.TestCase):
    """x4g_check asserts the activation in the handoff lane and only records it otherwise."""

    def check(self, h2, before, after):
        with tempfile.TemporaryDirectory() as out:
            script = f'''set -u
cd "{ROOT}"
export H3_DIR="{out}/h3" P85_DEPLOY={out}/dep.json X4G_DIR="{out}/gov" X4G_WAIT=3 X4_H2_LANE={1 if h2 else 0}
mkdir -p "$X4G_DIR"; echo '{{"policyIdBefore": {before}, "rateProposed": "500", "nonce": 1}}' >"$X4G_DIR/queued.json"
p85_call() {{ case "$2" in 'currentPolicyID()(uint32)') echo {after} ;; 'currentRewardRate()(uint128)') echo "{'500' if after > before else '1000'}" ;; *) echo 0 ;; esac; }}
p85_open_result() {{ echo 0x0; }}
p85_election() {{ echo E; }}
sleep() {{ :; }}
source scripts/x4pos/gov-lib.sh
x4g_gov() {{ echo G; }}; x4g_roots() {{ echo R; }}
x4g_check
'''
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60, cwd=ROOT)
            return r, json.loads((Path(out) / "gov/outcome.json").read_text())

    def test_the_activation_is_required_with_the_handoff_lane(self):
        r, o = self.check(True, 1, 2)
        self.assertEqual(r.returncode, 0, r.stderr); self.assertTrue(o["activated"] and o["activationRequired"])
        r, o = self.check(True, 1, 1)
        self.assertEqual(r.returncode, 1); self.assertIn("was not activated", r.stderr); self.assertFalse(o["activated"])

    def test_it_is_only_recorded_without_it(self):
        r, o = self.check(False, 1, 1)
        self.assertEqual(r.returncode, 0, r.stderr); self.assertFalse(o["activated"]); self.assertFalse(o["activationRequired"])


OFFENCE = r'''
set -u
cd "$ROOT"
export H3_DIR=$OUT/h3 X4O_DIR=$OUT/s4b X4O_EPOCH=4 P85_K=0xk
mkdir -p "$H3_DIR" "$X4O_DIR"
source scripts/x4pos/offence-lib.sh
s4_pass() { echo "PASS: s4: $*"; }
sleep() { :; }
s4_equivocate() { rec equivocate "epoch=$S4_EPOCH"; }
s4_collect_after_rotation() { rec collect; }
s4_submit_settle() { rec submit "epoch=$S4_EPOCH" "hook=$S4_ADMITTED_HOOK"; touch "$OUT/settled"; }
s4_check() { rec check; }
s4_epoch() { cat "$OUT/rootepoch"; }
s4_round() { n=$(cat "$OUT/round" 2>/dev/null || echo 100); echo $((n + 1)) >"$OUT/round"; echo $n; }
p85_open_result() { if [ -f "$OUT/settled" ]; then cat "$OUT/open-after"; else cat "$OUT/open-before"; fi; }
p85_last_acked() { echo 0xack; }
p85_election() { echo E; }
p85_call() { :; }
p85_dec() { cat >/dev/null; jq -c -n --arg p "$(cat "$OUT/predecessor")" '{state: 1, predecessor: $p}'; }
x4o_lost() { if [ -f "$OUT/settled" ]; then echo 1; else cat "$OUT/lost-before"; fi; }
p85_result_state() { if [ -f "$OUT/settled" ]; then cat "$OUT/state-after"; else echo 1; fi; }
p85_paid() { rec paid "$1"; }
p85_cursor() { echo 9; }
p85_log_count() { echo 9; }
p85_log_dump() { echo "7 1 100 100 $(cat "$OUT/open-before") -"; }
rec() { printf '%s' "$1" >>"$OUT/calls.log"; shift; for v in "$@"; do printf ' %s' "$v" >>"$OUT/calls.log"; done; printf '\n' >>"$OUT/calls.log"; }
'''


def run_offence(**over):
    sc = {"rootepoch": "4", "open-before": R2, "open-after": ZERO, "predecessor": "0xack", "lost-before": "0", "state-after": "5"}
    sc.update(over)
    with tempfile.TemporaryDirectory() as out:
        o = Path(out)
        for k, v in sc.items():
            (o / k).write_text(v)
        (o / "calls.log").write_text("")
        r = subprocess.run(["bash", "-c", f"{OFFENCE}\nx4o_second\n"], env=dict(os.environ, OUT=out, ROOT=str(ROOT)), capture_output=True, text=True, timeout=120, cwd=ROOT)
        post = json.loads((o / "s4b/post-settle.json").read_text()) if (o / "s4b/post-settle.json").exists() else None
        pre = json.loads((o / "s4b/pre-submit.json").read_text()) if (o / "s4b/pre-submit.json").exists() else None
        return r, (o / "calls.log").read_text().splitlines(), pre, post


class OffenceTwoRejection(unittest.TestCase):
    """x4o_second in the X4 campaign: delivered in epoch 4 against the result that is open, which the roots reject once the admission marks it lost."""

    def test_the_result_is_rejected_by_the_roots_and_the_running_assignment_keeps_going(self):
        r, calls, pre, post = run_offence()
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertEqual([c.split()[0] for c in calls], ["equivocate", "collect", "submit", "check", "paid"])
        self.assertIn("epoch=4", calls[0]); self.assertIn("epoch=4 hook=x4o_admitted", calls[2]); self.assertEqual(calls[4], "paid 4")
        self.assertEqual((pre["epoch"], pre["state"], pre["predecessorIsLastAcked"], pre["lostBefore"], pre["openResult"]), (4, 1, True, 0, R2))
        self.assertEqual((post["epoch"], post["lostAfterSettlement"], post["laterResultStateAfter"], post["openResultIsNotTheRejected"], post["lastAckedUnchanged"], post["cursor"], post["count"]), (4, 1, 5, True, True, 9, 9))
        self.assertEqual(post["sessionClosedRecords"], 1)
        self.assertIn("REJECTED by the roots", r.stdout)

    def test_a_result_the_roots_never_reject_is_a_failure(self):
        r, _, _, post = run_offence(**{"state-after": "1"})
        self.assertEqual(r.returncode, 1); self.assertIn("was not rejected by the roots", r.stderr); self.assertIsNone(post)

    def test_the_rejected_result_must_not_still_be_the_open_one(self):
        r, _, _, post = run_offence(**{"open-after": R2})
        self.assertEqual(r.returncode, 1); self.assertIn("moved after the second admission", r.stderr)

    def test_the_preconditions_of_the_submission(self):
        for over, needle in (({"predecessor": "0xother"}, "not a Reserved result from the last acknowledged assignment"), ({"lost-before": "1"}, "already marked lost before offence 2"),
                             ({"open-before": ZERO}, "no later election result opened")):
            with self.subTest(over):
                r, calls, pre, post = run_offence(**over)
                self.assertEqual(r.returncode, 1, r.stdout); self.assertIn(needle, r.stderr); self.assertNotIn("submit", [c.split()[0] for c in calls])

    def test_the_epoch_the_lane_is_in_must_be_the_epoch_offence_2_was_delivered_in(self):
        r, _, _, _ = run_offence(rootepoch="3")
        self.assertEqual(r.returncode, 1); self.assertIn("moved after the second admission", r.stderr)


if __name__ == "__main__":
    unittest.main()
