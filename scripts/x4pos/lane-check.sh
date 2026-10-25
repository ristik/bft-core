#!/usr/bin/env bash
# X4 B6d: the `check` of a campaign `lane` step (scripts/x4pos/driver.py): a phase of the lane's own shell is done iff the lane's record SAYS its steps passed and the artifacts the
# phase leaves behind show its effect. Usage: lane-check.sh <phase>. Environment: X4_LANE_DIR (the lane's $H3_DIR/x4pos: lane-steps.log, snapshots.jsonl, steps/**) and X4_S4B_DIR
# (offence 2's directory, default test-nodes/p85/s4b). Read-only; starts nothing. The lane appends the name of every step that passed to $X4_LANE_DIR/lane-steps.log (p85_step).
# The step names are the lane's (scripts/p85-recovery-steps.sh); a phase that needs a step the lane did not run is not done.
set -uo pipefail
phase=${1:?usage: lane-check.sh <phase>}
d=${X4_LANE_DIR:?X4_LANE_DIR is not set}
s4b=${X4_S4B_DIR:-test-nodes/p85/s4b}
log=$d/lane-steps.log
fail() { echo "lane-check $phase: $*" >&2; exit 1; }
ran() { local s; for s in "$@"; do grep -qx "$s" "$log" 2>/dev/null || fail "step $s is not recorded as passed in $log"; done; }
zero=0x0000000000000000000000000000000000000000000000000000000000000000
case "$phase" in
  baseline) ran p85_baseline x4a_snapshot; [ -s "$d/snapshots.jsonl" ] || fail "no accounting snapshot" ;;
  governance-queue)
    ran x4g_queue
    jq -e '.nonce >= 1 and .policyIdBefore >= 1 and (.rateProposed | tonumber) < (.rateBefore | tonumber)' "$d/steps/gov/queued.json" >/dev/null 2>&1 || fail "steps/gov/queued.json is not a record of a queued, lower reward rate" ;;
  governance)
    ran x4g_execute x4g_check
    # the queued rate became the policy in force (bft-core#856: the open results are resolved, so ElectionPolicy.elect reaches activateDue); the outcome file also shows that it was REQUIRED
    jq -e '.activated == true and .activationRequired == true and .policyIdAfter > .policyIdBefore and (.rateAfter | tonumber) == (.rateProposed | tonumber) and .waitedSeconds > 0' "$d/steps/gov/outcome.json" >/dev/null 2>&1 || fail "steps/gov/outcome.json does not show the queued rate activated (activated true, required, rateAfter = rateProposed)" ;;
  rewards)
    ran x4r_intervals x4r_dry_refill x4r_claim
    line=$(sed -n 's/^REWARDS-REPLAY ok //p' "$d/steps/xr/replay-after.txt" 2>/dev/null | tail -n 1)
    jq -e '.intervals >= 4 and .zeroBudget >= 1 and .fundings >= 1 and .refilledAfterExhaustion == true' <<<"${line:-null}" >/dev/null 2>&1 || fail "the replay does not show a dry, refilled pool with 4 closed intervals (intervals >= 4, zeroBudget >= 1, fundings >= 1)"
    [ "$(tail -n 1 "$d/snapshots.jsonl" 2>/dev/null | jq -r '.payments | length' 2>/dev/null)" -ge 1 ] 2>/dev/null || fail "the last snapshot has no pool payment (the payee's claim)" ;;
  replacement) ran p85_joiner_nodes p85_joiner_onboard p85_election_reserved p85_proofs p85_handoff p85_install_activation ;;
  recovery) ran p85_j_stalls p85_recovery p85_resolved ;;
  second-handoff)
    ran x4h_second
    jq -e '.resultState == 3 and .rootEpochBefore == 3 and .rootEpochAfter == 4 and .lastAckedAfter != .lastAckedBefore and .kClosed == true and .k2Open == true and .cursor == .count and .count == .target and (.entities | length) == 4' "$d/steps/handoff2/second-handoff.json" >/dev/null 2>&1 \
      || fail "steps/handoff2/second-handoff.json does not show the open result acknowledged: K closed, K' open, root epoch 3 -> 4, four members, records reconciled" ;;
  epoch-switches) ran p85_restarts p85_epoch_switches ;;
  offence-1) ran s4_equivocate s4_collect_after_rotation s4_submit_settle s4_check ;;
  offence-2)
    ran x4o_second x4o_claim
    # delivered in epoch 4 (after the second handoff) against a Reserved result from the last acknowledged assignment; the result is lost on the admission and REJECTED by the roots (Closed, 5)
    jq -e '.epoch == 4 and .roundAfterPaidTx > .roundAfterSettle and .lastAckedUnchanged == true and .paidTxOk == true and .openResultIsNotTheRejected == true and .lostAfterSettlement == 1 and .laterResultStateAfter == 5 and .cursor == .count and .rejectedAfterSeconds >= 0' "$s4b/post-settle.json" >/dev/null 2>&1 || fail "$s4b/post-settle.json does not show the running assignment untouched and the later result lost and rejected by the roots"
    jq -e --arg z "$zero" '.epoch >= 4 and (.openResult | type == "string") and .openResult != $z and .state == 1 and .predecessorIsLastAcked == true and .lostBefore == 0' "$s4b/pre-submit.json" >/dev/null 2>&1 || fail "$s4b/pre-submit.json: offence 2 was not submitted in epoch 4 against a Reserved later result from the last acknowledged assignment"
    [ "$(cat "$s4b/lost-after-admission.txt" 2>/dev/null)" = 1 ] || fail "$s4b/lost-after-admission.txt: the later result was not seen lost between admission and settlement" ;;
  exit-request)
    ran x4e_request
    jq -e '.imported == true and .pRet > 0 and .tRet > 0' "$d/steps/exit-request/request.json" >/dev/null 2>&1 || fail "exit-request/request.json does not show an imported Retirement"
    jq -e '.outcome == "refused" and .reason == "EvidenceHoldPending"' "$d/steps/exit-request/hold-probe.json" >/dev/null 2>&1 || fail "exit-request/hold-probe.json: no EvidenceHoldPending refusal while the case was admitted" ;;
  exit-claim)
    ran x4e_claim
    jq -e '.outcome == "refused" and .lawfulEarly == true' "$d/steps/exit-claim/refusal.json" >/dev/null 2>&1 || fail "exit-claim/refusal.json: the early mature was not refused for a lawful reason"
    jq -e '.creditDelta > 0' "$d/steps/exit-claim/matured.json" >/dev/null 2>&1 || fail "exit-claim/matured.json: no credit delta"
    jq -e '.received > 0' "$d/steps/exit-claim/claimed.json" >/dev/null 2>&1 || fail "exit-claim/claimed.json: nothing claimed" ;;
  fault-root-restart|fault-evm-restart|fault-pair-restart)
    n=${phase#fault-}; ran "x4f_${n//-/_}"
    jq -e '.stable == true and .paidTxOk == true and .fault == "'"$n"'"' "$d/steps/faults/$n.json" >/dev/null 2>&1 || fail "steps/faults/$n.json does not show unchanged state and a certified paid transaction"
    if [ "$n" = pair-restart ]; then
      jq -e '.byteIdentical == true and .pool.unchanged == true and (.blockHash | length) > 10' "$d/steps/faults/$n.json" >/dev/null 2>&1 || fail "steps/faults/pair-restart.json: the retained block or the reward pool changed"
    fi ;;
  fault-delayed-episode)
    ran x4f_delayed_episode
    jq -e '.stable == true and .paidTxOk == true and .shardFrozenDuringOutage == true and .rootsExtendedDuringOutage == true and .logOrdered == true and .after.cursor == .after.count and (.during.rootRound > .before.rootRound) and (.during.evmRound <= .before.evmRound + 1)' "$d/steps/faults/delayed-episode.json" >/dev/null 2>&1 || fail "steps/faults/delayed-episode.json does not show a delayed, then recovered shard with ordered records"
    ;;
  soak)
    ran x4f_soak
    jq -e '.snapshots >= 3' "$d/steps/faults/soak.json" >/dev/null 2>&1 || fail "steps/faults/soak.json: fewer than 3 soak snapshots" ;;
  reconcile)
    ran x4f_reconcile
    jq -e '.converged == true' "$d/steps/faults/reconcile-cursors.json" >/dev/null 2>&1 || fail "steps/faults/reconcile-cursors.json: the records did not converge"
    jq -e '.conserved == true and .intervals >= 4 and .zeroBudget >= 1 and .fundings >= 1 and .refilledAfterExhaustion == true' "$d/steps/reconcile/reconcile.json" >/dev/null 2>&1 || fail "steps/reconcile/reconcile.json is not a conserved, replayed, refilled pool" ;;
  accounting)
    ran x4a_final
    need=$(jq -r '.accountingSpanSeconds // 0' "${X4_CAMPAIGN:-$(dirname "$0")/campaign.json}" 2>/dev/null || echo 0)
    jq -e '.status == "PASS" and .snapshots >= 4' "$d/accounting.txt" >/dev/null 2>&1 || fail "accounting.txt is not a PASS over at least 4 snapshots"
    jq -e --argjson need "${need:-0}" '.spanSeconds >= $need' "$d/accounting.txt" >/dev/null 2>&1 || fail "accounting.txt: the snapshots span less than the manifest's accountingSpanSeconds ($need)" ;;
  *) fail "unknown phase" ;;
esac
echo "lane-check $phase: ok"
