#!/bin/bash
# reth-chaos.sh - real-reth workload, fault and retained-data recovery evidence (F1a, #88).
#
# scripts/chaos-evm.sh runs the same scenarios against --executor fake, which models no
# execution at all: every round is quiet, the state root never moves, and nothing it reports
# says anything about the execution path. This is its real-execution counterpart. One pinned
# reth per validator, driven by the actual Go adapter, with a funded transaction workload, so
# "did the shard recover" is answered by executed blocks and receipts rather than by round
# counters that advance whether or not anything ran.
#
# There is deliberately no fake fallback: a missing or unpinned reth binary fails.
#
# Usage:
#   ./scripts/reth-chaos.sh [-v validators] [-t workload-txs] [-s scenarios] [-k] [-F]
#     -v  validators, each with its own reth (default 4; >=4 to tolerate one fault)
#     -t  transactions per workload burst (default 3)
#     -s  comma-separated scenarios to run, out of
#           baseline,follower-restart,leader-kill,reth-only-restart,pair-restart,quiet-restart,
#           multi-leader
#         Each runs on its own devnet, so any subset is a complete run of those scenarios and not
#         a partial run of all of them. Re-running one scenario is minutes rather than half an hour,
#         which is the difference between investigating a failure and guessing at it.
#     -k  keep everything running afterwards
#     -F  inject a harness failure, to exercise the evidence-collection path on purpose
#         (#88 requires that path be tested; a passing run never proves it)
#
# Exit code is nonzero if any scenario's assertion failed.

#
# THIS FILE IS INITIALISATION AND ORCHESTRATION ONLY. Every function lives in
# scripts/lib/reth-chaos-lib.sh, which is sourceable with no side effects so the assertion oracle
# can be exercised without reth or a devnet (scripts/reth-chaos-selftest.sh).

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# shellcheck source=lib/reth-chaos-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/reth-chaos-lib.sh"

while getopts "hv:t:s:kF" o; do
  case "${o}" in
  v) validators=${OPTARG} ;;
  t) workloadTxs=${OPTARG} ;;
  s) scenarios=${OPTARG} ;;
  k) keep=true ;;
  F) injectFailure=true ;;
  h | *) sed -n '2,33p' "$0"; exit 0 ;;
  esac
done

[ "$validators" -ge 4 ] || { echo "need at least 4 validators to tolerate one fault" >&2; exit 1; }

# Validate the selection BEFORE anything is started, stopped or deleted. An unknown name used to
# select nothing and still exit 0 with "evidence complete".
validateScenarios || exit 2

# --- the fork client, no fake fallback --------------------------------------------------------
# Every validator here runs `--executor engine-api`, and the shard node refuses a client that does
# not advertise the three engine_*WithSealV1 methods. The client this lane needs is therefore the
# fork, not the stock `reth` that used to be on PATH, and urethPinResolve verifies it by revision.
urethPinResolve || exit 1

# --- supervisor boundary ----------------------------------------------------------------------
#
# Evidence collection and teardown are owned by a PARENT PROCESS, not by a trap inside the process
# that runs the scenarios.
#
# Why not an EXIT trap: helper.sh backgrounds each validator, and a forked child inherited this
# script's EXIT trap and ran teardown with a call stack of "cleanup start_one_evm_validator main",
# killing the devnet mid-scenario while the parent carried on. Every later assertion then failed
# against a dead cluster and looked exactly like a protocol fault. No PID test fixes that portably:
# bash keeps the parent's $$ in a forked child, macOS /bin/bash 3.2 has no BASHPID, and $PPID via
# command substitution reports the substitution subshell.
#
# A separate process has none of those problems. The parent re-executes this script with
# F1_CHAOS_SUPERVISED=1; the child runs the scenarios and writes its failure count to a file. The
# parent then collects evidence and tears down NO MATTER HOW THE CHILD ENDED — a nounset abort, an
# unhandled error, a kill, or a clean finish. Nothing the child does can inherit a trap from the
# parent, because they are different processes.
#
# What this still does not claim: the parent itself being SIGKILLed leaves the clients running.
# That is recoverable with ./stop-evm.sh -a and is the more useful outcome anyway (#88 wants the
# evidence kept), but it is a limitation, not universal teardown.
failuresFile=$runDir/.failures

if [ "${F1_CHAOS_SUPERVISED:-0}" != "1" ]; then
  childStatus=0
  # The manifest is this run's identity and is written once, by the supervisor, before any scenario
  # is selected — so a subset run records the revisions it measured just as a full run does.
  writeRunManifest "$@"
  # A fresh, private scan-inputs file for this run; the child records each cluster's secrets into it.
  rethScanInputsInit "$(chaosScanFile)" || exit 1
  # The child must write into the SAME run directory; it re-executes this script, which would
  # otherwise generate a new id.
  export F1_CHAOS_RUN_DIR="$runDir"
  F1_CHAOS_SUPERVISED=1 "$0" "$@" &
  childPid=$!
  trap 'echo; echo "=== interrupted ==="; kill "$childPid" 2>/dev/null; wait "$childPid" 2>/dev/null; finish; exit 130' INT TERM
  wait "$childPid"; childStatus=$?
  trap - INT TERM

  echo
  echo "=== evidence (collected by the supervisor, whatever happened to the run) ==="
  # The verdict lives in superviseResult (scripts/lib/reth-chaos-lib.sh) rather than here, so that
  # the self-test can execute it. It combines the supervisor's OWN failures — evidence collection
  # runs in this process and reports through the same fail() — with the child's, and returns
  # nonzero if either is nonzero.
  superviseResult "$childStatus" "$failuresFile"
  exit $?
fi

# F1_CHAOS_ABORT_AFTER lets the supervisor boundary itself be tested, which #88 requires: a passing
# run never proves the failure path. Set it to a stage name and the child dies there the way an
# unhandled error would — the parent must still collect evidence, tear down and report a failure.
#   nounset  : an unset-variable abort (set -u), the case a trap-based design misses
#   kill     : the child is SIGKILLed, so no in-child handler can run at all
#   hang     : the child waits, so an interrupt to the supervisor can be exercised
abortIf() {
  case "${F1_CHAOS_ABORT_AFTER:-}" in
    "$1")
      echo "  ..   INJECTED: aborting the scenario process at '$1' to exercise the supervisor"
      case "${F1_CHAOS_ABORT_MODE:-nounset}" in
        kill) kill -9 $$ ;;
        hang) sleep 600 ;;
        *)    echo "${thisVariableIsDeliberatelyUnset}" ;;
      esac
      ;;
  esac
}

# ----------------------------------------------------------------------------------------------
# From here down this process is the SUPERVISED CHILD. It installs no teardown trap: the parent
# owns evidence and teardown, and a trap here is exactly what caused the mid-scenario teardown bug.


echo "=== reth-chaos.sh: real-reth workload and fault evidence (F1a #88) ==="
echo "reth:        $rethCommit"
echo "validators:  $validators, one pinned reth each"
echo "workload:    $workloadTxs transactions per burst, nonce read from the chain per send"
echo

abortIf startup

echo "=== 0. clean fixtures ==="
mkdir -p "$runDir"
: >"$runDir/workload.txt"
: >"$runDir/convergence.txt"
if ! wantScenario baseline; then
  echo "  --  skipped by -s $scenarios"
else
# The cluster comes up first: setup-evm-nodes.sh runs `make clean`, so anything written to
# test-nodes before it is deleted, and the chain fixtures it hashes below do not exist until after.
scenariosRun=$((scenariosRun + 1))
bringUpCluster baseline || { finish; exit 1; }
{
  echo "reth=$rethCommit"
  echo "bft=$(git rev-parse HEAD)"
  echo "validators=$validators workloadTxs=$workloadTxs chainID=$chainID"
  echo "sender=$senderAcct (nonce read from eth_getTransactionCount pending before each send)"
  echo "logLevel=$EVM_VALIDATOR_LOG_LEVEL (debug is required: leader/block correlation reads it)"
  echo "genesis=$(shasum -a 256 test-nodes/evm-genesis.json | cut -d' ' -f1)"
  echo "fundedGenesis=$(shasum -a 256 test-nodes/evm-genesis-funded.json | cut -d' ' -f1)"
  echo "shardConf=$(shasum -a 256 "test-nodes/shard-conf-${partitionID}_0.json" | cut -d' ' -f1)"
  echo "NOTE: each fault scenario below runs on its OWN cluster, regenerated the same way; the"
  echo "      genesis/shard-conf hashes are per-cluster and are re-recorded in each scenario's"
  echo "      snapshot directory."
} | tee "$runDir/baseline-pins.txt"
snapshot 00-baseline
fi
echo
# ==============================================================================================
# Scenarios. One failure at a time; the returning node must demonstrably execute and certify NEW
# work before the next fault is injected (#88 stage 2).
# ==============================================================================================


echo "=== 1. workload before any fault ==="
if ! wantScenario baseline; then
  echo "  --  skipped by -s $scenarios"
else
runWorkload "pre-fault" "$workloadTxs"
leadersBefore=$(cat "$runDir/.leaders-pre-fault")
# The pre-fault baseline is itself a gate: injecting a fault into a cluster that does not already
# agree cannot produce evidence about the fault.
convergenceGate "pre-fault" || true
snapshot 01-pre-fault
fi
echo

echo "=== 2. shard follower process restart, its reth retained ==="
if ! wantScenario "follower-restart"; then
  echo "  --  skipped by -s $scenarios"
elif ! freshCluster "follower-restart"; then
  fail "follower-restart: NOT RUN — its own clean cluster did not execute and converge before the fault, so nothing here would be about this fault"
else
# The shard process dies; its execution client keeps running and keeps its datadir. This is the
# same-host retained-data case. Disk loss / replacement host is #14 and is NOT claimed here.
follower=2
survivor=3
beforeRound=$(certifiedRound "$survivor")
snapshot 02a-before-follower-restart
info "stopping shard node $follower (pid $(cat "test-nodes/evm$follower/pid" 2>/dev/null)); its reth pid is $(cat "test-nodes/reth$follower/pid" 2>/dev/null)"
stop_one_evm_validator "$follower"
sleep 2
if rpc "$(ethURL "$follower")" eth_chainId '[]' | grep -q result; then
  pass "reth$follower survived stopping its shard node (this scenario retains the executor)"
else
  fail "reth$follower died when its shard node was stopped — the executor must be retained here"
fi
if waitForCertifiedProgress "$survivor" "$beforeRound" 120; then
  pass "shard kept certifying with validator $follower down (round $beforeRound -> $(certifiedRound "$survivor"))"
else
  fail "shard stalled with one of $validators validators down (quorum should permit it)"
  snapshot 02a-stall
fi
# Positive execution while it is absent: the shard must still do real work, not just tick rounds.
submitAndConfirm 1 && pass "a transaction executed while validator $follower was absent"
mark=$(logLines "$follower")
start_one_evm_validator "$follower" "$validators" "$partitionID" "$rootBoot" engine-api ""
recoveredAndWorking "$follower" "$mark" "follower-restart" && convergenceGate "post-follower-restart"
snapshot 02b-after-follower-restart
fi
echo

echo "=== 3. shard leader process kill, quorum of others live ==="
if ! wantScenario "leader-kill"; then
  echo "  --  skipped by -s $scenarios"
elif ! freshCluster "leader-kill"; then
  fail "leader-kill: NOT RUN — its own clean cluster did not execute and converge before the fault, so nothing here would be about this fault"
else
# Take the target from the authenticated technical record — the leader the shard's own latest
# accepted certificate names for the next round — and record that boundary as evidence.
leaderCtx=$(currentShardLeader 1) || leaderCtx=""
if [ -n "$leaderCtx" ]; then
  leader=$(echo "$leaderCtx" | awk '{print $1}')
  info "assigned shard leader from the latest technical record: validator $leader (peer $(echo "$leaderCtx" | awk '{print $2}'), nextRound $(echo "$leaderCtx" | awk '{print $3}'))"
  echo "leader-kill target: $leaderCtx" >>"$runDir/workload.txt"
else
  leader=1
  info "could not read an assigned leader from the technical record; falling back to validator 1 — this scenario is then a shard-process restart, not a verified leader experiment"
fi
survivor=$(( leader % validators + 1 ))
beforeRound=$(certifiedRound "$survivor")
snapshot 03a-before-leader-kill
stop_one_evm_validator "$leader"
if waitForCertifiedProgress "$survivor" "$beforeRound" 150; then
  pass "shard rotated past the killed leader $leader (round $beforeRound -> $(certifiedRound "$survivor"))"
else
  fail "shard did not recover from killing leader $leader within 150s"
  snapshot 03a-stall
fi
submitAndConfirm "$survivor" && pass "a transaction executed with leader $leader absent"
mark=$(logLines "$leader")
start_one_evm_validator "$leader" "$validators" "$partitionID" "$rootBoot" engine-api ""
recoveredAndWorking "$leader" "$mark" "leader-restart" && convergenceGate "post-leader-restart"
snapshot 03b-after-leader-restart
fi
echo

echo "=== 4. reth-only restart, datadir retained (the shard process stays up) ==="
if ! wantScenario "reth-only-restart"; then
  echo "  --  skipped by -s $scenarios"
elif ! freshCluster "reth-only-restart"; then
  fail "reth-only-restart: NOT RUN — its own clean cluster did not execute and converge before the fault, so nothing here would be about this fault"
else
# The executor disappears from under a running shard node. Two things matter: the shard must
# abstain rather than certify something it cannot execute, and it must resume once the client
# returns with its retained data.
target=4
snapshot 04a-before-reth-restart
execBefore=$(execHead "$target")
mark=$(logLines "$target")
stopReth "$target"
info "reth$target stopped; shard process $target left running"
sleep 10 # let the shard node notice and attempt at least one round without its executor
# Safe abstention: with its executor gone the node must not have certified new EVM work of its
# own. Everyone else continues, which is what keeps the shard live.
if awk -v n="$mark" 'NR > n' "$(log "$target")" 2>/dev/null | grep -qiE 'error|refus|unavailable|connection refused'; then
  pass "validator $target reported its executor unavailable instead of proceeding silently"
else
  info "validator $target logged no executor error in the window (it may not have been asked to build)"
fi
otherRound=$(certifiedRound 1)
if waitForCertifiedProgress 1 "$otherRound" 120; then
  pass "the rest of the shard kept certifying while reth$target was down"
else
  fail "shard stalled while one validator's execution client was down"
fi
startReth "$target"
waitReth "$target" 90 || fail "reth$target did not come back"
info "reth$target restarted with its retained datadir (head was $execBefore)"
recoveredAndWorking "$target" "$mark" "reth-restart" && convergenceGate "post-reth-restart"
snapshot 04b-after-reth-restart
fi
echo

echo "=== 5. complete shard+reth pair restart, both datadirs retained ==="
if ! wantScenario "pair-restart"; then
  echo "  --  skipped by -s $scenarios"
elif ! freshCluster "pair-restart"; then
  fail "pair-restart: NOT RUN — its own clean cluster did not execute and converge before the fault, so nothing here would be about this fault"
else
pair=2
snapshot 05a-before-pair-restart
mark=$(logLines "$pair")
stop_one_evm_validator "$pair"
stopReth "$pair"
info "validator $pair and reth$pair both stopped"
otherRound=$(certifiedRound 1)
if waitForCertifiedProgress 1 "$otherRound" 120; then
  pass "shard kept certifying with the whole pair $pair down"
else
  fail "shard stalled with one complete pair down"
fi
submitAndConfirm 1 && pass "a transaction executed with pair $pair fully absent"
startReth "$pair"
waitReth "$pair" 90 || fail "reth$pair did not come back"
start_one_evm_validator "$pair" "$validators" "$partitionID" "$rootBoot" engine-api ""
recoveredAndWorking "$pair" "$mark" "pair-restart" && convergenceGate "post-pair-restart"
snapshot 05b-after-pair-restart
fi
echo

echo "=== 5b. quiet-tail recovery control (#92): does a returning pair recover with NO new work? ==="
if ! wantScenario "quiet-restart"; then
  echo "  --  skipped by -s $scenarios"
elif ! freshCluster "quiet-restart"; then
  fail "quiet-restart: NOT RUN — its own clean cluster did not execute and converge before the fault"
else
# The pair-restart shape with the recovery transaction REMOVED. #110 established that a returning
# pair recovers after a fresh non-quiet round supplies it with an anchor; it did not establish
# whether the pair recovers when the shard stays quiet, because the harness's own recovery
# transaction was the fresh non-quiet round. This scenario separates the two: observe first,
# inject afterwards, and label the injection as the control it is.
pair=2
survivor=1
snapshot 5b-a-before-quiet-restart
mark=$(logLines "$pair")
stop_one_evm_validator "$pair"
stopReth "$pair"
info "validator $pair and reth$pair both stopped"

otherRound=$(certifiedRound "$survivor")
if waitForCertifiedProgress "$survivor" "$otherRound" 120; then
  pass "quiet-restart: shard kept certifying with the whole pair $pair down"
else
  fail "quiet-restart: shard stalled with one complete pair down"
fi

# The LAST transaction of this scenario's fault phase: a state-changing block certified while the
# pair is absent, so the returning node is genuinely behind a certified block. Nothing is submitted
# after this until the control below.
if submitAndConfirm "$survivor"; then
  pass "quiet-restart: a state-changing block was certified while pair $pair was absent"
else
  fail "quiet-restart: could not certify a block while the pair was absent"
fi
if ! targetHead=$(execHead "$survivor"); then
  fail "quiet-restart: the shard's canonical head is unobservable, so there is nothing to measure recovery against"
  targetHead=UNOBSERVABLE
fi
info "quiet-restart: the shard's canonical head is now $targetHead; no further work will be submitted"

startReth "$pair"
waitReth "$pair" 90 || fail "quiet-restart: reth$pair did not come back"
start_one_evm_validator "$pair" "$validators" "$partitionID" "$rootBoot" engine-api ""

echo "  --  OBSERVATION: quiet rounds only, nothing injected"
quietRecovered=no
observeQuietRecovery "$pair" "$targetHead" 120
case $? in
  0)
    quietRecovered=yes
    pass "quiet-restart: validator $pair recovered to the certified head during a QUIET interval, with no new work"
    quietObservationRecord "$pair" "$mark" recovered
    ;;
  1)
    info "quiet-restart: validator $pair did NOT recover during the quiet interval — recorded, not asserted; establishing this is the point of the scenario"
    quietObservationRecord "$pair" "$mark" observed-behind
    ;;
  *)
    # NOT a result. An executor that could not be read says nothing about recovery, and the
    # positive control below can bring the client back and leave the run green having measured
    # nothing — which is why this counts as a failure of the run and not as the negative outcome.
    fail "quiet-restart: the observation was INVALID — validator $pair's executor could not be read well enough during the window to say whether it recovered"
    quietObservationRecord "$pair" "$mark" invalid-observation
    ;;
esac
quietPrecondition "$pair" "$survivor" "$targetHead" "$mark" || true
snapshot 5b-b-after-quiet-observation

# Safety must hold either way: a node that has not caught up must not be voting.
if [ "$(awk -v n="$mark" 'NR > n && /submitting block certification/' "$(log "$pair")" 2>/dev/null | wc -l | tr -d ' ')" = "0" ]; then
  pass "quiet-restart: validator $pair signed nothing while it was behind"
else
  fail "quiet-restart: validator $pair submitted a certification request while behind the certified head"
fi

echo "  --  POSITIVE CONTROL: one transaction, so a non-quiet round supplies an anchor"
if submitAndConfirm "$survivor"; then
  pass "quiet-restart control: a transaction executed and certified"
else
  fail "quiet-restart control: the control transaction did not execute"
fi
controlTarget=$(execHead "$survivor") || controlTarget=UNOBSERVABLE
observeQuietRecovery "$pair" "$controlTarget" 120
case $? in
  0) pass "quiet-restart control: validator $pair reached $controlTarget after the control transaction"
     quietObservationRecord "$pair" "$mark" control-recovered ;;
  1) fail "quiet-restart control: validator $pair did not reach $controlTarget even after a non-quiet round"
     quietObservationRecord "$pair" "$mark" control-behind ;;
  *) fail "quiet-restart control: the control observation was INVALID — validator $pair's executor could not be read"
     quietObservationRecord "$pair" "$mark" control-invalid ;;
esac
snapshot 5b-c-after-control
info "quiet-restart summary: recovered without new work = $quietRecovered"
convergenceGate "post-quiet-restart" || true
fi
echo

echo "=== 6. multi-leader execution evidence (#88 stage 1) ==="
if ! wantScenario "multi-leader"; then
  echo "  --  skipped by -s $scenarios"
elif ! freshCluster "multi-leader"; then
  fail "multi-leader: NOT RUN — its own clean cluster did not execute and converge first"
else
leadersBefore=$(cat "$runDir/.leaders-multi-leader-pre")
runWorkload "post-fault" "$workloadTxs"
leadersAfter=$(cat "$runDir/.leaders-post-fault")
convergenceGate "final" || true

# MULTI-LEADER COVERAGE IS NOT CLAIMED HERE, and this used to assert it.
#
# shardLeadersSince counts submissions whose technical record named that node as leader. A
# submission is not an executed block: quiet rounds and uncertified attempts count the same as real
# work, so "two distinct leaders submitted" does not establish "two distinct leaders each produced
# an executed, certified EVM block". Review made that point and it is right; asserting PASS on the
# count would be claiming coverage this harness does not have.
#
# So it is reported as an observation, and the requirement stays OUTSTANDING on #88. Closing it
# needs each leader correlated with the workload block hashes and the certifying UCs, which is a
# larger change than this harness repair.
allLeaders=$(echo "$leadersBefore $leadersAfter" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')
leaderCount=$(echo "$allLeaders" | wc -w | tr -d ' ')
info "distinct nodes that SUBMITTED as leader on this cluster: $leaderCount ($allLeaders)"
info "a submission is not an executed certified block, so that count decides nothing on its own;"
info "the assertion below correlates each executed block with the round that certified it and the"
info "leader that produced it, and is what #88 stage 1 asks for."
assertMultiLeaderExecution 1 2 6

blocks=$(hexToDec "$(rpc "$(ethURL 1)" eth_getBlockByNumber '["latest", false]' | pyget "['result']['number']")")
expected=${#txHashes[@]}
if [ "$blocks" -ge "$expected" ]; then
  pass "reth produced $blocks EVM blocks for ${expected} transactions (blocks counted, not quiet rounds)"
else
  fail "only $blocks EVM blocks for ${expected} transactions"
fi
snapshot 06-final
fi
echo

if [ "$injectFailure" = true ]; then
  echo "=== 7. injected harness failure, to exercise the evidence-collection path ==="
  fail "INJECTED: deliberate failure (-F) so the artifact path is proven, not assumed"
fi


echo
# Hand the result to the supervisor, which owns evidence, teardown and the exit code. Writing the
# count is the child's LAST act: if it dies before this, the parent reports an incomplete run
# rather than a clean one.
if [ "$scenariosRun" -eq 0 ]; then
  fail "no scenario executed: -s '$scenarios' selected nothing, and a run that did no work is not evidence"
fi

mkdir -p "$(dirname "$failuresFile")"
echo "$failures" >"$failuresFile"
exit 0
