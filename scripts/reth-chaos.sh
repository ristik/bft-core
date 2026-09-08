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
#   ./scripts/reth-chaos.sh [-v validators] [-t workload-txs] [-k] [-F]
#     -v  validators, each with its own reth (default 4; >=4 to tolerate one fault)
#     -t  transactions per workload burst (default 3)
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

while getopts "hv:t:kF" o; do
  case "${o}" in
  v) validators=${OPTARG} ;;
  t) workloadTxs=${OPTARG} ;;
  k) keep=true ;;
  F) injectFailure=true ;;
  h | *) sed -n '2,21p' "$0"; exit 0 ;;
  esac
done

[ "$validators" -ge 4 ] || { echo "need at least 4 validators to tolerate one fault" >&2; exit 1; }

# --- pinned client, no fake fallback ----------------------------------------------------------
command -v reth >/dev/null || { echo "no reth binary on PATH; this lane has no fake fallback" >&2; exit 1; }
rethCommit=$(reth --version | sed -n 's/^Commit SHA: //p')
if [ "$rethCommit" != "$pinnedRethCommit" ]; then
  echo "FAIL: reth is $rethCommit, pinned is $pinnedRethCommit" >&2
  echo "      Set F1_ALLOW_UNPINNED_RETH=1 to explore; output is then not evidence." >&2
  [ "${F1_ALLOW_UNPINNED_RETH:-0}" = "1" ] || exit 1
fi

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
failuresFile=test-nodes/evidence/.failures

if [ "${F1_CHAOS_SUPERVISED:-0}" != "1" ]; then
  childStatus=0
  F1_CHAOS_SUPERVISED=1 "$0" "$@" &
  childPid=$!
  trap 'echo; echo "=== interrupted ==="; kill "$childPid" 2>/dev/null; wait "$childPid" 2>/dev/null; finish; exit 130' INT TERM
  wait "$childPid"; childStatus=$?
  trap - INT TERM

  echo
  echo "=== evidence (collected by the supervisor, whatever happened to the run) ==="
  finish

  if [ -s "$failuresFile" ]; then
    failures=$(cat "$failuresFile")
  else
    # The child never got far enough to record a count. That is itself a failure: the run did not
    # complete, and reporting 0 would read as success.
    echo "  FAIL: the scenario process ended without recording a result (exit $childStatus) — the run did not complete"
    failures=1
  fi
  if [ "$childStatus" -ne 0 ] && [ "$failures" -eq 0 ]; then
    echo "  FAIL: the scenario process exited $childStatus with no assertion failure recorded — treating as a harness failure"
    failures=1
  fi
  if [ "$failures" -gt 0 ]; then
    echo "=== reth-chaos.sh: $failures assertion(s)/failure(s) — evidence retained ==="
    exit 1
  fi
  echo "=== reth-chaos.sh: real-reth workload and fault evidence complete ==="
  exit 0
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
./stop-evm.sh -a >/dev/null 2>&1
for i in $(seq 1 "$validators"); do stopReth "$i"; done
./setup-evm-nodes.sh -r 3 -v "$validators" >/dev/null || { echo "setup failed" >&2; cleanup; exit 1; }  # nothing to collect yet
mkdir -p test-nodes/evidence
: >test-nodes/evidence/workload.txt
: >test-nodes/evidence/convergence.txt

python3 - <<'PY'
import json, subprocess
g = json.load(open("test-nodes/evm-genesis.json"))
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
json.dump(g, open("test-nodes/evm-genesis-funded.json", "w"), indent=2)
PY
{
  echo "reth=$rethCommit"
  echo "bft=$(git rev-parse HEAD)"
  echo "genesis=$(shasum -a 256 test-nodes/evm-genesis.json | cut -d' ' -f1)"
  echo "fundedGenesis=$(shasum -a 256 test-nodes/evm-genesis-funded.json | cut -d' ' -f1)"
  echo "shardConf=$(shasum -a 256 "test-nodes/shard-conf-${partitionID}_0.json" | cut -d' ' -f1)"
  echo "validators=$validators workloadTxs=$workloadTxs chainID=$chainID"
  echo "sender=$senderAcct (nonce read from eth_getTransactionCount pending before each send)"
} | tee test-nodes/evidence/pins.txt

for i in $(seq 1 "$validators"); do
  openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  startReth "$i"
done
for i in $(seq 1 "$validators"); do
  waitReth "$i" 90 || { fail "reth$i did not start"; finish; exit 1; }
done
peerReths
pass "$validators pinned reth instances up and statically peered"

source helper.sh
for i in $(seq 1 "$validators"); do
  export "EVM_ENGINE_URL_$i=$(engineURL "$i")"
  export "EVM_ETH_URL_$i=$(ethURL "$i")"
done
./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1
rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")

waited=0
until grep -q 'accepted certificate' "$(log 1)" 2>/dev/null; do
  [ "$waited" -ge 180 ] && { fail "shard never certified"; finish; exit 1; }
  sleep 2; waited=$((waited + 2))
done
pass "shard certifying on --executor engine-api against real reth"
snapshot 00-baseline
echo
# ==============================================================================================
# Scenarios. One failure at a time; the returning node must demonstrably execute and certify NEW
# work before the next fault is injected (#88 stage 2).
# ==============================================================================================


echo "=== 1. workload before any fault ==="
runWorkload "pre-fault" "$workloadTxs"
leadersBefore=$(cat test-nodes/evidence/.leaders-pre-fault)
# The pre-fault baseline is itself a gate: injecting a fault into a cluster that does not already
# agree cannot produce evidence about the fault.
convergenceGate "pre-fault" || true
snapshot 01-pre-fault
echo

echo "=== 2. shard follower process restart, its reth retained ==="
if skipIfUnrecovered "follower restart"; then :; else
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
if skipIfUnrecovered "leader kill"; then :; else
# Take the target from the authenticated technical record — the leader the shard's own latest
# accepted certificate names for the next round — and record that boundary as evidence.
leaderCtx=$(currentShardLeader 1) || leaderCtx=""
if [ -n "$leaderCtx" ]; then
  leader=$(echo "$leaderCtx" | awk '{print $1}')
  info "assigned shard leader from the latest technical record: validator $leader (peer $(echo "$leaderCtx" | awk '{print $2}'), nextRound $(echo "$leaderCtx" | awk '{print $3}'))"
  echo "leader-kill target: $leaderCtx" >>test-nodes/evidence/workload.txt
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
if skipIfUnrecovered "reth-only restart"; then :; else
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
if skipIfUnrecovered "shard+reth pair restart"; then :; else
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

echo "=== 6. final workload and multi-leader evidence ==="
if skipIfUnrecovered "final workload"; then
  echo "  SKIP: multi-leader and EVM-block-count evidence NOT RUN for the same reason."
else
runWorkload "post-fault" "$workloadTxs"
leadersAfter=$(cat test-nodes/evidence/.leaders-post-fault)
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
info "distinct nodes that SUBMITTED as leader across the run: $leaderCount ($allLeaders)"
info "#88's multi-leader EXECUTION requirement is NOT satisfied by this count and remains outstanding:"
info "  a submission is not an executed certified block, and this harness does not correlate leaders"
info "  with the workload's block hashes and certifying certificates"

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
mkdir -p "$(dirname "$failuresFile")"
echo "$failures" >"$failuresFile"
exit 0
