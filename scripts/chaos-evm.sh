#!/bin/bash
# chaos-evm.sh - formalizes the failure scenarios exercised manually while
# building the shard-node framework (see docs/engine-api-adapter-plan.md
# C3.1): a validator dying and coming back, whether as a follower or as the
# round's current leader, and a corrupted on-disk certificate store. Runs
# entirely against --executor fake, so it needs nothing beyond this repo.
#
# What this does and does not prove, honestly: the CLI's fake executor is
# never given entries to certify (there is no transaction-ingestion path
# wired to it), so every round after genesis is quiet and the state root
# never leaves all-zero. That makes "does a restarted validator resume
# without equivocating or falling out of sync with the root chain" a real,
# live-exercised question here (handshake, LUC store continuity, round
# numbering) — but it means Executor.Commit's own recovery path (a
# restarted node reconciling a *non-quiet* head against a persisted block
# store) never actually triggers, because fake has no persistence to
# recover FROM and quiet rounds never move the head to begin with. That
# path is covered instead by shardnode/round_recovery_test.go, in-process,
# where a real non-quiet round can be constructed. See
# docs/adr/0001-executor-boundary.md.
#
# Usage: scripts/chaos-evm.sh [-v validators] [-p partition id] [-k]
#   -v  number of validators (default 4; needs >=4 to tolerate one fault)
#   -p  partition id (default 8)
#   -k  keep test-nodes/ and the running processes afterwards (default:
#       stop everything and exit)
#
# Exit code is nonzero if any scenario's assertion failed.

set -e
cd "$(dirname "${BASH_SOURCE[0]}")/.."

validators=4
partition_id=8
keep=false

usage() {
  echo "Usage: $0 [-h usage] [-v number of validators] [-p partition id] [-k keep nodes running after]"
  exit 0
}

while getopts "hv:p:k" o; do
  case "${o}" in
  v) validators=${OPTARG} ;;
  p) partition_id=${OPTARG} ;;
  k) keep=true ;;
  h | *) usage ;;
  esac
done

if [ "$validators" -lt 4 ]; then
  echo "need at least 4 validators to tolerate one fault (got $validators)" >&2
  exit 1
fi

failures=0
pass() { echo "  PASS: $1"; }
fail() {
  echo "  FAIL: $1" >&2
  failures=$((failures + 1))
}

# check_divergence <validator> <context> [afterLine] - report whether a validator logged a
# divergence or equivocation since afterLine, distinguishing the cases the old flat grep conflated:
#
#   shardnode/round.go:317  WARN "executor head diverges ... attempting recovery via Commit"
#                           — expected after an outage, and benign IF recovery then succeeds
#   shardnode/round.go:326  the fatal "cannot safely build round N" error
#   shardnode/uc.go         ErrEquivocatingUC — never benign
#
# A run in CI (job 101727627944, cold-restart) tripped the old check while the adjacent
# "resumed certifying" assertion passed, and nobody could tell which message fired, because the
# script matched both and then discarded the log. So on any match this prints the offending lines
# and only fails hard for the ones that are actually faults.
check_divergence() {
  local v=$1 context=$2 after=${3:-0}
  # Declared separately on purpose: referring to $v inside the same `local` that assigns it is
  # not reliably left-to-right across shells, and silently yields test-nodes/evm/debug.log.
  local log="test-nodes/evm$v/debug.log"
  local hits
  # Scoped to lines after the restart marker. Without that this scans the whole appended log and
  # attributes startup-time messages to whatever scenario happens to be running: CI job on
  # b9c1ae53 reported a FATAL equivocation "during outage-and-catchup" from line 8 of the log,
  # which was the node's very first startup, minutes earlier.
  hits=$(awk -v n="$after" 'NR > n && tolower($0) ~ /diverges|equivocat/ {print NR ":" $0}' "$log" 2>/dev/null || true)
  if [ -z "$hits" ]; then
    pass "validator $v's $context logged no divergence or equivocation error"
    return
  fi
  echo "  --- divergence/equivocation lines from validator $v ---" >&2
  echo "$hits" >&2
  echo "  --- end ---" >&2
  if echo "$hits" | grep -qi 'equivocat\|cannot safely build round'; then
    fail "validator $v logged a FATAL divergence/equivocation during $context (see lines above)"
    return
  fi
  # Recovery only counts if it happened AFTER the warning: the log is appended across restarts, so
  # certificates from before the outage are still in it and would otherwise mask a stuck node.
  local lastWarn firstCertAfter
  lastWarn=$(echo "$hits" | tail -1 | cut -d: -f1)
  firstCertAfter=$(awk -v n="$lastWarn" 'NR > n && /accepted certificate/ {print NR; exit}' "$log" || true)
  if [ -n "$firstCertAfter" ]; then
    pass "validator $v warned about a diverged head during $context (line $lastWarn), then recovered and certified (line $firstCertAfter)"
  else
    fail "validator $v logged a diverged head during $context (line $lastWarn) and certified nothing afterwards"
  fi
}

# dump_stall_evidence <observed-validator> - print what the live validators were doing when a
# progress assertion failed.
#
# A stall here has two very different explanations and the pass/fail line alone cannot separate
# them: the shard genuinely wedged, or the budget was too short for the root chain's T2 timeout to
# reissue the dead leader's round to the next leader in rotation. "Submitting block certification
# request" lines with rising round numbers mean the shard is working and the budget was tight;
# their absence means it is actually stuck. Print both, plus any error, so the next occurrence in
# CI is decidable instead of another round of timeout guessing.
dump_stall_evidence() {
  local observed=$1 i
  echo "  --- stall evidence ---" >&2
  for i in $(seq 1 "$validators"); do
    [ -f "test-nodes/evm$i/pid" ] || { echo "  evm$i: stopped" >&2; continue; }
    echo "  evm$i last rounds: $(grep -o 'partitionRound=[0-9]*' "test-nodes/evm$i/debug.log" 2>/dev/null | tail -3 | tr '\n' ' ')" >&2
    echo "  evm$i last submits: $(grep 'submitting block certification request' "test-nodes/evm$i/debug.log" 2>/dev/null | tail -2 | grep -oE 'round=[0-9]+ quiet=\w+ leader=\w+' | tr '\n' ' ')" >&2
    echo "  evm$i last error: $(grep -iE 'level=(ERROR|WARN)' "test-nodes/evm$i/debug.log" 2>/dev/null | tail -1 | cut -c1-200)" >&2
  done
  echo "  observed validator was evm$observed" >&2
  echo "  --- end ---" >&2
}

# log_lines - current line count of validator $1's log, for use as a "everything before here is
# history" marker across a restart.
log_lines() {
  local n
  n=$(wc -l <"test-nodes/evm$1/debug.log" 2>/dev/null || echo 0)
  echo "${n:-0}"
}

# wait_for_after - poll (up to $2 seconds) until pattern $1 appears in $3 BEYOND line $4.
#
# Validator logs are opened with >> (helper.sh's start_one_evm_validator), so they accumulate
# across restarts. A plain `wait_for 'accepted certificate'` after a restart therefore matches a
# certificate the node accepted *before* it was killed and returns immediately, making every
# "rejoined and resumed certifying" assertion vacuous. That is not academic: it let this script
# stop a third validator while a previously-restarted one had not actually rejoined, dropping the
# shard below its 3-of-4 quorum and producing a genuine stall that then looked like a flaky
# progress check.
wait_for_after() {
  local pattern=$1 timeout=$2 file=$3 after=$4 waited=0
  while ! awk -v n="$after" -v p="$pattern" 'NR > n && index($0, p) {found=1; exit} END {exit !found}' "$file" 2>/dev/null; do
    if [ "$waited" -ge "$timeout" ]; then
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 0
}

# wait_for - poll (up to $2 seconds) until `grep -q "$1" "$3"` succeeds.
wait_for() {
  local pattern=$1 timeout=$2 file=$3 waited=0
  while ! grep -q "$pattern" "$file" 2>/dev/null; do
    if [ "$waited" -ge "$timeout" ]; then
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 0
}

# latest_round - highest partitionRound this validator has logged accepting,
# or 0 if it hasn't logged one yet (keeps callers' arithmetic/comparisons
# well-defined under set -e rather than tripping over an empty string).
latest_round() {
  local r
  r=$(grep -o 'partitionRound=[0-9]*' "test-nodes/evm$1/debug.log" 2>/dev/null | tail -1 | cut -d= -f2)
  echo "${r:-0}"
}

# recent_leader - true if validator $1 logged itself as leader in its last
# 20 "submitting block certification request" lines.
was_recent_leader() {
  tail -n 200 "test-nodes/evm$1/debug.log" 2>/dev/null | grep 'submitting block certification request' | tail -20 | grep -q 'leader=true'
}

# wait_for_progress - poll (up to $3 seconds) for validator $1's
# partitionRound to exceed $2. Deliberately a poll with a generous budget,
# not a fixed sleep-then-compare: a round assigned to a currently-dead
# leader only recovers once the root chain's own T2 timeout reissues a
# repeat certificate with the next leader in rotation (see
# docs/shard-protocol.md), which can take a few multiples of T2 — a short
# fixed window flags healthy self-recovery as a stall.
wait_for_progress() {
  local validator=$1 above=$2 timeout=$3 waited=0
  while [ "$(latest_round "$validator")" -le "$above" ]; do
    if [ "$waited" -ge "$timeout" ]; then
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 0
}

echo "=== chaos-evm.sh: setting up $validators-validator fake-executor shard ==="
buildLog=$(mktemp)
make clean build >"$buildLog" 2>&1 || { cat "$buildLog"; exit 1; }
rm -f "$buildLog"
rm -rf test-nodes
mkdir test-nodes
source helper.sh

init_root_nodes 3
init_evm_validators "$validators"
generate_evm_shard_conf "$validators" "$partition_id" 31337 3000 exec
generate_log_configuration "test-nodes/*/"

echo -n "starting root nodes..." && start_root_nodes
wait_for_root_chain_settle
rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")
start_evm_validators "$validators" "$partition_id" "$rootBoot" fake rpc

cleanup() {
  if [ "$keep" != true ]; then
    echo "=== stopping everything ==="
    stop_evm_validators
    ./stop.sh -a
  else
    echo "=== leaving test-nodes/ running (-k) ==="
  fi
}
trap cleanup EXIT

echo "=== waiting for certification to get underway ==="
# 90s, not 30s: a validator that handshakes before the root chain's own
# consensus has caught up on a freshly-registered shard conf gets "unknown
# partition" and has to wait out its own 30s inactivity timeout to retry —
# sometimes more than once. This is expected first-launch behavior, not a
# bug in this script; see docs/troubleshooting.md.
for i in $(seq 1 "$validators"); do
  if ! wait_for 'accepted certificate' 90 "test-nodes/evm$i/debug.log"; then
    fail "validator $i never certified a round within 90s — aborting, see test-nodes/evm$i/debug.log"
    exit 1
  fi
done
pass "all $validators validators are certifying"

echo
echo "=== scenario: kill-follower ==="
follower=1
for i in $(seq 1 "$validators"); do
  if ! was_recent_leader "$i"; then
    follower=$i
    break
  fi
done
before=$(latest_round "$follower")
echo "stopping validator $follower (not recently leader, round $before) ..."
stop_one_evm_validator "$follower"
survivor=$((follower % validators + 1))
survivorBefore=$(latest_round "$survivor")
if wait_for_progress "$survivor" "$survivorBefore" 30; then
  pass "remaining $((validators - 1)) validators kept certifying without validator $follower (round $survivorBefore -> $(latest_round "$survivor"))"
else
  fail "quorum stalled after killing validator $follower (round stuck at $survivorBefore for 30s)"
  dump_stall_evidence "$survivor"
fi
echo "restarting validator $follower ..."
followerMark=$(log_lines "$follower")
start_one_evm_validator "$follower" "$validators" "$partition_id" "$rootBoot" fake rpc
if wait_for_after 'accepted certificate' 30 "test-nodes/evm$follower/debug.log" "$followerMark"; then
  pass "validator $follower rejoined and resumed certifying"
else
  fail "validator $follower did not resume certifying within 20s after restart"
fi
check_divergence "$follower" "restart" "$followerMark"

echo
echo "=== scenario: kill-leader ==="
leader=1
for i in $(seq 1 "$validators"); do
  if was_recent_leader "$i"; then
    leader=$i
    break
  fi
done
before=$(latest_round "$leader")
echo "stopping validator $leader (recently leader, round $before) ..."
stop_one_evm_validator "$leader"
survivor=$((leader % validators + 1))
survivorBefore=$(latest_round "$survivor")
if wait_for_progress "$survivor" "$survivorBefore" 30; then
  pass "remaining $((validators - 1)) validators kept certifying without leader $leader (round $survivorBefore -> $(latest_round "$survivor"), leader rotation recovered)"
else
  fail "quorum stalled after killing leader $leader (round stuck at $survivorBefore for 30s)"
  dump_stall_evidence "$survivor"
fi
echo "restarting validator $leader ..."
leaderMark=$(log_lines "$leader")
start_one_evm_validator "$leader" "$validators" "$partition_id" "$rootBoot" fake rpc
if wait_for_after 'accepted certificate' 30 "test-nodes/evm$leader/debug.log" "$leaderMark"; then
  pass "validator $leader rejoined and resumed certifying"
else
  fail "validator $leader did not resume certifying within 20s after restart"
fi

echo
echo "=== scenario: cold-restart (longer outage) ==="
target=$survivor
before=$(latest_round "$target")
echo "stopping validator $target for an extended outage (others keep certifying without it) ..."
stop_one_evm_validator "$target"
other=$((target % validators + 1))
otherBefore=$(latest_round "$other")
# The verdict below is taken from the measurement, not from whether this wait won its race.
# Those were two different things and they contradicted each other in CI: runs 101730435909 and
# 101730449401 both reported "shard made no progress during validator N's outage" from a failed
# 15s wait, and then, five seconds later, "resumed certifying after a 7-round outage" from the
# measurement. The shard had progressed; only the race had been lost.
#
# 15s was too tight for what this scenario deliberately provokes. wait_for_progress's own comment
# says a round assigned to a currently-dead leader recovers only once the root chain's T2 timeout
# reissues it to the next leader in rotation, "a few multiples of T2" — and T2 here is 3000ms
# (see generate_evm_shard_conf above), so 15s is five of them, with no allowance for a loaded
# runner. The wait is now 45s and exists only to avoid sleeping the full budget when the shard
# recovers quickly.
wait_for_progress "$other" "$otherBefore" 45 || true
sleep 5 # let a few more rounds pass while target is still down, for a real "outage", not a blink
otherRoundDuringOutage=$(latest_round "$other")
if [ "$otherRoundDuringOutage" -gt "$otherBefore" ]; then
  pass "shard progressed well past validator $target's last round ($before -> $otherRoundDuringOutage) while it was down"
else
  fail "shard made no progress during validator $target's outage (validator $other stuck at round $otherBefore for 50s)"
  dump_stall_evidence "$other"
fi
targetMark=$(log_lines "$target")
start_one_evm_validator "$target" "$validators" "$partition_id" "$rootBoot" fake rpc
if wait_for_after 'accepted certificate' 30 "test-nodes/evm$target/debug.log" "$targetMark"; then
  pass "validator $target caught up and resumed certifying after a $((otherRoundDuringOutage - before))-round outage"
else
  fail "validator $target did not resume after its outage"
fi
check_divergence "$target" "outage-and-catchup" "$targetMark"

echo
echo "=== scenario: tampered-block (corrupted on-disk certificate store) ==="
victim=$target
echo "stopping validator $victim and corrupting its persisted LUC store ..."
stop_one_evm_validator "$victim"
lucFile="test-nodes/evm$victim/shard-node-luc.json"
if [ -f "$lucFile" ]; then
  echo '{this is not valid json, simulating disk corruption or tampering' >"$lucFile"
else
  fail "no LUC store found at $lucFile to tamper with — was round 1 ever certified?"
fi
: >"test-nodes/evm$victim/debug.log" # isolate this scenario's log output
start_one_evm_validator "$victim" "$validators" "$partition_id" "$rootBoot" fake rpc
sleep 2
if grep -q 'unmarshaling stored certificate' "test-nodes/evm$victim/debug.log" 2>/dev/null; then
  pass "validator $victim refused to start on a corrupted certificate store (failed loudly, did not silently resume from scratch)"
else
  fail "validator $victim did not report the expected unmarshal error on a corrupted LUC store — see test-nodes/evm$victim/debug.log"
fi
# The process above exits immediately on that error (shardNodeRun returns
# it before Run starts) — nothing left to stop, but remove any stale pid
# file so the final stop_evm_validators sweep doesn't try to kill a pid
# that already exited.
rm -f "test-nodes/evm$victim/pid"

echo
if [ "$failures" -eq 0 ]; then
  echo "=== chaos-evm.sh: all scenarios passed ==="
else
  echo "=== chaos-evm.sh: $failures scenario(s) failed ===" >&2
fi
exit "$failures"
