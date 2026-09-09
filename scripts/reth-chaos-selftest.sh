#!/bin/bash
# reth-chaos-selftest.sh - regression tests for scripts/reth-chaos.sh's own assertion oracle.
#
# A chaos harness that reports agreement when nothing answered is worse than no harness. The
# reviewer of PR #91 demonstrated exactly that: with every block and receipt RPC returning a
# JSON-RPC error, assertConvergence printed three PASS lines and a failure count of zero, because
# each node produced the same empty observation and the empty strings matched.
#
# This runs the harness's real functions against stubbed RPCs. It starts no node, needs no reth,
# and writes nothing outside its temporary directory.
#
# It sources scripts/lib/reth-chaos-lib.sh, which is definitions only. It used to source a PREFIX
# of reth-chaos.sh instead, which dragged that script's `cd`, `getopts`, reth prerequisite check
# and INT/TERM trap along with it: on a machine without reth the prerequisite check exited every
# case before a single assertion ran, and the suite reported "0 ok, 6 bad" — testing nothing while
# appearing to fail honestly. Verify after any change that this still passes with no reth on PATH:
#
#   PATH=/usr/bin:/bin:/usr/sbin:/sbin ./scripts/reth-chaos-selftest.sh
#
#   ./scripts/reth-chaos-selftest.sh

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

selfPass=0
selfFail=0
ok()  { echo "  ok   $1"; selfPass=$((selfPass + 1)); }
bad() { echo "  BAD  $1"; selfFail=$((selfFail + 1)); }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The library is sourceable as-is: no cd, no getopts, no prerequisite check, no traps. It is
# referenced by absolute path so a case may cd into the work directory without losing it.
harness=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/lib/reth-chaos-lib.sh
[ -r "$harness" ] || { echo "missing $harness" >&2; exit 1; }

runCase() {
  local name=$1 stub=$2 expectFail=$3
  local out
  out=$(
    cd "$work" || exit 1
    validators=4
    # shellcheck disable=SC1090
    set +u; source "$harness" >/dev/null 2>&1; set -u
    mkdir -p test-nodes/evidence
    : >test-nodes/evidence/convergence.txt
    : >test-nodes/evidence/workload.txt
    for i in 1 2 3 4; do mkdir -p "test-nodes/reth$i"; echo 1 >"test-nodes/reth$i/pid"; done
    export CONVERGE_WAIT_BUDGET=0
    txHashes=(0x1234)
    failures=0
    eval "$stub"
    assertConvergence selftest >/dev/null 2>&1
    echo "$failures"
  )
  if [ "$expectFail" = yes ]; then
    [ "${out:-0}" -gt 0 ] && ok "$name: reported ${out} failure(s)" || bad "$name: reported NO failures"
  else
    [ "${out:-1}" -eq 0 ] && ok "$name: reported no failures" || bad "$name: reported ${out} failure(s)"
  fi
}

echo "=== assertConvergence oracle ==="

# The reviewer's exact reproduction.
runCase "every block/receipt RPC errors" '
rpc() {
  case "$2" in
    eth_getTransactionCount) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}" ;;
    *) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"unavailable\"}}" ;;
  esac
}' yes

runCase "every RPC returns empty (transport dead)" '
rpc() { echo ""; }' yes

runCase "receipt missing for a recorded transaction" '
rpc() {
  case "$2" in
    eth_getTransactionCount) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}" ;;
    eth_getBlockByNumber) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"number\":\"0x4\",\"hash\":\"0xabc\"}}" ;;
    *) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}" ;;
  esac
}' yes

runCase "one node reports a different head" '
rpc() {
  local port=${1##*:}
  case "$2" in
    eth_getTransactionCount) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}" ;;
    eth_getBlockByNumber)
      if [ "$port" = "18547" ]; then echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"number\":\"0x9\",\"hash\":\"0xdead\"}}"
      else echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"number\":\"0x4\",\"hash\":\"0xabc\"}}"; fi ;;
    *) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"blockNumber\":\"0x4\",\"status\":\"0x1\"}}" ;;
  esac
}' yes

runCase "all nodes healthy and agreeing" '
rpc() {
  case "$2" in
    eth_getTransactionCount) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}" ;;
    eth_getBlockByNumber) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"number\":\"0x4\",\"hash\":\"0xabc\"}}" ;;
    *) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"blockNumber\":\"0x4\",\"status\":\"0x1\"}}" ;;
  esac
}' no

echo
echo "=== recoveredAndWorking: an unobservable client is not a recovered one ==="

# Review's exact reproduction: the first observation succeeds (4:0xabc) and every later one fails.
# The old loop substituted UNOBSERVABLE, which differs from headBefore, so it exited immediately
# and printed two PASS lines with return 0 and failures 0 — declaring the node recovered BECAUSE
# its client had stopped answering.
runRecoveryCase() {
  local name=$1 headStub=$2 expectFail=$3 out rc
  out=$(
    cd "$work" || exit 1
    validators=4
    # shellcheck disable=SC1090
    set +u; source "$harness" >/dev/null 2>&1; set -u
    mkdir -p test-nodes/evm1 test-nodes/evidence
    echo "accepted certificate" >test-nodes/evm1/debug.log
    recoveryFailed=""
    failures=0
    # Only the observation is stubbed; recoveredAndWorking itself is the real function.
    submitAndConfirm() { return 0; }
    eval "$headStub"
    recoveredAndWorking 1 0 selftest 4 >/dev/null 2>&1
    rc=$?
    echo "$rc $failures ${recoveryFailed:-none}"
  )
  rc=$(echo "$out" | awk '{print $1}')
  local f state
  f=$(echo "$out" | awk '{print $2}')
  state=$(echo "$out" | awk '{print $3}')
  if [ "$expectFail" = yes ]; then
    if [ "${rc:-0}" -ne 0 ] && [ "${f:-0}" -gt 0 ] && [ "$state" != none ]; then
      ok "$name: returned $rc, $f failure(s), recoveryFailed=$state"
    else
      bad "$name: returned ${rc:-?} with ${f:-?} failure(s) and recoveryFailed=${state:-?}"
    fi
  else
    if [ "${rc:-1}" -eq 0 ] && [ "${f:-1}" -eq 0 ]; then
      ok "$name: returned 0 with no failures"
    else
      bad "$name: returned ${rc:-?} with ${f:-?} failure(s)"
    fi
  fi
}

# The counter lives in a FILE: headBefore=$(execHead ...) runs in a subshell, so a shell variable
# would be reset for every call and the stub would never advance past its first state.
runRecoveryCase "observable once, then never again" '
echo 0 >calls
execHead() {
  n=$(( $(cat calls) + 1 )); echo "$n" >calls
  [ "$n" -eq 1 ] && { echo "4:0xabc"; return 0; }
  return 1
}' yes

runRecoveryCase "observable throughout but the head never moves" '
execHead() { echo "4:0xabc"; }' yes

runRecoveryCase "observable and the head advances" '
echo 0 >calls
execHead() {
  n=$(( $(cat calls) + 1 )); echo "$n" >calls
  if [ "$n" -eq 1 ]; then echo "4:0xabc"; else echo "5:0xdef"; fi
}' no

echo
echo "=== a failed prerequisite gates the NEXT scenario ==="

# Review's second reproduction: valid but differing heads produced a canonical-head FAIL while the
# function still returned 0 and left recoveryFailed empty, so the next fault was injected into a
# cluster already known to disagree. The assertion here is not "the failure count rose" but "the
# later fault function is never invoked".
gateOut=$(
  cd "$work" || exit 1
  validators=4
  # shellcheck disable=SC1090
  set +u; source "$harness" >/dev/null 2>&1; set -u
  mkdir -p test-nodes/evidence
  : >test-nodes/evidence/convergence.txt
  : >test-nodes/evidence/workload.txt
  for i in 1 2 3 4; do mkdir -p "test-nodes/reth$i"; echo 1 >"test-nodes/reth$i/pid"; done
  export CONVERGE_WAIT_BUDGET=0
  txHashes=(0x1234)
  failures=0
  recoveryFailed=""
  # Valid replies throughout; the nodes simply disagree about the head.
  #
  # if/elif rather than case: bash 3.2 mis-parses a case pattern's unbalanced ")" inside a $( )
  # command substitution, which is what this whole block is.
  rpc() {
    port=${1##*:}
    if [ "$2" = eth_getTransactionCount ]; then
      printf '%s' '{"jsonrpc":"2.0","id":1,"result":"0x1"}'
    elif [ "$2" = eth_getBlockByNumber ] && [ "$port" = 18547 ]; then
      printf '%s' '{"jsonrpc":"2.0","id":1,"result":{"number":"0x4","hash":"0xdef"}}'
    elif [ "$2" = eth_getBlockByNumber ]; then
      printf '%s' '{"jsonrpc":"2.0","id":1,"result":{"number":"0x4","hash":"0xabc"}}'
    else
      printf '%s' '{"jsonrpc":"2.0","id":1,"result":{"blockNumber":"0x4","status":"0x1"}}'
    fi
  }
  convergenceGate selftest >/dev/null 2>&1
  gateRc=$?

  # Now the thing that actually matters: would the next scenario run?
  nextFaultInjected=no
  injectNextFault() { nextFaultInjected=yes; }
  if skipIfUnrecovered "next scenario" >/dev/null 2>&1; then :; else injectNextFault; fi

  echo "$gateRc ${recoveryFailed:-none} $nextFaultInjected"
)
gateRc=$(echo "$gateOut" | awk '{print $1}')
gateState=$(echo "$gateOut" | awk '{print $2}')
gateNext=$(echo "$gateOut" | awk '{print $3}')
if [ "${gateRc:-0}" -ne 0 ] && [ "$gateState" != none ] && [ "$gateNext" = no ]; then
  ok "differing heads: gate returned $gateRc, recoveryFailed=$gateState, next fault NOT injected"
else
  bad "differing heads: gate returned ${gateRc:-?}, recoveryFailed=${gateState:-?}, next fault injected=${gateNext:-?}"
fi

echo
echo "=== execHead ==="
(
  cd "$work" || exit 1
  validators=4
  set +u; source "$harness" >/dev/null 2>&1; set -u
  rpc() { echo '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}'; }
  if execHead 1 >/dev/null 2>&1; then echo "  BAD  execHead succeeded on an RPC error"; exit 1; fi
  echo "  ok   execHead fails on an RPC error instead of returning a sentinel"
) && selfPass=$((selfPass + 1)) || selfFail=$((selfFail + 1))

echo
echo "=== supervisor verdict: the supervisor's own failures survive combining ==="

# The boundary the oracle cases above cannot reach. superviseResult runs in the PARENT process,
# where evidence collection reports through the same fail() the scenarios use, and then combines
# that with the child's recorded count. Conflating the two is what let a successful child plus a
# failed archive print FAIL and exit 0 (#91 review 5144079322).
#
# These execute the real superviseResult and the real collectEvidence, against a fabricated
# test-nodes tree. Only cleanup is stubbed: tearing down a devnet is not what is under test, and
# there is none here. The failures are provoked with real filesystem permissions rather than by
# stubbing tar or cp, so the case fails for the reason it claims to.
runSupervisorCase() {
  local name=$1 childStatus=$2 childResult=$3 setup=$4 expectRc=$5 expectText=$6
  local out rc
  out=$(
    cd "$work" || exit 1
    rm -rf super && mkdir super && cd super || exit 1
    validators=2
    # shellcheck disable=SC1090
    set +u; source "$harness" >/dev/null 2>&1; set -u
    keep=false
    cleanup() { :; }
    # A fixed run directory so a setup can make the exact thing it wants to break unwritable.
    runID=case
    runDir=$PWD/evidence-runs/case
    mkdir -p "$runDir"

    for i in 1 2; do
      mkdir -p "test-nodes/evm$i" "test-nodes/reth$i"
      echo x >"test-nodes/evm$i/debug.log"
      echo x >"test-nodes/reth$i/reth.log"
    done
    for i in 1 2 3; do mkdir -p "test-nodes/root$i"; echo x >"test-nodes/root$i/debug.log"; done

    resultFile=$runDir/.failures
    [ "$childResult" = none ] || echo "$childResult" >"$resultFile"
    eval "$setup"
    superviseResult "$childStatus" "$resultFile"
    echo "RC=$?"
  )
  chmod -R u+w "$work/super" 2>/dev/null
  rc=$(echo "$out" | sed -n 's/^RC=//p')
  if [ "${rc:-x}" = "$expectRc" ] && echo "$out" | grep -q "$expectText"; then
    ok "$name: returned $rc"
  else
    bad "$name: returned ${rc:-?}, expected $expectRc matching '$expectText' — got: $(echo "$out" | tr '\n' '|')"
  fi
}

# The positive control. Without it every case below could pass because the verdict is always 1.
runSupervisorCase "clean child, clean evidence" 0 0 ':' 0 'evidence complete'

# The reviewer's reproduction: a successful child must not erase the supervisor's own failures.
# The run directory's PARENT is made read-only, so the per-scenario copies still succeed and only
# the archive cannot be written — the exact shape of "the run worked, the evidence did not survive".
runSupervisorCase "clean child, archive cannot be written" 0 0 'chmod 555 "$(dirname "$runDir")"' 1 'archive was not produced'

# A required artefact that exists but cannot be copied: the destination directory is present, so
# the collection gets as far as copying, and every copy fails.
runSupervisorCase "clean child, evidence copy fails" 0 0 'mkdir -p "$runDir/scenarios/final"; chmod 555 "$runDir/scenarios/final"' 1 'evidence collection incomplete'

# The secret check, with a successful child. keys.json is never copied; this is the backstop for
# one arriving by some other route, and it must fail the run rather than be reported and dropped.
runSupervisorCase "clean child, secret file in the archive" 0 0 'touch "$runDir/keys.json"' 1 'secret file'

# The child's own count still decides when the supervisor is clean, and the summary attributes
# each side, so a reader can tell an evidence failure from a scenario failure.
runSupervisorCase "child reported failures, clean evidence" 0 2 ':' 1 '2 from the run, 0 from evidence'

# Abnormal endings, unchanged in behaviour but now covered.
runSupervisorCase "child never recorded a result" 0 none ':' 1 'without recording a result'
runSupervisorCase "child exited nonzero with nothing recorded" 7 0 ':' 1 'exited 7 with no assertion failure'
runSupervisorCase "child recorded an unreadable result" 0 banana ':' 1 'unreadable result'

echo
echo "=== leader/block correlation reads the runtime's real log line ==="

# The correlation joins a receipt to a partition round through a line the SHARD NODE writes, so its
# field names are a contract with shardnode/round.go. #109 replaced "execution anchor installed"
# with "continuity: observed certificate" and this parser had to move with it; nothing but this case
# ties the two together. The sample below is a verbatim line from a real validator's debug log.
correlationOut=$(
  cd "$work" || exit 1
  rm -rf correlate && mkdir correlate && cd correlate || exit 1
  validators=1
  # shellcheck disable=SC1090
  set +u; source "$harness" >/dev/null 2>&1; set -u
  mkdir -p test-nodes/evm1
  cat >test-nodes/evm1/debug.log <<'LOG'
time=2026-09-09T09:01:04.2920+0300 level=DEBUG source=/x/shardnode/round.go:331 msg="continuity: observed certificate" transition=installed reason="non-quiet certificate: this block becomes the anchor" partitionRound=1 assignedNext=2 quiet=false blockHash=bf375b629e8a70c291209cd8c7a3926beae26136fa0ce9fc476bfaf2a7094b22 stateRoot=bf375b629e8a70c291209cd8c7a3926beae26136fa0ce9fc476bfaf2a7094b22 previousHash= expectedNextBefore=0 throughBefore=0 anchorRoundBefore=0 anchorBlockBefore= brokenBefore=false expectedNextAfter=2 throughAfter=1 anchorRoundAfter=1 rootRound=4 nodeID=16Uiu2
time=2026-09-09T09:01:09.1000+0300 level=DEBUG source=/x/shardnode/round.go:331 msg="continuity: observed certificate" transition=extended reason="the assigned next round, quiet, at the anchor's state" partitionRound=2 assignedNext=3 quiet=true blockHash= stateRoot=bf375b629e8a70c291209cd8c7a3926beae26136fa0ce9fc476bfaf2a7094b22 previousHash=bf375b629e8a70c291209cd8c7a3926beae26136fa0ce9fc476bfaf2a7094b22 expectedNextBefore=2 throughBefore=1 anchorRoundBefore=1 anchorBlockBefore=bf375b62 brokenBefore=false expectedNextAfter=3 throughAfter=2 anchorRoundAfter=1 rootRound=7 nodeID=16Uiu2
time=2026-09-09T09:01:11.5000+0300 level=INFO source=/x/shardnode/round.go:400 msg="submitting block certification request" round=1 quiet=false leader=true go_id=402
LOG
  echo "round=$(certifiedRoundOfBlock 1 0xbf375b629e8a70c291209cd8c7a3926beae26136fa0ce9fc476bfaf2a7094b22 || echo NOTFOUND)"
  echo "leader=$(leaderOfRound 1 || echo NOTFOUND)"
  # A quiet round names no block, so it must not be matched by an empty hash.
  echo "quiet=$(certifiedRoundOfBlock 1 0x || echo REFUSED)"
)
if [ "$(echo "$correlationOut" | sed -n 's/^round=//p')" = "1" ] &&
   [ "$(echo "$correlationOut" | sed -n 's/^leader=//p')" = "1" ] &&
   [ "$(echo "$correlationOut" | sed -n 's/^quiet=//p')" = "REFUSED" ]; then
  ok "the parser reads a verbatim runtime log line: block -> round -> leader"
else
  bad "correlation against the real line: $(echo "$correlationOut" | tr '\n' ' ')"
fi

echo
echo "=== evidence retention across cluster resets ==="

# A cluster whose logs, trust base and identities live under test-nodes/ is destroyed by
# setup-evm-nodes.sh's `make clean` at every scenario boundary. These cases run the REAL
# bringUpCluster, collectEvidence and archiveEvidence with only process and chain startup stubbed,
# and check what survives — the defect they pin is that everything except the summary snapshots
# used to be gone by the time the run ended.
stubCluster() {
  # A fake devnet: setup wipes test-nodes and re-creates it, exactly as the real one does.
  cat >stop-evm.sh <<'SH'
#!/bin/sh
exit 0
SH
  cat >start-evm.sh <<'SH'
#!/bin/sh
exit 0
SH
  cat >setup-evm-nodes.sh <<'SH'
#!/bin/sh
rm -rf test-nodes
mkdir -p test-nodes/evm1 test-nodes/root1 test-nodes/reth1
printf '%s accepted certificate\n' "$SENTINEL" >test-nodes/evm1/debug.log
printf '%s\n' "$SENTINEL" >test-nodes/root1/debug.log
printf '%s\n' "$SENTINEL" >test-nodes/reth1/reth.log
printf '%s\n' "$SENTINEL" >test-nodes/trust-base.json
printf '%s\n' "$SENTINEL" >test-nodes/evm1/node-info.json
SH
  printf 'rootPortStart=1000\nboot_node() { echo stub; }\n' >helper.sh
  chmod +x stop-evm.sh start-evm.sh setup-evm-nodes.sh
  stopReth() { :; }
  startReth() { :; }
  waitReth() { :; }
  peerReths() { :; }
  python3() { cat >/dev/null; }
  openssl() { echo fake-test-secret; }
}

# scenarioLifecycle <body> - run <body> against a stubbed cluster in a fresh directory, with the
# REAL bringUpCluster/collectEvidence/archiveEvidence/finish. Only process and chain startup are
# stubbed; every lifecycle decision under test is the harness's own.
scenarioLifecycle() {
  local dir=$1 body=$2
  (
    cd "$work" || exit 1
    rm -rf "$dir" && mkdir "$dir" && cd "$dir" || exit 1
    validators=1
    # shellcheck disable=SC1090
    set +u; source "$harness" >/dev/null 2>&1; set -u
    runID=selftest
    runDir=$PWD/evidence-runs/$runID
    keep=false
    cleanup() { :; }
    stubCluster
    eval "$body"
  )
}

retentionOut=$(scenarioLifecycle retention '
  SENTINEL=SCENARIO_ONE bringUpCluster scenario-one >/dev/null 2>&1 || echo BRINGUP1_FAILED
  SENTINEL=SCENARIO_TWO bringUpCluster scenario-two >/dev/null 2>&1 || echo BRINGUP2_FAILED
  finish >/dev/null 2>&1
  grep -Rl SCENARIO_ONE "$runDir/scenarios/scenario-one" >/dev/null 2>&1 && echo ONE_KEPT || echo ONE_LOST
  grep -Rl SCENARIO_TWO "$runDir/scenarios/scenario-two" >/dev/null 2>&1 && echo TWO_KEPT || echo TWO_LOST
  [ -s "$runDir.tar.gz" ] && echo ARCHIVED || echo NO_ARCHIVE
')
if echo "$retentionOut" | grep -q ONE_KEPT && echo "$retentionOut" | grep -q TWO_KEPT &&
   echo "$retentionOut" | grep -q ARCHIVED; then
  ok "two scenarios: each is sealed under its own name and the first survives the second's reset"
else
  bad "two scenarios: $(echo "$retentionOut" | tr '\n' ' ')"
fi

abortOut=$(scenarioLifecycle abort '
  SENTINEL=SCENARIO_ONE bringUpCluster scenario-one >/dev/null 2>&1
  # The destination cannot be written: sealing must fail, and the reset must NOT happen.
  mkdir -p "$runDir/scenarios"; chmod 500 "$runDir/scenarios"
  if SENTINEL=SCENARIO_TWO bringUpCluster scenario-two >/dev/null 2>&1; then echo RESET_PROCEEDED; else echo RESET_ABORTED; fi
  chmod 700 "$runDir/scenarios" 2>/dev/null
  grep -q SCENARIO_ONE test-nodes/evm1/debug.log 2>/dev/null && echo CLUSTER_INTACT || echo CLUSTER_DESTROYED
')
if echo "$abortOut" | grep -q RESET_ABORTED && echo "$abortOut" | grep -q CLUSTER_INTACT; then
  ok "a failed seal aborts the reset and leaves the cluster it could not preserve"
else
  bad "failed seal: $(echo "$abortOut" | tr '\n' ' ')"
fi

# THE OWNERSHIP CASE. The reset succeeded and the STARTUP failed, so the previous scenario's name
# must already have moved on: filing this cluster under it would write a broken cluster over the
# evidence of the one that worked.
startupOut=$(scenarioLifecycle startup '
  SENTINEL=SCENARIO_ONE bringUpCluster scenario-one >/dev/null 2>&1
  waitReth() { return 1; }   # the new cluster never comes up, after the old one is already gone
  SENTINEL=SCENARIO_TWO bringUpCluster scenario-two >/dev/null 2>&1 || echo BRINGUP2_FAILED
  finish >/dev/null 2>&1
  grep -Rl SCENARIO_ONE "$runDir/scenarios/scenario-one" >/dev/null 2>&1 && echo ONE_INTACT || echo ONE_CLOBBERED
  grep -Rq SCENARIO_TWO "$runDir/scenarios/scenario-one" 2>/dev/null && echo ONE_HAS_TWOS_LOGS || echo ONE_CLEAN
  [ -d "$runDir/scenarios/scenario-two" ] && echo TWO_FILED || echo TWO_MISSING
')
if echo "$startupOut" | grep -q BRINGUP2_FAILED && echo "$startupOut" | grep -q ONE_INTACT &&
   echo "$startupOut" | grep -q ONE_CLEAN && echo "$startupOut" | grep -q TWO_FILED; then
  ok "a failed startup files the broken cluster under its OWN scenario, not over the previous one"
else
  bad "startup failure: $(echo "$startupOut" | tr '\n' ' ')"
fi

# Cancellation: the INT/TERM trap calls finish while a scenario is live. It must be sealed under its
# own name, and the scenario before it must not be touched.
cancelOut=$(scenarioLifecycle cancel '
  SENTINEL=SCENARIO_ONE bringUpCluster scenario-one >/dev/null 2>&1
  SENTINEL=SCENARIO_TWO bringUpCluster scenario-two >/dev/null 2>&1
  finish >/dev/null 2>&1   # as the interrupt handler does, mid-scenario
  grep -Rl SCENARIO_ONE "$runDir/scenarios/scenario-one" >/dev/null 2>&1 && echo ONE_INTACT || echo ONE_CLOBBERED
  grep -Rl SCENARIO_TWO "$runDir/scenarios/scenario-two" >/dev/null 2>&1 && echo TWO_SEALED || echo TWO_LOST
  [ -d "$runDir/scenarios/final" ] && echo FILED_AS_FINAL || echo NAMED_PROPERLY
')
if echo "$cancelOut" | grep -q ONE_INTACT && echo "$cancelOut" | grep -q TWO_SEALED &&
   echo "$cancelOut" | grep -q NAMED_PROPERLY; then
  ok "an interrupted run seals the live scenario under its own name and leaves the earlier one alone"
else
  bad "cancellation: $(echo "$cancelOut" | tr '\n' ' ')"
fi

overwriteOut=$(scenarioLifecycle overwrite '
  SENTINEL=SCENARIO_ONE bringUpCluster scenario-one >/dev/null 2>&1
  collectEvidence scenario-one >/dev/null 2>&1 || echo FIRST_SEAL_FAILED
  if collectEvidence scenario-one >/dev/null 2>&1; then echo OVERWROTE; else echo REFUSED; fi
  grep -Rl SCENARIO_ONE "$runDir/scenarios/scenario-one" >/dev/null 2>&1 && echo STILL_THERE || echo LOST
')
if echo "$overwriteOut" | grep -q REFUSED && echo "$overwriteOut" | grep -q STILL_THERE; then
  ok "sealing the same scenario twice is refused rather than silently overwriting it"
else
  bad "overwrite: $(echo "$overwriteOut" | tr '\n' ' ')"
fi

echo
echo "=== scenario selection ==="

selectionCase() {
  local name=$1 sel=$2 expect=$3 got
  got=$(
    cd "$work" || exit 1
    # shellcheck disable=SC1090
    set +u; source "$harness" >/dev/null 2>&1; set -u
    scenarios=$sel
    if validateScenarios >/dev/null 2>&1; then echo accepted; else echo rejected; fi
  )
  if [ "$got" = "$expect" ]; then ok "selection '$sel': $got"; else bad "selection '$sel': $got, expected $expect"; fi
}
selectionCase "unknown only" "bogus" rejected
selectionCase "mixed valid and unknown" "follower-restart,bogus" rejected
selectionCase "empty token" "follower-restart,,leader-kill" rejected
selectionCase "valid subset" "follower-restart,multi-leader" accepted
selectionCase "all" "" accepted

# And through the real entrypoint, which is where the empty run reported success.
entry=$(cd "$(dirname "$harness")/.." >/dev/null && pwd)/reth-chaos.sh
if "$entry" -s definitely-not-a-scenario >/dev/null 2>&1; then
  bad "entrypoint: an unknown -s selection exited 0"
else
  ok "entrypoint: an unknown -s selection is refused before anything is started or stopped"
fi

echo
echo "=== run manifest ==="
manifestOut=$(
  cd "$work" || exit 1
  rm -rf manifest && mkdir manifest && cd manifest || exit 1
  validators=4
  # shellcheck disable=SC1090
  set +u; source "$harness" >/dev/null 2>&1; set -u
  runID=selftest-manifest
  runDir=$PWD/evidence-runs/$runID
  scenarios=multi-leader
  writeRunManifest -s multi-leader >/dev/null 2>&1
  cat "$runDir/manifest.txt" 2>/dev/null
)
if echo "$manifestOut" | grep -q '^bft=' && echo "$manifestOut" | grep -q 'scenariosSelected=multi-leader' &&
   echo "$manifestOut" | grep -q '^rethPinned='; then
  ok "a subset run records its own revisions and selection, in its own run directory"
else
  bad "manifest: $(echo "$manifestOut" | tr '\n' ' ')"
fi

echo
echo "selftest: $selfPass ok, $selfFail bad"
[ "$selfFail" -eq 0 ]
