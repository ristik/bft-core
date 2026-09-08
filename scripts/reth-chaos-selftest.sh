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
echo "selftest: $selfPass ok, $selfFail bad"
[ "$selfFail" -eq 0 ]
