#!/bin/bash
# reth-chaos-selftest.sh - regression tests for scripts/reth-chaos.sh's own assertion oracle.
#
# A chaos harness that reports agreement when nothing answered is worse than no harness. The
# reviewer of PR #91 demonstrated exactly that: with every block and receipt RPC returning a
# JSON-RPC error, assertConvergence printed three PASS lines and a failure count of zero, because
# each node produced the same empty observation and the empty strings matched.
#
# This runs the harness's real functions against stubbed RPCs. It starts no node and needs no reth.
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

# Load the harness's functions without running it: everything above the marker is definitions.
harness=$work/harness.sh
sed -n '1,/^# --- HARNESS DEFINITIONS END/p' scripts/reth-chaos.sh >"$harness"

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
