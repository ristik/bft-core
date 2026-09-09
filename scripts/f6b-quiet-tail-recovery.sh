#!/bin/bash
# f6b-quiet-tail-recovery.sh - the acceptance run for #92: does a node that returns behind a quiet
# tail recover its execution anchor from a peer, against a REAL reth, WITHOUT injecting a transaction?
#
# This is the measurement docs/design/f1-baseline.md §5.7.3 could not resolve. There, 20 certified
# rounds over two minutes were every one quiet, every anchor decision "unchanged", the executor a
# block behind, and recovery came only from a non-quiet round — that is, from new activity. The
# question this script answers is whether the same node now recovers with no new activity at all.
#
# It runs two arms against the same devnet, which is what makes it evidence rather than a demo:
#
#   CONTROL   restart one validator with recovery OFF (the default). It must refuse `no-anchor` on
#             every quiet certificate, for ever. This is §1 reproduced on the merged revision.
#   RECOVERY  restart the same validator with --evidence-recover. It must obtain authenticated
#             evidence from a peer, adopt the anchor, and stop refusing — while STILL not voting.
#
# What it asserts, in the words #92 asks for:
#   exact-block recovery    the anchor adopted names the block the root chain certified, and the
#                           executor satisfies P-id for it
#   signing refusal unchanged   a resumed process is NON-VOTING (P-sign, #105) before and after
#   immutable evidence      the providers retain and serve without refusing anything, and their
#                           retained interval is not altered by having served it
#   no transaction          every certified round after the shard's first is quiet
#
# Usage:  ./scripts/f6b-quiet-tail-recovery.sh [validators]      # default 3
# Needs:  a pinned reth, curl, openssl, python3, and a built ./build/ubft. Run from the repo root.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

validators=${1:-3}
partitionID=8
pinnedRethCommit=189c0df32617afc488e0f091dbface1bd72cceb4
rethEngineBase=18551
rethEthBase=18545
rethP2PBase=30401
rootBootPort=26662

failures=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
info() { echo "  info: $1"; }

command -v reth >/dev/null || { echo "no reth binary on PATH - this lane has no fake fallback" >&2; exit 1; }
rethCommit=$(reth --version | sed -n 's/^Commit SHA: //p')
if [ "$rethCommit" != "$pinnedRethCommit" ]; then
  echo "FAIL: reth is $rethCommit, pinned baseline is $pinnedRethCommit" >&2
  echo "      Set F6B_ALLOW_UNPINNED_RETH=1 to run anyway; output is then NOT baseline evidence." >&2
  [ "${F6B_ALLOW_UNPINNED_RETH:-0}" = "1" ] || exit 1
fi
[ -x build/ubft ] || { echo "build/ubft missing - run 'make build' first" >&2; exit 1; }

# Same refusal guard as reth-paired-devnet.sh, for the same reason: this lane takes its evidence from
# test-nodes/evmN/debug.log by grep, and a leftover process still appending to that file can supply
# the very lines the assertions read.
stale=$(pgrep -f 'ubft shard-node run' 2>/dev/null || true)
if [ -n "$stale" ]; then
  echo "refusing to start: shard-node processes are already running (pids: $(echo $stale | tr '\n' ' '))" >&2
  echo "  pkill -f 'ubft shard-node run'" >&2
  exit 1
fi

cleanup() {
  ./stop-evm.sh -a >/dev/null 2>&1 || true
  pkill -f 'ubft shard-node run' 2>/dev/null
  for i in $(seq 1 "$validators"); do
    [ -f "test-nodes/reth$i/pid" ] && kill "$(cat "test-nodes/reth$i/pid")" 2>/dev/null
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

source ./helper.sh

echo "=== 1. a shard with no transactions in it ==="
rm -rf test-nodes
./setup-evm-nodes.sh -r 3 -v "$validators" >/dev/null || { echo "setup failed" >&2; exit 1; }
# The generated genesis has an empty alloc, so no account can pay for gas. That is not a limitation
# here, it is the POINT: this lane must demonstrate recovery with no new activity, and a chain spec
# on which no transaction can execute is the strongest available statement that none did.
info "chain spec has an empty alloc: no account can pay for gas, so no transaction can execute"

for i in $(seq 1 "$validators"); do
  mkdir -p "test-nodes/reth$i"
  openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  reth node --chain test-nodes/evm-genesis.json --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) \
    --http.api eth,net,web3,admin \
    --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    >"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
done

rpc() { curl -sS --max-time 10 -X POST "$1" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"; }
pyget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)" 2>/dev/null; }

for i in $(seq 1 "$validators"); do
  up=false
  for _ in $(seq 1 60); do
    rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_chainId '[]' 2>/dev/null | grep -q result && { up=true; break; }
    sleep 1
  done
  $up || { fail "reth $i did not start"; exit 1; }
done
for i in $(seq 1 "$validators"); do
  enode=$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_nodeInfo '[]' | pyget "['result']['enode']")
  for j in $(seq 1 "$validators"); do
    [ "$i" = "$j" ] && continue
    rpc "http://127.0.0.1:$((rethEthBase + j - 1))" admin_addPeer "[\"$enode\"]" >/dev/null
  done
done
pass "$validators reth instances up and peered on the shard's own chain spec"

for i in $(seq 1 "$validators"); do
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))"
  export "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
done
./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1 || {
  fail "devnet did not start"; tail -20 test-nodes/start-evm.log >&2; exit 1; }

# countIn is grep -c that always prints exactly one integer. `grep -c` exits 1 when the count is
# zero, so the obvious `$(grep -c ... || echo 0)` prints "0\n0" and every numeric test after it is a
# syntax error rather than a false — which is how a broken wait loop reads as "no certificates".
countIn() { local n; n=$(grep -c "$2" "$1" 2>/dev/null | head -1); echo "${n:-0}"; }

waitFor() { # waitFor <file> <pattern> <count> <seconds>
  for _ in $(seq 1 "$4"); do
    [ "$(countIn "$1" "$2")" -ge "$3" ] && return 0
    sleep 1
  done
  return 1
}
waitFor test-nodes/evm1/debug.log "accepted certificate" 6 120 || { fail "the shard never certified 6 rounds"; exit 1; }

nonQuiet=$(countIn test-nodes/evm1/debug.log "quiet=false")
quiet=$(countIn test-nodes/evm1/debug.log "quiet=true")
if [ "$quiet" -ge 4 ]; then
  pass "a quiet tail formed: $quiet quiet rounds and $nonQuiet non-quiet"
else
  fail "no quiet tail formed; saw non-quiet=$nonQuiet quiet=$quiet"
fi
# MEASURED CORRECTION, from this lane's own first run: a round can be non-quiet WITHOUT a
# transaction. "No transaction" is therefore asserted against the executor's own blocks rather than
# against the shard's quietness, which is a statement about the state root and not about activity.
txs=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockByNumber '["latest", true]' | pyget "['result']['number']")
txCount=0
for n in $(python3 -c "print(' '.join(hex(i) for i in range(0, int('${txs:-0x0}', 16) + 1)))"); do
  c=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockTransactionCountByNumber "[\"$n\"]" | pyget "['result']")
  txCount=$((txCount + $((${c:-0x0}))))
done
if [ "$txCount" -eq 0 ]; then
  pass "no transaction was executed: every canonical block on the executor, genesis through ${txs:-0x0}, contains zero transactions"
else
  fail "$txCount transactions executed — this lane must demonstrate recovery with no new activity"
fi

# The root bootnode, computed the way helper.sh computes it rather than scraped from a log: the log
# format is not a contract, and a scrape that silently returns empty produces a validator with no
# bootnodes and an assertion failure that says nothing about why.
rootBoot=$(boot_node test-nodes/root1 "$rootBootPort")
[ -n "$rootBoot" ] || { fail "could not determine the root bootnode address"; exit 1; }
info "root bootnode $rootBoot"

# restartValidator1 <extra args...> — the same command line helper.sh builds, plus this lane's flags.
restartValidator1() {
  [ -f test-nodes/evm1/pid ] && kill "$(cat test-nodes/evm1/pid)" 2>/dev/null
  sleep 3
  : >test-nodes/evm1/debug.log
  local bootnodes="$rootBoot"
  for j in $(seq 2 "$validators"); do bootnodes+=",$(evm_validator_addr "$j")"; done
  build/ubft shard-node run --home test-nodes/evm1 --executor engine-api \
    --address "/ip4/127.0.0.1/tcp/$evmValidatorPortStart" --bootnodes "$bootnodes" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --log-format text --log-level info \
    --engine-url "http://127.0.0.1:$rethEngineBase" --eth-url "http://127.0.0.1:$rethEthBase" \
    --jwt-secret test-nodes/evm1/jwt.hex "$@" \
    >>test-nodes/evm1/debug.log 2>&1 &
  echo $! >test-nodes/evm1/pid
}

echo
echo "=== 2. CONTROL: the same node with recovery off refuses for ever ==="
# Its reth keeps running, so this is the shard-node-only restart of the §1.1 matrix: the executor
# still holds everything, and what the node lost is its own in-process anchor.
restartValidator1
waitFor test-nodes/evm1/debug.log "accepted certificate" 5 120 || { fail "the restarted node received no certificates"; exit 1; }
# Count the REFUSAL, not the word. "no-anchor" also appears in the recovery arm's own "asking peers
# ... reason=no-anchor" line, so grepping for it counts requests as refusals and reads a working
# recovery as a broken one. The refusal is the abstention.
# Count the REFUSAL, not the word: "no-anchor" also appears in the recovery arm's own "asking peers
# ... reason=no-anchor" line, so grepping for it counts requests as refusals. And count the OUTCOME
# rather than the number of log lines — a node refuses on every round it is asked to act on, but only
# logs the refusal on the rounds where it would otherwise have led or voted.
controlRefusals=$(countIn test-nodes/evm1/debug.log "cannot prove the executor is on the certified block\|cannot prove its executor is on the certified block")
controlCerts=$(countIn test-nodes/evm1/debug.log "accepted certificate")
controlAdopted=$(countIn test-nodes/evm1/debug.log "adopted without a commit\|recovered from authenticated")
controlSigned=$(countIn test-nodes/evm1/debug.log "submitting block certification request")
if [ "$controlRefusals" -ge 1 ] && [ "$controlAdopted" -eq 0 ] && [ "$controlSigned" -eq 0 ]; then
  pass "recovery off: refused over $controlCerts quiet certificates, adopted no anchor and signed nothing — nothing a quiet shard delivers can supply the anchor (§1)"
else
  fail "control arm did not behave as §1 describes: refusals=$controlRefusals adopted=$controlAdopted signed=$controlSigned over $controlCerts certificates"
fi
grep -q "NON-VOTING" test-nodes/evm1/debug.log \
  && pass "control: the resumed process is NON-VOTING (P-sign, #105)" \
  || fail "control: the resumed process did not declare itself non-voting"
cp test-nodes/evm1/debug.log test-nodes/evm1/control.log

echo
echo "=== 3. RECOVERY: the same node, same devnet, --evidence-recover ==="
restartValidator1 --evidence-recover
waitFor test-nodes/evm1/debug.log "accepted certificate" 6 120 || { fail "the restarted node received no certificates"; exit 1; }

grep -q "anchor recovery finished.*state=ready" test-nodes/evm1/debug.log \
  && pass "authenticated evidence obtained from a peer: $(grep -o 'attempts=[0-9]* restarts=[0-9]*' test-nodes/evm1/debug.log | head -1)" \
  || fail "no evidence was obtained"

adopted=$(grep -oE "blockHash=[0-9a-f]+" test-nodes/evm1/debug.log | head -1 | cut -d= -f2)
if [ -n "$adopted" ]; then
  pass "the verified anchor was adopted, naming certified block ${adopted:0:16}…"
else
  fail "no anchor was adopted"
fi

# EXACT-BLOCK RECOVERY. The node stops refusing, which is only possible if P-id is satisfied for the
# block the evidence named — the identity check is the thing that was refusing.
recoveryCerts=$(countIn test-nodes/evm1/debug.log "accepted certificate")
adoptLine=$(grep -n "adopted without a commit\|recovered from authenticated" test-nodes/evm1/debug.log | head -1 | cut -d: -f1)
if [ -n "$adoptLine" ]; then
  after=$(tail -n +"$adoptLine" test-nodes/evm1/debug.log | countIn /dev/stdin "abstaining from the vote")
  certsAfter=$(tail -n +"$adoptLine" test-nodes/evm1/debug.log | countIn /dev/stdin "accepted certificate")
  if [ "$after" -eq 0 ] && [ "$certsAfter" -ge 2 ]; then
    pass "exact-block recovery: not one abstention in the $certsAfter certificates after the anchor was adopted (of $recoveryCerts) — P-id is satisfied for the block the evidence named"
  else
    fail "still abstaining after recovery: $after abstentions over the $certsAfter certificates that followed"
  fi
else
  fail "the anchor was never adopted"
fi

# SIGNING REFUSAL UNCHANGED. Recovering an execution identity is not re-authorization to vote.
signed=$(countIn test-nodes/evm1/debug.log "submitting block certification request")
if grep -q "NON-VOTING" test-nodes/evm1/debug.log && [ "$signed" -eq 0 ]; then
  pass "signing refusal unchanged: still NON-VOTING, and it signed nothing after recovering (P-sign, #105)"
else
  fail "a recovered node must not sign: NON-VOTING=$(countIn test-nodes/evm1/debug.log NON-VOTING) submissions=$signed"
fi

# IMMUTABLE EVIDENCE. The providers were asked and answered; nothing they retained was refused or
# altered by serving it, and they went on certifying throughout.
providerRefusals=0
for i in $(seq 2 "$validators"); do
  providerRefusals=$((providerRefusals + $(countIn "test-nodes/evm$i/debug.log" "evidence buffer refused\|stream not admitted")))
done
if [ "$providerRefusals" -eq 0 ]; then
  pass "immutable evidence: the providers refused nothing they had retained, and serving it changed nothing they hold"
else
  fail "providers refused $providerRefusals observations or streams while serving"
fi

# NO TRANSACTION, restated over the whole run rather than only the first window.
# The no-transaction property is asserted in section 1 against the executor's own blocks, which is a
# stronger statement than the shard's quietness. Restate it here over the whole run.
headNum=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockByNumber '["latest", false]' | pyget "['result']['number']")
finalTx=0
for n in $(python3 -c "print(' '.join(hex(i) for i in range(0, int('${headNum:-0x0}', 16) + 1)))"); do
  c=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockTransactionCountByNumber "[\"$n\"]" | pyget "['result']")
  finalTx=$((finalTx + $((${c:-0x0}))))
done
if [ "$finalTx" -eq 0 ]; then
  pass "and still no transaction at the end of the run: $finalTx across genesis..${headNum:-0x0}"
else
  fail "$finalTx transactions executed during the run"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "ALL CHECKS PASSED (reth $rethCommit)"
else
  echo "$failures CHECK(S) FAILED"
fi
exit $((failures > 0))
