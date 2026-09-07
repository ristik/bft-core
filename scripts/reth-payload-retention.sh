#!/bin/bash
# reth-payload-retention.sh - does a pinned reth retain a payload it accepted via newPayload but
# was never told to make canonical, across a process restart with its datadir intact?
#
# #92 stage 2 turns on this question. shardnode/round.go's recovery path assumes it does ("reth
# writes a block to disk the moment newPayload succeeds, before any forkchoiceUpdate makes it
# canonical"), and the whole idea of retained-local-payload recovery depends on it. The #92 design
# contract says to verify it against the pinned client rather than infer it from newPayload
# returning VALID. This script answers it with no Unicity code involved.
#
#   ./scripts/reth-payload-retention.sh
#
# Needs a pinned reth, curl, openssl, python3, and test-nodes/evm-genesis.json.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

pinnedRethCommit=189c0df32617afc488e0f091dbface1bd72cceb4
genesis=test-nodes/evm-genesis.json
enginePort=18951
ethPort=18945

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
info() { echo "  ..   $1"; }
failures=0

command -v reth >/dev/null || { echo "no reth binary on PATH" >&2; exit 1; }
[ -f "$genesis" ] || { echo "missing $genesis - run ./setup-evm-nodes.sh -r 3 -v 4 first" >&2; exit 1; }
rethCommit=$(reth --version | sed -n 's/^Commit SHA: //p')
if [ "$rethCommit" != "$pinnedRethCommit" ]; then
  echo "FAIL: reth is $rethCommit, pinned is $pinnedRethCommit" >&2
  [ "${F1_ALLOW_UNPINNED_RETH:-0}" = "1" ] || exit 1
fi
echo "reth: $rethCommit"

work=$(mktemp -d)
jwt=$work/jwt.hex
openssl rand -hex 32 >"$jwt"
rethPid=""

stopReth() {
  [ -n "$rethPid" ] || return 0
  kill "$rethPid" 2>/dev/null
  local waited=0
  while ps -p "$rethPid" >/dev/null 2>&1; do
    [ "$waited" -ge 30 ] && { kill -9 "$rethPid" 2>/dev/null; break; }
    sleep 1; waited=$((waited + 1))
  done
  rethPid=""
}
cleanup() { stopReth; rm -rf "$work"; }
trap cleanup EXIT

startReth() {
  reth node --chain "$genesis" --datadir "$work/dd" \
    --authrpc.jwtsecret "$jwt" --authrpc.addr 127.0.0.1 --authrpc.port "$enginePort" \
    --http --http.addr 127.0.0.1 --http.port "$ethPort" --http.api eth,net,web3 \
    --disable-discovery --ipcdisable --port 30699 >>"$work/reth.log" 2>&1 &
  rethPid=$!
  disown "$rethPid" 2>/dev/null || true   # keep the shell from reporting the kill as an abort
  local waited=0
  until rpc "http://127.0.0.1:$ethPort" eth_chainId '[]' | grep -q result; do
    [ "$waited" -ge 90 ] && return 1
    sleep 1; waited=$((waited + 1))
  done
  return 0
}

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
mintJWT() {
  local hex header claims si sig
  hex=$(tr -d ' \n' <"$jwt" | sed 's/^0x//')
  header=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
  claims=$(printf '{"iat":%d}' "$(date +%s)" | b64url)
  si="${header}.${claims}"
  sig=$(printf '%s' "$si" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$hex" -binary | b64url)
  printf '%s.%s' "$si" "$sig"
}
rpc() {
  curl -sS --max-time 20 -X POST "$1" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(mintJWT)" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" 2>/dev/null
}
pyget() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }

engine="http://127.0.0.1:$enginePort"
eth="http://127.0.0.1:$ethPort"

echo "=== 1. start reth and build one block WITHOUT making it canonical ==="
startReth || { fail "reth did not start"; exit 1; }

genesisBlock=$(rpc "$eth" eth_getBlockByNumber '["0x0", false]')
head=$(echo "$genesisBlock" | pyget "['result']['hash']")
ts=$(python3 -c "print(int('$(echo "$genesisBlock" | pyget "['result']['timestamp']")',16)+1)")
zero32="0x$(printf '%064x' 0)"
attrs=$(printf '{"timestamp":"0x%x","prevRandao":"%s","suggestedFeeRecipient":"0x0000000000000000000000000000000000000000","withdrawals":[],"parentBeaconBlockRoot":"%s"}' "$ts" "$zero32" "$zero32")

pid=$(rpc "$engine" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$head\",\"safeBlockHash\":\"$head\",\"finalizedBlockHash\":\"$head\"},$attrs]" | pyget "['result']['payloadId']")
[ -n "$pid" ] && [ "$pid" != "None" ] || { fail "no payloadId"; exit 1; }
sleep 1
payload=$(rpc "$engine" engine_getPayloadV3 "[\"$pid\"]" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['result']['executionPayload']))")
blockHash=$(echo "$payload" | pyget "['blockHash']")

status=$(rpc "$engine" engine_newPayloadV3 "[$payload,[],\"$zero32\"]" | pyget "['result']['status']")
[ "$status" = "VALID" ] && pass "newPayload accepted block $blockHash as VALID" || { fail "newPayload returned $status"; exit 1; }

# Deliberately NO forkchoiceUpdated here: this is the exact state a shard node is in when it
# submitted a certification request and died before the confirming certificate arrived.
canon=$(rpc "$eth" eth_getBlockByNumber '["latest", false]' | pyget "['result']['number']")
[ "$canon" = "0x0" ] && pass "the block is accepted but NOT canonical (head still genesis)" \
  || fail "expected head to still be genesis, got $canon"

byHash=$(rpc "$eth" eth_getBlockByHash "[\"$blockHash\", false]" | pyget "['result']['hash']")
[ "$byHash" = "$blockHash" ] && pass "before restart: the non-canonical block is retrievable by hash" \
  || info "before restart: eth_getBlockByHash does not return it (result was '$byHash')"

echo
echo "=== 1b. CONTROL: the same block is recoverable WITHOUT a restart ==="
# This separates "reth never stored it" from "reth stored it but not across a process lifetime".
# If forkchoiceUpdated succeeds here and fails after the restart, the payload was live-process
# state, not durable state — which is exactly the distinction #92 stage 2 has to design against.
ctlStatus=$(rpc "$engine" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$blockHash\",\"safeBlockHash\":\"$blockHash\",\"finalizedBlockHash\":\"$blockHash\"},null]" | pyget "['result']['payloadStatus']['status']")
if [ "$ctlStatus" = "VALID" ]; then
  pass "in-process: forkchoiceUpdated to the non-canonical block returns VALID (recovery works while the process lives)"
else
  fail "in-process: forkchoiceUpdated returned $ctlStatus — the block is not usable even without a restart"
fi

# Now build a SECOND block on top and leave it non-canonical, so the restart test has a payload
# that was accepted but never finalised, exactly like a node that died mid-round.
ts2=$((ts + 1))
attrs2=$(printf '{"timestamp":"0x%x","prevRandao":"%s","suggestedFeeRecipient":"0x0000000000000000000000000000000000000000","withdrawals":[],"parentBeaconBlockRoot":"%s"}' "$ts2" "$zero32" "$zero32")
pid2=$(rpc "$engine" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$blockHash\",\"safeBlockHash\":\"$blockHash\",\"finalizedBlockHash\":\"$blockHash\"},$attrs2]" | pyget "['result']['payloadId']")
[ -n "$pid2" ] && [ "$pid2" != "None" ] || { fail "no second payloadId"; exit 1; }
sleep 1
payload2=$(rpc "$engine" engine_getPayloadV3 "[\"$pid2\"]" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['result']['executionPayload']))")
blockHash2=$(echo "$payload2" | pyget "['blockHash']")
status2=$(rpc "$engine" engine_newPayloadV3 "[$payload2,[],\"$zero32\"]" | pyget "['result']['status']")
[ "$status2" = "VALID" ] && pass "second block $blockHash2 accepted as VALID and left non-canonical" \
  || { fail "second newPayload returned $status2"; exit 1; }
blockHash=$blockHash2   # the restart test now targets the never-finalised block

echo
echo "=== 2. restart reth with the same datadir ==="
stopReth
startReth || { fail "reth did not restart"; exit 1; }
pass "reth restarted on the retained datadir"

canonAfter=$(rpc "$eth" eth_getBlockByNumber '["latest", false]' | pyget "['result']['number']")
info "canonical head after restart: $canonAfter"

byHashAfter=$(rpc "$eth" eth_getBlockByHash "[\"$blockHash\", false]" | pyget "['result']['hash']")
if [ "$byHashAfter" = "$blockHash" ]; then
  pass "RETAINED: the non-canonical block survives the restart and is retrievable by hash"
  retained=yes
else
  fail "NOT RETAINED: the block is gone after restart (eth_getBlockByHash returned '$byHashAfter')"
  retained=no
fi

echo
echo "=== 3. can forkchoiceUpdated still make it canonical after the restart? ==="
fcu=$(rpc "$engine" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$blockHash\",\"safeBlockHash\":\"$blockHash\",\"finalizedBlockHash\":\"$blockHash\"},null]")
fcuStatus=$(echo "$fcu" | pyget "['result']['payloadStatus']['status']")
info "forkchoiceUpdated -> $fcuStatus"
if [ "$fcuStatus" = "VALID" ]; then
  finalHead=$(rpc "$eth" eth_getBlockByNumber '["latest", false]' | pyget "['result']['hash']")
  [ "$finalHead" = "$blockHash" ] && pass "RECOVERABLE: the retained block became canonical after restart" \
    || fail "forkchoiceUpdated reported VALID but head is $finalHead"
else
  fail "forkchoiceUpdated returned $fcuStatus — a retained payload is NOT directly recoverable this way"
fi

echo
echo "=== conclusion ==="
echo "  payload retained across restart: ${retained}"
echo "  forkchoiceUpdated after restart: ${fcuStatus}"
[ "$failures" -eq 0 ] && echo "=== retained-local-payload recovery is viable against this pinned client ===" \
  || echo "=== $failures check(s) failed — see above ==="
exit $((failures > 0))
