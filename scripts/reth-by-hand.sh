#!/bin/bash
# reth-by-hand.sh - drives a real reth instance through one full round of the Engine API by hand,
# with curl and no Unicity code involved at all — this is Track B's B1.1 from
# docs/engine-api-adapter-plan.md: "prove reth's Engine API by hand" before trusting the Go adapter
# (engineapi/) to be talking to it correctly. If this script can't get a block from genesis to
# certified-equivalent (forkchoiceUpdated -> getPayload -> newPayload -> forkchoiceUpdated), nothing
# built on top of it will either — that's the point of running it standalone.
#
# NOT RUN IN THIS REPOSITORY'S BUILD/TEST ENVIRONMENT — there is no reth binary here (only an
# aarch64 macOS release exists upstream at the time this was written; this environment is x86_64,
# and building reth from source was judged not worth the time cost — see the build plan §10). Every
# request/response shape below matches engineapi/types.go's JSON encoding exactly (same field names,
# same V3 method names), and the JWT minting matches engineapi/jwt.go's algorithm exactly, but this
# script itself has not been executed against a live reth. Run it — and fix whatever it finds — as
# the first thing you do on a machine that has reth, before touching `--executor engine-api`.
#
# Usage:
#   ./scripts/reth-by-hand.sh /path/to/jwt.hex [engine-url] [eth-url]
#
# Needs: curl, openssl, python3 (for JSON pretty-printing and payloadId extraction only — nothing
# about the Engine API calls themselves depends on it).

set -e

jwtFile=${1:?"usage: $0 <jwt.hex> [engine-url] [eth-url]"}
engineURL=${2:-http://127.0.0.1:8551}
ethURL=${3:-http://127.0.0.1:8545}

# --- JWT: HS256 over {"alg":"HS256","typ":"JWT"}.{"iat":<unix seconds>}, base64url, no padding —
# see engineapi/jwt.go's Token, which this must byte-for-byte agree with. Reth requires iat within
# 60s of its own clock, so this mints a fresh one per call rather than reusing one across the script.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

mint_jwt() {
  local secret_hex header claims signing_input sig
  secret_hex=$(tr -d ' \n' <"$jwtFile" | sed 's/^0x//')
  header=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
  claims=$(printf '{"iat":%d}' "$(date +%s)" | b64url)
  signing_input="${header}.${claims}"
  sig=$(printf '%s' "$signing_input" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$secret_hex" -binary | b64url)
  printf '%s.%s' "$signing_input" "$sig"
}

# rpc <url> <method> <json-array-of-params> — always mints a fresh JWT, harmless for the plain
# eth_* calls (they ignore the header) and required for every engine_* one.
rpc() {
  local url=$1 method=$2 params=$3
  curl -sS -X POST "$url" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(mint_jwt)" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

jq_get() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)"; }

echo "=== 1. engine_exchangeCapabilities — the exact V3 set this adapter requires ==="
resp=$(rpc "$engineURL" engine_exchangeCapabilities '[["engine_forkchoiceUpdatedV3","engine_getPayloadV3","engine_newPayloadV3"]]')
echo "$resp"
echo

echo "=== 2. eth_chainId, eth_getBlockByNumber(0x0) — genesis, plain RPC, no auth needed ==="
chainID=$(rpc "$ethURL" eth_chainId '[]' | jq_get "['result']")
genesis=$(rpc "$ethURL" eth_getBlockByNumber '["0x0", false]')
echo "chainId: $chainID"
echo "$genesis"
genesisHash=$(echo "$genesis" | jq_get "['result']['hash']")
genesisTimestamp=$(echo "$genesis" | jq_get "['result']['timestamp']")
echo "genesis hash: $genesisHash, timestamp: $genesisTimestamp"
echo

echo "=== 3. engine_forkchoiceUpdatedV3 — head=genesis, WITH payload attributes to trigger a build ==="
# Deliberately simple, fixed values here (not a derivation of a real Unicity certificate — there
# isn't one, this script runs with no Unicity involved) — just enough for reth to accept them and
# build a real block: timestamp strictly after genesis's own, prevRandao/parentBeaconBlockRoot as
# 32 zero bytes, zero fee recipient, no withdrawals. Compare against engineapi/params.go's
# DeriveAttributes for what a real round derives these from.
ts=$((genesisTimestamp + 1))
attrs=$(printf '{"timestamp":"0x%x","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","suggestedFeeRecipient":"0x0000000000000000000000000000000000000000","withdrawals":[],"parentBeaconBlockRoot":"0x0000000000000000000000000000000000000000000000000000000000000000"}' "$ts")
fcuResp=$(rpc "$engineURL" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$genesisHash\",\"safeBlockHash\":\"$genesisHash\",\"finalizedBlockHash\":\"$genesisHash\"},$attrs]")
echo "$fcuResp"
payloadStatus=$(echo "$fcuResp" | jq_get "['result']['payloadStatus']['status']")
payloadID=$(echo "$fcuResp" | jq_get "['result']['payloadId']")
echo "payloadStatus: $payloadStatus, payloadId: $payloadID"
if [ "$payloadStatus" != "VALID" ] || [ -z "$payloadID" ] || [ "$payloadID" = "None" ]; then
  echo "STOP: expected status VALID with a non-null payloadId — nothing past here will work" >&2
  exit 1
fi
echo

echo "=== 4. engine_getPayloadV3 — collect what reth built ==="
sleep 1 # give reth a moment to actually finish assembling the payload
payloadResp=$(rpc "$engineURL" engine_getPayloadV3 "[\"$payloadID\"]")
echo "$payloadResp"
echo

echo "=== 5. engine_newPayloadV3 — validate it (this is the call that actually executes the block) ==="
payload=$(echo "$payloadResp" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['result']['executionPayload']))")
newPayloadResp=$(rpc "$engineURL" engine_newPayloadV3 "[$payload,[],\"0x0000000000000000000000000000000000000000000000000000000000000000\"]")
echo "$newPayloadResp"
newStatus=$(echo "$newPayloadResp" | jq_get "['result']['status']")
blockHash=$(echo "$payload" | jq_get "['blockHash']")
echo "newPayload status: $newStatus, blockHash: $blockHash"
if [ "$newStatus" != "VALID" ]; then
  echo "STOP: expected VALID" >&2
  exit 1
fi
echo

echo "=== 6. engine_forkchoiceUpdatedV3 — make it canonical, head=blockHash, no attributes ==="
finalFcu=$(rpc "$engineURL" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$blockHash\",\"safeBlockHash\":\"$blockHash\",\"finalizedBlockHash\":\"$blockHash\"},null]")
echo "$finalFcu"
finalStatus=$(echo "$finalFcu" | jq_get "['result']['payloadStatus']['status']")
echo "final status: $finalStatus"
echo

if [ "$finalStatus" = "VALID" ]; then
  echo "=== reth went from genesis to a real, canonical block 1 over the raw Engine API. ==="
  echo "=== Track B's B1 gate (docs/engine-api-adapter-plan.md §7) is satisfied by this reth build. ==="
else
  echo "STOP: final forkchoiceUpdated did not report VALID" >&2
  exit 1
fi
