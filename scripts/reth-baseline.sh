#!/bin/bash
# reth-baseline.sh - the real-reth regression baseline required by F1 (#9).
#
# scripts/reth-by-hand.sh proves one round works. This proves the *baseline holds*: it pins the
# execution client revision, drives a run of empty blocks through the Engine API, and asserts the
# header-level behaviour that the Unicity profile depends on. Two of those assertions currently
# encode deviations we know we have to fix (see docs/design/f1-baseline.md §4) rather than
# behaviour we want — they are written as "this is still broken in exactly this way", so the day
# reth or a fork changes it, this script says so instead of silently passing.
#
# Unlike reth-by-hand.sh, this one HAS been run against a live client:
#   reth 2.5.0-dev, commit 189c0df32617afc488e0f091dbface1bd72cceb4 — ristik/ureth branch
#   unicity/main, which at this pin is byte-identical to upstream paradigmxyz/reth tag v2.5.0.
# See docs/design/f1-baseline.md §2 for the pinned revision table and §5 for the recorded results.
#
# Usage:
#   ./scripts/reth-baseline.sh [blocks]        # default 40; needs test-nodes/evm-genesis.json
#
# Needs: a `reth` binary on PATH, curl, openssl, python3. Run from the repository root, after
# ./setup-evm-nodes.sh has generated test-nodes/evm-genesis.json.

set -euo pipefail

blocks=${1:-40}
genesis=test-nodes/evm-genesis.json
pinnedRethCommit=189c0df32617afc488e0f091dbface1bd72cceb4   # ristik/ureth, branch unicity/main

# The genesis this profile starts from, and the two rates measured against the pinned reth.
# Sourced from the generated chain spec rather than hardcoded, so a change to
# `ubft engine-api genesis` shows up here as a failure rather than a stale constant.
genesisBaseFee=$(python3 -c "import json;print(int(json.load(open('$genesis'))['baseFeePerGas'],16))" 2>/dev/null || echo 0)
genesisGasLimit=$(python3 -c "import json;print(int(json.load(open('$genesis'))['gasLimit'],16))")

if [ ! -f "$genesis" ]; then
  echo "missing $genesis - run ./setup-evm-nodes.sh -r 3 -v 4 first" >&2
  exit 1
fi
command -v reth >/dev/null || { echo "no reth binary on PATH - this is the real-execution lane, there is no fake fallback" >&2; exit 1; }

echo "=== 0. execution client revision ==="
rethCommit=$(reth --version | sed -n 's/^Commit SHA: //p')
reth --version | sed -n '1p;2p'
if [ "$rethCommit" != "$pinnedRethCommit" ]; then
  echo "WARNING: reth commit $rethCommit is not the pinned $pinnedRethCommit;" >&2
  echo "         results below are evidence for THIS revision, not for the pinned baseline." >&2
fi
echo

workDir=$(mktemp -d)
jwtFile="$workDir/jwt.hex"
openssl rand -hex 32 >"$jwtFile"
rethLog="$workDir/reth.log"
enginePort=18551
ethPort=18545
engineURL="http://127.0.0.1:$enginePort"
ethURL="http://127.0.0.1:$ethPort"

cleanup() {
  [ -n "${rethPid:-}" ] && kill "$rethPid" 2>/dev/null || true
  wait "${rethPid:-}" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 1. start reth on the shard's own generated chain spec ==="
reth node --chain "$genesis" --datadir "$workDir/dd" \
  --authrpc.jwtsecret "$jwtFile" --authrpc.addr 127.0.0.1 --authrpc.port "$enginePort" \
  --http --http.addr 127.0.0.1 --http.port "$ethPort" --http.api eth,net,web3 \
  --disable-discovery --port 30399 >"$rethLog" 2>&1 &
rethPid=$!

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
rpc() {
  curl -sS -X POST "$1" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(mint_jwt)" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"
}
pyget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)"; }

for _ in $(seq 1 60); do
  if rpc "$ethURL" eth_chainId '[]' 2>/dev/null | grep -q result; then break; fi
  sleep 1
done
rpc "$ethURL" eth_chainId '[]' | grep -q result || { echo "reth did not come up:" >&2; tail -30 "$rethLog" >&2; exit 1; }
echo "reth up, chainId $(rpc "$ethURL" eth_chainId '[]' | pyget "['result']")"
echo

echo "=== 2. drive $blocks empty blocks (forkchoiceUpdated -> getPayload -> newPayload -> forkchoiceUpdated) ==="
head=$(rpc "$ethURL" eth_getBlockByNumber '["latest", false]')
headHash=$(echo "$head" | pyget "['result']['hash']")
ts=$(python3 -c "print(int('$(echo "$head" | pyget "['result']['timestamp']")', 16))")
zero32="0x$(printf '%064x' 0)"

csv="$workDir/blocks.csv"
echo "block,baseFeePerGas_wei,gasLimit,gasUsed" >"$csv"
for _ in $(seq 1 "$blocks"); do
  ts=$((ts + 1))
  attrs=$(printf '{"timestamp":"0x%x","prevRandao":"%s","suggestedFeeRecipient":"0x0000000000000000000000000000000000000000","withdrawals":[],"parentBeaconBlockRoot":"%s"}' "$ts" "$zero32" "$zero32")
  fcu=$(rpc "$engineURL" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$headHash\",\"safeBlockHash\":\"$headHash\",\"finalizedBlockHash\":\"$headHash\"},$attrs]")
  payloadID=$(echo "$fcu" | pyget "['result']['payloadId']")
  [ "$payloadID" = "None" ] && { echo "no payloadId: $fcu" >&2; exit 1; }
  sleep 0.35 # let the builder finish assembling before collecting
  payload=$(rpc "$engineURL" engine_getPayloadV3 "[\"$payloadID\"]" |
    python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['result']['executionPayload']))")
  status=$(rpc "$engineURL" engine_newPayloadV3 "[$payload,[],\"$zero32\"]" | pyget "['result']['status']")
  [ "$status" != "VALID" ] && { echo "newPayload returned $status" >&2; exit 1; }
  headHash=$(echo "$payload" | pyget "['blockHash']")
  rpc "$engineURL" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$headHash\",\"safeBlockHash\":\"$headHash\",\"finalizedBlockHash\":\"$headHash\"},null]" >/dev/null
  python3 -c "
import json
p = json.loads('''$payload''')
print('%d,%d,%d,%d' % (int(p['blockNumber'], 16), int(p['baseFeePerGas'], 16),
                       int(p['gasLimit'], 16), int(p['gasUsed'], 16)))" >>"$csv"
done
cat "$csv"
echo

echo "=== 3. assertions ==="
python3 - "$csv" "$genesisBaseFee" "$genesisGasLimit" <<'PY'
import csv, sys

path, genesisBaseFee, genesisGasLimit = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rows = list(csv.DictReader(open(path)))
rows = [{k: int(v) for k, v in r.items()} for r in rows]
failures = []

def check(name, ok, detail):
    print(("PASS " if ok else "FAIL ") + name + ": " + detail)
    if not ok:
        failures.append(name)

# --- Behaviour we want, and have. ---
check("blocks are contiguous",
      [r["block"] for r in rows] == list(range(rows[0]["block"], rows[0]["block"] + len(rows))),
      "%d..%d" % (rows[0]["block"], rows[-1]["block"]))
check("empty blocks consume no gas",
      all(r["gasUsed"] == 0 for r in rows),
      "max gasUsed %d" % max(r["gasUsed"] for r in rows))

# --- Deviations F5 (#13) owns. These assert the CURRENT broken behaviour on purpose: they are
# the regression baseline, so a fix flips them to FAIL and forces this file and F5 to be updated
# together. ---

# D-1: EIP-1559 decays the base fee by 7/8 per empty block, unbounded downward. The genesis
# baseFeePerGas is therefore not a fee floor - it is just a starting point that idle rounds erase.
ratios = [rows[i]["baseFeePerGas_wei"] / rows[i-1]["baseFeePerGas_wei"] for i in range(1, len(rows))]
decays = all(abs(r - 0.875) < 1e-6 for r in ratios)
first, last = rows[0]["baseFeePerGas_wei"], rows[-1]["baseFeePerGas_wei"]
check("D-1 base fee still decays 7/8 per empty block (no floor)",
      decays and last < first,
      "%d -> %d wei over %d blocks; genesis was %d wei"
      % (first, last, len(rows), genesisBaseFee))

# D-2: the builder walks the gas limit up by 1/1024 per block toward its own default target, so
# the configured total capacity is not actually configured - it grows without bound.
deltas = [rows[i]["gasLimit"] - rows[i-1]["gasLimit"] for i in range(1, len(rows))]
drifts = all(d > 0 and abs(d - rows[i]["gasLimit"] // 1024) <= 1 for i, d in enumerate(deltas))
check("D-2 gas limit still drifts +1/1024 per block (capacity not pinned)",
      drifts and rows[-1]["gasLimit"] > genesisGasLimit,
      "%d -> %d; genesis gasLimit was %d" % (rows[0]["gasLimit"], rows[-1]["gasLimit"], genesisGasLimit))

print()
if failures:
    print("BASELINE CHANGED: " + ", ".join(failures))
    print("This is not necessarily a regression - if a fee-floor or gas-limit fix landed, update")
    print("docs/design/f1-baseline.md §4 and this script together, and tell F5 (#13).")
    sys.exit(1)
print("baseline holds: real reth agrees with docs/design/f1-baseline.md §4.")
PY
