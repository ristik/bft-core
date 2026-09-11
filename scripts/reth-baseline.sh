#!/bin/bash
# reth-baseline.sh - the stock-client header-economics baseline required by F1 (#9).
#
# SCOPE, precisely: this drives reth with curl and no Unicity code at all. It establishes things
# about the *execution client's* header behaviour. It establishes NOTHING about the Go adapter,
# which it bypasses entirely - scripts/reth-paired-devnet.sh is the lane that exercises that, and
# it is the one that carries F1's integration evidence.
#
# What this measures is the base-fee and gas-limit behaviour the Unicity fee profile has to live
# with, under two controls:
#
#   A. reth's default builder configuration
#   B. the same client with --builder.gaslimit pinned to the chain spec's own gasLimit
#
# Running both is the point: the difference between them separates "the client does something we
# must change" from "we had not configured the client". See docs/design/f1-baseline.md §4.
#
# Pinned client: reth commit 189c0df32617afc488e0f091dbface1bd72cceb4 - ristik/ureth branch
# unicity/main, byte-identical to upstream paradigmxyz/reth tag v2.5.0 at this pin.
#
# Usage:
#   ./scripts/reth-baseline.sh [blocks]        # default 160; needs test-nodes/evm-genesis.json
#
# A wrong client revision FAILS by default. Set F1_ALLOW_UNPINNED_RETH=1 to explore against
# another build; output is then labelled and is not baseline evidence.
#
# Needs: a `reth` binary, curl, openssl, python3. Run from the repository root, after
# ./setup-evm-nodes.sh has generated test-nodes/evm-genesis.json.

set -euo pipefail

blocks=${1:-160}
genesis=test-nodes/evm-genesis.json
pinnedRethCommit=189c0df32617afc488e0f091dbface1bd72cceb4   # ristik/ureth, branch unicity/main

[ -f "$genesis" ] || { echo "missing $genesis - run ./setup-evm-nodes.sh -r 3 -v 4 first" >&2; exit 1; }
command -v reth >/dev/null || { echo "no reth binary on PATH - this is the real-execution lane, there is no fake fallback" >&2; exit 1; }

# Sourced from the generated chain spec rather than hardcoded, so a change to
# `ubft engine-api genesis` shows up as a failure here rather than a stale constant.
genesisBaseFee=$(python3 -c "import json;print(int(json.load(open('$genesis'))['baseFeePerGas'],16))")
genesisGasLimit=$(python3 -c "import json;print(int(json.load(open('$genesis'))['gasLimit'],16))")
genesisChainID=$(python3 -c "import json;print(json.load(open('$genesis'))['config']['chainId'])")

echo "=== 0. execution client revision ==="
reth --version | sed -n '1p;2p'
rethCommit=$(reth --version | sed -n 's/^Commit SHA: //p')
baselineEvidence=true
if [ "$rethCommit" != "$pinnedRethCommit" ]; then
  if [ "${F1_ALLOW_UNPINNED_RETH:-0}" = "1" ]; then
    baselineEvidence=false
    echo "NOT BASELINE EVIDENCE: reth is $rethCommit, pinned baseline is $pinnedRethCommit" >&2
  else
    echo "FAIL: reth is $rethCommit, pinned baseline is $pinnedRethCommit." >&2
    echo "      This gate refuses to certify a baseline against an unpinned client." >&2
    echo "      Set F1_ALLOW_UNPINNED_RETH=1 to explore anyway (output is then not evidence)." >&2
    exit 1
  fi
fi
echo

workDir=$(mktemp -d)
rethPid=""
cleanup() { [ -n "$rethPid" ] && kill "$rethPid" 2>/dev/null; wait "$rethPid" 2>/dev/null || true; }
trap cleanup EXIT

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
mint_jwt() {
  local secret_hex header claims signing_input sig
  secret_hex=$(tr -d ' \n' <"$1" | sed 's/^0x//')
  header=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
  claims=$(printf '{"iat":%d}' "$(date +%s)" | b64url)
  signing_input="${header}.${claims}"
  sig=$(printf '%s' "$signing_input" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$secret_hex" -binary | b64url)
  printf '%s.%s' "$signing_input" "$sig"
}
# rpc <jwtfile> <url> <method> <params> - fails the script on transport or JSON-RPC error rather
# than letting a null result flow into an assertion as if it were data.
rpc() {
  local jwt=$1 url=$2 method=$3 params=$4 body
  body=$(curl -sS --max-time 20 -X POST "$url" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(mint_jwt "$jwt")" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}") || {
      echo "RPC transport failure on $method" >&2; return 1; }
  if printf '%s' "$body" | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin).get('error') else 1)" 2>/dev/null; then
    echo "JSON-RPC error on $method: $body" >&2
    return 1
  fi
  printf '%s' "$body"
}
pyget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)"; }

# run_control <label> <csv-out> [extra reth args...]
# Starts a fresh reth on its own datadir and ports, drives $blocks empty blocks, and verifies at
# every step that the client actually accepted and canonicalised what it built.
run_control() {
  local label=$1 csv=$2; shift 2
  local dd="$workDir/$label" jwt="$workDir/$label.jwt"
  local enginePort=18551 ethPort=18545
  [ "$label" = "pinned-gaslimit" ] && { enginePort=18561; ethPort=18555; }
  local engineURL="http://127.0.0.1:$enginePort" ethURL="http://127.0.0.1:$ethPort"

  openssl rand -hex 32 >"$jwt"
  # Inside a packaged lane (scripts/reth-smoke.sh) the JWT is recorded as a scan input BEFORE any
  # process can use it: it lives in a temporary directory deleted at exit, while this script's output
  # stays in the lane's run log, so otherwise nothing would know to search that log for it. A value
  # that cannot be recorded is never used — the control stops here.
  if [ -n "${RETH_EVIDENCE_SCAN_FILE:-}" ]; then
    local secret; secret=$(tr -d ' \n' <"$jwt")
    if ! { ( umask 077; printf '%s\n' "$secret" >>"$RETH_EVIDENCE_SCAN_FILE" ) 2>/dev/null && grep -qxF -- "$secret" "$RETH_EVIDENCE_SCAN_FILE"; }; then
      echo "reth-baseline: FAIL could not record control '$label''s JWT as a scan input; not starting reth with it" >&2
      rm -f "$jwt"
      return 1
    fi
  fi
  reth node --chain "$genesis" --datadir "$dd" \
    --authrpc.jwtsecret "$jwt" --authrpc.addr 127.0.0.1 --authrpc.port "$enginePort" \
    --http --http.addr 127.0.0.1 --http.port "$ethPort" --http.api eth,net,web3 \
    --disable-discovery --ipcdisable --port $((30399 + enginePort - 18551)) "$@" \
    >"$workDir/$label.log" 2>&1 &
  rethPid=$!

  local up=false i
  for i in $(seq 1 60); do
    if rpc "$jwt" "$ethURL" eth_chainId '[]' >/dev/null 2>&1; then up=true; break; fi
    sleep 1
  done
  $up || { echo "reth did not come up for control '$label':" >&2; tail -30 "$workDir/$label.log" >&2; return 1; }

  # The client must be on the chain we think it is, from the genesis we think it is.
  local gotChain
  gotChain=$(rpc "$jwt" "$ethURL" eth_chainId '[]' | pyget "['result']")
  gotChain=$(python3 -c "print(int('$gotChain', 16))")
  [ "$gotChain" = "$genesisChainID" ] || { echo "chainId $gotChain != chain spec's $genesisChainID" >&2; return 1; }

  local genesisBlock genesisHash
  genesisBlock=$(rpc "$jwt" "$ethURL" eth_getBlockByNumber '["0x0", false]')
  genesisHash=$(echo "$genesisBlock" | pyget "['result']['hash']")
  local gotGenesisFee
  gotGenesisFee=$(python3 -c "print(int('$(echo "$genesisBlock" | pyget "['result']['baseFeePerGas']")', 16))")
  [ "$gotGenesisFee" = "$genesisBaseFee" ] || { echo "genesis baseFee $gotGenesisFee != chain spec's $genesisBaseFee" >&2; return 1; }
  echo "  [$label] genesis $genesisHash, chainId $gotChain, baseFee $gotGenesisFee, gasLimit $genesisGasLimit"

  local headHash=$genesisHash ts zero32
  ts=$(python3 -c "print(int('$(echo "$genesisBlock" | pyget "['result']['timestamp']")', 16))")
  zero32="0x$(printf '%064x' 0)"

  echo "block,baseFeePerGas_wei,gasLimit,gasUsed" >"$csv"
  for i in $(seq 1 "$blocks"); do
    ts=$((ts + 1))
    local attrs fcu status payloadID payload npStatus finalFcu finalStatus canonical canonHash canonNum
    attrs=$(printf '{"timestamp":"0x%x","prevRandao":"%s","suggestedFeeRecipient":"0x0000000000000000000000000000000000000000","withdrawals":[],"parentBeaconBlockRoot":"%s"}' "$ts" "$zero32" "$zero32")

    fcu=$(rpc "$jwt" "$engineURL" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$headHash\",\"safeBlockHash\":\"$headHash\",\"finalizedBlockHash\":\"$headHash\"},$attrs]") || return 1
    # P2: the build-triggering forkchoice status was previously never checked.
    status=$(echo "$fcu" | pyget "['result']['payloadStatus']['status']")
    [ "$status" = "VALID" ] || { echo "block $i: build forkchoiceUpdated returned $status" >&2; return 1; }
    payloadID=$(echo "$fcu" | pyget "['result']['payloadId']")
    [ "$payloadID" != "None" ] || { echo "block $i: no payloadId" >&2; return 1; }

    sleep 0.35 # let the builder finish assembling before collecting
    payload=$(rpc "$jwt" "$engineURL" engine_getPayloadV3 "[\"$payloadID\"]" |
      python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['result']['executionPayload']))") || return 1

    npStatus=$(rpc "$jwt" "$engineURL" engine_newPayloadV3 "[$payload,[],\"$zero32\"]" | pyget "['result']['status']") || return 1
    [ "$npStatus" = "VALID" ] || { echo "block $i: newPayload returned $npStatus" >&2; return 1; }

    headHash=$(echo "$payload" | pyget "['blockHash']")
    # P2: the final forkchoice response was previously discarded entirely.
    finalFcu=$(rpc "$jwt" "$engineURL" engine_forkchoiceUpdatedV3 "[{\"headBlockHash\":\"$headHash\",\"safeBlockHash\":\"$headHash\",\"finalizedBlockHash\":\"$headHash\"},null]") || return 1
    finalStatus=$(echo "$finalFcu" | pyget "['result']['payloadStatus']['status']")
    [ "$finalStatus" = "VALID" ] || { echo "block $i: canonicalising forkchoiceUpdated returned $finalStatus" >&2; return 1; }

    # P2: and the canonical head was never confirmed to be the block we just committed.
    canonical=$(rpc "$jwt" "$ethURL" eth_getBlockByNumber '["latest", false]') || return 1
    canonHash=$(echo "$canonical" | pyget "['result']['hash']")
    canonNum=$(python3 -c "print(int('$(echo "$canonical" | pyget "['result']['number']")', 16))")
    [ "$canonHash" = "$headHash" ] || { echo "block $i: canonical head is $canonHash, committed $headHash" >&2; return 1; }
    [ "$canonNum" = "$i" ] || { echo "block $i: canonical head is number $canonNum" >&2; return 1; }

    python3 -c "
import json
p = json.loads('''$payload''')
print('%d,%d,%d,%d' % (int(p['blockNumber'], 16), int(p['baseFeePerGas'], 16),
                       int(p['gasLimit'], 16), int(p['gasUsed'], 16)))" >>"$csv"
  done

  kill "$rethPid" 2>/dev/null; wait "$rethPid" 2>/dev/null || true
  rethPid=""
}

echo "=== 1. control A: reth's default builder configuration ==="
run_control default "$workDir/default.csv"
echo

echo "=== 2. control B: the same client with --builder.gaslimit $genesisGasLimit ==="
run_control pinned-gaslimit "$workDir/pinned.csv" --builder.gaslimit "$genesisGasLimit"
echo

echo "=== 3. assertions ==="
python3 - "$workDir/default.csv" "$workDir/pinned.csv" "$genesisBaseFee" "$genesisGasLimit" <<'PY'
import csv, sys

defPath, pinPath, genesisBaseFee, genesisGasLimit = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
load = lambda p: [{k: int(v) for k, v in r.items()} for r in csv.DictReader(open(p))]
default, pinned = load(defPath), load(pinPath)
failures = []

def check(name, ok, detail):
    print(("PASS " if ok else "FAIL ") + name + ": " + detail)
    if not ok:
        failures.append(name)

def show(rows, field):
    return "%d -> %d over %d blocks" % (rows[0][field], rows[-1][field], len(rows))

# --- Behaviour we want, and have. -------------------------------------------------------------
for label, rows in (("A/default", default), ("B/pinned-gaslimit", pinned)):
    check("%s blocks are contiguous" % label,
          [r["block"] for r in rows] == list(range(1, len(rows) + 1)),
          "1..%d" % rows[-1]["block"])
    check("%s empty blocks consume no gas" % label,
          all(r["gasUsed"] == 0 for r in rows),
          "max gasUsed %d" % max(r["gasUsed"] for r in rows))

# --- D-1: the exact integer fee recurrence. ---------------------------------------------------
# EIP-1559 for an empty block is next = parent - floor(parent / 8), applied in integer
# arithmetic from the genesis base fee. It is NOT repeated multiplication by 7/8: the floor makes
# the sequence terminate. 7 is a fixed point, because floor(7/8) == 0, so the fee descends to 7
# and stays there forever. An earlier version of this script asserted the float ratio and so
# falsely reported BASELINE CHANGED once rounding began to dominate.
def predict(n, start):
    out, b = [], start
    for _ in range(n):
        b -= b // 8
        out.append(b)
    return out

for label, rows in (("A/default", default), ("B/pinned-gaslimit", pinned)):
    expected = predict(len(rows), genesisBaseFee)
    observed = [r["baseFeePerGas_wei"] for r in rows]
    first_bad = next((i for i, (e, o) in enumerate(zip(expected, observed)) if e != o), None)
    check("D-1 %s base fee follows next = parent - floor(parent/8) exactly" % label,
          first_bad is None,
          show(rows, "baseFeePerGas_wei") if first_bad is None
          else "block %d: expected %d, got %d" % (first_bad + 1, expected[first_bad], observed[first_bad]))

floor_reached = [r["baseFeePerGas_wei"] for r in default if r["baseFeePerGas_wei"] == 7]
if len(default) >= 145:
    check("D-1 the descent settles at the 7-wei fixed point, it does not reach 1",
          bool(floor_reached) and default[-1]["baseFeePerGas_wei"] == 7,
          "block 145 onward is 7 wei; final %d wei" % default[-1]["baseFeePerGas_wei"])
else:
    print("SKIP D-1 fixed point: needs >= 145 blocks, ran %d" % len(default))

# The fixed point is an artefact of integer division, not a configured floor: nothing lets an
# operator choose it, and it is ~8 orders of magnitude below the genesis base fee. A real
# configurable floor remains an F5 (#13) validity requirement.
check("D-1 the genesis base fee is not preserved",
      default[-1]["baseFeePerGas_wei"] < genesisBaseFee,
      "genesis %d wei -> %d wei" % (genesisBaseFee, default[-1]["baseFeePerGas_wei"]))

# --- D-2: gas limit, default versus configured. -----------------------------------------------
# The builder walks toward its own default target, clamped per block to the allowed range
# (EthereumBuilderConfig::gas_limit_with_target -> calculate_block_gas_limit). That is a
# configuration default, not a client defect: --builder.gaslimit already pins it.
deltas = [default[i]["gasLimit"] - default[i-1]["gasLimit"] for i in range(1, len(default))]
check("D-2A default builder drifts the gas limit upward by ~1/1024 per block",
      all(d > 0 for d in deltas) and default[-1]["gasLimit"] > genesisGasLimit,
      show(default, "gasLimit") + " (chain spec says %d)" % genesisGasLimit)

check("D-2B --builder.gaslimit holds it at the chain spec value with no client change",
      all(r["gasLimit"] == genesisGasLimit for r in pinned),
      "every block %d" % genesisGasLimit)

print()
if failures:
    print("BASELINE CHANGED: " + ", ".join(failures))
    print("If a fee-floor or gas-limit change landed, update docs/design/f1-baseline.md §4 and")
    print("this script together, and tell F5 (#13).")
    sys.exit(1)
print("baseline holds: real reth agrees with docs/design/f1-baseline.md §4.")
PY

if [ "$baselineEvidence" = false ]; then
  echo
  echo "REMINDER: this ran against an unpinned client. Not baseline evidence."
fi
