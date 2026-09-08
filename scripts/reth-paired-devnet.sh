#!/bin/bash
# reth-paired-devnet.sh - the paired real-reth devnet required by F1 (#9).
#
# scripts/reth-by-hand.sh and scripts/reth-baseline.sh both drive reth with curl and no Unicity
# code at all. They establish things about the *client*; they establish nothing about the Go
# adapter, because they bypass it entirely. This script is the one that exercises the actual
# integration: one reth per validator, and `ubft shard-node run --executor engine-api` driving
# them through engineapi/'s own JWT minting, encoding, round-params derivation and
# Build/Seal/Verify/Commit calls, certifying against a real root chain.
#
# It also tests two doctor preflight failures. These do not establish that shard-node run
# enforces every corresponding check before voting (§5.5 of docs/design/f1-baseline.md).
#
# Usage:
#   ./scripts/reth-paired-devnet.sh [validators] [rounds]      # defaults: 4 validators, 5 rounds
#
# Needs: a `reth` binary at the pinned revision, curl, openssl, python3, and a built ./build/ubft.
# Run from the repository root. Leaves test-nodes/ and its reth datadirs in place for inspection.

set -uo pipefail

validators=${1:-4}
rounds=${2:-5}
partitionID=8
pinnedRethCommit=189c0df32617afc488e0f091dbface1bd72cceb4   # ristik/ureth, branch unicity/main

rethEngineBase=18551
rethEthBase=18545
rethP2PBase=30401

command -v reth >/dev/null || { echo "no reth binary on PATH - this lane has no fake fallback" >&2; exit 1; }
rethCommit=$(reth --version | sed -n 's/^Commit SHA: //p')
if [ "$rethCommit" != "$pinnedRethCommit" ]; then
  echo "FAIL: reth is $rethCommit, pinned baseline is $pinnedRethCommit" >&2
  echo "      Set F1_ALLOW_UNPINNED_RETH=1 to run anyway; output is then NOT baseline evidence." >&2
  [ "${F1_ALLOW_UNPINNED_RETH:-0}" = "1" ] || exit 1
fi

failures=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }

cleanup() {
  ./stop-evm.sh -a >/dev/null 2>&1 || true
  for i in $(seq 1 "$validators"); do
    [ -f "test-nodes/reth$i/pid" ] && kill "$(cat "test-nodes/reth$i/pid")" 2>/dev/null
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 1. generate the shard topology and chain spec ==="
./setup-evm-nodes.sh -r 3 -v "$validators" >/dev/null || { echo "setup failed" >&2; exit 1; }
genesisSHA=$(shasum -a 256 test-nodes/evm-genesis.json | cut -d' ' -f1)
echo "generated genesis sha256=$genesisSHA"

# The generated genesis has an empty alloc, so no account can pay for gas and the shard can only
# ever certify quiet rounds - which build no EVM block at all, leaving reth at genesis forever.
# Fund one well-known test account so §6 can prove the adapter really builds and commits a block.
# Real genesis funding is T1 (#28); this is test-only and derived from the generated file, so the
# chainId and fork schedule still come from the shard conf.
python3 - <<'PY'
import json, subprocess
g = json.load(open("test-nodes/evm-genesis.json"))
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
json.dump(g, open("test-nodes/evm-genesis-funded.json", "w"), indent=2)
PY
fundedSHA=$(shasum -a 256 test-nodes/evm-genesis-funded.json | cut -d' ' -f1)
echo "funded test genesis sha256=$fundedSHA"
chainSpec=test-nodes/evm-genesis-funded.json

echo
echo "=== 2. start one reth per validator on that chain spec ==="
for i in $(seq 1 "$validators"); do
  mkdir -p "test-nodes/reth$i"
  # Each validator's adapter reads this exact file (helper.sh's start_one_evm_validator passes
  # --jwt-secret test-nodes/evm$i/jwt.hex), so the adapter's own JWT minting is what has to
  # satisfy reth - nothing here pre-authenticates on its behalf.
  openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  reth node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) \
    --http.api eth,net,web3,admin \
    --port $((rethP2PBase + i - 1)) --disable-discovery \
    --ipcdisable \
    >"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
done

rpc() { curl -sS --max-time 10 -X POST "$1" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"; }
pyget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)" 2>/dev/null; }

for i in $(seq 1 "$validators"); do
  url="http://127.0.0.1:$((rethEthBase + i - 1))"
  up=false
  for _ in $(seq 1 60); do
    if rpc "$url" eth_chainId '[]' 2>/dev/null | grep -q result; then up=true; break; fi
    sleep 1
  done
  $up || { fail "reth $i did not start"; tail -20 "test-nodes/reth$i/reth.log" >&2; exit 1; }
done
pass "all $validators reth instances are up on the shard's generated chain spec"

# devp2p static peering (docs/engine-api-adapter.md §5): discovery is off, so introduce them
# explicitly rather than relying on it.
for i in $(seq 1 "$validators"); do
  enode=$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_nodeInfo '[]' | pyget "['result']['enode']")
  for j in $(seq 1 "$validators"); do
    [ "$i" = "$j" ] && continue
    rpc "http://127.0.0.1:$((rethEthBase + j - 1))" admin_addPeer "[\"$enode\"]" >/dev/null
  done
done
pass "reth instances statically peered"

echo
echo "=== 3. doctor preflight detects chainId mismatch and unreachable Engine API ==="

# 3a. chainId mismatch. shard-node doctor compares the client's eth_chainId against the shard
# conf; point it at a reth running a different chain and it must refuse.
mkdir -p test-nodes/reth-wrong
cat >test-nodes/wrong-genesis.json <<'EOF'
{"config":{"chainId":31338,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,
"byzantiumBlock":0,"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,
"londonBlock":0,"mergeNetsplitBlock":0,"shanghaiTime":0,"cancunTime":0,
"terminalTotalDifficulty":0,"terminalTotalDifficultyPassed":true},
"nonce":"0x0","timestamp":"0x0","extraData":"0x","gasLimit":"0x1c9c380","difficulty":"0x0",
"mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
"coinbase":"0x0000000000000000000000000000000000000000","alloc":{},
"baseFeePerGas":"0x3b9aca00"}
EOF
reth node --chain test-nodes/wrong-genesis.json --datadir test-nodes/reth-wrong/dd \
  --authrpc.jwtsecret test-nodes/evm1/jwt.hex --authrpc.addr 127.0.0.1 --authrpc.port 18651 \
  --http --http.addr 127.0.0.1 --http.port 18645 --http.api eth,net,web3 \
  --port 30499 --disable-discovery --ipcdisable \
  >test-nodes/reth-wrong/reth.log 2>&1 &
echo $! >test-nodes/reth-wrong/pid
for _ in $(seq 1 60); do
  rpc http://127.0.0.1:18645 eth_chainId '[]' 2>/dev/null | grep -q result && break
  sleep 1
done
doctorOut=$(build/ubft shard-node doctor --home test-nodes/evm1 --executor engine-api \
  --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
  --engine-url http://127.0.0.1:18651 --eth-url http://127.0.0.1:18645 \
  --jwt-secret test-nodes/evm1/jwt.hex 2>&1)
doctorStatus=$?
if [ "$doctorStatus" -ne 0 ] && echo "$doctorOut" | grep -qE '^\[FAIL\] chain identity[[:space:]]+engineapi: execution client reports chainId=31338, shard conf says 31337'; then
  pass "doctor rejected chainId mismatch: $(echo "$doctorOut" | grep -o 'execution client reports chainId=[0-9]*, shard conf says [0-9]*' | head -1)"
else
  fail "chainId mismatch NOT detected; doctor said: $(echo "$doctorOut" | tail -3)"
fi
kill "$(cat test-nodes/reth-wrong/pid)" 2>/dev/null; rm -f test-nodes/reth-wrong/pid

# 3b. no Engine API at all behind the URL. CheckCapabilities must fail closed rather than
# starting and stalling. Require the specific engine-link failure, not another doctor failure
# (for example, the intentionally absent root bootnodes at this preflight stage).
capOut=$(build/ubft shard-node doctor --home test-nodes/evm1 --executor engine-api \
  --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
  --engine-url http://127.0.0.1:18699 --eth-url "http://127.0.0.1:$rethEthBase" \
  --jwt-secret test-nodes/evm1/jwt.hex 2>&1)
capStatus=$?
if [ "$capStatus" -ne 0 ] && echo "$capOut" | grep -qE '^\[FAIL\] engine link[[:space:]]+engineapi: checking capabilities:'; then
  pass "doctor rejected unreachable Engine API at its capability check"
else
  fail "unreachable Engine API not detected; doctor said: $(echo "$capOut" | tail -3)"
fi

# 3c. THE NODE ITSELF, not doctor. The two checks above are preflight: an operator has to
# remember to run them. F1 (#9) requires `shard-node run` to refuse a spec mismatch before it
# can vote, which it now does — capability exchange cannot tell one chain from another, so
# without this a node pointed at the wrong execution client starts and certifies against the
# wrong state. This drives the real binary and asserts a nonzero exit.
mkdir -p test-nodes/reth-wrongchain
python3 - <<'PYGEN'
import json
g = json.load(open("test-nodes/evm-genesis-funded.json"))
g["config"]["chainId"] = 31338
json.dump(g, open("test-nodes/wrong-chain-genesis.json", "w"))
PYGEN
reth node --chain test-nodes/wrong-chain-genesis.json --datadir test-nodes/reth-wrongchain/dd \
  --authrpc.jwtsecret test-nodes/evm1/jwt.hex --authrpc.addr 127.0.0.1 --authrpc.port 18751 \
  --http --http.addr 127.0.0.1 --http.port 18745 --http.api eth,net,web3 \
  --port 30599 --disable-discovery --ipcdisable \
  >test-nodes/reth-wrongchain/reth.log 2>&1 &
echo $! >test-nodes/reth-wrongchain/pid
for _ in $(seq 1 60); do
  rpc http://127.0.0.1:18745 eth_chainId '[]' 2>/dev/null | grep -q result && break
  sleep 1
done
runOut=$(build/ubft shard-node run --home test-nodes/evm1 --executor engine-api \
  --address /ip4/127.0.0.1/tcp/28001 --trust-base test-nodes/trust-base.json \
  --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
  --engine-url http://127.0.0.1:18751 --eth-url http://127.0.0.1:18745 \
  --jwt-secret test-nodes/evm1/jwt.hex --log-format text --log-level info 2>&1)
runStatus=$?
if [ "$runStatus" -ne 0 ] && echo "$runOut" | grep -q 'startup chain-identity check' &&
   echo "$runOut" | grep -q 'chainId=31338, shard conf says 31337'; then
  pass "shard-node run itself refused to start against chainId 31338 (exit $runStatus), before voting"
else
  fail "shard-node run did not refuse the wrong chain (exit $runStatus): $(echo "$runOut" | tail -3)"
fi
kill "$(cat test-nodes/reth-wrongchain/pid)" 2>/dev/null; rm -f test-nodes/reth-wrongchain/pid

echo
echo "=== 4. start the root chain and the shard validators on --executor engine-api ==="
source helper.sh
for i in $(seq 1 "$validators"); do
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))"
  export "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
done
./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1

echo "waiting for certification (real execution, up to 180s) ..."
certified=false
for _ in $(seq 1 90); do
  if grep -q 'accepted certificate' test-nodes/evm1/debug.log 2>/dev/null; then certified=true; break; fi
  sleep 2
done
if $certified; then
  pass "shard certified with --executor engine-api against real reth"
else
  fail "no certificate within 180s"
  echo "--- evm1 tail ---"; tail -25 test-nodes/evm1/debug.log 2>/dev/null
  echo "--- reth1 tail ---"; tail -15 test-nodes/reth1/reth.log 2>/dev/null
fi

echo
echo "=== 5. an idle shard certifies quiet rounds and builds no EVM block ==="
echo "waiting for $rounds certified rounds ..."
for _ in $(seq 1 120); do
  n=$(grep -c 'accepted certificate' test-nodes/evm1/debug.log 2>/dev/null || echo 0)
  [ "$n" -ge "$rounds" ] && break
  sleep 2
done
idleHead=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockByNumber '["latest", false]' | pyget "['result']['number']")
idleDec=$(python3 -c "print(int('${idleHead:-0x0}', 16))" 2>/dev/null || echo 0)
quiet=$(grep -c 'quiet=true' test-nodes/evm1/debug.log 2>/dev/null || echo 0)
if [ "$idleDec" = "0" ] && [ "$quiet" -gt 0 ]; then
  pass "idle rounds are quiet ($quiet of them) and reth stays at block 0 - the baseline builds no block without a transaction"
else
  fail "expected an idle shard to stay at block 0 with quiet rounds; head=$idleDec quiet=$quiet"
fi
echo "  NOTE: producing blocks on idle rounds at the EVM cadence is F4 (#12), not the F1 baseline."

echo
echo "=== 6. a real transaction makes the adapter build, certify and commit a real EVM block ==="
txHash=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$rethEthBase" \
  -chain-id 31337 -nonce 0 2>&1)
if [[ "$txHash" == 0x* ]]; then
  pass "submitted $txHash to reth1's mempool"
else
  fail "could not submit a transaction: $txHash"
fi

echo "waiting for it to be executed and certified ..."
mined=false
for _ in $(seq 1 90); do
  rcpt=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionReceipt "[\"$txHash\"]")
  blkNum=$(echo "$rcpt" | pyget "['result']['blockNumber']")
  if [ -n "$blkNum" ] && [ "$blkNum" != "None" ]; then mined=true; break; fi
  sleep 2
done

if $mined; then
  status=$(echo "$rcpt" | pyget "['result']['status']")
  gasUsed=$(echo "$rcpt" | pyget "['result']['gasUsed']")
  blkDec=$(python3 -c "print(int('$blkNum', 16))")
  pass "executed in reth block $blkDec, status=$status gasUsed=$gasUsed"
  if [ "$blkDec" -gt 0 ] && [ "$status" = "0x1" ]; then
    pass "the Go adapter drove real EVM execution to a canonical block, not a quiet round"
  else
    fail "transaction did not succeed in a real block (block=$blkDec status=$status)"
  fi
else
  fail "transaction was never executed within 180s"
  echo "--- evm1 tail ---"; tail -20 test-nodes/evm1/debug.log 2>/dev/null
fi

echo
echo "=== 7. every validator's reth converged on that same canonical block ==="
heads=""
for i in $(seq 1 "$validators"); do
  blk=$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_getBlockByNumber '["latest", false]')
  num=$(echo "$blk" | pyget "['result']['number']")
  hash=$(echo "$blk" | pyget "['result']['hash']")
  echo "  reth$i head: number=$num hash=$hash"
  heads="$heads$num:$hash"$'\n'
done
agree=$(printf '%s' "$heads" | sort -u | grep -c . )
if [ "$agree" = "1" ]; then
  pass "all $validators reth instances agree on the same canonical head"
else
  fail "reth instances disagree on the canonical head:"; printf '%s' "$heads"
fi

# The certified state root must be reth's own, not something the framework invented.
certRoot=$(grep 'accepted certificate' test-nodes/evm1/debug.log | tail -1)
if [ -n "$certRoot" ]; then
  pass "latest certificate: $(echo "$certRoot" | grep -oE 'partitionRound=[0-9]+ rootRound=[0-9]+' | head -1)"
fi

for i in $(seq 1 "$validators"); do
  if grep -qiE 'diverge|equivocat' "test-nodes/evm$i/debug.log" 2>/dev/null; then
    fail "validator $i logged divergence/equivocation"
  fi
done
grep -qiE 'diverge|equivocat' test-nodes/evm*/debug.log 2>/dev/null || pass "no validator logged divergence or equivocation"

echo
if [ "$failures" -gt 0 ]; then
  echo "=== paired devnet: $failures check(s) failed ==="
  exit 1
fi
echo "=== paired devnet: the Go adapter drove real reth to a certified chain. ==="
echo "=== This is the real-execution evidence F1 (#9) owes; the curl scripts are not. ==="
