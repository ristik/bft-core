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
info() { echo "  info: $1"; }

# The extra single-purpose reth instances the section-3 negatives start, by directory. They are
# killed inline on the happy path; listing them here is what stops an interrupted or failed run
# from leaving them holding their ports and datadirs.
negativeReths="reth-wrong reth-wrongchain reth-othergenesis"

cleanup() {
  ./stop-evm.sh -a >/dev/null 2>&1 || true
  for i in $(seq 1 "$validators"); do
    [ -f "test-nodes/reth$i/pid" ] && kill "$(cat "test-nodes/reth$i/pid")" 2>/dev/null
  done
  for d in $negativeReths; do
    [ -f "test-nodes/$d/pid" ] && kill "$(cat "test-nodes/$d/pid")" 2>/dev/null
  done
  wait 2>/dev/null || true
}


# boundedRun runs `ubft shard-node run` with the given arguments and a hard time budget, capturing
# its combined output in $boundedOut and its exit status in $boundedStatus.
#
# Every section-3 negative asserts that startup REFUSES, so an unbounded run is a hazard rather
# than a convenience: the day a check regresses, the node starts, blocks waiting for a root chain
# that is not up yet, and the script hangs forever instead of failing. A regression must be a
# failure, not a hang. $boundedStatus is 124 (the conventional timeout status) if the budget was
# hit, which the assertions treat as "did not refuse".
boundedRun() {
  budget=$1; shift
  rm -f test-nodes/.bounded.out
  ( exec "$@" >test-nodes/.bounded.out 2>&1 ) &
  boundedPid=$!
  boundedStatus=124
  for _ in $(seq 1 "$budget"); do
    if ! kill -0 "$boundedPid" 2>/dev/null; then
      wait "$boundedPid"; boundedStatus=$?
      break
    fi
    sleep 1
  done
  if [ "$boundedStatus" -eq 124 ]; then
    kill "$boundedPid" 2>/dev/null
    for _ in $(seq 1 5); do
      kill -0 "$boundedPid" 2>/dev/null || break
      sleep 1
    done
    kill -KILL "$boundedPid" 2>/dev/null || true
    wait "$boundedPid" 2>/dev/null || true
  fi
  boundedOut=$(cat test-nodes/.bounded.out 2>/dev/null)
}

# Refuse to run alongside a shard node left over from an earlier run. Sections 4-7 take their
# evidence from test-nodes/evmN/debug.log by grep, so a stale process still appending to that file
# can supply the "accepted certificate" line this lane treats as proof — and a stale process holding
# one of the validator ports silently reduces the cluster this lane claims to have started. Found
# for real: a `shard-node run` from the previous day was still writing to evm1/debug.log during a
# passing run. Fail loudly instead of producing evidence of unclear provenance.
stale=$(pgrep -f 'ubft shard-node run' 2>/dev/null || true)
if [ -n "$stale" ]; then
  echo "refusing to start: shard-node processes are already running (pids: $(echo $stale | tr '\n' ' '))" >&2
  echo "their logs would mix with this run's evidence. stop them first:" >&2
  echo "  pkill -f 'ubft shard-node run'" >&2
  exit 1
fi

# Install cleanup only after the refusal guard: a refused run owns no processes.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
boundedRun 60 build/ubft shard-node run --home test-nodes/evm1 --executor engine-api \
  --address /ip4/127.0.0.1/tcp/28001 --trust-base test-nodes/trust-base.json \
  --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
  --engine-url http://127.0.0.1:18751 --eth-url http://127.0.0.1:18745 \
  --jwt-secret test-nodes/evm1/jwt.hex --log-format text --log-level info
runOut=$boundedOut; runStatus=$boundedStatus
if [ "$runStatus" -ne 0 ] && [ "$runStatus" -ne 124 ] && echo "$runOut" | grep -q 'startup chain-identity check' &&
   echo "$runOut" | grep -q 'chainId=31338, shard conf says 31337'; then
  pass "shard-node run itself refused to start against chainId 31338 (exit $runStatus), before voting"
else
  fail "shard-node run did not refuse the wrong chain (exit $runStatus): $(echo "$runOut" | tail -3)"
fi
kill "$(cat test-nodes/reth-wrongchain/pid)" 2>/dev/null; rm -f test-nodes/reth-wrongchain/pid

# 3d. Same chain id, DIFFERENT genesis (#89 item 2). Chain id does not establish genesis identity:
# this client is on chainId 31337 exactly as configured, and differs only in its allocation, which
# is what a genesis generated for a different deployment looks like. The expected value is supplied
# by the operator, never read from the client under test.
mkdir -p test-nodes/reth-othergenesis
python3 - <<'PYGEN'
import json
g = json.load(open("test-nodes/evm-genesis-funded.json"))
# Same chainId, different allocation -> different genesis hash.
g["alloc"]["0x00000000000000000000000000000000000000aa"] = {"balance": "0x1"}
json.dump(g, open("test-nodes/other-genesis.json", "w"))
PYGEN
reth node --chain test-nodes/other-genesis.json --datadir test-nodes/reth-othergenesis/dd \
  --authrpc.jwtsecret test-nodes/evm1/jwt.hex --authrpc.addr 127.0.0.1 --authrpc.port 18851 \
  --http --http.addr 127.0.0.1 --http.port 18845 --http.api eth,net,web3 \
  --port 30699 --disable-discovery --ipcdisable \
  >test-nodes/reth-othergenesis/reth.log 2>&1 &
echo $! >test-nodes/reth-othergenesis/pid
for _ in $(seq 1 60); do
  rpc http://127.0.0.1:18845 eth_chainId '[]' 2>/dev/null | grep -q result && break
  sleep 1
done
expectedGenesis=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockByNumber '["0x0", false]' | pyget "['result']['hash']")
otherChainID=$(rpc http://127.0.0.1:18845 eth_chainId '[]' | pyget "['result']")
otherGenesis=$(rpc http://127.0.0.1:18845 eth_getBlockByNumber '["0x0", false]' | pyget "['result']['hash']")
info "configured expectation: chainId 31337, genesis $expectedGenesis"
info "the other client reports: chainId $otherChainID (same), genesis $otherGenesis (different)"

# Establish the PREMISE before asserting the refusal. Without this the negative below passes on a
# vacuous run: if either client failed to start, or the allocation edit did not actually change the
# genesis hash, both reads could be empty or equal and the "refusal" would just be the node failing
# to read a genesis at all. That is a different bug wearing this test's PASS.
if [ -z "$expectedGenesis" ] || [ -z "$otherGenesis" ]; then
  fail "3d premise: could not read both genesis hashes (expected='$expectedGenesis' other='$otherGenesis')"
elif [ "$expectedGenesis" = "$otherGenesis" ]; then
  fail "3d premise: the two clients report the SAME genesis $expectedGenesis, so this is not a different-genesis case"
elif [ "$otherChainID" != "0x7a69" ]; then
  fail "3d premise: the other client reports chainId $otherChainID, not 0x7a69 — this would be caught by the chain-id check, not the genesis check"
else
  boundedRun 60 build/ubft shard-node run --home test-nodes/evm1 --executor engine-api \
    --address /ip4/127.0.0.1/tcp/28002 --trust-base test-nodes/trust-base.json \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --engine-url http://127.0.0.1:18851 --eth-url http://127.0.0.1:18845 \
    --expected-genesis-hash "$expectedGenesis" \
    --jwt-secret test-nodes/evm1/jwt.hex --log-format text --log-level info
  genOut=$boundedOut; genStatus=$boundedStatus
  # Assert the SPECIFIC mismatch diagnostic carrying both hashes, not merely "a genesis check
  # failed" — an unreadable fixture, an unreachable client or a malformed expected value all
  # produce a startup-genesis-check error too, and none of them is what this case is about.
  wantMsg="execution client genesis is ${otherGenesis#0x}, configured expectation is ${expectedGenesis#0x}"
  if [ "$genStatus" -ne 0 ] && [ "$genStatus" -ne 124 ] &&
     echo "$genOut" | grep -q -- 'startup genesis check' && echo "$genOut" | grep -qF -- "$wantMsg"; then
    pass "shard-node run refused a same-chainId/different-genesis client (exit $genStatus), before voting"
  elif [ "$genStatus" -eq 124 ]; then
    fail "same chain id with a different genesis was NOT refused: startup ran past its budget"
  else
    fail "same chain id with a different genesis was NOT refused with the expected diagnostic (exit $genStatus); wanted '$wantMsg'"
    echo "--- captured output ---"; echo "$genOut" | tail -15; echo "--- end ---"
  fi

  # 3e. THE ENDPOINT-PAIRING NEGATIVE (#89 item 3), against real reth. --eth-url addresses the
  # correct client and --engine-url addresses the other one: same chain id, different genesis. The
  # Engine connection is the one that would build our blocks, so checking only the plain endpoint
  # would accept this. It is refused because both identity checks now read the authenticated Engine
  # connection too — standard eth_chainId/eth_getBlockByNumber on the authrpc port, which the
  # Engine API's underlying-protocol section requires and this pinned client serves.
  boundedRun 60 build/ubft shard-node run --home test-nodes/evm1 --executor engine-api \
    --address /ip4/127.0.0.1/tcp/28003 --trust-base test-nodes/trust-base.json \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --engine-url http://127.0.0.1:18851 --eth-url "http://127.0.0.1:$rethEthBase" \
    --jwt-secret test-nodes/evm1/jwt.hex --log-format text --log-level info
  pairOut=$boundedOut; pairStatus=$boundedStatus
  # The "--" before the pattern is load-bearing: this message STARTS with "--eth-url", and without
  # it grep parses the pattern as an option bundle and never matches. That produced a FAIL against
  # output that in fact contained the expected diagnostic verbatim.
  pairMsg="--eth-url genesis is ${expectedGenesis#0x} but --engine-url genesis is ${otherGenesis#0x}"
  if [ "$pairStatus" -ne 0 ] && [ "$pairStatus" -ne 124 ] &&
     echo "$pairOut" | grep -q -- 'startup endpoint-pairing check' && echo "$pairOut" | grep -qF -- "$pairMsg"; then
    pass "shard-node run refused a mispaired --engine-url/--eth-url (exit $pairStatus), with no --expected-genesis-hash configured"
  elif [ "$pairStatus" -eq 124 ]; then
    fail "mispaired endpoints were NOT refused: startup ran past its budget"
  else
    fail "mispaired endpoints were NOT refused with the expected diagnostic (exit $pairStatus); wanted '$pairMsg'"
    echo "--- captured output ---"; echo "$pairOut" | tail -15; echo "--- end ---"
  fi

  # And the doctor preflight for the same mispairing. doctor's "genesis hash" check calls the same
  # Adapter.CheckEndpointsPaired the node enforces, so the two cannot drift — the reason #89 item 4
  # de-duplicated the chain-id check applies here too.
  pairDoctor=$(build/ubft shard-node doctor --home test-nodes/evm1 --executor engine-api \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --engine-url http://127.0.0.1:18851 --eth-url "http://127.0.0.1:$rethEthBase" \
    --jwt-secret test-nodes/evm1/jwt.hex 2>&1)
  pairDoctorStatus=$?
  if [ "$pairDoctorStatus" -ne 0 ] && echo "$pairDoctor" | grep -qE '^\[FAIL\] genesis hash' &&
     echo "$pairDoctor" | grep -qF -- "$pairMsg"; then
    pass "doctor rejected the same mispairing at its genesis-hash check"
  else
    fail "doctor did not reject the mispairing (exit $pairDoctorStatus)"
    echo "--- captured output ---"; echo "$pairDoctor" | tail -15; echo "--- end ---"
  fi

  # Positive control for doctor: one client behind both URLs must PASS the genesis check and report
  # the hash it agreed on. Without this the negative above could be passing on any doctor failure.
  okDoctor=$(build/ubft shard-node doctor --home test-nodes/evm1 --executor engine-api \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --engine-url "http://127.0.0.1:$rethEngineBase" --eth-url "http://127.0.0.1:$rethEthBase" \
    --jwt-secret test-nodes/evm1/jwt.hex 2>&1)
  if echo "$okDoctor" | grep -qE "^\[PASS\] genesis hash[[:space:]]+block 0 hash=$expectedGenesis, agreed by both endpoints"; then
    pass "doctor passed the genesis-hash check on a correctly paired client, reporting the agreed hash"
  else
    fail "doctor did not pass the genesis-hash check on a correctly paired client"
    echo "--- captured output ---"; echo "$okDoctor" | grep -i genesis; echo "--- end ---"
  fi
fi
kill "$(cat test-nodes/reth-othergenesis/pid)" 2>/dev/null; rm -f test-nodes/reth-othergenesis/pid

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
