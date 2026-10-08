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
#   ./scripts/reth-paired-devnet.sh [validators] [rounds]      # defaults: 4 validators, 10 blocks
#
# Needs: a `reth` binary at the pinned revision, curl, openssl, python3, and a built ./build/ubft.
# Run from the repository root. Leaves test-nodes/ and its reth datadirs in place for inspection.

set -uo pipefail
# Definitions only; sourced here, before cleanup can run, for its ownership-scoped stop functions.
source helper.sh
# Definitions only: the fork-client resolver and the flag the seal-capable client requires.
. scripts/lib/reth-pin.sh
if [ "${H4_RESTORE_PROBE:-0}" = 1 ]; then
  [ -n "${H4_URETH_BIN:-}" ] && [ -n "${H4_URETH_COMMIT:-}" ] || {
    echo "H4 restore probe requires an explicit ureth binary and source commit with engine_sealConfigV1" >&2
    exit 2
  }
  URETH_BIN=$H4_URETH_BIN
  URETH_PIN_COMMIT=$H4_URETH_COMMIT
elif [ -n "${POST_M2A_URETH_BIN:-}" ] || [ -n "${POST_M2A_URETH_COMMIT:-}" ]; then
  [ "${M2_PROFILE2:-0}" = 1 ] || [ "${D2C_RESTART_PROBE:-0}" = 1 ] || { echo "POST_M2A_URETH_BIN is only supported by profile-2 and D2C restart-probe lanes" >&2; exit 2; }
  [ -n "${POST_M2A_URETH_BIN:-}" ] && [ -n "${POST_M2A_URETH_COMMIT:-}" ] || {
    echo "post-M2a lanes require both POST_M2A_URETH_BIN and POST_M2A_URETH_COMMIT" >&2
    exit 2
  }
  URETH_BIN=$POST_M2A_URETH_BIN
  URETH_PIN_COMMIT=$POST_M2A_URETH_COMMIT
  M2_RUN_LOG_DIR=${M2_RUN_LOG_DIR:-/Users/risto/uni/agre/briefs/devnet-runs/m2-p2-$(date -u +%Y%m%dT%H%M%SZ)}
  echo "profile-2 logs: $M2_RUN_LOG_DIR"
elif [ "${M2_PROFILE2:-0}" = 1 ]; then
  URETH_PIN_COMMIT=ae6e6be94d6dc45d0df6574cb5fbedef398f5c2e
  M2_RUN_LOG_DIR=${M2_RUN_LOG_DIR:-/Users/risto/uni/agre/briefs/devnet-runs/m2-p2-$(date -u +%Y%m%dT%H%M%SZ)}
  echo "profile-2 logs: $M2_RUN_LOG_DIR"
fi

validators=${1:-4}
rounds=${2:-10}
postM2aMode=${POST_M2A_MODE:-}
postM2aChainID=${POST_M2A_CHAIN_ID:-31337}
if [ -n "$postM2aMode" ]; then
  case "$postM2aMode" in f7 | t1 | t4 | t6) ;; *) echo "POST_M2A_MODE must be f7, t1, t4 or t6" >&2; exit 2 ;; esac
  [ "${M2_PROFILE2:-0}" = 1 ] || { echo "post-M2a evidence requires M2_PROFILE2=1" >&2; exit 2; }
  [ "$validators" -eq 4 ] || { echo "post-M2a evidence requires four validators" >&2; exit 2; }
  if [ "${POST_M2A_SKIP_HANDOFF:-0}" = 1 ] && [ "$postM2aMode" != t4 ]; then
    echo "POST_M2A_SKIP_HANDOFF is only supported by the T4 audit lane" >&2
    exit 2
  fi
fi
if [ "${M2_PROFILE2:-0}" = 1 ] && [ "$validators" -ne 4 ]; then
  echo "profile-2 handoff lane requires four validators" >&2
  exit 2
fi
if [ "${M2A_FINAL_RESTORE:-0}" = 1 ] && { [ "${M2_PROFILE2:-0}" != 1 ] || [ "${SIGNING:-local}" != authority ] || [ "$validators" -ne 4 ]; }; then
  echo "M2a final restore requires M2_PROFILE2=1, SIGNING=authority and four validators" >&2
  exit 2
fi
partitionID=8
if [ "${M1_FEE_ACCOUNTING:-0}" = 1 ] && { [ "$validators" -ne 4 ] || [ "$rounds" -lt 10 ]; }; then
  echo "M1 fee accounting requires four validators and at least 10 rounds" >&2
  exit 2
fi
case "${SIGNING:-local}" in
  local | authority) ;;
  *) echo "SIGNING must be local or authority" >&2; exit 2 ;;
esac
if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
  [ "${M2_PROFILE2:-0}" = 1 ] || { echo "F8 mixed lane requires M2_PROFILE2=1 for the live root handoff" >&2; exit 2; }
  # Defines the three pinned Rust aggregator fixture and its trace/reconnect probes.
  source scripts/f8-mixed-lane.sh
fi
if [ "${H4_RESTORE_PROBE:-0}" = 1 ] && { [ "${SIGNING:-local}" != authority ] || [ "$validators" -ne 4 ] || [ "$rounds" -lt 15 ]; }; then
  echo "H4 restore probe requires SIGNING=authority, four validators and at least 15 blocks" >&2
  exit 2
fi

rethEngineBase=18551
rethEthBase=18545
rethP2PBase=30401
engineProxyPort=18651
d2cPersistenceThreshold=${D2C_PERSISTENCE_THRESHOLD:-64}
echo "ureth engine.persistence-threshold=$d2cPersistenceThreshold blocks (D2C replay visibility)"

# The fork client. Every validator runs `--executor engine-api`, and the shard node refuses a
# client without the three engine_*WithSealV1 methods, so this lane resolves the pinned fork
# client and verifies it by revision. It used to run the stock `reth` on PATH; that client cannot
# start a shard node, so every paired lane was pointed at a client it would refuse.
urethPinResolve || exit 1
export URETH_PIN_FEE_COLLECTOR
echo "bft source commit=$(git rev-parse HEAD)"
echo "ureth source commit=$URETH_PIN_COMMIT binary sha256=$(shasum -a 256 "$URETH_BIN" | cut -d' ' -f1)"

failures=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
info() { echo "  info: $1"; }

if [ -n "$postM2aMode" ]; then
  source scripts/post-m2a-evidence-lib.sh || { echo "post-M2a evidence helper could not be loaded" >&2; exit 2; }
  export URETH_PIN_FEE_COLLECTOR_OVERRIDE
fi

# The extra single-purpose reth instances the section-3 negatives start, by directory. They are
# killed inline on the happy path; listing them here is what stops an interrupted or failed run
# from leaving them holding their ports and datadirs.
negativeReths="reth-wrong reth-wrongchain reth-othergenesis reth-laterfork"

# Everything here is ownership-scoped (helper.sh, "ownership"): stop-evm.sh -a stops this checkout's
# nodes only, and a reth is stopped by its pid file only if that pid is still a `reth node` running
# from this checkout. This runs nested inside scripts/reth-smoke.sh, whose own teardown cannot undo
# anything a machine-wide sweep here had already killed.
cleanup() {
  if [ "${F8_MIXED_LANE:-0}" = 1 ]; then f8_stop; fi
  ./stop-evm.sh -a >/dev/null 2>&1 || true
  stop_root_nodes
  # These daemons can outlive TERM while their P2P/RPC servers drain. Interrupt only
  # processes whose command and working directory identify this checkout.
  for p in $(owned_pids 'ubft root-node run|ubft shard-node run'); do
    kill -INT "$p" 2>/dev/null || true
  done
  stop_pidfile "test-nodes/h4-replaced/pid" 'ubft shard-node restore'
  stop_pidfile "test-nodes/proof-proxy/pid" 'd2c-proof-proxy.py'
  stop_pidfile "test-nodes/engine-proxy/pid" 'd2c-engine-proxy.py'
  for i in $(seq 1 "$validators"); do
    stop_pidfile "test-nodes/auth$i/pid" 'ubft signing-authority run'
  done
  # Lanes that start spare validators (the T6 rotation's evm5/auth5/reth5/root5) own processes beyond $validators; a step that aborts
  # the shell never reaches its own teardown, and `wait` below would otherwise block on the orphans. Sweep by ownership.
  for p in $(owned_pids 'ubft signing-authority run|ubft shard-node (run|restore)'); do
    kill "$p" 2>/dev/null || true
  done
  for i in $(seq 1 "$validators"); do
    stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' INT
  done
  for d in $negativeReths; do
    stop_pidfile "test-nodes/$d/pid" 'reth.* node' INT
  done
  for p in $(owned_pids 'reth.* node'); do
    kill -INT "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ "${M2_PROFILE2:-0}" = 1 ]; then
    mkdir -p "$M2_RUN_LOG_DIR"
    cp test-nodes/start-evm.log test-nodes/m2-pauses.log "$M2_RUN_LOG_DIR/" 2>/dev/null || true
    for d in test-nodes/root* test-nodes/evm* test-nodes/reth*; do
      [ -d "$d" ] || continue
      mkdir -p "$M2_RUN_LOG_DIR/$(basename "$d")"
      cp "$d"/*.log "$M2_RUN_LOG_DIR/$(basename "$d")/" 2>/dev/null || true
    done
    for d in test-nodes/h4-replaced test-nodes/auth1; do
      [ -d "$d" ] || continue
      mkdir -p "$M2_RUN_LOG_DIR/$(basename "$d")"
      cp -R "$d"/. "$M2_RUN_LOG_DIR/$(basename "$d")/" 2>/dev/null || true
    done
  fi
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
# can supply the "certificate admitted" line this lane treats as proof — and a stale process holding
# one of the validator ports silently reduces the cluster this lane claims to have started. Found
# for real: a `shard-node run` from the previous day was still writing to evm1/debug.log during a
# passing run. Fail loudly instead of producing evidence of unclear provenance.
stale=$(owned_pids 'ubft shard-node (run|restore)')
if [ -n "$stale" ]; then
  echo "refusing to start: this checkout's shard-node processes are already running (pids: $(echo $stale | tr '\n' ' '))" >&2
  echo "their logs would mix with this run's evidence. stop them first:" >&2
  echo "  pkill -f 'ubft shard-node run'" >&2
  exit 1
fi

# Install cleanup only after the refusal guard: a refused run owns no processes.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A failed mixed lane can leave a partial partition frontier in root storage. Reuse the
# generated root identities and trust base, but start its databases clean so a retry cannot
# inherit half-certified shard schemes from the prior attempt. Stop only processes owned by
# this checkout while holding the devnet lock.
if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
  stop_root_nodes
  sleep 2
  rm -f test-nodes/root{1,2,3,4}/root-trust-history.db \
    test-nodes/root{1,2,3,4}/rootchain.db \
    test-nodes/root{1,2,3,4}/orchestration.db \
    test-nodes/root{1,2,3,4}/trustbase.db
fi

echo "=== 1. generate the shard topology and chain spec ==="
rootValidators=3
if [ "${M2_PROFILE2:-0}" = 1 ]; then rootValidators=4; fi
./setup-evm-nodes.sh -r "$rootValidators" -v "$validators" -c "$postM2aChainID" >/dev/null || { echo "setup failed" >&2; exit 1; }
registry_layout_require || exit 1
echo "registry artifact (layout $(registry_layout)) sha256=$(shasum -a 256 "$(registry_artifact)" | cut -d' ' -f1)"
genesisSHA=$(shasum -a 256 test-nodes/evm-genesis.json | cut -d' ' -f1)
echo "generated genesis sha256=$genesisSHA"

# The generated genesis has an empty alloc, so no account can pay for gas and the shard can only
# ever certify quiet rounds - which build no EVM block at all, leaving reth at genesis forever.
# Fund one well-known test account so §6 can prove the adapter really builds and commits a block.
# Real genesis funding is T1 (#28); this is test-only and derived from the generated file, so the
# chainId and fork schedule still come from the shard conf.
if [ "$postM2aMode" = t1 ] || [ "$postM2aMode" = t4 ] || [ "$postM2aMode" = t6 ]; then
  post_m2a_compile_manifest_genesis || { fail "default T1 manifest export/compile failed"; exit 1; }
  chainSpec=test-nodes/evm-genesis-finalized-funded.json
  fullShardConf=test-nodes/evm-full-shard-conf-v2.json
  fundedSHA=$(shasum -a 256 "$chainSpec" | cut -d' ' -f1)
  pass "default allocation manifest exported and compiled into the finalized genesis (sha256=$fundedSHA)"
else
python3 - <<'PY'
import json, subprocess
g = json.load(open("test-nodes/evm-genesis.json"))
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
if __import__("os").environ.get("M1_FEE_ACCOUNTING") == "1":
    # Start one wei above ureth's fixed M1 floor. B1 has ordinary gas well below target,
    # so its fee must clamp to the floor and every following idle block must hold there.
    g["baseFeePerGas"] = "0xf4241"  # 1,000,001 wei; production floor is 1,000,000 wei
json.dump(g, open("test-nodes/evm-genesis-funded.json", "w"), indent=2)
PY
fundedSHA=$(shasum -a 256 test-nodes/evm-genesis-funded.json | cut -d' ' -f1)
echo "funded genesis source sha256=$fundedSHA"
# The funding edit replaces alloc, so finalize it again through U5a. That inserts the pinned
# SealRegistry account and emits the full shard configuration whose hash the v2 certificate binds.
chainSpec=test-nodes/evm-genesis-finalized-funded.json
fullShardConf=test-nodes/evm-full-shard-conf-v2.json
build/ubft engine-api genesis --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
  --alloc-source test-nodes/evm-genesis-funded.json --out "$chainSpec" \
  --full-shard-conf "$fullShardConf" --registry-layout "$(registry_layout)" || { echo "finalized funded genesis failed" >&2; exit 1; }
echo "finalized funded genesis sha256=$(shasum -a 256 "$chainSpec" | cut -d' ' -f1)"
fi
if [ "${SIGNING:-local}" = authority ]; then
  # The full configuration is the one the root chain will certify, so enroll against it rather
  # than the base configuration emitted by setup-evm-nodes.sh.
  source helper.sh
  cp "$fullShardConf" "test-nodes/shard-conf-${partitionID}_0.json"
  enroll_evm_authorities "$validators" "$partitionID" || exit 1
  echo "enrolled $validators independent signing authorities against the full shard configuration"
fi

echo
echo "=== 2. start one reth per validator on that chain spec ==="
rethStorageArgs=()
if [ "$postM2aMode" = t1 ] || [ "$postM2aMode" = t4 ]; then rethStorageArgs=(--storage.v2 false); fi
for i in $(seq 1 "$validators"); do
  mkdir -p "test-nodes/reth$i"
  # Each validator's adapter reads this exact file (helper.sh's start_one_evm_validator passes
  # --jwt-secret test-nodes/evm$i/jwt.hex), so the adapter's own JWT minting is what has to
  # satisfy reth - nothing here pre-authenticates on its behalf.
  openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  registry_layout_require || exit 1
  "$URETH_BIN" node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) \
    --http.api eth,net,web3,admin,debug --rpc.eth-proof-window 64 \
    --port $((rethP2PBase + i - 1)) --disable-discovery \
    --ipcdisable --engine.persistence-threshold "$d2cPersistenceThreshold" \
    --builder.gaslimit 30000000 \
    ${rethStorageArgs[@]+"${rethStorageArgs[@]}"} \
    $(urethPinUnicityFlags) \
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

if [ "${D2C_FAULT_SCENARIO:-}" = proof-outage ] || [ "${D2C_FAULT_SCENARIO:-}" = proof-corrupt ]; then
  mkdir -p test-nodes/proof-proxy
  printf '{"mode":"pass","until":0}\n' >test-nodes/proof-proxy/control.json
  python3 scripts/d2c-proof-proxy.py --listen 127.0.0.1:18645 \
    --target "http://127.0.0.1:$rethEthBase" \
    --control test-nodes/proof-proxy/control.json --log test-nodes/proof-proxy/proxy.log \
    >test-nodes/proof-proxy/stdout.log 2>&1 &
  echo $! >test-nodes/proof-proxy/pid
  ready=false
  for _ in $(seq 1 20); do
    if curl -sS --max-time 2 -X POST http://127.0.0.1:18645 \
      -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' 2>/dev/null | grep -q result; then
      ready=true; break
    fi
    sleep 0.25
  done
  $ready || { echo "D2C proof proxy did not start" >&2; exit 1; }
  echo "D2C proof proxy routes validator 1 HTTP RPC through 127.0.0.1:18645"
fi

if [ "${D2C_FAULT_SCENARIO:-}" = hostile-builder ] || [ "${D2C_FAULT_SCENARIO:-}" = hostile-fee-recipient ]; then
  mkdir -p test-nodes/engine-proxy
  engineMutation=gas-used
  [ "${D2C_FAULT_SCENARIO:-}" != hostile-fee-recipient ] || engineMutation=fee-recipient
  printf '{"armed":false}\n' >test-nodes/engine-proxy/control.json
  python3 scripts/d2c-engine-proxy.py --listen "127.0.0.1:$engineProxyPort" \
    --target "http://127.0.0.1:$rethEngineBase" --mutation "$engineMutation" \
    --control test-nodes/engine-proxy/control.json --log test-nodes/engine-proxy/engine.log \
    >test-nodes/engine-proxy/stdout.log 2>&1 &
  echo $! >test-nodes/engine-proxy/pid
  ready=false
  for _ in $(seq 1 20); do
    if python3 - "$engineProxyPort" <<'PYPORT'
import socket, sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.5):
        pass
except OSError:
    raise SystemExit(1)
PYPORT
    then
      ready=true; break
    fi
    sleep 0.25
  done
  $ready || { echo "D2C Engine proxy did not start" >&2; exit 1; }
  echo "D2C Engine proxy ($engineMutation mutation) routes only validator 1 Engine API through 127.0.0.1:$engineProxyPort"
fi

echo
if [ "${M2_PROFILE2:-0}" != 1 ]; then
echo "=== 3. doctor preflight detects chainId mismatch and unreachable Engine API ==="
if [ "${SIGNING:-local}" = authority ] || [ "${D2C_RESTART_PROBE:-0}" = 1 ]; then
  echo "D2C mode: skipping unrelated startup negatives; the execution lane starts in section 4"
else

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
registry_layout_require || exit 1
"$URETH_BIN" node --chain test-nodes/wrong-genesis.json --datadir test-nodes/reth-wrong/dd \
  --authrpc.jwtsecret test-nodes/evm1/jwt.hex --authrpc.addr 127.0.0.1 --authrpc.port 18651 \
  --http --http.addr 127.0.0.1 --http.port 18645 --http.api eth,net,web3 \
  --port 30499 --disable-discovery --ipcdisable \
  $(urethPinUnicityFlags) \
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
stop_pidfile test-nodes/reth-wrong/pid 'reth.* node'   # ownership-checked; removes the pid file

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
g = json.load(open("test-nodes/evm-genesis-finalized-funded.json"))
g["config"]["chainId"] = 31338
json.dump(g, open("test-nodes/wrong-chain-genesis.json", "w"))
PYGEN
registry_layout_require || exit 1
"$URETH_BIN" node --chain test-nodes/wrong-chain-genesis.json --datadir test-nodes/reth-wrongchain/dd \
  --authrpc.jwtsecret test-nodes/evm1/jwt.hex --authrpc.addr 127.0.0.1 --authrpc.port 18751 \
  --http --http.addr 127.0.0.1 --http.port 18745 --http.api eth,net,web3 \
  --port 30599 --disable-discovery --ipcdisable \
  $(urethPinUnicityFlags) \
  >test-nodes/reth-wrongchain/reth.log 2>&1 &
echo $! >test-nodes/reth-wrongchain/pid
for _ in $(seq 1 60); do
  rpc http://127.0.0.1:18745 eth_chainId '[]' 2>/dev/null | grep -q result && break
  sleep 1
done
boundedRun 60 build/ubft shard-node run --home test-nodes/evm1 --executor engine-api --registry-layout "$(registry_layout)" \
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
stop_pidfile test-nodes/reth-wrongchain/pid 'reth.* node'   # ownership-checked; removes the pid file

# 3d. Same chain id, DIFFERENT genesis (#89 item 2). Chain id does not establish genesis identity:
# this client is on chainId 31337 exactly as configured, and differs only in its allocation, which
# is what a genesis generated for a different deployment looks like. The expected value is supplied
# by the operator, never read from the client under test.
mkdir -p test-nodes/reth-othergenesis
python3 - <<'PYGEN'
import json
g = json.load(open("test-nodes/evm-genesis-finalized-funded.json"))
# Same chainId, different allocation -> different genesis hash.
g["alloc"]["0x00000000000000000000000000000000000000aa"] = {"balance": "0x1"}
json.dump(g, open("test-nodes/other-genesis.json", "w"))
PYGEN
registry_layout_require || exit 1
"$URETH_BIN" node --chain test-nodes/other-genesis.json --datadir test-nodes/reth-othergenesis/dd \
  --authrpc.jwtsecret test-nodes/evm1/jwt.hex --authrpc.addr 127.0.0.1 --authrpc.port 18851 \
  --http --http.addr 127.0.0.1 --http.port 18845 --http.api eth,net,web3 \
  --port 30699 --disable-discovery --ipcdisable \
  $(urethPinUnicityFlags) \
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
  boundedRun 60 build/ubft shard-node run --home test-nodes/evm1 --executor engine-api --registry-layout "$(registry_layout)" \
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
  boundedRun 60 build/ubft shard-node run --home test-nodes/evm1 --executor engine-api --registry-layout "$(registry_layout)" \
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
stop_pidfile test-nodes/reth-othergenesis/pid 'reth.* node'   # ownership-checked; removes the pid file

# 3f. Same chain id, SAME genesis, a different FORK SCHEDULE (#89 item 2). The client below is started
# from exactly the funded spec the validators use, plus one field: Prague scheduled for a future
# timestamp. A fork that has not activated changes no genesis header field, so this client reports the
# configured chain id AND the configured genesis hash, and passes every identity check before this one.
# It would then require engine_newPayloadV4 once Prague activated. This Unicity client only supports
# the fixed Cancun EVM profile: EthConfigHandler asks its EVM for the future fork's precompiles,
# which refuses Prague. Thus eth_config returns a typed RPC error, and startup must fail closed on
# the unreadable execution profile. The loaded schedule is independently visible in the node log.
threeFFailuresBefore=$failures
mkdir -p test-nodes/reth-laterfork
python3 - <<'PYFORK'
import json
g = json.load(open("test-nodes/evm-genesis-finalized-funded.json"))
g["config"]["pragueTime"] = 4102444800  # 2100-01-01; far enough that it cannot activate during a run
json.dump(g, open("test-nodes/laterfork-genesis.json", "w"))
PYFORK
registry_layout_require || exit 1
"$URETH_BIN" node --chain test-nodes/laterfork-genesis.json --datadir test-nodes/reth-laterfork/dd \
  --authrpc.jwtsecret test-nodes/evm1/jwt.hex --authrpc.addr 127.0.0.1 --authrpc.port 18951 \
  --http --http.addr 127.0.0.1 --http.port 18945 --http.api eth,net,web3 \
  --port 30799 --disable-discovery --ipcdisable \
  $(urethPinUnicityFlags) \
  >test-nodes/reth-laterfork/reth.log 2>&1 &
echo $! >test-nodes/reth-laterfork/pid
for _ in $(seq 1 60); do
  rpc http://127.0.0.1:18945 eth_chainId '[]' 2>/dev/null | grep -q result && break
  sleep 1
done
configuredGenesis=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockByNumber '["0x0", false]' | pyget "['result']['hash']")
laterChainID=$(rpc http://127.0.0.1:18945 eth_chainId '[]' | pyget "['result']")
laterGenesis=$(rpc http://127.0.0.1:18945 eth_getBlockByNumber '["0x0", false]' | pyget "['result']['hash']")
laterConfig=$(rpc http://127.0.0.1:18945 eth_config '[]')
laterCode=$(echo "$laterConfig" | pyget "['error']['code']")
laterError=$(echo "$laterConfig" | pyget "['error']['message']")
okNext=$(rpc "http://127.0.0.1:$rethEthBase" eth_config '[]' | pyget "['result']['next']")
info "the later-fork client reports: chainId $laterChainID, genesis $laterGenesis, eth_config error $laterCode: ${laterError:-?}"
info "the configured client reports: genesis $configuredGenesis, next fork ${okNext:-?}"

# The premise, established before the refusal is asserted: same chain id, the SAME genesis as the
# configured client, and a fork actually loaded. Without it this case could pass because the client
# failed to start, or because the spec edit changed the genesis and the genesis check refused instead.
if [ -z "$laterGenesis" ] || [ -z "$configuredGenesis" ]; then
  fail "3f premise: could not read both genesis hashes (configured='$configuredGenesis' later-fork='$laterGenesis')"
elif [ "$laterGenesis" != "$configuredGenesis" ]; then
  fail "3f premise: the later-fork client's genesis $laterGenesis differs from $configuredGenesis, so the genesis check — not the profile — would refuse it"
elif [ "$laterChainID" != "0x7a69" ]; then
  fail "3f premise: the later-fork client reports chainId $laterChainID, not 0x7a69"
elif ! grep -qE 'Prague[[:space:]]+@4102444800' test-nodes/reth-laterfork/reth.log; then
  fail "3f premise: the later-fork client did not log Prague at timestamp 4102444800 as loaded"
elif [ "$laterCode" != "-32603" ] || [ "$laterError" != "only the fixed Cancun profile is supported" ]; then
  fail "3f premise: later-fork eth_config did not refuse unsupported Prague as fixed-Cancun (code='$laterCode' message='$laterError')"
elif [ "$okNext" != "None" ]; then
  fail "3f premise: the configured client's eth_config reports a scheduled fork ('$okNext'), so the positive path would be refused too"
else
  info "premise holds: identical chain id and genesis, Prague loaded at 4102444800, eth_config refuses unsupported Prague"
  boundedRun 60 build/ubft shard-node run --home test-nodes/evm1 --executor engine-api --registry-layout "$(registry_layout)" \
    --address /ip4/127.0.0.1/tcp/28004 --trust-base test-nodes/trust-base.json \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --engine-url http://127.0.0.1:18951 --eth-url http://127.0.0.1:18945 \
    --expected-genesis-hash "$configuredGenesis" \
    --jwt-secret test-nodes/evm1/jwt.hex --log-format text --log-level info
  forkOut=$boundedOut; forkStatus=$boundedStatus
  forkMsg="only the fixed Cancun profile is supported"
  if [ "$forkStatus" -ne 0 ] && [ "$forkStatus" -ne 124 ] &&
     echo "$forkOut" | grep -q -- 'startup execution-profile check' && echo "$forkOut" | grep -q -- 'reading eth_config (EIP-7910)' && echo "$forkOut" | grep -qF -- "$forkMsg" &&
     ! echo "$forkOut" | grep -q -- 'startup genesis check'; then
    pass "shard-node run refused a same-chainId/same-genesis client with unsupported Prague loaded (exit $forkStatus), before voting"
  elif [ "$forkStatus" -eq 124 ]; then
    fail "unsupported Prague was NOT refused: startup ran past its budget"
  else
    fail "unsupported Prague was NOT refused with the expected diagnostic (exit $forkStatus); wanted '$forkMsg'"
    echo "--- captured output ---"; echo "$forkOut" | tail -15; echo "--- end ---"
  fi

  # doctor calls the same Adapter.CheckExecutionProfile.
  forkDoctor=$(build/ubft shard-node doctor --home test-nodes/evm1 --executor engine-api \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --engine-url http://127.0.0.1:18951 --eth-url http://127.0.0.1:18945 \
    --jwt-secret test-nodes/evm1/jwt.hex 2>&1)
  forkDoctorStatus=$?
  if [ "$forkDoctorStatus" -ne 0 ] && echo "$forkDoctor" | grep -qE '^\[FAIL\] execution profile' &&
     echo "$forkDoctor" | grep -q -- 'reading eth_config (EIP-7910)' && echo "$forkDoctor" | grep -qF -- "$forkMsg" && echo "$forkDoctor" | grep -qE '^\[PASS\] genesis hash'; then
    pass "doctor rejected unsupported Prague at its execution-profile check, having passed its genesis check"
  else
    fail "doctor did not reject the later fork as expected (exit $forkDoctorStatus)"
    echo "--- captured output ---"; echo "$forkDoctor" | tail -15; echo "--- end ---"
  fi

  # Positive control for doctor's profile check on a configured client.
  okProfile=$(build/ubft shard-node doctor --home test-nodes/evm1 --executor engine-api \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --engine-url "http://127.0.0.1:$rethEngineBase" --eth-url "http://127.0.0.1:$rethEthBase" \
    --jwt-secret test-nodes/evm1/jwt.hex 2>&1)
  if echo "$okProfile" | grep -qE '^\[PASS\] execution profile[[:space:]]+Cancun at genesis, nothing scheduled after'; then
    pass "doctor passed the execution-profile check on a configured client: $(echo "$okProfile" | grep -o 'forkId=[0-9a-fx]*')"
  else
    fail "doctor did not pass the execution-profile check on a configured client"
    echo "--- captured output ---"; echo "$okProfile" | grep -i profile; echo "--- end ---"
  fi
fi
stop_pidfile test-nodes/reth-laterfork/pid 'reth.* node'   # ownership-checked; removes the pid file
threeFFailureCount=$((failures - threeFFailuresBefore))
if [ "$threeFFailureCount" -eq 0 ]; then
  echo "3f status: PASS"
else
  echo "3f status: FAIL ($threeFFailureCount check(s) failed)"
fi
fi

echo
fi
echo "=== 4. configure the checked v2 origin and seed the block-1 transaction ==="
# The root chain must certify the FULL shard configuration emitted beside the finalized genesis.
# Registration happens when start-evm.sh starts the root nodes, so replace the generated base conf
# only now, after the startup negatives above have used it.
cp "$fullShardConf" "test-nodes/shard-conf-${partitionID}_0.json"
if [ "${F8_MIXED_LANE:-0}" = 1 ]; then f8_prepare; fi
# Both the standalone H4 probe and the M2a final lane need persistent archive
# publication before they stop validator 1; M2a restores it after Handoff 2.
if [ "${H3_ASSIGNMENT_LANE:-0}" = 1 ]; then
  export EVM_ARCHIVE_ROOT=test-nodes/h3-archives
  mkdir -p "$EVM_ARCHIVE_ROOT"
elif [ "${H4_RESTORE_PROBE:-0}" = 1 ] || [ "${M2A_FINAL_RESTORE:-0}" = 1 ]; then
  export EVM_ARCHIVE_ROOT=test-nodes/h4-archives
  mkdir -p "$EVM_ARCHIVE_ROOT"
elif [ "$postM2aMode" = f7 ]; then
  export EVM_ARCHIVE_ROOT=test-nodes/post-m2a-archives
  mkdir -p "$EVM_ARCHIVE_ROOT"
fi
export EVM_GENESIS_FILE="$chainSpec"
if [ "${H3_ASSIGNMENT_LANE:-0}" = 1 ]; then export EVM_REGISTRY_LAYOUT=2; fi
export EVM_FULL_SHARD_CONF="test-nodes/shard-conf-${partitionID}_0.json"
export EVM_ENGINE_FEE_COLLECTOR="${POST_M2A_FEE_COLLECTOR:-$URETH_PIN_FEE_COLLECTOR}"
if [ -n "$postM2aMode" ]; then export EVM_OPERATOR_STATUS_RPC=1; fi
export M2_CHAIN_ID="$postM2aChainID"
if [ -n "${D2C_FAULT_SCENARIO:-}" ]; then
  export EVM_EXECUTION_JOURNAL_ROOT="test-nodes/execution-journals"
  mkdir -p "$EVM_EXECUTION_JOURNAL_ROOT"
fi
source helper.sh
for i in $(seq 1 "$validators"); do
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))"
  export "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
done
if [ "${D2C_FAULT_SCENARIO:-}" = proof-outage ] || [ "${D2C_FAULT_SCENARIO:-}" = proof-corrupt ]; then
  export EVM_ETH_URL_1=http://127.0.0.1:18645
fi
if [ "${D2C_FAULT_SCENARIO:-}" = hostile-builder ] || [ "${D2C_FAULT_SCENARIO:-}" = hostile-fee-recipient ]; then
  export EVM_ENGINE_URL_1="http://127.0.0.1:$engineProxyPort"
fi

# Every validator may lead. P2P transaction propagation is disabled in M1, so seed the same
# three paid nonce-ordered transactions into each local mempool before shard voting starts.
txHash=""
txHashes=""
for nonce in 0 1 2; do
  expected=""
  for i in $(seq 1 "$validators"); do
    sent=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase + i - 1))" \
      -chain-id "$postM2aChainID" -nonce "$nonce" 2>&1)
    if [[ "$sent" != 0x* ]]; then
      fail "could not seed validator $i's mempool at nonce $nonce: $sent"
      exit 1
    fi
    if [ -n "$expected" ] && [ "$sent" != "$expected" ]; then
      fail "validators received different signed transaction hashes at nonce $nonce: $expected / $sent"
      exit 1
    fi
    expected=$sent
  done
  [ "$nonce" = 0 ] && txHash=$expected
  txHashes+="$expected\n"
  echo "  paid nonce $nonce hash=$expected seeded on all $validators reth clients"
done
if [ "${M1_FEE_ACCOUNTING:-0}" = 1 ]; then
  printf '%b' "$txHashes" >test-nodes/m1-fee-tx-hashes.txt
fi
pass "seeded three paid user transactions in every reth mempool before block 1"

echo
echo "=== 5. the v2 bootstrap certifies a real EVM block 1 ==="
preflightFailures=$failures
./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1

echo "waiting for block 1 and a certificate (up to 180s) ..."
mined=false
certified=false
for attempt in $(seq 1 90); do
  rcpt=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionReceipt "[\"$txHash\"]")
  blkNum=$(echo "$rcpt" | pyget "['result']['blockNumber']" || true)
  if [ -n "$blkNum" ] && [ "$blkNum" != "None" ]; then mined=true; fi
  blkHash=$(echo "$rcpt" | pyget "['result']['blockHash']" || true)
  if [ -n "$blkHash" ] && [ "$blkHash" != "None" ]; then
    blkHash=${blkHash#0x}
    if grep -Eq 'msg="certificate admitted".* block='"$blkHash"' height=1 round=[0-9]+ rootRound=[0-9]+' \
      test-nodes/evm1/debug.log 2>/dev/null; then certified=true; fi
  fi
  echo "  bootstrap probe $attempt: mined=$mined certified=$certified block=${blkNum:-none}"
  $mined && $certified && break
  sleep 2
done
if $mined && $certified; then
  status=$(echo "$rcpt" | pyget "['result']['status']")
  blkDec=$(python3 -c "print(int('$blkNum', 16))")
  if [ "$blkDec" = "1" ] && [ "$status" = "0x1" ]; then
    pass "real reth executed $txHash in certified v2 block 1"
  else
    fail "transaction receipt did not confirm successful block 1: block=$blkDec status=$status"
  fi
else
  fail "v2 bootstrap did not produce a certified transaction block within 180s (mined=$mined certified=$certified)"
  echo "--- evm1 tail ---"; tail -25 test-nodes/evm1/debug.log 2>/dev/null
  echo "--- reth1 tail ---"; tail -15 test-nodes/reth1/reth.log 2>/dev/null
fi
if [ "${H4_RESTORE_PROBE:-0}" = 1 ]; then
  for i in $(seq 1 "$validators"); do
    ready=false
    for _ in $(seq 1 30); do
      head=$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_blockNumber '[]' | pyget "['result']")
      if [ -n "$head" ] && [ "$head" != None ] && [ "$((head))" -ge 1 ]; then
        ready=true
        break
      fi
      sleep 1
    done
    if ! $ready; then
      fail "H4 requires every validator to have certified B1 before selecting a replacement; validator $i stayed at genesis"
      exit 1
    fi
  done
  pass "all four validators imported the certified bootstrap block before H4"
fi

if [ -n "$postM2aMode" ]; then
  post_m2a_after_bootstrap || { fail "post-M2a transaction evidence failed"; exit 1; }
fi
if [ "${FAUCET_PROBE:-0}" = 1 ]; then
  python3 deploy/testnet/faucet/devnet_probe.py || { fail "faucet acceptance probe failed"; exit 1; }
  pass "faucet fresh wallet, paid transfer, limits and identity checks"
  echo "FAUCET probe complete; stopping paired nodes before unrelated handoff/continuous-execution probes"
  exit "$failures"
fi

# Wait until the bootstrap partition certificate is committed before joining the three
# independent aggregator shards. Their handshakes ask roots for partition state, so starting
# them before block 1 is certified creates a needless unknown-partition retry loop.
if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
  if ! $mined || ! $certified; then
    fail "cannot start mixed aggregators without the certified EVM bootstrap"
    exit 1
  fi
  f8_start || { fail "mixed aggregator startup failed"; exit 1; }
  for _ in $(seq 1 90); do
    if f8_trace >/dev/null 2>&1; then break; fi
    sleep 1
  done
  f8_trace >/dev/null || { fail "not all mixed shards entered certified root state"; exit 1; }
  pass "three aggregator shards certified alongside the EVM partition; UC/TR/EVM trace recorded"
fi

if [ "${M2_PROFILE2:-0}" = 1 ] && [ "${POST_M2A_SKIP_HANDOFF:-0}" != 1 ]; then
  echo "=== M2 profile-2: two certified root handoffs with paid execution ==="
  if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
    f8_slow_stop_resume_evm || { fail "EVM delay/stop/resume probe failed"; exit 1; }
    f8_reconnect_probe || { fail "non-default aggregator shard reconnect failed"; exit 1; }
    f8_inflight_evm_probe || { fail "EVM proposal did not certify during root leader rotation"; exit 1; }
    pass "aggregators continued through delayed/stopped EVM; reconnect and in-flight EVM proposal passed"
  fi
  handoffScript=scripts/m2-profile2-handoffs.sh
  if [ "${H3_ASSIGNMENT_LANE:-0}" = 1 ]; then handoffScript=scripts/h3-assignment-steps.sh; fi
  if [ "${Q4_LIVE_LANE:-0}" = 1 ]; then handoffScript=scripts/q4-live-steps.sh; fi
  if ! source "$handoffScript"; then
    fail "profile-2 two-handoff lane failed"
    exit 1
  fi
  if [ "${Q4_LIVE_LANE:-0}" = 1 ]; then
    # The Q4 lane asserts its own stalls and recoveries; a stopped or killed root would trip the D1 monitor below.
    echo "Q4 lane failures: $failures"
    [ "$failures" -eq 0 ] && exit 0 || exit 1
  fi
  if [ "${H3_ASSIGNMENT_LANE:-0}" = 1 ]; then
    # The H3 lane makes its own agreement checks; the D1 monitor below assumes every validator stays live.
    echo "H3 lane failures: $failures"
    [ "$failures" -eq 0 ] && exit 0 || exit 1
  fi
  if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
    f8_trace || { fail "aggregator shards lost root coverage after handoff"; exit 1; }
    pass "one root handoff replaced validator keys and certified paid transactions"
    pass "all three aggregator shards remained live through the root handoff"
  else
    pass "two profile-2 handoffs replaced validator keys and certified paid transactions"
  fi
elif [ "${M2_PROFILE2:-0}" = 1 ] && [ "${POST_M2A_SKIP_HANDOFF:-0}" = 1 ]; then
  pass "T4 audit lane skipped the optional profile-2 root handoffs"
fi

echo
echo "=== 6. D1 continuous certified execution through block $rounds ==="
echo "timing: witness attempt=400ms episode=500ms, T2=5000ms, proof window=64 blocks"
probeArgs=()
faultArgs=()
traceArgs=()
if [ "$postM2aMode" = t4 ]; then
  traceArgs=(--capture-t4-traces test-nodes/post-m2a-evidence/t4-traces --trace-rpc-base "$rethEthBase")
fi
if [ "${D2C_RESTART_PROBE:-0}" = 1 ]; then
  [ "$validators" -eq 4 ] && [ "$rounds" -ge 10 ] || { echo "D2C probe requires four validators and >=10 blocks" >&2; exit 2; }
  probeArgs=(--restart-validator 1 --signing "${SIGNING:-local}")
fi
if [ "${H4_RESTORE_PROBE:-0}" = 1 ]; then
  probeArgs=(--h4-restore-validator 1 --signing authority)
fi
if [ "${M2A_FINAL_RESTORE:-0}" = 1 ]; then
  probeArgs=(--already-restored-validator 1)
fi
if [ -n "${D2C_FAULT_SCENARIO:-}" ]; then
  [ "$validators" -eq 4 ] && [ "$rounds" -ge 10 ] || { echo "D2C fault scenarios require four validators and >=10 blocks" >&2; exit 2; }
  faultArgs=(--fault-scenario "$D2C_FAULT_SCENARIO")
fi
d2cRecoveryProbe=${D2C_RESTART_PROBE:-0}
[ -n "${D2C_FAULT_SCENARIO:-}" ] && d2cRecoveryProbe=1
d1Timeout=900
if [ "$rounds" -gt 100 ]; then d1Timeout=6000; fi
if [ -n "${D1_MONITOR_TIMEOUT:-}" ]; then d1Timeout=$D1_MONITOR_TIMEOUT; fi
if python3 scripts/d1-monitor.py --nodes test-nodes --validators "$validators" --blocks "$rounds" --timeout "$d1Timeout" \
  ${traceArgs[@]+"${traceArgs[@]}"} ${probeArgs[@]+"${probeArgs[@]}"} ${faultArgs[@]+"${faultArgs[@]}"}; then
  pass "D1 observed $rounds consecutive blocks with a fresh canonical survivor quorum"
else
  fail "D1 continuous block observation failed"
  for i in $(seq 1 "$validators"); do
    echo "--- evm$i at stall ---"; tail -40 "test-nodes/evm$i/debug.log" 2>/dev/null
    echo "--- reth$i at stall ---"; tail -40 "test-nodes/reth$i/reth.log" 2>/dev/null
  done
fi

divergenceLogged=false
for i in $(seq 1 "$validators"); do
  log="test-nodes/evm$i/debug.log"
  if ! python3 - "$log" "$i" "$d2cRecoveryProbe" "${D2C_FAULT_SCENARIO:-}" <<'PYDIVERGENCE'
import json, re, sys
from pathlib import Path

path, validator, probe, scenario = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1", sys.argv[4]
expected_fee_recipient = None
if scenario == "hostile-fee-recipient":
    try:
        expected_fee_recipient = json.loads(Path("test-nodes/d2c-hostile-fee-recipient-expected-invalid.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"expected fee-recipient INVALID marker missing or malformed: {exc}")
        raise SystemExit(1)
expected_fee_recipient_lines = 0
try:
    lines = Path(path).read_text(errors="replace").splitlines()
except OSError as exc:
    print(f"missing validator log {path}: {exc}")
    raise SystemExit(1)

warning = "executor head diverges from certified state — attempting recovery via Commit before giving up"
recovered = "recovered: executor held the certified block, now committed"
boundaries = [n for n, line in enumerate(lines) if "D2C_RESTART_BOUNDARY" in line]
warnings = [n for n, line in enumerate(lines) if warning in line]
for line_no, line in enumerate(lines):
    if re.search(r"diverge|equivocat|impossible certificate ordering", line, re.I) and warning not in line:
        expected = expected_fee_recipient
        round_match = re.search(r"engineapi: round (\d+) suggestedFeeRecipient diverges: got ([0-9a-f]+), want ([0-9a-f]+)", line)
        if (expected and 'msg="rejecting round before execution: attributes diverge from local derivation"' in line
                and ('status=INVALID' in line or 'status="INVALID"' in line) and round_match
                and int(round_match.group(1)) == expected["round"]
                and round_match.group(2) == expected["got"] and round_match.group(3) == expected["want"]):
            expected_fee_recipient_lines += 1
            continue
        print(f"unexpected divergence/equivocation at {path}:{line_no + 1}: {line}")
        raise SystemExit(1)

if expected_fee_recipient and expected_fee_recipient_lines == 0:
    print(f"validator {validator} lacks the armed fee-recipient INVALID diagnostic")
    raise SystemExit(1)
if expected_fee_recipient_lines:
    print(f"validator {validator} logged {expected_fee_recipient_lines} expected fee-recipient INVALID diagnostic(s)")

if warnings and probe and not boundaries:
    print(f"recovery warning is only allowed after this validator's D2C_RESTART_BOUNDARY ({path})")
    raise SystemExit(1)

if warnings and not probe:
    print(f"recovery warning is forbidden outside restart-probe mode ({path})")
    raise SystemExit(1)

for index, warning_line in enumerate(warnings):
    boundary_after = next((n for n in boundaries if n > warning_line), len(lines))
    if probe and (not boundaries or warning_line < boundaries[0]):
        print(f"recovery warning before this validator's restart boundary at {path}:{warning_line + 1}")
        raise SystemExit(1)
    warning_hash = re.search(r"(?:^|\s)recoveryBlockHash=([^\s]+)", lines[warning_line])
    if not warning_hash:
        print(f"recovery warning lacks recoveryBlockHash at {path}:{warning_line + 1}")
        raise SystemExit(1)
    end = min(boundary_after, warnings[index + 1] if index + 1 < len(warnings) else len(lines))
    match = next((n for n in range(warning_line + 1, end)
                  if recovered in lines[n]
                  and re.search(r"(?:^|\s)blockHash=" + re.escape(warning_hash.group(1)) + r"(?:\s|$)", lines[n])), None)
    if match is None:
        print(f"no recovery for block {warning_hash.group(1)} before next warning/process boundary in {path}")
        raise SystemExit(1)

if warnings:
    print(f"validator {validator} recovered {len(warnings)} matching certified block(s)")
PYDIVERGENCE
  then
    fail "validator $i logged unresolved divergence/equivocation or has no log"
    divergenceLogged=true
  fi
done
if ! $divergenceLogged; then
  if [ "${D2C_FAULT_SCENARIO:-}" = hostile-fee-recipient ]; then
    pass "no unexpected divergence or equivocation; each validator logged the armed fee-recipient INVALID refusal"
  else
    pass "no validator logged divergence or equivocation"
  fi
fi

if [ -n "$postM2aMode" ]; then
  if [ "$failures" -eq 0 ]; then
    if ! post_m2a_after_lane; then
      if [ "$postM2aMode" = t4 ]; then
        fail "post-M2a T4 audit evidence failed"
      else
        fail "post-M2a post-handoff/prune evidence failed"
      fi
    fi
  else
    fail "post-M2a evidence collection skipped because an earlier lane check failed"
  fi
fi

# T6 rehearsal: one key-replacing coupled rotation after every existing T6 check (kept green by construction: they all ran before it).
if [ "$postM2aMode" = t6 ] && [ "${T6_COUPLED_ROTATION:-0}" = 1 ]; then
  echo
  echo "=== T6: coupled key-replacing rotation s=1 (evm4 retires, evm5 joins) ==="
  if [ "$failures" -eq 0 ]; then
    source scripts/t6/coupled-rotation.sh
    if t6_coupled_rotation_s1; then
      pass "T6 coupled rotation s=1: authority-backed PoPs, handoff, acknowledgement (registry shard epoch 1), and a paid mint under the new set verified offline"
    else
      fail "T6 coupled rotation s=1 failed"
    fi
    t6_rotation_teardown
  else
    fail "T6 coupled rotation skipped because an earlier lane check failed"
  fi
fi

if [ "$failures" -gt "$preflightFailures" ]; then
  echo "D1 FAIL ($((failures - preflightFailures)) lane check(s) failed)"
else
  echo "D1 PASS"
fi
if [ "${M1_FEE_ACCOUNTING:-0}" = 1 ]; then
  echo
  echo "=== 7. audit paid receipt accounting, then reach and hold the fee floor across a reth restart ==="
  if [ "$failures" -eq 0 ]; then
    python3 scripts/m1-fee-accounting.py before-restart --nodes test-nodes \
      --tx-hashes test-nodes/m1-fee-tx-hashes.txt --floor 1000000 --restart-height "$rounds" || \
      fail "paid transaction fee accounting or pre-restart floor check failed"
  fi
  if [ "$failures" -eq 0 ]; then
    feeRestartHeight=$(cat test-nodes/m1-fee-pre-restart-head.txt)
    echo "restarting only reth1 at the certified idle head B$feeRestartHeight"
    feeOldRethPid=$(cat test-nodes/reth1/pid)
    stop_pidfile "test-nodes/reth1/pid" 'reth.* node' TERM || fail "could not stop reth1 for fee-floor restart"
    for _ in $(seq 1 200); do
      feeOldRethState=$(ps -o stat= -p "$feeOldRethPid" 2>/dev/null | tr -d ' ')
      [ -z "$feeOldRethState" ] || [[ "$feeOldRethState" == Z* ]] && break
      sleep 0.1
    done
    feeOldRethState=$(ps -o stat= -p "$feeOldRethPid" 2>/dev/null | tr -d ' ')
    if [ -n "$feeOldRethState" ] && [[ "$feeOldRethState" != Z* ]]; then
      fail "reth1 process $feeOldRethPid did not exit before fee-floor restart"
    fi
    if [ "$failures" -eq 0 ]; then
      registry_layout_require || exit 1
      "$URETH_BIN" node --chain "$chainSpec" --datadir test-nodes/reth1/dd \
        --authrpc.jwtsecret test-nodes/evm1/jwt.hex \
        --authrpc.addr 127.0.0.1 --authrpc.port "$rethEngineBase" \
        --http --http.addr 127.0.0.1 --http.port "$rethEthBase" \
        --http.api eth,net,web3,admin,debug --rpc.eth-proof-window 64 \
        --port "$rethP2PBase" --disable-discovery --ipcdisable \
        --engine.persistence-threshold "$d2cPersistenceThreshold" --builder.gaslimit 30000000 \
        $(urethPinUnicityFlags) >test-nodes/reth1/reth-restart.log 2>&1 &
      echo $! >test-nodes/reth1/pid
      python3 scripts/m1-fee-accounting.py after-restart --nodes test-nodes \
        --floor 1000000 --restart-height "$feeRestartHeight" --further-heights 3 --timeout 120 || \
        fail "base-fee floor was not held across the reth restart"
    fi
  fi
fi
[ "$failures" -eq 0 ]
