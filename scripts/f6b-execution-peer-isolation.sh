#!/bin/bash
# f6b-execution-peer-isolation.sh - the acquisition experiment §8 of the design has been asking for.
#
# THE QUESTION. Both accepted lanes end at the same open point. A node returns, verifies an
# execution anchor from authenticated BFT evidence, commits it, and its reth reaches the certified
# block. What the logs cannot say is WHERE THE BLOCK BODY CAME FROM: reth reported
# `Received forkchoice updated message when syncing` and canonicalised the missed blocks about 40 ms
# later, which does not distinguish "it fetched them from its execution peers on the forkchoice
# update" from "it already held them from gossip during the outage and merely made them canonical".
# Forty milliseconds is not a trace of a mechanism, and no inference was drawn from it.
#
# THE EXPERIMENT, which is that measurement and not a demonstration. The returning client's
# EXECUTION-layer peering is severed before the blocks it will miss are created, and the run then has
# two arms across that one variable:
#
#   ISOLATED    execution peers disconnected, BFT transport untouched. The node must still OBTAIN
#               AND VERIFY the anchor from its BFT peers — that path has nothing to do with devp2p —
#               and must then FAIL CLOSED: report the payload unavailable, keep the verified target,
#               retry, adopt nothing, move nothing, sign nothing. This arm is what makes the second
#               one mean anything: it establishes that the block was NOT already in the client.
#   RECONNECTED execution peers restored, and NOT ONE TRANSACTION submitted. Whether the standard
#               Engine API and client sync then obtain the blocks is the result.
#
# A NEGATIVE RESULT IS A RESULT. If the reconnected client does not obtain the blocks either, that is
# evidence about the existing mechanism's limits and this lane reports it as such. What it must never
# do is report either answer without having established the premise, so isolation is READ from both
# ends and re-read for the whole window rather than inferred from an admin call returning true.
#
# Usage:  ./scripts/f6b-execution-peer-isolation.sh [validators]   # default 3
#         ./scripts/f6b-execution-peer-isolation.sh --self-test    # no reth, no root chain
# Needs:  a pinned reth, curl, openssl, python3, go, and a built ./build/ubft. Run from the repo root.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

selfTest=false
if [ "${1:-}" = "--self-test" ]; then selfTest=true; shift; fi

validators=${1:-3}
partitionID=8
chainID=31337
pinnedRethCommit=189c0df32617afc488e0f091dbface1bd72cceb4
rethEngineBase=18551
rethEthBase=18545
rethP2PBase=30401
rootBootPort=26662

failures=0
reached="startup"

source "$(dirname "${BASH_SOURCE[0]}")/lib/f6b-acceptance-lib.sh"

artifactDir="${F6B_ARTIFACT_DIR:-artifacts/f6b-peer-isolation/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
manifestTitle="f6b execution-peer isolation: payload acquisition experiment"
manifestLogs="test-nodes/connectivity.log test-nodes/peermon.log test-nodes/evm1/isolated.log $(seq -f "test-nodes/evm%g/debug.log" 1 "$validators" | tr '\n' ' ')$(seq -f " test-nodes/reth%g/reth.log" 1 "$validators" | tr -d '\n')"
manifestLines=()

$selfTest && { f6bSelfTest; exit $?; }

command -v reth >/dev/null || { echo "no reth binary on PATH - this lane has no fake fallback" >&2; exit 1; }
rethCommit=$(reth --version | sed -n 's/^Commit SHA: //p')
if [ "$rethCommit" != "$pinnedRethCommit" ]; then
  echo "FAIL: reth is $rethCommit, pinned baseline is $pinnedRethCommit" >&2
  echo "      Set F6B_ALLOW_UNPINNED_RETH=1 to run anyway; output is then NOT baseline evidence." >&2
  [ "${F6B_ALLOW_UNPINNED_RETH:-0}" = "1" ] || exit 1
fi
[ -x build/ubft ] || { echo "build/ubft missing - run 'make build' first" >&2; exit 1; }

# Nothing may already be listening on the ports this run needs. A previous run's clients would
# answer every probe while this run's own clients failed to bind, and the result would describe a
# devnet this run did not create. See refuseStaleListeners.
refuseStaleListeners $(seq -s" " "$rethEngineBase" $((rethEngineBase + validators - 1))) $(seq -s" " "$rethEthBase" $((rethEthBase + validators - 1))) || exit 1

stale=$(pgrep -f 'ubft shard-node run' 2>/dev/null || true)
if [ -n "$stale" ]; then
  echo "refusing to start: shard-node processes are already running (pids: $(echo $stale | tr '\n' ' '))" >&2
  echo "  pkill -f 'ubft shard-node run'" >&2
  exit 1
fi

cleanup() {
  stopPeerMonitor
  if ! writeManifest; then
    failures=$((failures + 1))
    echo "$failures CHECK(S) FAILED — no run artifact was written" >&2
    trap - EXIT
    ./stop-evm.sh -a >/dev/null 2>&1 || true
    pkill -f 'ubft shard-node run' 2>/dev/null
    for i in $(seq 1 "$validators"); do
      [ -f "test-nodes/reth$i/pid" ] && kill "$(cat "test-nodes/reth$i/pid")" 2>/dev/null
    done
    exit 1
  fi
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

# --- the connectivity record ---------------------------------------------------------------------
#
# Every phase boundary and every connectivity reading is appended here with a UTC timestamp, and the
# file is preserved and hashed in the run artifact. The brief for this experiment asks for actual
# peer connectivity rather than the assertion that it was arranged, so the readings are kept whether
# or not any assertion consulted them.
connLog=test-nodes/connectivity.log
note() { # note <text>
  mkdir -p test-nodes
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1" >>"$connLog"
}
snapshot() { # snapshot <label>
  local i n ids
  mkdir -p test-nodes
  for i in $(seq 1 "$validators"); do
    n=$(peerCount "http://127.0.0.1:$((rethEthBase + i - 1))" 2>/dev/null) || n="unreadable"
    ids=$(peerIds "http://127.0.0.1:$((rethEthBase + i - 1))" 2>/dev/null | cut -c1-16 | tr '\n' ',' )
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1 reth$i peers=$n sessions=${ids:-none}" >>"$connLog"
  done
}

sendTx() { # sendTx <ethURL> <nonce>
  local out
  out=$(go run ./scripts/evmtx -send -eth-url "$1" -chain-id "$chainID" -nonce "$2" 2>&1) || {
    echo "evmtx failed for nonce $2: $out" >&2; return 1; }
  isHash32 "$out" || { echo "evmtx returned no transaction hash for nonce $2: $out" >&2; return 1; }
  printf '%s' "$out"
}

waitForReceipt() { # waitForReceipt <ethURL> <txHash> <seconds>
  local url=$1 tx=$2 secs=$3 n
  for _ in $(seq 1 "$secs"); do
    n=$(rpc "$url" eth_getTransactionReceipt "[\"$tx\"]" | pyget "['result']['blockNumber']")
    if isQuantity "${n:-}"; then printf '%s' "$n"; return 0; fi
    sleep 2
  done
  echo "transaction $tx was never executed within $((secs * 2))s" >&2
  return 1
}

dec() { python3 -c "print(int('$1', 16))" 2>/dev/null; }

reached="section 1: a funded chain with a real block"
echo "=== 1. a funded chain, one real block, every executor on it ==="
rm -rf test-nodes
./setup-evm-nodes.sh -r 3 -v "$validators" >/dev/null || { echo "setup failed" >&2; exit 1; }
python3 - <<'PY' || { echo "could not fund the test genesis" >&2; exit 1; }
import json, subprocess
g = json.load(open("test-nodes/evm-genesis.json"))
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
json.dump(g, open("test-nodes/evm-genesis-funded.json", "w"), indent=2)
PY
chainSpec=test-nodes/evm-genesis-funded.json
note "run start, chain spec $(shasum -a 256 "$chainSpec" | cut -d' ' -f1)"

for i in $(seq 1 "$validators"); do
  mkdir -p "test-nodes/reth$i"
  openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  # --no-persist-peers matters here and nowhere else in this repository: a client that reloads its
  # peer file re-dials the very sessions this experiment severs, and the isolation would then be a
  # property of how fast the next phase ran. reth1 additionally logs its network and download
  # activity, because "where did the block come from" is the question and the default filter answers
  # it with two INFO lines.
  extra=(--no-persist-peers)
  # Plain `debug`, not a target list: reth's per-target directives are only as good as the target
  # names, and a filter naming targets that do not exist produces a log with nothing in it and no
  # error — a run whose network trace is empty for the same reason a passing assertion can be
  # vacuous. `debug` cannot be wrong about a name.
  [ "$i" = "1" ] && extra+=(--log.stdout.filter debug)
  reth node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) \
    --http.api eth,net,web3,admin,txpool \
    --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    "${extra[@]}" \
    >"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
done

for i in $(seq 1 "$validators"); do
  up=false
  for _ in $(seq 1 60); do
    rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_chainId '[]' 2>/dev/null | grep -q result && { up=true; break; }
    sleep 1
  done
  $up || { fail "reth $i did not start"; exit 1; }
done

# Enodes are recorded now, before anything is severed: the subject's own id is what the survivors
# list it as, and the survivors' enodes are what reconnects it later.
declare -a enodes
for i in $(seq 1 "$validators"); do
  enodes[$i]=$(rpcRequire "http://127.0.0.1:$((rethEthBase + i - 1))" admin_nodeInfo '[]' "['result']['enode']" "enode") \
    || { fail "could not read reth $i's enode"; exit 1; }
done
# The id the SURVIVORS list it as, not the enode public key: see nodeAdminID.
subjectID=$(nodeAdminID "http://127.0.0.1:$rethEthBase") || { fail "could not read the subject's admin node id"; exit 1; }
survivorEth=()
for i in $(seq 2 "$validators"); do survivorEth+=("http://127.0.0.1:$((rethEthBase + i - 1))"); done

# ADD, THEN RE-ADD UNTIL IT TAKES. `admin_addPeer` against a client whose listener is not yet
# accepting returns true and does nothing, and with discovery disabled and no persisted peers there
# is no second attempt from anywhere else — which is how a run that waited a full minute found the
# subject holding one peer instead of two. The mesh is asserted, so it is also retried.
mesh() {
  local i j
  for i in $(seq 1 "$validators"); do
    for j in $(seq 1 "$validators"); do
      [ "$i" = "$j" ] && continue
      rpc "http://127.0.0.1:$((rethEthBase + j - 1))" admin_addPeer "[\"${enodes[$i]}\"]" >/dev/null 2>&1
    done
  done
}
# EVERY node must reach the full mesh, not just the subject. A first version broke out of this loop
# as soon as the SUBJECT had its peers, and the run it produced had the survivors connected only to
# the subject and not to each other — so severing the subject's peering severed the whole network,
# and the reconnect restored more than one variable. The check is over all of them.
meshed=false
for _ in $(seq 1 20); do
  mesh
  sleep 3
  meshed=true
  for i in $(seq 1 "$validators"); do
    n=$(peerCount "http://127.0.0.1:$((rethEthBase + i - 1))" 2>/dev/null) || n=0
    [ "$n" -ge $((validators - 1)) ] || meshed=false
  done
  $meshed && break
done
if $meshed; then
  pass "every executor is fully peered at the execution layer ($((validators - 1)) peers each) — the isolation below is targeted, not a network outage"
else
  fail "the execution mesh never formed: $(for i in $(seq 1 "$validators"); do printf "reth%s=%s " "$i" "$(peerCount "http://127.0.0.1:$((rethEthBase + i - 1))" 2>/dev/null || echo unreadable)"; done)"
  snapshot "phase=peering-failed"
  exit 1
fi
# AND THE IDENTITY THE ISOLATION CHECK USES IS ONE THAT CAN MATCH. Proved here, while the subject is
# still peered: it must appear by this exact id in a survivor's list. An identity that never matches
# anything is indistinguishable from an isolation that holds, and the earlier revision compared a
# 128-character enode key against 64-character admin ids — so that half of the check was inert while
# reading as PASS.
seen=false
for u in "${survivorEth[@]}"; do
  peerIds "$u" 2>/dev/null | grep -qx "$subjectID" && { seen=true; break; }
done
if $seen; then
  pass "a survivor lists the subject by the exact id the isolation check looks for (${subjectID:0:16}…, 32 bytes) — the comparison is one that can match"
else
  fail "no survivor lists the subject as $subjectID while it is peered, so the isolation check has no identity it could ever match"
  exit 1
fi
snapshot "phase=peered-at-start"

genesisBlock=$(blockAt "http://127.0.0.1:$rethEthBase" 0x0) || { fail "could not read the subject's genesis block"; exit 1; }
genesisHash=$(echo "$genesisBlock" | cut -d' ' -f2)

for i in $(seq 1 "$validators"); do
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))"
  export "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
done
./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1 || {
  fail "devnet did not start"; tail -20 test-nodes/start-evm.log >&2; exit 1; }
waitFor test-nodes/evm1/debug.log "accepted certificate" 3 120 || { fail "the shard never certified 3 rounds"; exit 1; }

setupTxs=0
tx0=$(sendTx "http://127.0.0.1:$rethEthBase" 0) || { fail "could not submit the first setup transaction"; exit 1; }
setupTxs=$((setupTxs + 1))
blk0=$(waitForReceipt "http://127.0.0.1:$rethEthBase" "$tx0" 90) || { fail "the first setup transaction was never certified"; exit 1; }
for i in $(seq 1 "$validators"); do
  waitForHead "http://127.0.0.1:$((rethEthBase + i - 1))" "$(dec "$blk0")" 90 \
    || { fail "executor $i never reached block $(dec "$blk0")"; exit 1; }
done
preOutage=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read the subject's head"; exit 1; }
preOutageNum=$(dec "$(echo "$preOutage" | cut -d' ' -f1)")
preOutageHash=$(echo "$preOutage" | cut -d' ' -f2)
if [ "$preOutageNum" -ge 1 ] && [ "$preOutageHash" != "$genesisHash" ]; then
  pass "every executor is on real block $preOutageNum ${preOutageHash:0:18}… before anything is severed"
else
  fail "the subject is not past genesis before the experiment starts: number=$preOutageNum"
  exit 1
fi
note "pre-outage subject head block $preOutageNum $preOutageHash"

echo
reached="section 2: execution-layer isolation, confirmed"
echo "=== 2. sever the subject's EXECUTION peering, and confirm it from both ends ==="
# BFT transport is deliberately untouched: the shard node keeps its libp2p bootnodes and its
# engine/eth endpoints on localhost, so evidence retrieval has exactly the connectivity it had. The
# only variable in this experiment is devp2p.
for i in $(seq 2 "$validators"); do
  rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_removePeer "[\"${enodes[1]}\"]" >/dev/null
  rpc "http://127.0.0.1:$rethEthBase" admin_removePeer "[\"${enodes[$i]}\"]" >/dev/null
done
isolation=$(waitForIsolation "http://127.0.0.1:$rethEthBase" "$subjectID" 60 10 "${survivorEth[@]}")
if [ "$isolation" = "ok" ]; then
  pass "the subject has no execution peers, by its own count, by its own session list, and by every survivor's — held for 10s of re-reading"
else
  fail "execution isolation could not be established: $isolation"
  snapshot "phase=isolation-failed"
  exit 1
fi
# AND THE SURVIVORS ARE UNTOUCHED. Only the subject's edges were removed; if the survivors lost each
# other too, this is a network partition rather than the single-client isolation the experiment
# claims, and the reconnect would restore more than the one variable under test.
survivorsIntact=true
for u in "${survivorEth[@]}"; do
  n=$(peerCount "$u" 2>/dev/null) || n=0
  [ "$n" -ge $((validators - 2)) ] || survivorsIntact=false
done
if $survivorsIntact; then
  pass "the survivors are still peered with each other: the isolation removed the subject's edges and nothing else"
else
  fail "the survivors lost execution peers too, so this is a partition and not a targeted isolation: $(for u in "${survivorEth[@]}"; do printf "%s " "$(peerCount "$u" 2>/dev/null || echo unreadable)"; done)"
fi
snapshot "phase=isolated"
note "isolation established"
# FROM HERE THE WINDOW IS OBSERVED, not sampled at its ends. The monitor records a reading every
# second — including the readings it could not take — and the client's own session events are
# checked over the same window when it closes. See monitorClean.
isolationAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)
startPeerMonitor "http://127.0.0.1:$rethEthBase" test-nodes/peermon.log 1

rootBoot=$(boot_node test-nodes/root1 "$rootBootPort")
[ -n "$rootBoot" ] || { fail "could not determine the root bootnode address"; exit 1; }

stopValidator1() {
  [ -f test-nodes/evm1/pid ] && kill "$(cat test-nodes/evm1/pid)" 2>/dev/null
  sleep 3
}

# restartValidator1 runs the subject at DEBUG. Every recovery attempt that is not `applied` is logged
# at debug level (evidencerecovery.go), and the outcome of every attempt is precisely what this
# experiment is measuring — at info level a node failing closed and retrying is silent about it.
# This is a harness choice and changes nothing in the node; it is recorded in the manifest because it
# changes what is observable.
restartValidator1() {
  stopValidator1
  : >test-nodes/evm1/debug.log
  local bootnodes="$rootBoot"
  for j in $(seq 2 "$validators"); do bootnodes+=",$(evm_validator_addr "$j")"; done
  build/ubft shard-node run --home test-nodes/evm1 --executor engine-api \
    --address "/ip4/127.0.0.1/tcp/$evmValidatorPortStart" --bootnodes "$bootnodes" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --log-format text --log-level debug \
    --engine-url "http://127.0.0.1:$rethEngineBase" --eth-url "http://127.0.0.1:$rethEthBase" \
    --jwt-secret test-nodes/evm1/jwt.hex "$@" \
    >>test-nodes/evm1/debug.log 2>&1 &
  echo $! >test-nodes/evm1/pid
}

echo
reached="section 3: blocks created while the subject is isolated"
echo "=== 3. real blocks are certified while the subject is down AND execution-isolated ==="
stopValidator1
peerEth="http://127.0.0.1:$((rethEthBase + 1))"
declare -a missedTx
for nonce in 1 2; do
  tx=$(sendTx "$peerEth" "$nonce") || { fail "could not submit setup transaction $((nonce + 1))"; exit 1; }
  setupTxs=$((setupTxs + 1))
  missedTx+=("$tx")
  blk=$(waitForReceipt "$peerEth" "$tx" 120) || { fail "setup transaction $((nonce + 1)) was never certified"; exit 1; }
  note "transaction $((nonce + 1)) $tx executed in block $(dec "$blk") on a survivor"
done
note "no transaction is submitted from here on"

certifiedHash=""
for i in $(seq 2 "$validators"); do
  b=$(blockAt "http://127.0.0.1:$((rethEthBase + i - 1))" latest) || { fail "could not read executor $i's head"; exit 1; }
  h=$(echo "$b" | cut -d' ' -f2)
  if [ -z "$certifiedHash" ]; then
    certifiedNum=$(dec "$(echo "$b" | cut -d' ' -f1)"); certifiedHash=$h; certifiedRoot=$(echo "$b" | cut -d' ' -f3)
  elif [ "$h" != "$certifiedHash" ]; then
    fail "the survivors do not agree on the head: $certifiedHash vs $h"; exit 1
  fi
done
[ "$certifiedNum" -gt "$preOutageNum" ] \
  && pass "the survivors certified through block $certifiedNum ${certifiedHash:0:18}… while the subject was down and isolated" \
  || { fail "no block was certified during the outage: head is still $certifiedNum"; exit 1; }

# ISOLATION HELD ACROSS THE WINDOW THAT MATTERS. Confirming it before the blocks existed says
# nothing about whether it was still true while they were being gossiped.
# An ENDPOINT reading. It says the isolation still holds now, and nothing about the interval just
# passed; the window record checked at the reconnect is what covers that, and this must not be
# described as if it did.
isolation=$(holdsIsolation "http://127.0.0.1:$rethEthBase" "$subjectID" "${survivorEth[@]}")
[ "$isolation" = "ok" ] \
  && pass "the subject still has no execution peers now that the blocks exist (an endpoint reading; the window is checked at the reconnect)" \
  || fail "isolation lapsed by the time the missed blocks were created: $isolation"
snapshot "phase=blocks-created-while-isolated"

# AND THE CLIENT ITSELF SAYS IT NEVER SAW THEM. Independent of the peer readings: reth logs every
# block it adds to its canonical chain, and the subject must have added neither.
if grep -qE "Block added to canonical chain.*number=($((preOutageNum + 1))|$certifiedNum)\b" test-nodes/reth1/reth.log; then
  fail "the subject's client logged adding a block it was supposed to have missed"
else
  pass "the subject's client logged no block beyond $preOutageNum: it does not hold the missed blocks"
fi
behind=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read the subject's executor"; exit 1; }
behindNum=$(dec "$(echo "$behind" | cut -d' ' -f1)")
[ "$behindNum" = "$preOutageNum" ] \
  && pass "the subject's canonical head is still block $behindNum" \
  || { fail "the subject's head moved while isolated: $behindNum"; exit 1; }

providerLogs=""
for i in $(seq 2 "$validators"); do providerLogs="$providerLogs test-nodes/evm$i/debug.log"; done
quietTail=$(waitForQuietTail 4 180 $providerLogs) \
  || { fail "the shard never went quiet after the last transaction: tail is $quietTail entries"; exit 1; }
pass "the shard is quiet again: $quietTail quiet request entries since the last non-quiet one"

echo
reached="section 4: the isolated arm"
echo "=== 4. ISOLATED: BFT evidence reaches it, the payload does not ==="
isolatedMark=$(markNow)
note "isolated arm begins"
restartValidator1 --evidence-recover
waitFor test-nodes/evm1/debug.log "accepted certificate" 6 180 || { fail "the restarted node received no certificates"; exit 1; }
# Give it room to try, fail closed and try again. The budget renews per certificate, so this is
# several attempts, not one.
waitForLinesAfter test-nodes/evm1/debug.log "anchor recovery finished" "outcome=payload-unavailable" 2 180 >/dev/null \
  || info "fewer than 2 unavailability outcomes were logged within 180s; the counts below say what happened"

# 1. THE EVIDENCE PATH IS UNAFFECTED. This is the half of the experiment that must still work: devp2p
#    is severed, libp2p is not, and obtaining an authenticated anchor has nothing to do with the
#    execution client's peers.
if grep -q "anchor recovery finished.*state=ready" test-nodes/evm1/debug.log; then
  pass "authenticated evidence still obtained over BFT transport with the execution client isolated: $(grep -o 'attempts=[0-9]* restarts=[0-9]*' test-nodes/evm1/debug.log | head -1)"
else
  fail "no evidence was obtained — the experiment cannot separate evidence from payload if the evidence never arrived"
fi

# 2. AND IT NAMES THE RIGHT BLOCK. The verified target is the survivors' certified block, established
#    with no execution-layer connectivity of any kind.
target=$(grep -o "targetBlock=[0-9a-f]\{64\}" test-nodes/evm1/debug.log | head -1 | cut -d= -f2)
if [ -z "$target" ]; then
  fail "no verified target was ever logged"
elif [ "0x$target" = "$certifiedHash" ]; then
  pass "the verified target is ${certifiedHash:0:18}…, the survivors' certified block — named from BFT evidence alone"
else
  fail "the verified target 0x$target is not the certified block $certifiedHash"
fi

# 3. FAIL CLOSED. Unavailable, retryable, retried, and nothing adopted, moved or signed.
# COUNTED SINCE THIS ARM BEGAN, not over the whole file. The shard node is not restarted between
# the two arms, so a whole-log count in the reconnected arm below is satisfied by outcomes from this
# one — an assertion about a phase that its own predecessor can satisfy.
unavailable=$(linesSince "$isolatedMark" "outcome=payload-unavailable" test-nodes/evm1/debug.log)
adopted=$(linesSince "$isolatedMark" "recovered from authenticated" test-nodes/evm1/debug.log)
signed=$(linesSince "$isolatedMark" "submitting block certification request" test-nodes/evm1/debug.log)
if [ "$unavailable" -ge 2 ] && [ "$adopted" -eq 0 ] && [ "$signed" -eq 0 ]; then
  pass "fail-closed: $unavailable payload-unavailable outcomes, target retained and retried, nothing adopted and nothing signed"
else
  fail "the isolated arm did not fail closed: payload-unavailable=$unavailable adopted=$adopted signed=$signed"
fi
if grep -q "outcome=payload-unavailable retryable=true" test-nodes/evm1/debug.log; then
  pass "and the outcome is reported as RETRYABLE, not as a fault — an unobtainable payload is not an invalid one"
else
  fail "the unavailability was not reported as retryable"
fi
isolatedHead=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read the subject's executor"; exit 1; }
isolatedNum=$(dec "$(echo "$isolatedHead" | cut -d' ' -f1)")
[ "$isolatedNum" = "$preOutageNum" ] \
  && pass "the subject's executor is still on block $isolatedNum: a verified anchor did not move it, because the block itself is not obtainable" \
  || fail "the subject's executor moved while isolated: block $isolatedNum"
grep -q "NON-VOTING" test-nodes/evm1/debug.log \
  && pass "isolated: still NON-VOTING (P-sign, #105)" \
  || fail "isolated: the resumed process did not declare itself non-voting"
assertTransactionCount "the isolated subject" "http://127.0.0.1:$rethEthBase" 1 \
  "it holds only the transaction it executed before the outage"

isolation=$(holdsIsolation "http://127.0.0.1:$rethEthBase" "$subjectID" "${survivorEth[@]}")
[ "$isolation" = "ok" ] \
  && pass "and it was still isolated at the end of the arm" \
  || fail "isolation lapsed during the isolated arm: $isolation"
isolatedBlocks=$(nonQuietSince "$isolatedMark" $providerLogs)
[ "$isolatedBlocks" = "0" ] \
  && pass "isolated arm: no provider logged a non-quiet request while it ran" \
  || fail "isolated arm: $isolatedBlocks non-quiet request(s) while it ran"
cp test-nodes/evm1/debug.log test-nodes/evm1/isolated.log
snapshot "phase=isolated-arm-end"

echo
reached="section 5: the reconnected arm"
echo "=== 5. RECONNECTED: execution peers restored, no transaction submitted ==="
# ONE VARIABLE CHANGES. The shard node is not restarted, the flags are identical, the anchor is
# already verified and retained, and nothing is submitted. The only difference is devp2p.
reconnectMark=$(markNow)
reconnectAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)
stopPeerMonitor

# THE WINDOW, CLOSED AND CHECKED. Everything above this line happened between $isolationAt and
# $reconnectAt: the missed blocks were created, the subject returned, it verified its anchor and it
# failed closed. The claim the whole experiment rests on is that it had no execution connectivity at
# ANY point in that interval, and two independent records are required to say so.
windowSecs=$(python3 -c "
from datetime import datetime
f='%Y-%m-%dT%H:%M:%SZ'
print(int((datetime.strptime('$reconnectAt',f)-datetime.strptime('$isolationAt',f)).total_seconds()))
" 2>/dev/null)
minSamples=$(( ${windowSecs:-0} / 2 ))
[ "$minSamples" -lt 20 ] && minSamples=20
window=$(monitorClean test-nodes/peermon.log "$isolationAt" "$reconnectAt" "$minSamples")
if [ "$window" = "ok" ]; then
  pass "connectivity was OBSERVED for the whole ${windowSecs}s window, not sampled at its ends: $(linesBetween "$isolationAt" "$reconnectAt" "status=" test-nodes/peermon.log) readings, every one of them readable, every one of them zero peers and no session"
else
  fail "the isolation window is not an observed window: $window"
fi
# The second record, of a different kind: the client logs every session it establishes, so this is
# an event trace rather than a sample, and a transient connection that opened and closed between two
# samples would still appear here.
sed $'s/\033\\[[0-9;]*m//g' test-nodes/reth1/reth.log >test-nodes/reth1/reth-plain.log 2>/dev/null \
  || { fail "could not snapshot the session trace"; exit 1; }
sessionsInWindow=$(linesBetween "$isolationAt" "$reconnectAt" "Session established" test-nodes/reth1/reth-plain.log) \
  || { fail "could not verify the session-event window"; exit 1; }
if [ "${sessionsInWindow:-1}" = "0" ]; then
  pass "and the client's own session-event trace records no session established at any point in that window — a transient connection between two samples would still have been logged"
else
  fail "the client established $sessionsInWindow execution session(s) inside the isolation window, so the blocks may have been received over one"
fi

note "reconnecting execution peers"
reconnected=0
for _ in $(seq 1 20); do
  for i in $(seq 2 "$validators"); do
    rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_addPeer "[\"${enodes[1]}\"]" >/dev/null 2>&1
    rpc "http://127.0.0.1:$rethEthBase" admin_addPeer "[\"${enodes[$i]}\"]" >/dev/null 2>&1
  done
  sleep 3
  reconnected=$(peerCount "http://127.0.0.1:$rethEthBase" 2>/dev/null) || reconnected=0
  [ "$reconnected" -ge 1 ] && break
done
if [ "$reconnected" -ge 1 ]; then
  pass "the subject has $reconnected execution peer(s) again"
else
  fail "the subject never regained an execution peer (saw $reconnected) — the reconnected arm did not run"
fi
snapshot "phase=reconnected"

# THE RESULT. Both branches are measured and both are asserted; neither is a formality. The lane is
# not entitled to a particular answer here — a client that still cannot obtain the blocks is
# evidence about the existing mechanism's limits, which is what this experiment was asked for.
acquisitionResult="not-run"
if waitForHead "http://127.0.0.1:$rethEthBase" "$certifiedNum" 180; then
  acquisitionResult="acquired"
  recovered=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read the subject's executor"; exit 1; }
  recoveredNum=$(dec "$(echo "$recovered" | cut -d' ' -f1)")
  recoveredHash=$(echo "$recovered" | cut -d' ' -f2)
  recoveredRoot=$(echo "$recovered" | cut -d' ' -f3)
  if [ "$recoveredHash" = "$certifiedHash" ] && [ "$recoveredNum" = "$certifiedNum" ] && [ "$recoveredRoot" = "$certifiedRoot" ]; then
    pass "RESULT — ACQUIRED: reconnecting execution peers, with no transaction submitted, was sufficient. The subject went from block $preOutageNum to block $recoveredNum $recoveredHash at the certified state"
  else
    fail "the subject moved but not to the certified block: $recoveredNum ${recoveredHash:0:18}… at $recoveredRoot"
  fi

  # IDENTITY BEYOND THE HEAD HASH. Two clients can agree on a head hash and disagree about which
  # block a transaction landed in; the receipts are read from the subject and from a survivor and
  # must name the same block, for each transaction the subject missed.
  same=0
  for tx in "${missedTx[@]}"; do
    mine=$(receiptIdentity "http://127.0.0.1:$rethEthBase" "$tx") || { fail "no receipt for $tx on the subject"; continue; }
    theirs=$(receiptIdentity "$peerEth" "$tx") || { fail "no receipt for $tx on a survivor"; continue; }
    if [ "$mine" = "$theirs" ]; then same=$((same + 1)); else fail "receipt for $tx differs: subject '$mine', survivor '$theirs'"; fi
  done
  [ "$same" = "${#missedTx[@]}" ] \
    && pass "every missed transaction has the same receipt identity on the subject as on a survivor ($same of ${#missedTx[@]}): same block number, same block hash" \
    || true
  [ "$(waitForLinesSinceAll "$reconnectMark" test-nodes/evm1/debug.log 1 60 \
        "recovered from authenticated evidence" "blockHash=${certifiedHash#0x}")" -ge 1 ] \
    && pass "and ADOPTION followed ACQUISITION after the reconnect: the node recorded adopting ${certifiedHash:0:18}…, the target it verified while isolated — two separate completion conditions, both reached" \
    || fail "the executor ACQUIRED block $certifiedNum but the node never recorded ADOPTING ${certifiedHash:0:18}… after the reconnect within 60s"

  # THE MECHANISM, NAMED BY THE CLIENT ITSELF. This is what §8 said forty milliseconds could not
  # distinguish, and it is why this lane runs the client at debug: reth reports the missed blocks
  # arriving as DOWNLOADED blocks after the sessions are established, not as blocks it already held.
  # Together with the isolation that preceded it, that is the acquisition source.
  # Counted by INSTANT, not by string: an event inside the marked second sorts before it as text,
  # and the whole trace can then read as empty. See linesFrom.
  # A FRESH SNAPSHOT. reth-plain.log was taken deliberately BEFORE the reconnect, so that the
  # isolation window could not be contaminated by events the reconnect itself caused; that same file
  # therefore cannot contain the download this check is looking for. Reading it here found nothing
  # and reported it as "the trace does not show it" — a stale snapshot answering a question about
  # the present.
  sed $'s/\033\\[[0-9;]*m//g' test-nodes/reth1/reth.log >test-nodes/reth1/reth-after.log 2>/dev/null \
    || { fail "could not snapshot the client trace after the reconnect"; exit 1; }
  sessions=$(linesFrom "$reconnectAt" "Session established" test-nodes/reth1/reth-after.log) \
    || { fail "could not read the client's session trace"; exit 1; }
  downloadedTarget=$(linesFrom "$reconnectAt" "on_downloaded_block{block_hash=$certifiedHash" test-nodes/reth1/reth-after.log) \
    || { fail "could not read the client's download trace"; exit 1; }
  if [ "$sessions" -ge 1 ] && [ "$downloadedTarget" -ge 1 ]; then
    pass "the client names the source: $sessions execution session(s) established, then the certified block ${certifiedHash:0:18}… arrives as a DOWNLOADED block — acquired from execution peers after the forkchoice update, not held from gossip"
  else
    fail "the executor reached the block but its trace does not show it being downloaded after a session was established (sessions=$sessions downloads-of-target=$downloadedTarget) — this run does not identify the acquisition source"
  fi
else
  acquisitionResult="not-acquired"
  # A NEGATIVE IS A RESULT — BUT ONLY IF THE OBSERVATION BEHIND IT WAS VALID. An earlier version
  # called fail() here while saying in the same sentence that this was not a harness failure, and
  # checked unavailability over the WHOLE log, which the isolated arm alone already satisfies. So it
  # could neither tell a measured "the client did not obtain the block" from "the experiment did not
  # run", nor notice that its evidence predated the phase it was describing.
  #
  # Four readings, all taken now and all bounded to this phase, decide which this is. If they hold,
  # the client was reachable, still held the right verified target, and was still reporting the
  # payload unavailable rather than invalid — a real measurement of the mechanism's limit, and not a
  # check failure. If any of them does not, the observation is invalid and that IS a failure.
  stuck=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read the subject's executor"; exit 1; }
  stuckNum=$(dec "$(echo "$stuck" | cut -d' ' -f1)")
  nowPeers=$(peerCount "http://127.0.0.1:$rethEthBase" 2>/dev/null) || nowPeers=0
  freshTarget=$(linesSince "$reconnectMark" "targetBlock=${certifiedHash#0x}" test-nodes/evm1/debug.log)
  freshUnavailable=$(linesSince "$reconnectMark" "outcome=payload-unavailable" test-nodes/evm1/debug.log)
  freshInvalid=$(linesSince "$reconnectMark" "outcome=payload-invalid" test-nodes/evm1/debug.log)
  if [ "$nowPeers" -ge 1 ] && [ "$freshTarget" -ge 1 ] && [ "$freshUnavailable" -ge 1 ] \
     && [ "$freshInvalid" = "0" ] && [ "$stuckNum" = "$preOutageNum" ]; then
    info "RESULT — NOT ACQUIRED: 180s after execution peers were restored the subject is still on block $stuckNum, not $certifiedNum"
    pass "and this is a valid negative measurement, not a broken observation: $nowPeers execution peer(s) reachable now, the certified block still the verified target after the reconnect ($freshTarget reading(s)), still reported unavailable ($freshUnavailable) and never invalid ($freshInvalid). The existing client mechanism did not obtain the missed blocks under these conditions"
  else
    fail "the reconnected arm neither acquired the block nor produced a valid negative observation: head=$stuckNum (expected $preOutageNum) peers=$nowPeers target-after-reconnect=$freshTarget unavailable-after-reconnect=$freshUnavailable invalid-after-reconnect=$freshInvalid"
  fi
fi

# TRUE IN BOTH BRANCHES, and the reason this measures acquisition rather than activity.
signed=$(countIn test-nodes/evm1/debug.log "submitting block certification request")
if grep -q "NON-VOTING" test-nodes/evm1/debug.log && [ "$signed" -eq 0 ]; then
  pass "signing refusal unchanged throughout: NON-VOTING, and it signed nothing in either arm (P-sign, #105)"
else
  fail "the subject must not sign: NON-VOTING=$(countIn test-nodes/evm1/debug.log NON-VOTING) submissions=$signed"
fi
reconnectBlocks=$(nonQuietSince "$reconnectMark" $providerLogs)
[ "$reconnectBlocks" = "0" ] \
  && pass "reconnected arm: no provider logged a non-quiet request while it ran — nothing new was executed to help it" \
  || fail "reconnected arm: $reconnectBlocks non-quiet request(s) while it ran, so this arm does not isolate connectivity"
for i in $(seq 2 "$validators"); do
  assertTransactionCount "survivor $((i))" "http://127.0.0.1:$((rethEthBase + i - 1))" "$setupTxs" \
    "the same $setupTxs submitted before the subject returned, and nothing since"
done
snapshot "phase=end"

# THE TRACE, which is the point of running the client at debug. Printed and preserved; no mechanism
# is inferred here beyond what the lines say.
info "the subject's execution client, from the reconnect at $reconnectAt onwards:"
# ANSI first, THEN the timestamp comparison: reth colours its output, so the escape sequence is part
# of field one and every comparison against it silently matches nothing.
# One line per distinct event: the repeated per-span entries for a single downloaded block are the
# same fact many times over, and a trace nobody can read is not evidence anybody can check.
printLinesFrom "$reconnectAt" test-nodes/reth1/reth-after.log 2>/dev/null \
  | grep -Ei "Session established|DownloadedBlocks|on_downloaded_block\{|Received forkchoice|Block added to canonical chain|Canonical chain committed" \
  | sed -E 's/(on_downloaded_block\{[^}]*\}).*/\1/' \
  | awk '{ k = $0; sub(/^[^ ]+ /, "", k); if (!(k in seen)) { seen[k]; print } }' \
  | cut -c1-150 | head -14 | sed 's/^/    /'

reached="all sections"
echo
echo "=== 6. provenance ==="
# MONOTONIC TIMESTAMPS, checked rather than assumed. The connectivity record is the evidence that the
# isolation covered the window the blocks were created in, and a record whose entries are out of
# order cannot establish that any of them came before any other.
outOfOrder=$(awk '{ if ($1 < prev) n++; prev = $1 } END { print n + 0 }' "$connLog" 2>/dev/null)
if [ "${outOfOrder:-1}" = "0" ]; then
  pass "the connectivity record's $(grep -c "" "$connLog") entries are in non-decreasing time order"
else
  fail "the connectivity record has $outOfOrder entry/entries out of time order, so it cannot order the phases"
fi

manifestLines=(
  "subject:         validator 1 (reth1), execution-isolated before the missed blocks were created"
  "bft transport:   untouched throughout — libp2p bootnodes and localhost engine/eth endpoints"
  "subject log:     --log-level debug (every non-applied recovery attempt is logged at debug)"
  "reth1 log:       --log.stdout.filter debug (full client trace, preserved in the artifact)"
  "setup txs:       $setupTxs, all before the subject returned; none in either arm"
  "executor before: block $preOutageNum $preOutageHash"
  "certified head:  block $certifiedNum $certifiedHash"
  "isolated arm:    executor stayed on block ${isolatedNum:-unknown}, target verified, payload unavailable"
  "RESULT:          $acquisitionResult"
  "executor after:  block ${recoveredNum:-${stuckNum:-unknown}} ${recoveredHash:-unchanged}"
)
if writeManifest; then
  pass "run artifact written to $artifactDir"
  cat "$artifactDir/manifest.txt"
else
  fail "no run artifact could be written, so this run is not evidence"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "ALL CHECKS PASSED (reth $rethCommit) — result: $acquisitionResult — artifact: $artifactDir"
else
  echo "$failures CHECK(S) FAILED — result: $acquisitionResult — artifact: $artifactDir"
fi
exit $((failures > 0))
