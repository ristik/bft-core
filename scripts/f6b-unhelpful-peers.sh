#!/bin/bash
# f6b-unhelpful-peers.sh - the bound on payload acquisition that §8.1 identifies but does not measure.
#
# WHAT §8.1 ESTABLISHED. With the returning client's execution peering severed, the node still
# obtained and verified its anchor over BFT and then failed closed; reconnecting its peers, with no
# transaction submitted, was enough for the client's own block download to fetch the missed blocks.
# So the acquisition path is identified: reth downloads the missing blocks from its execution-layer
# peers when a forkchoice update names a descendant it does not hold.
#
# WHAT IT DID NOT ESTABLISH, in its own words: "the negative arm was never exercised against a peer
# set that could not help". Every peer in that run held the missing blocks, so the experiment
# separated CONNECTED from DISCONNECTED and said nothing about connected-but-unhelpful. A mechanism
# that is identified is not thereby bounded.
#
# THE EXPERIMENT. The subject is given execution peers that provably do not hold the blocks it needs:
# two BYSTANDER reth clients on the same chain spec, driven by no shard node, never connected to the
# validators that certified those blocks. Three states of one variable, in one run:
#
#   ISOLATED    no execution peers at all, while the blocks it will miss are created. The premise.
#   UNHELPFUL   connected — sessions established, peer count above zero for every sample of the
#               window — to peers that are checked, by hash, not to hold the missing blocks. The
#               node must obtain and verify its anchor over BFT and then FAIL CLOSED indefinitely.
#   HELPFUL     the survivors are added, and nothing else changes. This is the control: without it,
#               "it did not acquire" is indistinguishable from "it had stopped trying".
#
# The middle arm is expected to be NEGATIVE, and a negative is the result this lane exists to
# produce. What it must not do is report one without having established the premise, so the peers'
# ignorance is asserted by hash on every bystander, before and after, and connectivity is observed
# across the whole arm rather than sampled at its ends.
#
# Usage:  ./scripts/f6b-unhelpful-peers.sh [validators]   # default 3, plus 2 bystanders
#         ./scripts/f6b-unhelpful-peers.sh --self-test    # no reth, no root chain
# Needs:  a pinned reth, curl, openssl, python3, go, and a built ./build/ubft. Run from the repo root.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

selfTest=false
if [ "${1:-}" = "--self-test" ]; then selfTest=true; shift; fi

validators=${1:-3}
bystanders=2
partitionID=8
chainID=31337
pinnedRethCommit=189c0df32617afc488e0f091dbface1bd72cceb4
rethEngineBase=18551
rethEthBase=18545
rethP2PBase=30401
bystEthBase=18565
bystP2PBase=30421
rootBootPort=26662

failures=0
reached="startup"

source "$(dirname "${BASH_SOURCE[0]}")/lib/f6b-acceptance-lib.sh"

artifactDir="${F6B_ARTIFACT_DIR:-artifacts/f6b-unhelpful-peers/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
manifestTitle="f6b unhelpful execution peers: the bound on payload acquisition"
manifestLogs="test-nodes/connectivity.log test-nodes/peermon-isolated.log test-nodes/peermon-unhelpful.log test-nodes/evm1/unhelpful.log $(seq -f "test-nodes/evm%g/debug.log" 1 "$validators" | tr '\n' ' ')$(seq -f " test-nodes/reth%g/reth.log" 1 "$validators" | tr -d '\n')$(seq -f " test-nodes/byst%g/reth.log" 1 "$bystanders" | tr -d '\n')"
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
refuseStaleListeners $(seq -s" " "$rethEngineBase" $((rethEngineBase + validators - 1))) $(seq -s" " "$rethEthBase" $((rethEthBase + validators - 1))) $(seq -s" " "$bystEthBase" $((bystEthBase + bystanders - 1))) || exit 1

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
    for i in $(seq 1 "$validators"); do [ -f "test-nodes/reth$i/pid" ] && kill "$(cat "test-nodes/reth$i/pid")" 2>/dev/null; done
    for i in $(seq 1 "$bystanders"); do [ -f "test-nodes/byst$i/pid" ] && kill "$(cat "test-nodes/byst$i/pid")" 2>/dev/null; done
    exit 1
  fi
  ./stop-evm.sh -a >/dev/null 2>&1 || true
  pkill -f 'ubft shard-node run' 2>/dev/null
  for i in $(seq 1 "$validators"); do [ -f "test-nodes/reth$i/pid" ] && kill "$(cat "test-nodes/reth$i/pid")" 2>/dev/null; done
  for i in $(seq 1 "$bystanders"); do [ -f "test-nodes/byst$i/pid" ] && kill "$(cat "test-nodes/byst$i/pid")" 2>/dev/null; done
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

source ./helper.sh

connLog=test-nodes/connectivity.log
note() { mkdir -p test-nodes; echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1" >>"$connLog"; }
snapshot() { # snapshot <label>
  local i n ids
  mkdir -p test-nodes
  for i in $(seq 1 "$validators"); do
    n=$(peerCount "http://127.0.0.1:$((rethEthBase + i - 1))" 2>/dev/null) || n="unreadable"
    ids=$(peerIds "http://127.0.0.1:$((rethEthBase + i - 1))" 2>/dev/null | cut -c1-16 | tr '\n' ',')
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1 reth$i peers=$n sessions=${ids:-none}" >>"$connLog"
  done
  for i in $(seq 1 "$bystanders"); do
    n=$(peerCount "http://127.0.0.1:$((bystEthBase + i - 1))" 2>/dev/null) || n="unreadable"
    ids=$(peerIds "http://127.0.0.1:$((bystEthBase + i - 1))" 2>/dev/null | cut -c1-16 | tr '\n' ',')
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1 byst$i peers=$n sessions=${ids:-none}" >>"$connLog"
  done
}

# sendTx, waitForReceipt and dec now live in the shared library: one copy, see its header.

# assertBystandersLack checks, BY HASH and on every bystander, that none of them holds the blocks the
# subject is missing. It runs in the parent shell so its fail() counts.
assertBystandersLack() { # assertBystandersLack <label> <hash...>
  local label=$1; shift
  local i url h p bad=0 checked=0
  for i in $(seq 1 "$bystanders"); do
    url="http://127.0.0.1:$((bystEthBase + i - 1))"
    for h in "$@"; do
      p=$(blockPresence "$url" "$h" 2>/dev/null) || { fail "$label: could not ask bystander $i whether it holds ${h:0:18}…, so 'it does not' is unproven"; return 1; }
      checked=$((checked + 1))
      [ "$p" = "absent" ] || { bad=$((bad + 1)); info "bystander $i HOLDS ${h:0:18}…"; }
    done
  done
  if [ "$bad" -eq 0 ]; then
    pass "$label: none of the $bystanders bystanders holds any of the missed blocks ($checked hash lookups, every one answered 'absent')"
  else
    fail "$label: $bad of $checked lookups found a bystander holding a block it was supposed to lack"
  fi
}

reached="section 1: a funded chain, real blocks, and bystanders that follow nothing"
echo "=== 1. validators on a funded chain, plus bystanders driven by nobody ==="
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
  extra=(--no-persist-peers)
  [ "$i" = "1" ] && extra+=(--log.stdout.filter debug)
  reth node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) \
    --http.api eth,net,web3,admin,txpool \
    --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    "${extra[@]}" >"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
done

# THE BYSTANDERS. Same chain spec, so they are valid peers on the same network and will happily talk
# to the subject; no shard node drives them, so nothing ever tells them to build, execute or
# canonicalise anything, and they are never peered to the validators. They are execution peers that
# cannot help, which is the condition this lane exists to create.
for i in $(seq 1 "$bystanders"); do
  mkdir -p "test-nodes/byst$i"
  openssl rand -hex 32 >"test-nodes/byst$i/jwt.hex"
  reth node --chain "$chainSpec" --datadir "test-nodes/byst$i/dd" \
    --authrpc.jwtsecret "test-nodes/byst$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((18581 + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((bystEthBase + i - 1)) \
    --http.api eth,net,web3,admin \
    --port $((bystP2PBase + i - 1)) --disable-discovery --ipcdisable --no-persist-peers \
    >"test-nodes/byst$i/reth.log" 2>&1 &
  echo $! >"test-nodes/byst$i/pid"
done

waitUp() { # waitUp <ethURL> <what>
  for _ in $(seq 1 60); do
    rpc "$1" eth_chainId '[]' 2>/dev/null | grep -q result && return 0
    sleep 1
  done
  fail "$2 did not start"; return 1
}
for i in $(seq 1 "$validators"); do waitUp "http://127.0.0.1:$((rethEthBase + i - 1))" "reth $i" || exit 1; done
for i in $(seq 1 "$bystanders"); do waitUp "http://127.0.0.1:$((bystEthBase + i - 1))" "bystander $i" || exit 1; done

declare -a enodes bystEnodes bystIDs
for i in $(seq 1 "$validators"); do
  enodes[$i]=$(rpcRequire "http://127.0.0.1:$((rethEthBase + i - 1))" admin_nodeInfo '[]' "['result']['enode']" "enode") \
    || { fail "could not read reth $i's enode"; exit 1; }
done
for i in $(seq 1 "$bystanders"); do
  bystEnodes[$i]=$(rpcRequire "http://127.0.0.1:$((bystEthBase + i - 1))" admin_nodeInfo '[]' "['result']['enode']" "enode") \
    || { fail "could not read bystander $i's enode"; exit 1; }
  bystIDs[$i]=$(nodeAdminID "http://127.0.0.1:$((bystEthBase + i - 1))") \
    || { fail "could not read bystander $i's admin id"; exit 1; }
done
subjectID=$(nodeAdminID "http://127.0.0.1:$rethEthBase") || { fail "could not read the subject's admin node id"; exit 1; }
survivorEth=(); survivorIDs=()
for i in $(seq 2 "$validators"); do
  survivorEth+=("http://127.0.0.1:$((rethEthBase + i - 1))")
  survivorIDs+=("$(nodeAdminID "http://127.0.0.1:$((rethEthBase + i - 1))")") || { fail "could not read survivor $i's admin id"; exit 1; }
done

mesh() {
  local i j
  for i in $(seq 1 "$validators"); do
    for j in $(seq 1 "$validators"); do
      [ "$i" = "$j" ] && continue
      rpc "http://127.0.0.1:$((rethEthBase + j - 1))" admin_addPeer "[\"${enodes[$i]}\"]" >/dev/null 2>&1
    done
  done
}
meshed=false
for _ in $(seq 1 20); do
  mesh; sleep 3; meshed=true
  for i in $(seq 1 "$validators"); do
    n=$(peerCount "http://127.0.0.1:$((rethEthBase + i - 1))" 2>/dev/null) || n=0
    [ "$n" -ge $((validators - 1)) ] || meshed=false
  done
  $meshed && break
done
$meshed && pass "the $validators validator executors are fully peered with each other" \
  || { fail "the execution mesh never formed"; snapshot "phase=peering-failed"; exit 1; }

# The bystanders are peered to nothing at all, and that is checked rather than assumed: an
# accidental edge to a validator would give them the blocks and destroy the arm below.
bystIdle=true
for i in $(seq 1 "$bystanders"); do
  n=$(peerCount "http://127.0.0.1:$((bystEthBase + i - 1))" 2>/dev/null) || { fail "could not read bystander $i's peer count"; exit 1; }
  [ "$n" = "0" ] || bystIdle=false
done
$bystIdle && pass "the $bystanders bystanders have no execution peers at all: nothing can have reached them" \
  || { fail "a bystander is already peered to something"; exit 1; }

seen=false
for u in "${survivorEth[@]}"; do
  peerIds "$u" 2>/dev/null | grep -qx "$subjectID" && { seen=true; break; }
done
$seen && pass "a survivor lists the subject by the exact id the isolation checks look for (${subjectID:0:16}…)" \
  || { fail "no survivor lists the subject as $subjectID while it is peered"; exit 1; }
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
[ "$preOutageNum" -ge 1 ] && [ "$preOutageHash" != "$genesisHash" ] \
  && pass "every validator executor is on real block $preOutageNum ${preOutageHash:0:18}…, past genesis" \
  || { fail "the subject is not past genesis before the experiment starts: number=$preOutageNum"; exit 1; }
note "pre-outage subject head block $preOutageNum $preOutageHash"

rootBoot=$(boot_node test-nodes/root1 "$rootBootPort")
[ -n "$rootBoot" ] || { fail "could not determine the root bootnode address"; exit 1; }

stopValidator1() { [ -f test-nodes/evm1/pid ] && kill "$(cat test-nodes/evm1/pid)" 2>/dev/null; sleep 3; }

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
reached="section 2: isolation, then blocks the subject cannot see"
echo "=== 2. sever the subject's execution peering, then certify blocks without it ==="
for i in $(seq 2 "$validators"); do
  rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_removePeer "[\"${enodes[1]}\"]" >/dev/null
  rpc "http://127.0.0.1:$rethEthBase" admin_removePeer "[\"${enodes[$i]}\"]" >/dev/null
done
isolation=$(waitForIsolation "http://127.0.0.1:$rethEthBase" "$subjectID" 60 10 "${survivorEth[@]}")
[ "$isolation" = "ok" ] \
  && pass "the subject has no execution peers, by its own count, its own session list and every survivor's — held for 10s of re-reading" \
  || { fail "execution isolation could not be established: $isolation"; snapshot "phase=isolation-failed"; exit 1; }
snapshot "phase=isolated"
note "isolation established"
isolationAt=$(markNowUTC)
startPeerMonitor "http://127.0.0.1:$rethEthBase" test-nodes/peermon-isolated.log 1

stopValidator1
peerEth="http://127.0.0.1:$((rethEthBase + 1))"
declare -a missedTx
for nonce in 1 2; do
  tx=$(sendTx "$peerEth" "$nonce") || { fail "could not submit setup transaction $((nonce + 1))"; exit 1; }
  setupTxs=$((setupTxs + 1)); missedTx+=("$tx")
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
# The parent of the certified block is missing too, and the client needs both. Named explicitly so
# the bystanders' ignorance is checked for everything the subject actually has to obtain.
missedParent=$(blockAt "$peerEth" "$(python3 -c "print(hex($certifiedNum - 1))")") || { fail "could not read the certified block's parent"; exit 1; }
missedParentHash=$(echo "$missedParent" | cut -d' ' -f2)

behind=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read the subject's executor"; exit 1; }
[ "$(dec "$(echo "$behind" | cut -d' ' -f1)")" = "$preOutageNum" ] \
  && pass "the subject's canonical head is still block $preOutageNum" \
  || { fail "the subject's head moved while isolated"; exit 1; }
assertBystandersLack "before the arm" "$certifiedHash" "$missedParentHash"

providerLogs=""
for i in $(seq 2 "$validators"); do providerLogs="$providerLogs test-nodes/evm$i/debug.log"; done
quietTail=$(waitForQuietTail 4 180 $providerLogs) \
  || { fail "the shard never went quiet after the last transaction: tail is $quietTail entries"; exit 1; }
pass "the shard is quiet again: $quietTail quiet request entries since the last non-quiet one"

echo
reached="section 3: the unhelpful arm"
echo "=== 3. UNHELPFUL: connected, to peers that do not have the blocks ==="
stopPeerMonitor
# Close the isolation window before opening the connected one: the premise of this arm is that the
# subject held nothing it could have obtained earlier, and that is a claim about the interval just
# passed, not about this instant.
isolationEnd=$(markNowUTC)
windowSecs=$(python3 -c "
from datetime import datetime
i=lambda v: datetime.fromisoformat(v.replace('Z','+00:00'))
print(int((i('$isolationEnd')-i('$isolationAt')).total_seconds()))
" 2>/dev/null)
minSamples=$(( ${windowSecs:-0} / 2 )); [ "$minSamples" -lt 20 ] && minSamples=20
window=$(monitorClean test-nodes/peermon-isolated.log "$isolationAt" "$isolationEnd" "$minSamples")
[ "$window" = "ok" ] \
  && pass "the subject had no execution connectivity for the whole ${windowSecs}s in which the blocks were created: $(linesBetween "$isolationAt" "$isolationEnd" "status=" test-nodes/peermon-isolated.log) readings, all readable, all zero peers" \
  || fail "the isolation window is not an observed window: $window"
sed $'s/\033\\[[0-9;]*m//g' test-nodes/reth1/reth.log >test-nodes/reth1/reth-plain.log 2>/dev/null \
  || { fail "could not snapshot the session trace"; exit 1; }
sessionsIsolated=$(linesBetween "$isolationAt" "$isolationEnd" "Session established" test-nodes/reth1/reth-plain.log) \
  || { fail "could not verify the isolation session window"; exit 1; }
[ "$sessionsIsolated" = "0" ] \
  && pass "and its own session-event trace records no session established at any point in it" \
  || fail "the subject established $sessionsIsolated execution session(s) while it was supposed to be isolated"

# CONNECT IT — to the bystanders, and only to them.
note "connecting the subject to the bystanders only"
connected=0
for _ in $(seq 1 20); do
  for i in $(seq 1 "$bystanders"); do
    rpc "http://127.0.0.1:$((bystEthBase + i - 1))" admin_addPeer "[\"${enodes[1]}\"]" >/dev/null 2>&1
    rpc "http://127.0.0.1:$rethEthBase" admin_addPeer "[\"${bystEnodes[$i]}\"]" >/dev/null 2>&1
  done
  sleep 3
  connected=$(peerCount "http://127.0.0.1:$rethEthBase" 2>/dev/null) || connected=0
  [ "$connected" -ge 1 ] && break
done
if [ "$connected" -ge 1 ]; then
  pass "the subject has $connected execution peer(s) again — sessions established, not merely configured"
else
  fail "the subject never connected to a bystander, so the unhelpful arm did not run"; exit 1
fi

# AND THEY ARE THE ONLY ONES. Read from both sides: what the subject lists, and what the survivors
# list. A survivor session here would supply the very blocks the arm is about.
subjectPeers=$(peerIds "http://127.0.0.1:$rethEthBase") || { fail "could not read the subject's peer list"; exit 1; }
onlyBystanders=true
while read -r pid; do
  [ -z "$pid" ] && continue
  isByst=false
  for i in $(seq 1 "$bystanders"); do [ "$pid" = "${bystIDs[$i]}" ] && isByst=true; done
  $isByst || { onlyBystanders=false; info "the subject lists a peer that is not a bystander: ${pid:0:16}…"; }
done <<<"$subjectPeers"
for sid in "${survivorIDs[@]}"; do
  printf '%s\n' "$subjectPeers" | grep -qx "$sid" && onlyBystanders=false
done
for u in "${survivorEth[@]}"; do
  ids=$(peerIds "$u") || { fail "could not read a survivor's peer list"; exit 1; }
  printf '%s\n' "$ids" | grep -qx "$subjectID" && { onlyBystanders=false; info "a survivor lists the subject"; }
done
$onlyBystanders \
  && pass "every session the subject holds is with a bystander, and no survivor holds a session with it" \
  || { fail "the subject is connected to something other than a bystander — this arm cannot separate 'peers that cannot help' from 'peers that can'"; exit 1; }

assertBystandersLack "at the start of the arm" "$certifiedHash" "$missedParentHash"

unhelpfulMark=$(markNow)
unhelpfulAt=$(markNowUTC)
startPeerMonitor "http://127.0.0.1:$rethEthBase" test-nodes/peermon-unhelpful.log 1
restartValidator1 --evidence-recover
waitFor test-nodes/evm1/debug.log "accepted certificate" 6 180 || { fail "the restarted node received no certificates"; exit 1; }
waitForLinesAfter test-nodes/evm1/debug.log "anchor recovery finished" "outcome=payload-unavailable" 3 240 >/dev/null \
  || info "fewer than 3 unavailability outcomes were logged within 240s; the counts below say what happened"
# Give the client a fair chance to find the blocks it cannot find, so "it did not" is a measurement
# and not a stopwatch. If it acquires them from a bystander at any point in here, the head moves and
# the assertions below say so.
waitForHead "http://127.0.0.1:$rethEthBase" "$certifiedNum" 120 && acquiredFromBystanders=true || acquiredFromBystanders=false

stopPeerMonitor
unhelpfulEnd=$(markNowUTC)

# THE ARM'S PREMISE, over its whole length rather than at its ends: connected the entire time, and
# never to a survivor.
armSecs=$(python3 -c "
from datetime import datetime
i=lambda v: datetime.fromisoformat(v.replace('Z','+00:00'))
print(int((i('$unhelpfulEnd')-i('$unhelpfulAt')).total_seconds()))
" 2>/dev/null)
armMin=$(( ${armSecs:-0} / 2 )); [ "$armMin" -lt 20 ] && armMin=20
armWindow=$(monitorConnectedWithout test-nodes/peermon-unhelpful.log "$unhelpfulAt" "$unhelpfulEnd" "$armMin" "${survivorIDs[@]}")
[ "$armWindow" = "ok" ] \
  && pass "the subject was CONNECTED for the whole ${armSecs}s arm and never to a survivor: $(linesBetween "$unhelpfulAt" "$unhelpfulEnd" "status=" test-nodes/peermon-unhelpful.log) readings, all readable, all with at least one peer" \
  || fail "the unhelpful arm is not an observed connected window: $armWindow"
assertBystandersLack "at the end of the arm" "$certifiedHash" "$missedParentHash"

# 1. THE EVIDENCE PATH IS UNAFFECTED, again. Whatever devp2p can or cannot supply, the anchor comes
#    over BFT.
grep -q "anchor recovery finished.*state=ready" test-nodes/evm1/debug.log \
  && pass "authenticated evidence obtained over BFT while the only execution peers were unhelpful: $(grep -o 'attempts=[0-9]* restarts=[0-9]*' test-nodes/evm1/debug.log | head -1)" \
  || fail "no evidence was obtained — this arm cannot separate evidence from payload if the evidence never arrived"
target=$(grep -o "targetBlock=[0-9a-f]\{64\}" test-nodes/evm1/debug.log | head -1 | cut -d= -f2)
if [ -z "$target" ]; then
  fail "no verified target was ever logged"
elif [ "0x$target" = "$certifiedHash" ]; then
  pass "the verified target is ${certifiedHash:0:18}…, the survivors' certified block"
else
  fail "the verified target 0x$target is not the certified block $certifiedHash"
fi

# 2. THE RESULT OF THIS ARM.
unhelpfulHead=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read the subject's executor"; exit 1; }
unhelpfulNum=$(dec "$(echo "$unhelpfulHead" | cut -d' ' -f1)")
unavailable=$(linesSince "$unhelpfulMark" "outcome=payload-unavailable" test-nodes/evm1/debug.log)
invalid=$(linesSince "$unhelpfulMark" "outcome=payload-invalid" test-nodes/evm1/debug.log)
adopted=$(linesSince "$unhelpfulMark" "recovered from authenticated" test-nodes/evm1/debug.log)
signed=$(linesSince "$unhelpfulMark" "submitting block certification request" test-nodes/evm1/debug.log)
if $acquiredFromBystanders; then
  # Not the expected outcome, and not something to report as a discovery either: the bystanders were
  # checked by hash not to hold these blocks, at the start of the arm and at the end. If the subject
  # reached the block anyway, two checked facts contradict and the run cannot be interpreted.
  armResult="unexpected-acquisition"
  fail "RESULT — UNEXPECTED: the subject reached block $unhelpfulNum although every bystander answered 'absent' for both missing blocks throughout. Two checked observations contradict, so this run does not measure the bound"
elif [ "$unhelpfulNum" = "$preOutageNum" ] && [ "$unavailable" -ge 1 ] && [ "$invalid" = "0" ] \
     && [ "$adopted" -eq 0 ] && [ "$signed" -eq 0 ]; then
  armResult="not-acquired"
  info "RESULT — NOT ACQUIRED FROM UNHELPFUL PEERS: after ${armSecs}s connected to $connected peer(s) that do not hold the blocks, the executor is still on block $unhelpfulNum, not $certifiedNum"
  pass "and it is a valid negative measurement, not a broken observation: $unavailable payload-unavailable outcome(s) in this arm, never invalid ($invalid), nothing adopted ($adopted), nothing signed ($signed), the verified target retained"
else
  armResult="invalid-observation"
  fail "the unhelpful arm neither acquired the block nor failed closed cleanly: head=$unhelpfulNum (expected $preOutageNum) unavailable=$unavailable invalid=$invalid adopted=$adopted signed=$signed"
fi
# 3. WHAT THE CLIENT ITSELF DID. The negative is much weaker if the client never asked: "no peer had
#    it" and "it never looked" produce the same head. Its own trace settles that — it entered syncing
#    on the forkchoice update, and no block bearing the certified hash was ever downloaded.
sed $'s/\033\\[[0-9;]*m//g' test-nodes/reth1/reth.log >test-nodes/reth1/reth-plain.log 2>/dev/null \
  || { fail "could not snapshot the session trace"; exit 1; }
triedInArm=$(linesBetween "$unhelpfulAt" "$unhelpfulEnd" "forkchoice updated message when syncing" test-nodes/reth1/reth-plain.log) \
  || { fail "could not read the client's trace for the unhelpful arm"; exit 1; }
gotInArm=$(linesBetween "$unhelpfulAt" "$unhelpfulEnd" "on_downloaded_block{block_hash=$certifiedHash" test-nodes/reth1/reth-plain.log) \
  || { fail "could not read the client's download trace for the unhelpful arm"; exit 1; }
if [ "$triedInArm" -ge 1 ] && [ "$gotInArm" = "0" ]; then
  pass "the client ASKED and got nothing: it entered syncing on the forkchoice update ($triedInArm), and downloaded no block bearing the certified hash in the whole arm ($gotInArm)"
else
  fail "the unhelpful arm does not distinguish 'no peer had it' from 'it never looked': syncing-forkchoice=$triedInArm downloads-of-target=$gotInArm"
fi

grep -q "NON-VOTING" test-nodes/evm1/debug.log \
  && pass "unhelpful arm: still NON-VOTING (P-sign, #105)" \
  || fail "unhelpful arm: the resumed process did not declare itself non-voting"
unhelpfulBlocks=$(nonQuietSince "$unhelpfulMark" $providerLogs)
[ "$unhelpfulBlocks" = "0" ] \
  && pass "unhelpful arm: no provider logged a non-quiet request while it ran" \
  || fail "unhelpful arm: $unhelpfulBlocks non-quiet request(s) while it ran"
cp test-nodes/evm1/debug.log test-nodes/evm1/unhelpful.log
snapshot "phase=unhelpful-arm-end"

echo
reached="section 4: the control arm"
echo "=== 4. HELPFUL: the survivors are added, and nothing else changes ==="
# WITHOUT THIS ARM THE ONE ABOVE MEANS NOTHING. "It did not acquire the blocks" and "it had stopped
# trying" produce the same head. The node is not restarted, no flag changes, no transaction is
# submitted, the bystanders stay connected — the only difference is that peers which HAVE the blocks
# are now among its sessions.
controlMark=$(markNow)
controlAt=$(markNowUTC)
note "adding the survivors as execution peers"
for _ in $(seq 1 20); do
  for i in $(seq 2 "$validators"); do
    rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_addPeer "[\"${enodes[1]}\"]" >/dev/null 2>&1
    rpc "http://127.0.0.1:$rethEthBase" admin_addPeer "[\"${enodes[$i]}\"]" >/dev/null 2>&1
  done
  sleep 3
  ids=$(peerIds "http://127.0.0.1:$rethEthBase" 2>/dev/null) || ids=""
  hasSurvivor=false
  for sid in "${survivorIDs[@]}"; do printf '%s\n' "$ids" | grep -qx "$sid" && hasSurvivor=true; done
  $hasSurvivor && break
done
$hasSurvivor \
  && pass "the subject now holds a session with a survivor, which does have the blocks" \
  || fail "the subject never connected to a survivor, so the control arm did not run"

if waitForHead "http://127.0.0.1:$rethEthBase" "$certifiedNum" 180; then
  controlResult="acquired"
  recovered=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read the subject's executor"; exit 1; }
  recoveredNum=$(dec "$(echo "$recovered" | cut -d' ' -f1)")
  recoveredHash=$(echo "$recovered" | cut -d' ' -f2)
  recoveredRoot=$(echo "$recovered" | cut -d' ' -f3)
  if [ "$recoveredHash" = "$certifiedHash" ] && [ "$recoveredNum" = "$certifiedNum" ] && [ "$recoveredRoot" = "$certifiedRoot" ]; then
    pass "CONTROL — ACQUIRED: adding peers that hold the blocks, and nothing else, took the subject from block $preOutageNum to block $recoveredNum $recoveredHash at the certified state"
  else
    fail "the subject moved but not to the certified block: $recoveredNum ${recoveredHash:0:18}… at $recoveredRoot"
  fi
  same=0
  for tx in "${missedTx[@]}"; do
    mine=$(receiptIdentity "http://127.0.0.1:$rethEthBase" "$tx") || { fail "no receipt for $tx on the subject"; continue; }
    theirs=$(receiptIdentity "$peerEth" "$tx") || { fail "no receipt for $tx on a survivor"; continue; }
    [ "$mine" = "$theirs" ] && same=$((same + 1)) || fail "receipt for $tx differs: subject '$mine', survivor '$theirs'"
  done
  [ "$same" = "${#missedTx[@]}" ] \
    && pass "every missed transaction has the same receipt identity on the subject as on a survivor ($same of ${#missedTx[@]})" || true
  [ "$(waitForLinesSinceAll "$controlMark" test-nodes/evm1/debug.log 1 60 \
        "recovered from authenticated evidence" "blockHash=${certifiedHash#0x}")" -ge 1 ] \
    && pass "and ADOPTION followed ACQUISITION in this arm: the node recorded adopting ${certifiedHash:0:18}…, the same block the client downloaded — two separate completion conditions, both reached" \
    || fail "the executor ACQUIRED block $certifiedNum but the node never recorded ADOPTING ${certifiedHash:0:18}… in this arm within 60s: canonicalisation and adoption are separate, and only the first happened"

  # THE TWO INSTANTS, read only NOW — after the wait above has established that both happened, and
  # from a FRESH snapshot of the client's log.
  #
  # An earlier revision recorded them before the wait and from the snapshot taken in the previous
  # section, so the manifest said "none" for facts the assertions had just confirmed: a record
  # written before the thing it records, out of a file older than the event. Two of four runs showed
  # it for adoption and all four for acquisition, and neither was a failure of the run.
  sed $'s/\033\\[[0-9;]*m//g' test-nodes/reth1/reth.log >test-nodes/reth1/reth-plain.log 2>/dev/null \
    || { fail "could not snapshot the client trace after the control arm"; exit 1; }
  controlAcquiredAt=$(printLinesFrom "$controlAt" test-nodes/reth1/reth-plain.log 2>/dev/null \
    | grep "Canonical chain committed.*hash=$certifiedHash" | head -1 | awk '{print $1}')
  controlAdoptedAt=$(python3 "$f6bEvents" --mode show \
      --from "$controlMark" --pattern "recovered from authenticated evidence" \
      --pattern "blockHash=${certifiedHash#0x}" test-nodes/evm1/debug.log 2>/dev/null \
    | head -1 | awk '{print $1}' | sed 's/^time=//')
  # ONE CLOCK. The execution client logs UTC and the node logs local time with an offset; recording
  # them side by side as they come makes a two-millisecond gap read as a three-hour one. The raw node
  # stamp is kept alongside so the artifact can still be grepped for it.
  controlAdoptedRaw=$controlAdoptedAt
  controlAdoptedAt=$(python3 -c "
import sys
from datetime import datetime, timezone
v = '$controlAdoptedRaw'
print(datetime.fromisoformat(v).astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z' if v else '')
" 2>/dev/null)

  # AND THE RECORD MUST NOT BE EMPTY WHERE SOMETHING HAPPENED, NOR OUT OF ORDER. A manifest that says
  # "none" for a fact the run asserted is worse than a failing check, because it reads as a
  # measurement; one that puts adoption before acquisition would be describing something that did not
  # happen.
  if [ -z "$controlAcquiredAt" ] || [ -z "$controlAdoptedAt" ]; then
    fail "the control arm succeeded but its record is incomplete: ACQUIRED='${controlAcquiredAt:-none}' ADOPTED='${controlAdoptedAt:-none}'"
  elif ! [[ "$controlAcquiredAt" =~ Z$ && "$controlAdoptedAt" =~ Z$ ]]; then
    fail "the two recorded instants are not both UTC: ACQUIRED='$controlAcquiredAt' ADOPTED='$controlAdoptedAt'"
  elif [[ "$controlAcquiredAt" > "$controlAdoptedAt" ]]; then
    fail "the record puts ADOPTED ($controlAdoptedAt) before ACQUIRED ($controlAcquiredAt), which is not the order these happen in"
  else
    pass "and both instants are recorded on one clock and in order: ACQUIRED $controlAcquiredAt, then ADOPTED $controlAdoptedAt"
  fi
else
  controlResult="not-acquired"
  stuckNum=$(dec "$(blockAt "http://127.0.0.1:$rethEthBase" latest | cut -d' ' -f1)")
  fail "CONTROL FAILED: 180s after peers that hold the blocks were added, the subject is still on block $stuckNum. Without this arm succeeding, the negative above cannot be attributed to the peers rather than to the node having stopped trying"
fi

signed=$(countIn test-nodes/evm1/debug.log "submitting block certification request")
if grep -q "NON-VOTING" test-nodes/evm1/debug.log && [ "$signed" -eq 0 ]; then
  pass "signing refusal unchanged throughout: NON-VOTING, and it signed nothing in either arm (P-sign, #105)"
else
  fail "the subject must not sign: NON-VOTING=$(countIn test-nodes/evm1/debug.log NON-VOTING) submissions=$signed"
fi
controlBlocks=$(nonQuietSince "$controlMark" $providerLogs)
[ "$controlBlocks" = "0" ] \
  && pass "control arm: no provider logged a non-quiet request while it ran — nothing new was executed to help it" \
  || fail "control arm: $controlBlocks non-quiet request(s) while it ran"
for i in $(seq 2 "$validators"); do
  assertTransactionCount "survivor $i" "http://127.0.0.1:$((rethEthBase + i - 1))" "$setupTxs" \
    "the same $setupTxs submitted before the subject returned, and nothing since"
done
snapshot "phase=end"

# AND THE CONTROL NAMES THE SOURCE. Same two questions, opposite answers, one variable apart.
sed $'s/\033\\[[0-9;]*m//g' test-nodes/reth1/reth.log >test-nodes/reth1/reth-plain.log 2>/dev/null \
  || { fail "could not snapshot the session trace"; exit 1; }
if [ "${controlResult:-}" = "acquired" ]; then
  gotInControl=$(linesFrom "$controlAt" "on_downloaded_block{block_hash=$certifiedHash" test-nodes/reth1/reth-plain.log) \
    || { fail "could not read the client's download trace for the control arm"; exit 1; }
  sessInControl=$(linesFrom "$controlAt" "Session established" test-nodes/reth1/reth-plain.log) \
    || { fail "could not read the client's session trace for the control arm"; exit 1; }
  if [ "$sessInControl" -ge 1 ] && [ "$gotInControl" -ge 1 ]; then
    pass "the client names the source: $sessInControl session(s) established with peers that hold the blocks, and the certified block then arrives as a DOWNLOADED block ($gotInControl) — the same client, the same target, the same forkchoice, different peers"
  else
    fail "the executor reached the block but the control trace does not show it downloaded after a session: sessions=$sessInControl downloads-of-target=$gotInControl"
  fi
fi

info "the subject's execution client, from the moment the survivors were added at $controlAt:"
printLinesFrom "$controlAt" test-nodes/reth1/reth-plain.log 2>/dev/null \
  | grep -Ei "Session established|DownloadedBlocks|on_downloaded_block\{|Received forkchoice|Block added to canonical chain|Canonical chain committed" \
  | sed -E 's/(on_downloaded_block\{[^}]*\}).*/\1/' \
  | awk '{ k = $0; sub(/^[^ ]+ /, "", k); if (!(k in seen)) { seen[k]; print } }' \
  | cut -c1-150 | head -12 | sed 's/^/    /'

reached="all sections"
echo
echo "=== 5. provenance ==="
outOfOrder=$(awk '{ if ($1 < prev) n++; prev = $1 } END { print n + 0 }' "$connLog" 2>/dev/null)
[ "${outOfOrder:-1}" = "0" ] \
  && pass "the connectivity record's $(grep -c "" "$connLog") entries are in non-decreasing time order" \
  || fail "the connectivity record has $outOfOrder entry/entries out of time order"

manifestLines=(
  "subject:         validator 1 (reth1)"
  "bystanders:      $bystanders reth clients on the same spec, driven by no shard node, never peered to a validator"
  "bft transport:   untouched throughout"
  "subject log:     --log-level debug; reth1 --log.stdout.filter debug"
  "setup txs:       $setupTxs, all before the subject returned; none in either arm"
  "executor before: block $preOutageNum $preOutageHash"
  "certified head:  block $certifiedNum $certifiedHash"
  "missing blocks:  $certifiedHash and its parent $missedParentHash"
  "expected block:  $certifiedHash"
  "phase isolated:  $isolationAt -> $isolationEnd"
  "phase unhelpful: $unhelpfulAt -> $unhelpfulEnd"
  "phase control:   from $controlAt"
  "UNHELPFUL arm:   $armResult"
  "  ACQUIRED:      no — no canonical commit of the expected block in the arm; ${unavailable:-?} payload-unavailable outcomes"
  "  ADOPTED:       no — nothing adopted, nothing signed, head stayed at ${unhelpfulNum:-unknown}"
  "HELPFUL control: ${controlResult:-not-run}"
  "  ACQUIRED:      ${controlAcquiredAt:-none} (executor canonicalised the expected block)"
  "  ADOPTED:       ${controlAdoptedAt:-none} (node recorded adopting that block hash; node log reads ${controlAdoptedRaw:-none})"
)
if writeManifest; then
  pass "run artifact written to $artifactDir"
  cat "$artifactDir/manifest.txt"
else
  fail "no run artifact could be written, so this run is not evidence"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "ALL CHECKS PASSED (reth $rethCommit) — unhelpful: $armResult, control: ${controlResult:-not-run} — artifact: $artifactDir"
else
  echo "$failures CHECK(S) FAILED — unhelpful: ${armResult:-not-run}, control: ${controlResult:-not-run} — artifact: $artifactDir"
fi
exit $((failures > 0))
