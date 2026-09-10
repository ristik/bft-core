#!/bin/bash
# f6b-missed-block-recovery.sh - the second acceptance run for #92: does a node that was DOWN while a
# real block was certified recover to that exact block, against a real reth, with no new activity
# helping it?
#
# WHY A SECOND LANE. scripts/f6b-quiet-tail-recovery.sh answers the quiet-tail question and says so,
# but it names one thing it does NOT establish (§6.6 of the design, and the run's own output):
#
#     Not exact-block recovery against an ordinary block. It exercises the genesis-round anchor,
#     because that is the only anchor a shard with no transactions ever has — so row 13's exception
#     is what satisfied P-id there, not a head-hash match against an ordinary certified block.
#
# That exception is deliberately narrow (shardnode/anchor.go: "the executor is at its own genesis
# block, at the certified state"), and a lane that only ever exercises it has not measured P-id's
# ordinary comparison at all. THIS lane is constructed so the exception cannot apply: by the time
# the outage begins the executor is past its genesis block, and the anchor recovered is an ordinary
# certified block whose hash is a real EVM block hash. If the genesis exception were widened to
# admit this run, the run would still pass — which is why the assertions below check the executor's
# head number and hash directly rather than inferring recovery from the absence of a refusal.
#
# THE SHAPE, and where the transactions are allowed to be:
#
#   SETUP     a funded chain spec, and one transaction that makes the shard build, certify and
#             commit a real block on every executor. This is what gives the run an ordinary anchor.
#   OUTAGE    validator 1's shard node is stopped. Its reth keeps running and is NOT told anything,
#             so it stays at the block it had. More transactions are submitted to a peer, the
#             remaining validators certify further real blocks, and validator 1's executor misses
#             them. Injection STOPS here, and the shard is allowed to go quiet.
#   CONTROL   validator 1 returns with recovery off (the default). It must refuse for ever, and its
#             executor must not advance on its own.
#   RECOVERY  validator 1 returns with --evidence-recover, and nothing else differs. It must obtain
#             authenticated evidence, drive its executor to the certified block, satisfy P-id by an
#             exact block-hash match, and STILL not vote.
#
# No transaction is submitted from the moment validator 1 comes back, in either arm, and the lane
# asserts that by counting: the transaction total on every executor must be exactly the setup total,
# before and after. "Recovery came from new activity" is the F1 baseline's failure (§1) and it is
# the one result this lane must be unable to report by accident.
#
# Usage:  ./scripts/f6b-missed-block-recovery.sh [validators]   # default 3
#         ./scripts/f6b-missed-block-recovery.sh --self-test    # no reth, no root chain
# Needs:  a pinned reth, curl, openssl, python3, go, and a built ./build/ubft. Run from the repo root.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Argument handling before anything reads $1: --self-test is a mode, not a validator count.
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

# The assertion helpers, the manifest writer and the self-test are SHARED with
# scripts/f6b-quiet-tail-recovery.sh — see the library header for why there is exactly one copy.
source "$(dirname "${BASH_SOURCE[0]}")/lib/f6b-acceptance-lib.sh"

artifactDir="${F6B_ARTIFACT_DIR:-artifacts/f6b-missed-block/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
manifestTitle="f6b missed-block recovery acceptance run"
manifestLogs="test-nodes/evm1/control.log $(seq -f "test-nodes/evm%g/debug.log" 1 "$validators" | tr '\n' ' ')$(seq -f " test-nodes/reth%g/reth.log" 1 "$validators" | tr -d '\n')"
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

stale=$(pgrep -f 'ubft shard-node run' 2>/dev/null || true)
if [ -n "$stale" ]; then
  echo "refusing to start: shard-node processes are already running (pids: $(echo $stale | tr '\n' ' '))" >&2
  echo "  pkill -f 'ubft shard-node run'" >&2
  exit 1
fi

cleanup() {
  # The artifact is part of the result, so failing to write one fails the run — including from here,
  # where the exit status has otherwise already been decided. A trap can still set it.
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

# sendTx submits one transfer from the well-known test account and echoes its hash. Like every other
# helper that runs inside a command substitution, it reports failure by status and stderr, never by
# calling fail(): see the library header.
sendTx() { # sendTx <ethURL> <nonce>
  local out
  out=$(go run ./scripts/evmtx -send -eth-url "$1" -chain-id "$chainID" -nonce "$2" 2>&1) || {
    echo "evmtx failed for nonce $2: $out" >&2; return 1; }
  isHash32 "$out" || { echo "evmtx returned no transaction hash for nonce $2: $out" >&2; return 1; }
  printf '%s' "$out"
}

# waitForReceipt echoes the block number the transaction landed in.
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

reached="section 1: a funded chain with a real, ordinary block"
echo "=== 1. a real block, so the anchor is an ordinary one ==="
rm -rf test-nodes
./setup-evm-nodes.sh -r 3 -v "$validators" >/dev/null || { echo "setup failed" >&2; exit 1; }

# The generated genesis has an empty alloc, so no account can pay for gas and the shard can only
# certify quiet rounds — which is exactly what the quiet-tail lane wants and exactly what this lane
# cannot use. Fund one well-known test account, derived from the generated file so the chainId and
# fork schedule still come from the shard conf. Real genesis funding is T1 (#28); this is test-only.
python3 - <<'PY' || { echo "could not fund the test genesis" >&2; exit 1; }
import json, subprocess
g = json.load(open("test-nodes/evm-genesis.json"))
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
json.dump(g, open("test-nodes/evm-genesis-funded.json", "w"), indent=2)
PY
chainSpec=test-nodes/evm-genesis-funded.json
info "funded chain spec $(shasum -a 256 "$chainSpec" | cut -d' ' -f1)"

for i in $(seq 1 "$validators"); do
  mkdir -p "test-nodes/reth$i"
  openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  reth node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) \
    --http.api eth,net,web3,admin,txpool \
    --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
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
for i in $(seq 1 "$validators"); do
  enode=$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_nodeInfo '[]' | pyget "['result']['enode']")
  for j in $(seq 1 "$validators"); do
    [ "$i" = "$j" ] && continue
    rpc "http://127.0.0.1:$((rethEthBase + j - 1))" admin_addPeer "[\"$enode\"]" >/dev/null
  done
done
pass "$validators reth instances up and peered on the funded chain spec"

# THE EXECUTOR GENESIS, recorded now, because it is the thing row 13's exception compares against and
# therefore the thing this lane must show the recovered anchor is NOT.
genesisBlock=$(blockAt "http://127.0.0.1:$rethEthBase" 0x0) || { fail "could not read executor 1's genesis block"; exit 1; }
genesisHash=$(echo "$genesisBlock" | cut -d' ' -f2)
genesisRoot=$(echo "$genesisBlock" | cut -d' ' -f3)
info "executor 1 genesis block $genesisHash at state $genesisRoot"

for i in $(seq 1 "$validators"); do
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))"
  export "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
done
./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1 || {
  fail "devnet did not start"; tail -20 test-nodes/start-evm.log >&2; exit 1; }
waitFor test-nodes/evm1/debug.log "accepted certificate" 3 120 || { fail "the shard never certified 3 rounds"; exit 1; }

# SETUP TRANSACTION 1, submitted while every validator including validator 1 is up. Its whole purpose
# is to move every executor off its genesis block, so that the anchor this run recovers cannot be the
# genesis-round anchor and row 13 cannot be what satisfies P-id.
setupTxs=0
tx0=$(sendTx "http://127.0.0.1:$rethEthBase" 0) || { fail "could not submit the first setup transaction"; exit 1; }
setupTxs=$((setupTxs + 1))
blk0=$(waitForReceipt "http://127.0.0.1:$rethEthBase" "$tx0" 90) || { fail "the first setup transaction was never certified"; exit 1; }
pass "setup transaction 1 executed in block $(dec "$blk0") on validator 1's executor"

for i in $(seq 1 "$validators"); do
  waitForHead "http://127.0.0.1:$((rethEthBase + i - 1))" "$(dec "$blk0")" 90 \
    || { fail "executor $i never reached block $(dec "$blk0")"; exit 1; }
done
preOutage=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read executor 1's head"; exit 1; }
preOutageNum=$(dec "$(echo "$preOutage" | cut -d' ' -f1)")
preOutageHash=$(echo "$preOutage" | cut -d' ' -f2)
preOutageRoot=$(echo "$preOutage" | cut -d' ' -f3)

# THE PRECONDITION THIS LANE EXISTS FOR, asserted rather than assumed. If any of these three fails,
# every later "exact-block recovery" claim would be a claim about the genesis exception again.
if [ "$preOutageNum" -ge 1 ] && [ "$preOutageHash" != "$genesisHash" ] && [ "$preOutageHash" != "$preOutageRoot" ]; then
  pass "validator 1's executor is past genesis before the outage: block $preOutageNum ${preOutageHash:0:18}…, which is neither its genesis block nor a state root"
else
  fail "validator 1's executor is not on an ordinary block before the outage: number=$preOutageNum hash=$preOutageHash genesis=$genesisHash stateRoot=$preOutageRoot"
  exit 1
fi

# The root bootnode, computed the way helper.sh computes it rather than scraped from a log: the log
# format is not a contract, and a scrape that silently returns empty produces a validator with no
# bootnodes and an assertion failure that says nothing about why.
rootBoot=$(boot_node test-nodes/root1 "$rootBootPort")
[ -n "$rootBoot" ] || { fail "could not determine the root bootnode address"; exit 1; }
info "root bootnode $rootBoot"

stopValidator1() {
  [ -f test-nodes/evm1/pid ] && kill "$(cat test-nodes/evm1/pid)" 2>/dev/null
  sleep 3
}

# restartValidator1 <extra args...> — the same command line helper.sh builds, plus this lane's flags.
# Its reth is untouched: what the node lost is its own process state, and what its EXECUTOR lost is
# every block certified while the node was gone.
restartValidator1() {
  stopValidator1
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
reached="section 2: the outage, and the blocks missed during it"
echo "=== 2. the outage: real blocks are certified while validator 1 is gone ==="
stopValidator1
pass "validator 1's shard node stopped at executor block $preOutageNum — its reth keeps running and is told nothing"

# THE TRANSACTIONS THAT CREATE THE MISSED BLOCKS, submitted to a PEER while validator 1 is down, and
# the last ones this run submits at all. Everything after this point — both arms — happens on a shard
# with nothing left to execute, which is what makes the recovery attributable to the evidence rather
# than to new activity.
peerEth="http://127.0.0.1:$((rethEthBase + 1))"
for nonce in 1 2; do
  tx=$(sendTx "$peerEth" "$nonce") || { fail "could not submit setup transaction $((nonce + 1))"; exit 1; }
  setupTxs=$((setupTxs + 1))
  blk=$(waitForReceipt "$peerEth" "$tx" 120) || { fail "setup transaction $((nonce + 1)) was never certified"; exit 1; }
  info "transaction $((nonce + 1)) executed in block $(dec "$blk") on a peer, with validator 1 down"
done
info "no transaction is submitted from here on, in either arm"

# EVERY REMAINING VALIDATOR AGREES ON THE CERTIFIED HEAD. The lane compares validator 1's recovered
# anchor against this block, so reading it from ONE peer would compare the recovering node against a
# single unverified opinion. They must all say the same thing, or there is no certified block to
# name.
certifiedHash=""
for i in $(seq 2 "$validators"); do
  b=$(blockAt "http://127.0.0.1:$((rethEthBase + i - 1))" latest) || { fail "could not read executor $i's head"; exit 1; }
  h=$(echo "$b" | cut -d' ' -f2)
  if [ -z "$certifiedHash" ]; then
    certifiedNum=$(dec "$(echo "$b" | cut -d' ' -f1)")
    certifiedHash=$h
    certifiedRoot=$(echo "$b" | cut -d' ' -f3)
  elif [ "$h" != "$certifiedHash" ]; then
    fail "the validators that stayed up do not agree on the head: $certifiedHash vs $h"
    exit 1
  fi
done
if [ "$certifiedNum" -gt "$preOutageNum" ]; then
  pass "the shard certified through block $certifiedNum ${certifiedHash:0:18}… while validator 1 was down — $((certifiedNum - preOutageNum)) block(s) it never saw"
else
  fail "no block was certified during the outage: head is still $certifiedNum"
  exit 1
fi

# THE EXECUTOR REALLY IS BEHIND. This is the property the whole lane rests on, and it is also the
# first half of §8's open question, measured rather than assumed: a reth that is peered and gossiping
# does NOT advance its canonical head on its own, because nothing told it to.
behind=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read validator 1's executor"; exit 1; }
behindNum=$(dec "$(echo "$behind" | cut -d' ' -f1)")
if [ "$behindNum" = "$preOutageNum" ] && [ "$(echo "$behind" | cut -d' ' -f2)" = "$preOutageHash" ]; then
  pass "validator 1's executor is still at block $behindNum: a running, peered reth does not canonicalise a certified block nobody told it about"
else
  fail "validator 1's executor moved during the outage without being told: $behindNum vs $preOutageNum"
  exit 1
fi

# AND THE SHARD IS QUIET AGAIN, so the returning node is not handed a non-quiet certificate that
# would name the block for it. That is how the F1 baseline "recovered" (§1) and it is the one way
# this lane must not.
# A QUIET TAIL AS OF NOW, not four quiet rounds somewhere in the file. The root chain hands a
# returning node the LATEST certificate, so if the newest certificate is still the non-quiet one that
# names the missed block, the node is handed the answer and recovers by the live path — the F1
# baseline's "recovery from new activity" (§1), inside the lane built to rule it out. An earlier
# version of this wait counted cumulatively, was satisfied by quiet rounds from before the
# transactions were even submitted, and lost that race once in four runs.
providerLogs=""
for i in $(seq 2 "$validators"); do providerLogs="$providerLogs test-nodes/evm$i/debug.log"; done
quietTail=$(waitForQuietTail 4 180 $providerLogs) \
  || { fail "the shard never went quiet after the last transaction: tail is $quietTail quiet round(s)"; exit 1; }
pass "the shard is quiet again: $quietTail quiet rounds since the last block, so the newest certificate names nothing"

assertTransactionCount "before the first restart" "$peerEth" "$setupTxs" "all of them submitted before validator 1 returned"

echo
reached="section 3: control arm"
echo "=== 3. CONTROL: the same node with recovery off stays behind for ever ==="
controlMark=$(markNow)
restartValidator1
waitFor test-nodes/evm1/debug.log "accepted certificate" 5 120 || { fail "the restarted node received no certificates"; exit 1; }

# The refusal here is NOT the quiet-tail lane's abstention. This node's executor state does not match
# the certified state at all, so it refuses inside reconcile — "cannot identify the certified block
# to recover to" — and never reaches the vote. Both texts are matched because both are refusals of
# the same question, and which one a given round produces depends on where the node is standing.
controlRefusals=$(countIn test-nodes/evm1/debug.log "cannot identify the certified block to recover to\|cannot prove the executor is on the certified block\|cannot prove its executor is on the certified block")
controlCerts=$(countIn test-nodes/evm1/debug.log "accepted certificate")
controlAdopted=$(countIn test-nodes/evm1/debug.log "recovered from authenticated")
controlSigned=$(countIn test-nodes/evm1/debug.log "submitting block certification request")
if [ "$controlRefusals" -ge 1 ] && [ "$controlAdopted" -eq 0 ] && [ "$controlSigned" -eq 0 ]; then
  pass "recovery off: refused over $controlCerts certificates, adopted no anchor and signed nothing"
else
  fail "control arm did not refuse as §1 describes: refusals=$controlRefusals adopted=$controlAdopted signed=$controlSigned over $controlCerts certificates"
fi

# THE CONTROL'S REAL CONTENT. A node that refuses is not interesting on its own; a node whose
# EXECUTOR is still on the wrong block after five certificates is. This is what the recovery arm has
# to change, and it is measured on the same executor, the same devnet, one flag apart.
controlHead=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read validator 1's executor in the control arm"; exit 1; }
controlNum=$(dec "$(echo "$controlHead" | cut -d' ' -f1)")
if [ "$controlNum" = "$preOutageNum" ] && [ "$(echo "$controlHead" | cut -d' ' -f2)" = "$preOutageHash" ]; then
  pass "recovery off: the executor is STILL at block $controlNum while the shard is certified through $certifiedNum — the missed block is not recovered by returning"
else
  fail "the executor moved with recovery off: block $controlNum, expected to still be $preOutageNum"
fi
grep -q "NON-VOTING" test-nodes/evm1/debug.log \
  && pass "control: the resumed process is NON-VOTING (P-sign, #105)" \
  || fail "control: the resumed process did not declare itself non-voting"
assertTransactionCount "control arm" "$peerEth" "$setupTxs" "nothing new executed while the node was refusing"
# AND NO BLOCK WAS CERTIFIED WHILE THE ARM RAN. This is the direct form of "no new activity helped
# it": not "no transaction was submitted", which is a statement about what this script did, but "no
# non-quiet round was certified", which is a statement about what the shard did.
controlBlocks=$(nonQuietSince "$controlMark" $providerLogs)
if [ "$controlBlocks" = "0" ]; then
  pass "control arm: not one non-quiet round was certified while it ran — nothing arriving could have named the missed block"
else
  fail "control arm: $controlBlocks non-quiet round(s) were certified while it ran, so the arm was not run over a quiet shard"
fi
cp test-nodes/evm1/debug.log test-nodes/evm1/control.log

echo
reached="section 4: recovery arm"
echo "=== 4. RECOVERY: the same node, same devnet, --evidence-recover ==="
recoveryMark=$(markNow)
restartValidator1 --evidence-recover
waitFor test-nodes/evm1/debug.log "accepted certificate" 6 180 || { fail "the restarted node received no certificates"; exit 1; }
# The applier commits, and a reth that does not hold the block reports SYNCING — a retryable outcome
# by design, renewed by each new certificate. So the wait is for the executor, not for a log line.
waitForHead "http://127.0.0.1:$rethEthBase" "$certifiedNum" 120 \
  || info "validator 1's executor had not reached block $certifiedNum within 120s; the assertions below say what it did reach"
# Then give the node several more certificates to refuse on if it is still going to. "It stopped
# refusing" measured over one certificate is not a measurement, and the fetch is background work, so
# the first certificates after the restart legitimately refuse while evidence is still being obtained.
# Counted from the ADOPTION, not from here: see waitForLinesAfter.
waitForLinesAfter test-nodes/evm1/debug.log "recovered from authenticated" "accepted certificate" 3 120 >/dev/null \
  || info "fewer than 3 certificates arrived after adoption within 120s; the count below says how many"

grep -q "anchor recovery finished.*state=ready" test-nodes/evm1/debug.log \
  && pass "authenticated evidence obtained from a peer: $(grep -o 'attempts=[0-9]* restarts=[0-9]*' test-nodes/evm1/debug.log | head -1)" \
  || fail "no evidence was obtained"

# THE ANCHOR, taken from the applier's own line rather than from any hash that happens to appear in
# the log, and compared against the block the validators that stayed up agree on. `%x` renders it
# without the 0x prefix the RPC uses, so the comparison is made in one form deliberately.
adopted=$(grep "recovered from authenticated evidence" test-nodes/evm1/debug.log | grep -o 'blockHash=[0-9a-f]\{64\}' | head -1 | cut -d= -f2)
if [ -z "$adopted" ]; then
  fail "no anchor was adopted: the applier never reported a recovered block"
elif [ "0x$adopted" = "$certifiedHash" ]; then
  pass "EXACT-BLOCK RECOVERY: the anchor adopted is ${certifiedHash:0:18}…, the block the validators that stayed up certified — not merely a matching state"
else
  fail "the adopted anchor 0x$adopted is not the certified block $certifiedHash"
fi

# AND THE GENESIS EXCEPTION IS NOT WHAT ALLOWED IT. Row 13 permits a head that is the executor's own
# genesis block at the certified state, and only for the shard's first certified round. Every clause
# of it is denied here, explicitly, because this is the whole reason the lane exists.
recovered=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read validator 1's executor after recovery"; exit 1; }
recoveredNum=$(dec "$(echo "$recovered" | cut -d' ' -f1)")
recoveredHash=$(echo "$recovered" | cut -d' ' -f2)
recoveredRoot=$(echo "$recovered" | cut -d' ' -f3)
if [ "$recoveredHash" = "$certifiedHash" ] && [ "$recoveredNum" = "$certifiedNum" ]; then
  pass "P-id is satisfied by a head-hash match: the executor's head is block $recoveredNum $recoveredHash, moved from block $preOutageNum by the recovery"
else
  fail "the executor did not reach the certified block: head is $recoveredNum ${recoveredHash:0:18}…, certified is $certifiedNum ${certifiedHash:0:18}…"
fi
if [ "$recoveredNum" -gt 0 ] && [ "$recoveredHash" != "$genesisHash" ] && [ "$recoveredHash" != "$recoveredRoot" ]; then
  pass "row 13 cannot account for this: the head is block $recoveredNum, not the executor's genesis block, and its hash is not a state root"
else
  fail "the recovered head is one row 13 would have admitted: number=$recoveredNum hash=$recoveredHash genesis=$genesisHash stateRoot=$recoveredRoot"
fi
if [ "$recoveredRoot" = "$certifiedRoot" ]; then
  pass "and the block it reached produced the certified state $recoveredRoot"
else
  fail "the executor is on the certified block at the wrong state: $recoveredRoot, certified $certifiedRoot"
fi

# THE REFUSAL STOPS. Adoption is not the claim; ceasing to refuse afterwards is, because the identity
# check is the thing that was refusing.
adoptLine=$(grep -n "recovered from authenticated" test-nodes/evm1/debug.log | head -1 | cut -d: -f1)
if [ -n "$adoptLine" ]; then
  after=$(tail -n +"$adoptLine" test-nodes/evm1/debug.log | countIn /dev/stdin "cannot identify the certified block to recover to\|abstaining from the vote")
  certsAfter=$(tail -n +"$adoptLine" test-nodes/evm1/debug.log | countIn /dev/stdin "accepted certificate")
  if [ "$after" -eq 0 ] && [ "$certsAfter" -ge 3 ]; then
    pass "not one refusal in the $certsAfter certificates after adoption"
  else
    fail "still refusing after recovery: $after refusals over the $certsAfter certificates that followed"
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

# THE SAME QUESTION FOR THE ARM THAT MATTERS. If a block had been certified while this arm ran, the
# recovery would be attributable to a certificate that names the block rather than to the evidence,
# and every claim above it would be about the wrong thing.
recoveryBlocks=$(nonQuietSince "$recoveryMark" $providerLogs)
if [ "$recoveryBlocks" = "0" ]; then
  pass "recovery arm: not one non-quiet round was certified while it ran — the anchor came from the evidence, not from a certificate that named the block"
else
  fail "recovery arm: $recoveryBlocks non-quiet round(s) were certified while it ran, so this run does not separate evidence from new activity"
fi

# THE SUBJECT OF THE COMPARISON DID NOT MOVE UNDER THE LANE. certifiedHash was read at the end of
# the outage, and everything since has been compared against it. If a peer had certified another
# block in the meantime — a leader building on a transaction this lane did not submit, say — that
# value would be stale and "exact-block recovery" would be a claim about a block that is no longer
# the head. Re-read it from the same validators and require the same answer.
for i in $(seq 2 "$validators"); do
  b=$(blockAt "http://127.0.0.1:$((rethEthBase + i - 1))" latest) || { fail "could not re-read executor $i's head"; continue; }
  if [ "$(echo "$b" | cut -d' ' -f2)" = "$certifiedHash" ]; then
    pass "executor $i is still on block $certifiedNum ${certifiedHash:0:18}…: the block this run compared against never moved"
  else
    fail "executor $i moved during the arms: head is $(echo "$b" | cut -d' ' -f2), the comparison used $certifiedHash"
  fi
done

# NO NEW ACTIVITY, on every executor. This is the assertion that separates this run from the F1
# baseline, where recovery came only from a non-quiet round — that is, from a new transaction.
for i in $(seq 1 "$validators"); do
  assertTransactionCount "executor $i at the end of the run" "http://127.0.0.1:$((rethEthBase + i - 1))" "$setupTxs" \
    "the same $setupTxs submitted before validator 1 returned, and nothing since"
done

# WHERE THE BLOCK BODY CAME FROM — recorded, not claimed. §8 of the design leaves this open: the
# logs cannot distinguish "reth backfilled the missed block on receiving the forkchoice update" from
# "reth already held it via P2P gossip and merely canonicalised it now". This lane does not settle
# that either; it preserves reth1's log in the artifact and prints what it says, so the next
# measurement — a controlled peer-connectivity experiment — has a starting point rather than a guess.
info "how validator 1's reth reacted to the commit (its log is in the artifact):"
grep -E "forkchoice updated message when syncing|Block added to canonical chain|Canonical chain committed" \
  test-nodes/reth1/reth.log 2>/dev/null | tail -6 | sed $'s/\033\\[[0-9;]*m//g' | sed 's/^/    /'

reached="all sections"
echo
echo "=== 5. provenance ==="
manifestLines=(
  "control flags:   (defaults: --evidence-serve on, --evidence-recover off)"
  "recovery flags:  --evidence-recover"
  "setup txs:       $setupTxs, all before validator 1 returned"
  "executor before: block $preOutageNum $preOutageHash"
  "certified head:  block $certifiedNum $certifiedHash"
  "executor after:  block ${recoveredNum:-unknown} ${recoveredHash:-unknown}"
)
if writeManifest; then
  pass "run artifact written to $artifactDir"
  cat "$artifactDir/manifest.txt"
else
  fail "no run artifact could be written, so this run is not evidence"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "ALL CHECKS PASSED (reth $rethCommit) — artifact: $artifactDir"
else
  echo "$failures CHECK(S) FAILED — artifact: $artifactDir"
fi
exit $((failures > 0))
