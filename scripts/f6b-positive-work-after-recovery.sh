#!/bin/bash
# f6b-positive-work-after-recovery.sh - the fifth and final acceptance run for #92 (B1): after a node
# has recovered its execution anchor from authenticated evidence, does it take part in work the shard
# produces AFTERWARDS - and still not vote?
#
# WHY A FIFTH LANE. The four merged lanes all stop transaction injection at the moment the recovering
# node returns, and assert by counting that nothing new executed. That is what makes recovery
# attributable to the evidence rather than to new activity, and it is the whole reason the F1
# baseline's "recovery" was not recovery. The cost is that none of them shows the recovered node
# taking part in work produced AFTER it recovered - the one unmet clause of #92's acceptance line 4,
# recorded as B1 in docs/design/f6b-acceptance-ledger.md.
#
# THE ORDER IS THE MEASUREMENT. Adoption first, injection second, agreement third. If the transaction
# were submitted before the node had adopted its anchor, the certificate naming its block would name
# the missed block too, the node would recover by the live path, and this lane would be the F1
# baseline again wearing a different name. So the recovery phase below is preserved exactly as
# #119 built it - no transaction from the outage until adoption is established - and the injection
# mark is taken only after every recovery assertion has been made. Two checks hold the order:
#
#   * not one non-quiet round was certified between the restart and the injection mark, so nothing
#     arriving in that window could have named the missed block; and
#   * not one adoption line falls AFTER the injection mark, so the anchor this run reports was not
#     adopted on the strength of the transaction.
#
# WHAT "POSITIVE WORK AFTER" CAN MEAN HERE, which is not obvious. P-sign (#105) keeps a restored
# process non-voting for its whole lifetime, so the recovered node cannot contribute a signature to
# new work however well it recovered. "Positive work after" therefore means: the shard certifies a
# new block after the node has recovered, and the recovered node follows it, executes it, and agrees
# with the survivors on the resulting block, state and receipts. It does not, and under #105 must
# not, mean that the recovered node votes for it. That distinction is part of satisfying the line,
# and this lane asserts both halves - the agreement AND the continued silence.
#
# NO CONTROL ARM, deliberately, and this is the one thing this lane leaves to another. That a node
# with recovery off stays behind for ever is #119's result, measured on the same devnet one flag
# apart, and repeating it here would double the runtime without adding to this claim. What this lane
# must establish instead is that the node had ALREADY recovered before the transaction existed, and
# that is what the two ordering checks above do.
#
# Usage:  ./scripts/f6b-positive-work-after-recovery.sh [validators]   # default 3
#         ./scripts/f6b-positive-work-after-recovery.sh --self-test    # no reth, no root chain
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

# The assertion helpers, the transaction helpers, the manifest writer and the self-test are SHARED
# with every other lane — see the library header for why there is exactly one copy.
source "$(dirname "${BASH_SOURCE[0]}")/lib/f6b-acceptance-lib.sh"

artifactDir="${F6B_ARTIFACT_DIR:-artifacts/f6b-positive-work/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
manifestTitle="f6b positive-work-after-recovery acceptance run (B1)"
manifestLogs="$(seq -f "test-nodes/evm%g/debug.log" 1 "$validators" | tr '\n' ' ')$(seq -f " test-nodes/reth%g/reth.log" 1 "$validators" | tr -d '\n')"
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

# sendTx, waitForReceipt and dec now live in the shared library: one copy, see its header.

reached="section 1: a funded chain with a real, ordinary block"
echo "=== 1. a funded chain with a real, ordinary block ==="
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
# the last ones this run submits until the recovery is established. Everything from here to the
# injection mark in section 4 happens on a shard with nothing left to execute, which is what makes
# the recovery attributable to the evidence rather than to new activity. Section 4 is where that
# stops being true, deliberately, and only after the recovery has been asserted.
peerEth="http://127.0.0.1:$((rethEthBase + 1))"
for nonce in 1 2; do
  tx=$(sendTx "$peerEth" "$nonce") || { fail "could not submit setup transaction $((nonce + 1))"; exit 1; }
  setupTxs=$((setupTxs + 1))
  blk=$(waitForReceipt "$peerEth" "$tx" 120) || { fail "setup transaction $((nonce + 1)) was never certified"; exit 1; }
  info "transaction $((nonce + 1)) executed in block $(dec "$blk") on a peer, with validator 1 down"
done
info "no transaction is submitted from here until the recovery has been established in section 3"

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
pass "the shard is quiet again: $quietTail quiet request entries since the last non-quiet request, so the newest certificate names nothing"

assertTransactionCount "before validator 1 returned" "$peerEth" "$setupTxs" "all of them submitted while it was down"

echo
reached="section 3: recovery from evidence, with nothing new happening"
echo "=== 3. RECOVERY: the node returns with --evidence-recover, on a quiet shard ==="
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

echo
reached="section 4: positive work after recovery"
echo "=== 4. POSITIVE WORK AFTER RECOVERY: one transaction, submitted only now ==="

# THE PHASE BOUNDARY. A sub-second instant, not a whole second: a block certified 700ms into the next
# phase would otherwise belong to both windows, and one earlier run in this programme came within
# 254ms of exactly that. Everything above this mark is recovery; everything below it is new work.
injectMark=$(markNowUTC)

# ORDERING GATE 1 — NOTHING WAS CERTIFIED BEFORE THIS INSTANT. Counted over the closed window from
# the restart to the mark, not "since the restart": the latter would be evaluated later, after the
# transaction below has certified a block, and would then be a statement about the wrong interval.
quietWindow=$(linesBetween "$recoveryMark" "$injectMark" "quiet=false" $providerLogs)
if [ "$quietWindow" = "0" ]; then
  pass "ordering: not one non-quiet round was certified between the restart and this instant — nothing arriving could have named the missed block"
else
  fail "ordering: $quietWindow non-quiet round(s) were certified before the injection, so recovery is not separated from new activity"
fi

# ORDERING GATE 2 — THE ANCHOR WAS ADOPTED BEFORE THE TRANSACTION EXISTED. The count is of adoption
# lines AFTER the mark, and it must be zero. Stated this way round deliberately: "an adoption exists"
# is satisfied by an adoption at any time, including one the transaction caused.
lateAdoptions=$(linesSince "$injectMark" "recovered from authenticated evidence" test-nodes/evm1/debug.log)
totalAdoptions=$(countIn test-nodes/evm1/debug.log "recovered from authenticated evidence")
if [ "$totalAdoptions" -ge 1 ] && [ "$lateAdoptions" = "0" ]; then
  pass "ordering: all $totalAdoptions adoption(s) happened before the injection mark, and none after it"
else
  fail "ordering: adoptions=$totalAdoptions of which $lateAdoptions after the injection mark — the transaction may be what recovered this node"
fi

# AND THE NODE IS STANDING ON THE CERTIFIED BLOCK AS THIS PHASE OPENS, re-read now rather than
# carried down from the assertions above: the claim below is about a head that moves FROM here.
atInjection=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read validator 1's executor at the injection mark"; exit 1; }
atInjectionNum=$(dec "$(echo "$atInjection" | cut -d' ' -f1)")
if [ "$atInjectionNum" = "$certifiedNum" ] && [ "$(echo "$atInjection" | cut -d' ' -f2)" = "$certifiedHash" ]; then
  pass "the recovered node is on block $atInjectionNum ${certifiedHash:0:18}… as the new work begins"
else
  fail "the recovered node is not on the certified block as this phase opens: $atInjectionNum vs $certifiedNum"
  exit 1
fi

# THE TRANSACTION. One, submitted to a PEER — not to the recovered node's own executor, so that
# nothing about this depends on the recovered node being the entry point. It is the first and only
# transaction of the run that is submitted after validator 1 returned.
newTx=$(sendTx "$peerEth" 3) || { fail "could not submit the post-recovery transaction"; exit 1; }
afterTxs=$((setupTxs + 1))
info "post-recovery transaction $newTx submitted to a peer"
newBlkHex=$(waitForReceipt "$peerEth" "$newTx" 120) || { fail "the post-recovery transaction was never executed"; exit 1; }
newNum=$(dec "$newBlkHex")
if [ "$newNum" -gt "$certifiedNum" ]; then
  pass "the shard certified a NEW block $newNum after the recovery — $((newNum - certifiedNum)) block(s) beyond the one that was recovered"
else
  fail "no new block was produced: the transaction landed in block $newNum, at or below the recovered block $certifiedNum"
  exit 1
fi

# And the shard really did do state-changing work in this window, said as a property of the SHARD
# rather than of this script: a non-quiet round was certified after the mark.
newWork=$(nonQuietSince "$injectMark" $providerLogs)
if [ "$newWork" -ge 1 ]; then
  pass "$newWork non-quiet round(s) were certified after the injection mark — this phase contains real work, unlike every phase before it"
else
  fail "no non-quiet round was certified after the injection mark, so there is no new work to follow"
fi

# THE RECOVERED NODE FOLLOWS IT. Waited for on the executor, because reaching the block is the claim;
# a log line saying the certificate arrived is not.
waitForHead "http://127.0.0.1:$rethEthBase" "$newNum" 120 \
  || info "validator 1's executor had not reached block $newNum within 120s; the assertions below say what it did reach"

followed=$(blockAt "http://127.0.0.1:$rethEthBase" latest) || { fail "could not read validator 1's executor after the new block"; exit 1; }
followedNum=$(dec "$(echo "$followed" | cut -d' ' -f1)")
followedHash=$(echo "$followed" | cut -d' ' -f2)
followedRoot=$(echo "$followed" | cut -d' ' -f3)
if [ "$followedNum" -ge "$newNum" ]; then
  pass "POSITIVE WORK AFTER RECOVERY: the restored node followed the shard to block $followedNum, produced entirely after it recovered"
else
  fail "the restored node did not follow the new work: its head is block $followedNum, the new block is $newNum"
fi

# AGREEMENT, BLOCK BY BLOCK, against every validator that stayed up — read from THEM, at the same
# height, rather than from one opinion or from the recovered node's own view of itself.
mine=$(blockAt "http://127.0.0.1:$rethEthBase" "$newBlkHex") || { fail "the recovered node has no block $newNum"; exit 1; }
mineHash=$(echo "$mine" | cut -d' ' -f2)
mineRoot=$(echo "$mine" | cut -d' ' -f3)
agreed=0
for i in $(seq 2 "$validators"); do
  theirs=$(blockAt "http://127.0.0.1:$((rethEthBase + i - 1))" "$newBlkHex") || { fail "survivor $i has no block $newNum"; continue; }
  tHash=$(echo "$theirs" | cut -d' ' -f2)
  tRoot=$(echo "$theirs" | cut -d' ' -f3)
  if [ "$mineHash" = "$tHash" ] && [ "$mineRoot" = "$tRoot" ]; then
    agreed=$((agreed + 1))
  else
    fail "block $newNum differs from survivor $i: recovered node $mineHash/$mineRoot, survivor $tHash/$tRoot"
  fi
done
if [ "$agreed" -eq $((validators - 1)) ]; then
  pass "exact agreement on the new block with all $agreed survivor(s): same block hash ${mineHash:0:18}… and same state root ${mineRoot:0:18}…"
fi

# RECEIPTS. Head-hash equality cannot make this check: two clients agreeing on a head while
# disagreeing about which block a transaction landed in would be a defect this lane must report.
mineReceipt=$(receiptIdentity "http://127.0.0.1:$rethEthBase" "$newTx") || { fail "the recovered node has no receipt for the post-recovery transaction"; mineReceipt=""; }
if [ -n "$mineReceipt" ]; then
  same=0
  for i in $(seq 2 "$validators"); do
    theirs=$(receiptIdentity "http://127.0.0.1:$((rethEthBase + i - 1))" "$newTx") || { fail "survivor $i has no receipt for the post-recovery transaction"; continue; }
    if [ "$mineReceipt" = "$theirs" ]; then same=$((same + 1)); else fail "receipt differs: recovered node '$mineReceipt', survivor $i '$theirs'"; fi
  done
  [ "$same" -eq $((validators - 1)) ] \
    && pass "the recovered node EXECUTED the new transaction: its receipt names the same block number and hash as on all $same survivor(s) — $mineReceipt"
fi

# THE WHOLE SHARD, INCLUDING THE RECOVERED NODE, HAS EXECUTED EXACTLY ONE MORE TRANSACTION than the
# setup submitted. Not "at least one": a recovered node that replayed or double-executed anything
# would show a different total, and that is the failure this counts for.
for i in $(seq 1 "$validators"); do
  assertTransactionCount "executor $i at the end of the run" "http://127.0.0.1:$((rethEthBase + i - 1))" "$afterTxs" \
    "the $setupTxs submitted before validator 1 returned, plus the one submitted after it recovered"
done

# AND STILL NOT VOTING. This is the half of the acceptance line that is easiest to lose: following
# new work is not authorization to sign it, and a run that showed agreement while the node had
# quietly started voting would be reporting a P-sign regression as a success.
signedAfter=$(countIn test-nodes/evm1/debug.log "submitting block certification request")
signedSince=$(linesSince "$injectMark" "submitting block certification request" test-nodes/evm1/debug.log)
if grep -q "NON-VOTING" test-nodes/evm1/debug.log && [ "$signedAfter" -eq 0 ] && [ "$signedSince" = "0" ]; then
  pass "STILL NON-VOTING: the recovered node followed, executed and agreed on new work and signed none of it — $signedSince submissions since the injection, $signedAfter in the whole run (P-sign, #105)"
else
  fail "a recovered node must not sign, even for work it followed correctly: submissions=$signedAfter since-injection=$signedSince"
fi

# AND IT WAS NOT REFUSING EITHER. Silence could also mean the node had gone back to refusing rounds,
# which would be following nothing; the identity check must still be passing over the new work.
refusalsSince=$(linesSince "$injectMark" "cannot identify the certified block to recover to" test-nodes/evm1/debug.log)
refusalsSince=$((refusalsSince + $(linesSince "$injectMark" "cannot prove the executor is on the certified block" test-nodes/evm1/debug.log)))
certsSince=$(linesSince "$injectMark" "accepted certificate" test-nodes/evm1/debug.log)
if [ "$refusalsSince" -eq 0 ] && [ "$certsSince" -ge 1 ]; then
  pass "and it was not silent by refusing: $certsSince certificate(s) accepted since the injection, not one identity refusal among them"
else
  fail "the node refused $refusalsSince time(s) over the $certsSince certificate(s) after the injection"
fi

# THE SHARD AGREES WITH ITSELF AT THE END, the recovered node included. The comparison above was made
# at one height; this one is made on whatever every client now calls its head, so a node that agreed
# about block $newNum and then diverged is caught.
endHash=""
for i in $(seq 1 "$validators"); do
  b=$(blockAt "http://127.0.0.1:$((rethEthBase + i - 1))" latest) || { fail "could not re-read executor $i's head"; continue; }
  h=$(echo "$b" | cut -d' ' -f2)
  if [ -z "$endHash" ]; then endHash=$h; endNum=$(dec "$(echo "$b" | cut -d' ' -f1)")
  elif [ "$h" != "$endHash" ]; then fail "executor $i disagrees about the head at the end of the run: $h vs $endHash"; fi
done
[ -n "$endHash" ] && pass "every executor, the recovered one included, ends on block ${endNum} ${endHash:0:18}…"

reached="all sections"
echo
echo "=== 5. provenance ==="
manifestLines=(
  "recovery flags:  --evidence-recover"
  "setup txs:       $setupTxs, all before validator 1 returned"
  "post-recovery:   1, submitted after adoption was established"
  "executor before: block $preOutageNum $preOutageHash"
  "recovered block: block $certifiedNum $certifiedHash"
  "injection mark:  $injectMark"
  "new block:       block ${newNum:-unknown} ${mineHash:-unknown}"
  "new state root:  ${mineRoot:-unknown}"
  "receipt:         ${mineReceipt:-unknown}"
  "submissions:     ${signedAfter:-unknown} (P-sign, #105)"
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
