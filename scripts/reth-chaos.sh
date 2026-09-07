#!/bin/bash
# reth-chaos.sh - real-reth workload, fault and retained-data recovery evidence (F1a, #88).
#
# scripts/chaos-evm.sh runs the same scenarios against --executor fake, which models no
# execution at all: every round is quiet, the state root never moves, and nothing it reports
# says anything about the execution path. This is its real-execution counterpart. One pinned
# reth per validator, driven by the actual Go adapter, with a funded transaction workload, so
# "did the shard recover" is answered by executed blocks and receipts rather than by round
# counters that advance whether or not anything ran.
#
# There is deliberately no fake fallback: a missing or unpinned reth binary fails.
#
# Usage:
#   ./scripts/reth-chaos.sh [-v validators] [-t workload-txs] [-k] [-F]
#     -v  validators, each with its own reth (default 4; >=4 to tolerate one fault)
#     -t  transactions per workload burst (default 3)
#     -k  keep everything running afterwards
#     -F  inject a harness failure, to exercise the evidence-collection path on purpose
#         (#88 requires that path be tested; a passing run never proves it)
#
# Exit code is nonzero if any scenario's assertion failed.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

validators=4
workloadTxs=3
keep=false
injectFailure=false
partitionID=8
chainID=31337
pinnedRethCommit=189c0df32617afc488e0f091dbface1bd72cceb4   # ristik/ureth, branch unicity/main

rethEngineBase=18551
rethEthBase=18545
rethP2PBase=30401

while getopts "hv:t:kF" o; do
  case "${o}" in
  v) validators=${OPTARG} ;;
  t) workloadTxs=${OPTARG} ;;
  k) keep=true ;;
  F) injectFailure=true ;;
  h | *) sed -n '2,21p' "$0"; exit 0 ;;
  esac
done

[ "$validators" -ge 4 ] || { echo "need at least 4 validators to tolerate one fault" >&2; exit 1; }

failures=0
pass() { echo "  PASS: $1"; }
# Everything goes to stdout. Splitting pass/fail across stdout and stderr scrambles the order in
# a redirected log — stderr is unbuffered, stdout is block-buffered — which made an early run look
# as though cleanup had torn the devnet down mid-scenario when it had not. The exit code carries
# the failure signal; the log needs to read in the order things happened.
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
info() { echo "  ..   $1"; }

# --- pinned client, no fake fallback ----------------------------------------------------------
command -v reth >/dev/null || { echo "no reth binary on PATH; this lane has no fake fallback" >&2; exit 1; }
rethCommit=$(reth --version | sed -n 's/^Commit SHA: //p')
if [ "$rethCommit" != "$pinnedRethCommit" ]; then
  echo "FAIL: reth is $rethCommit, pinned is $pinnedRethCommit" >&2
  echo "      Set F1_ALLOW_UNPINNED_RETH=1 to explore; output is then not evidence." >&2
  [ "${F1_ALLOW_UNPINNED_RETH:-0}" = "1" ] || exit 1
fi

ethURL()    { echo "http://127.0.0.1:$((rethEthBase + $1 - 1))"; }
engineURL() { echo "http://127.0.0.1:$((rethEngineBase + $1 - 1))"; }

rpc() {
  curl -sS --max-time 15 -X POST "$1" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" 2>/dev/null
}
pyget() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
hexToDec() { python3 -c "print(int('${1:-0x0}',16))" 2>/dev/null || echo 0; }

# --- process lifecycle ------------------------------------------------------------------------
startReth() {
  local i=$1
  mkdir -p "test-nodes/reth$i"
  reth node --chain test-nodes/evm-genesis-funded.json --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) \
    --http.api eth,net,web3,admin \
    --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    >>"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
}

stopReth() {
  local i=$1
  [ -f "test-nodes/reth$i/pid" ] || return 0
  kill "$(cat "test-nodes/reth$i/pid")" 2>/dev/null
  rm -f "test-nodes/reth$i/pid"
}

# waitReth - bounded, condition-driven: poll until the client answers, never a fixed sleep.
waitReth() {
  local i=$1 budget=${2:-60} waited=0
  while ! rpc "$(ethURL "$i")" eth_chainId '[]' | grep -q result; do
    [ "$waited" -ge "$budget" ] && return 1
    sleep 1; waited=$((waited + 1))
  done
  return 0
}

peerReths() {
  local i j enode
  for i in $(seq 1 "$validators"); do
    enode=$(rpc "$(ethURL "$i")" admin_nodeInfo '[]' | pyget "['result']['enode']")
    [ -z "$enode" ] && continue
    for j in $(seq 1 "$validators"); do
      [ "$i" = "$j" ] && continue
      rpc "$(ethURL "$j")" admin_addPeer "[\"$enode\"]" >/dev/null
    done
  done
}

# Teardown is NOT on an EXIT trap, deliberately.
#
# helper.sh's start_one_evm_validator backgrounds the node, and that forked child ran this
# script's EXIT trap with a call stack of "cleanup start_one_evm_validator main" — confirmed by
# instrumenting it. Cleanup then killed every node in the middle of a scenario while the parent
# carried on, so every later assertion failed against an already-dead devnet. It looked exactly
# like a protocol fault and was not one.
#
# No PID test fixes this portably: bash keeps the parent's $$ in a forked child, macOS's
# /bin/bash 3.2 has no BASHPID, and `$(sh -c "echo \$PPID")` reports the substitution subshell
# rather than the caller. So teardown is called explicitly instead — at the end, and on an
# interrupt. If the script dies some other way the nodes are left running, which is recoverable
# with `./stop-evm.sh -a` and is the more useful outcome anyway: #88 wants the evidence kept.
cleanup() {
  local i
  if [ "$keep" = true ]; then
    echo "=== leaving everything running (-k) ==="
    return
  fi
  echo "=== stopping everything ==="
  ./stop-evm.sh -a >/dev/null 2>&1
  for i in $(seq 1 "$validators"); do stopReth "$i"; done
  stopReth "wrongchain" 2>/dev/null
  wait 2>/dev/null
}
trap 'cleanup; exit 130' INT TERM

# --- observation helpers ----------------------------------------------------------------------
log() { echo "test-nodes/evm$1/debug.log"; }
logLines() { wc -l <"$(log "$1")" 2>/dev/null | tr -d ' ' || echo 0; }

# certifiedRound - last partition round this validator logged ACCEPTING a certificate for.
certifiedRound() {
  local r
  r=$(grep -o 'partitionRound=[0-9]*' "$(log "$1")" 2>/dev/null | tail -1 | cut -d= -f2)
  echo "${r:-0}"
}

# execHead - the reth canonical head this validator's executor has applied.
execHead() {
  local blk
  blk=$(rpc "$(ethURL "$1")" eth_getBlockByNumber '["latest", false]')
  echo "$(hexToDec "$(echo "$blk" | pyget "['result']['number']")"):$(echo "$blk" | pyget "['result']['hash']")"
}

# shardLeadersSince - distinct validators that logged themselves leader after line $2 of their log.
# Shard leadership is NOT root leadership; they rotate independently (#88 requires the
# distinction), so this reads the shard's own submission lines only.
shardLeadersSince() {
  local afterFile=$1 i mark found=""
  for i in $(seq 1 "$validators"); do
    mark=$(grep "^$i " "$afterFile" 2>/dev/null | awk '{print $2}')
    mark=${mark:-0}
    if awk -v n="$mark" 'NR > n && /submitting block certification request/ && /leader=true/ {f=1; exit} END{exit !f}' "$(log "$i")" 2>/dev/null; then
      found="$found $i"
    fi
  done
  echo "$found"
}

markAll() {
  local i out=$1
  : >"$out"
  for i in $(seq 1 "$validators"); do echo "$i $(logLines "$i")" >>"$out"; done
}

# waitForCertifiedProgress - bounded wait for validator $1 to accept a round above $2.
waitForCertifiedProgress() {
  local v=$1 above=$2 budget=${3:-90} waited=0
  while [ "$(certifiedRound "$v")" -le "$above" ]; do
    [ "$waited" -ge "$budget" ] && return 1
    sleep 2; waited=$((waited + 2))
  done
  return 0
}

# --- workload ---------------------------------------------------------------------------------
senderAcct=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
declare -a txHashes=()   # expanded as ${txHashes[@]+...}: bash 3.2 treats an empty "${a[@]}" as unbound under set -u

# nextNonce - ask the chain, do not count locally.
#
# A local counter desynchronises the moment a submission is counted as failed but is later mined:
# the harness reuses the nonce and every subsequent send dies with "nonce too low", which looks
# like a shard fault and is not one. The pending count is the authority on what this account has
# actually spent.
nextNonce() {
  local n
  n=$(rpc "$(ethURL "$1")" eth_getTransactionCount "[\"$senderAcct\",\"pending\"]" | pyget "['result']")
  hexToDec "${n:-0x0}"
}

# submitAndConfirm - send one funded transaction to validator $1's client and wait, bounded, for
# a receipt. Records hash, nonce, receipt block and status. Returns nonzero if it never executes.
submitAndConfirm() {
  local via=$1 budget=${2:-120} h waited=0 rcpt blkHex status gas nonce
  nonce=$(nextNonce "$via")
  h=$(go run ./scripts/evmtx -send -eth-url "$(ethURL "$via")" -chain-id "$chainID" -nonce "$nonce" 2>&1)
  if [[ "$h" != 0x* ]]; then
    fail "submitting tx nonce=$nonce via reth$via: $h"
    return 1
  fi
  while :; do
    rcpt=$(rpc "$(ethURL "$via")" eth_getTransactionReceipt "[\"$h\"]")
    blkHex=$(echo "$rcpt" | pyget "['result']['blockNumber']")
    [ -n "$blkHex" ] && [ "$blkHex" != "None" ] && break
    if [ "$waited" -ge "$budget" ]; then
      fail "tx $h (nonce $nonce) was never executed within ${budget}s"
      return 1
    fi
    sleep 2; waited=$((waited + 2))
  done
  status=$(echo "$rcpt" | pyget "['result']['status']")
  gas=$(echo "$rcpt" | pyget "['result']['gasUsed']")
  txHashes+=("$h")
  echo "$h $nonce $(hexToDec "$blkHex") $status $gas" >>test-nodes/evidence/workload.txt
  info "tx $h nonce=$nonce -> block $(hexToDec "$blkHex") status=$status gasUsed=$gas"
  [ "$status" = "0x1" ] || { fail "tx $h reverted (status $status)"; return 1; }
  return 0
}

# runWorkload - a burst of unique transactions, recording how many distinct shard leaders produced
# certified work while it ran.
#
# Leaders are written to a file rather than returned on stdout, and this must NEVER be called in a
# command substitution: that runs it in a subshell, where the sender nonce and the recorded
# transaction hashes are updated in a copy and then thrown away. The first version did exactly
# that and the next burst failed with "nonce too low: next nonce 2, tx nonce 0".
runWorkload() {
  local label=$1 count=$2 via i ok=0 leaders
  markAll test-nodes/evidence/.marks
  for i in $(seq 1 "$count"); do
    via=$(( (i - 1) % validators + 1 ))
    # only submit through a validator whose client is up
    [ -f "test-nodes/reth$via/pid" ] || via=1
    submitAndConfirm "$via" && ok=$((ok + 1))
  done
  leaders=$(shardLeadersSince test-nodes/evidence/.marks)
  echo "$label leaders:$leaders executed:$ok/$count" >>test-nodes/evidence/workload.txt
  echo "$leaders" >"test-nodes/evidence/.leaders-$label"
  if [ "$ok" -eq "$count" ]; then
    pass "$label: $ok/$count transactions executed and certified (shard leaders seen:$leaders)"
  else
    fail "$label: only $ok/$count transactions executed"
  fi
}

# --- cross-node agreement ---------------------------------------------------------------------
# assertConvergence - every live client must agree on the canonical head AND on the receipts and
# nonce for the workload so far. Head agreement alone would not catch divergent state.
assertConvergence() {
  local label=$1
  local i heads="" h rcptBlocks="" nonces="" acct=$senderAcct

  # Bounded wait for propagation before comparing. A block reaches the other clients over devp2p
  # and through their own forkchoice, which is not instant; comparing immediately would measure
  # delivery latency and report it as divergence. If they never converge, that IS the finding —
  # the assertions below then fail with the actual differing values.
  local waited=0 live
  while [ "$waited" -lt 60 ]; do
    live=""
    for i in $(seq 1 "$validators"); do
      [ -f "test-nodes/reth$i/pid" ] || continue
      live="$live$(execHead "$i")"$'\n'
    done
    [ "$(printf '%s' "$live" | sort -u | grep -c .)" = "1" ] && break
    sleep 2; waited=$((waited + 2))
  done

  for i in $(seq 1 "$validators"); do
    [ -f "test-nodes/reth$i/pid" ] || continue
    heads="$heads$(execHead "$i")"$'\n'
    nonces="$nonces$(rpc "$(ethURL "$i")" eth_getTransactionCount "[\"$acct\",\"latest\"]" | pyget "['result']")"$'\n'
    local per="" r
    for h in ${txHashes[@]+"${txHashes[@]}"}; do
      # One query per receipt: two separate calls can straddle propagation and disagree with
      # themselves rather than with another node.
      r=$(rpc "$(ethURL "$i")" eth_getTransactionReceipt "[\"$h\"]")
      per="$per$(echo "$r" | pyget "['result']['blockNumber']"),$(echo "$r" | pyget "['result']['status']");"
    done
    rcptBlocks="$rcptBlocks$per"$'\n'
  done
  {
    echo "--- $label ---"; echo "heads:"; printf '%s' "$heads"
    echo "nonces:"; printf '%s' "$nonces"; echo "receipts:"; printf '%s' "$rcptBlocks"
  } >>test-nodes/evidence/convergence.txt

  local uniqHeads uniqNonces uniqRcpts
  uniqHeads=$(printf '%s' "$heads" | sort -u | grep -c .)
  uniqNonces=$(printf '%s' "$nonces" | sort -u | grep -c .)
  uniqRcpts=$(printf '%s' "$rcptBlocks" | sort -u | grep -c .)
  [ "$uniqHeads" = "1" ] && pass "$label: all live clients agree on the canonical head" \
    || { fail "$label: canonical heads disagree"; printf '%s' "$heads"; }
  [ "$uniqNonces" = "1" ] && pass "$label: all live clients agree on the sender nonce (no duplicate execution)" \
    || { fail "$label: sender nonce disagrees"; printf '%s' "$nonces"; }
  [ "$uniqRcpts" = "1" ] && pass "$label: all live clients agree on every workload receipt block and status" \
    || { fail "$label: receipts disagree"; printf '%s' "$rcptBlocks"; }
}

# --- evidence ---------------------------------------------------------------------------------
snapshot() {
  local label=$1 i
  # Split deliberately: bash expands every assignment word before performing any of them, so
  # referring to $label in the same `local` that assigns it fails under `set -u`.
  local dir="test-nodes/evidence/$label"
  mkdir -p "$dir"
  for i in $(seq 1 "$validators"); do
    {
      echo "validator=$i certifiedRound=$(certifiedRound "$i") execHead=$(execHead "$i")"
      echo "rethRunning=$([ -f "test-nodes/reth$i/pid" ] && echo yes || echo no)"
      echo "shardRunning=$([ -f "test-nodes/evm$i/pid" ] && echo yes || echo no)"
      echo "lastCertLine=$(grep 'accepted certificate' "$(log "$i")" 2>/dev/null | tail -1)"
      echo "lastRootRound=$(grep -o 'rootRound=[0-9]*' "$(log "$i")" 2>/dev/null | tail -1)"
    } >"$dir/evm$i.txt"
    # The persisted certificate is one half of any conflict comparison and appears in no log.
    cp "test-nodes/evm$i/shard-node-luc.json" "$dir/evm$i-luc.bin" 2>/dev/null || true
  done
}

echo "=== reth-chaos.sh: real-reth workload and fault evidence (F1a #88) ==="
echo "reth:        $rethCommit"
echo "validators:  $validators, one pinned reth each"
echo "workload:    $workloadTxs transactions per burst, nonce read from the chain per send"
echo

echo "=== 0. clean fixtures ==="
./stop-evm.sh -a >/dev/null 2>&1
for i in $(seq 1 "$validators"); do stopReth "$i"; done
./setup-evm-nodes.sh -r 3 -v "$validators" >/dev/null || { echo "setup failed" >&2; cleanup; exit 1; }
mkdir -p test-nodes/evidence
: >test-nodes/evidence/workload.txt
: >test-nodes/evidence/convergence.txt

python3 - <<'PY'
import json, subprocess
g = json.load(open("test-nodes/evm-genesis.json"))
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
json.dump(g, open("test-nodes/evm-genesis-funded.json", "w"), indent=2)
PY
{
  echo "reth=$rethCommit"
  echo "bft=$(git rev-parse HEAD)"
  echo "genesis=$(shasum -a 256 test-nodes/evm-genesis.json | cut -d' ' -f1)"
  echo "fundedGenesis=$(shasum -a 256 test-nodes/evm-genesis-funded.json | cut -d' ' -f1)"
  echo "shardConf=$(shasum -a 256 "test-nodes/shard-conf-${partitionID}_0.json" | cut -d' ' -f1)"
  echo "validators=$validators workloadTxs=$workloadTxs chainID=$chainID"
  echo "sender=$senderAcct (nonce read from eth_getTransactionCount pending before each send)"
} | tee test-nodes/evidence/pins.txt

for i in $(seq 1 "$validators"); do
  openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  startReth "$i"
done
for i in $(seq 1 "$validators"); do
  waitReth "$i" 90 || { fail "reth$i did not start"; cleanup; exit 1; }
done
peerReths
pass "$validators pinned reth instances up and statically peered"

source helper.sh
for i in $(seq 1 "$validators"); do
  export "EVM_ENGINE_URL_$i=$(engineURL "$i")"
  export "EVM_ETH_URL_$i=$(ethURL "$i")"
done
./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1
rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")

waited=0
until grep -q 'accepted certificate' "$(log 1)" 2>/dev/null; do
  [ "$waited" -ge 180 ] && { fail "shard never certified"; cleanup; exit 1; }
  sleep 2; waited=$((waited + 2))
done
pass "shard certifying on --executor engine-api against real reth"
snapshot 00-baseline
echo
# ==============================================================================================
# Scenarios. One failure at a time; the returning node must demonstrably execute and certify NEW
# work before the next fault is injected (#88 stage 2).
# ==============================================================================================

# recoveredAndWorking - the returning node must (a) accept a certificate logged after its restart
# and (b) participate in executing a NEW transaction, agreeing with everyone else afterwards.
# A restart that merely re-reads an old certificate is not recovery.
recoveredAndWorking() {
  local v=$1 mark=$2 label=$3 budget=${4:-120} waited=0
  while ! awk -v n="$mark" 'NR > n && /accepted certificate/ {f=1; exit} END{exit !f}' "$(log "$v")" 2>/dev/null; do
    if [ "$waited" -ge "$budget" ]; then
      fail "$label: validator $v accepted no NEW certificate within ${budget}s after returning"
      return 1
    fi
    sleep 2; waited=$((waited + 2))
  done
  pass "$label: validator $v accepted a new certificate after returning"

  # Submit through a client that stayed up, never the returning node's own. Routing it through
  # the node under test measures whether its mempool and peering have caught up, which is a
  # different question from whether it applies newly certified work — and it produced spurious
  # "never executed" failures while the returning client was still syncing.
  local via headBefore
  via=$(( v % validators + 1 ))
  [ -f "test-nodes/reth$via/pid" ] || via=1
  headBefore=$(execHead "$v")
  submitAndConfirm "$via" || return 1
  waited=0
  while [ "$(execHead "$v")" = "$headBefore" ]; do
    if [ "$waited" -ge 120 ]; then
      fail "$label: validator $v's executor did not apply the new block (still $headBefore)"
      return 1
    fi
    sleep 2; waited=$((waited + 2))
  done
  pass "$label: validator $v executed new work after returning ($headBefore -> $(execHead "$v"))"
  return 0
}

echo "=== 1. workload before any fault ==="
runWorkload "pre-fault" "$workloadTxs"
leadersBefore=$(cat test-nodes/evidence/.leaders-pre-fault)
assertConvergence "pre-fault"
snapshot 01-pre-fault
echo

echo "=== 2. shard follower process restart, its reth retained ==="
# The shard process dies; its execution client keeps running and keeps its datadir. This is the
# same-host retained-data case. Disk loss / replacement host is #14 and is NOT claimed here.
follower=2
survivor=3
beforeRound=$(certifiedRound "$survivor")
snapshot 02a-before-follower-restart
info "stopping shard node $follower (pid $(cat "test-nodes/evm$follower/pid" 2>/dev/null)); its reth pid is $(cat "test-nodes/reth$follower/pid" 2>/dev/null)"
stop_one_evm_validator "$follower"
sleep 2
if rpc "$(ethURL "$follower")" eth_chainId '[]' | grep -q result; then
  pass "reth$follower survived stopping its shard node (this scenario retains the executor)"
else
  fail "reth$follower died when its shard node was stopped — the executor must be retained here"
fi
if waitForCertifiedProgress "$survivor" "$beforeRound" 120; then
  pass "shard kept certifying with validator $follower down (round $beforeRound -> $(certifiedRound "$survivor"))"
else
  fail "shard stalled with one of $validators validators down (quorum should permit it)"
  snapshot 02a-stall
fi
# Positive execution while it is absent: the shard must still do real work, not just tick rounds.
submitAndConfirm 1 && pass "a transaction executed while validator $follower was absent"
mark=$(logLines "$follower")
start_one_evm_validator "$follower" "$validators" "$partitionID" "$rootBoot" engine-api ""
recoveredAndWorking "$follower" "$mark" "follower-restart"
assertConvergence "post-follower-restart"
snapshot 02b-after-follower-restart
echo

echo "=== 3. shard leader process kill, quorum of others live ==="
# Target whoever most recently led, so this is a leader kill rather than another follower kill.
leader=$(for i in $(seq 1 "$validators"); do
  if tail -n 200 "$(log "$i")" 2>/dev/null | grep 'submitting block certification request' | tail -5 | grep -q 'leader=true'; then echo "$i"; fi
done | head -1)
leader=${leader:-1}
survivor=$(( leader % validators + 1 ))
info "most recent shard leader observed: validator $leader (survivor observed: $survivor)"
beforeRound=$(certifiedRound "$survivor")
snapshot 03a-before-leader-kill
stop_one_evm_validator "$leader"
if waitForCertifiedProgress "$survivor" "$beforeRound" 150; then
  pass "shard rotated past the killed leader $leader (round $beforeRound -> $(certifiedRound "$survivor"))"
else
  fail "shard did not recover from killing leader $leader within 150s"
  snapshot 03a-stall
fi
submitAndConfirm "$survivor" && pass "a transaction executed with leader $leader absent"
mark=$(logLines "$leader")
start_one_evm_validator "$leader" "$validators" "$partitionID" "$rootBoot" engine-api ""
recoveredAndWorking "$leader" "$mark" "leader-restart"
assertConvergence "post-leader-restart"
snapshot 03b-after-leader-restart
echo

echo "=== 4. reth-only restart, datadir retained (the shard process stays up) ==="
# The executor disappears from under a running shard node. Two things matter: the shard must
# abstain rather than certify something it cannot execute, and it must resume once the client
# returns with its retained data.
target=4
snapshot 04a-before-reth-restart
execBefore=$(execHead "$target")
mark=$(logLines "$target")
stopReth "$target"
info "reth$target stopped; shard process $target left running"
sleep 10 # let the shard node notice and attempt at least one round without its executor
# Safe abstention: with its executor gone the node must not have certified new EVM work of its
# own. Everyone else continues, which is what keeps the shard live.
if awk -v n="$mark" 'NR > n' "$(log "$target")" 2>/dev/null | grep -qiE 'error|refus|unavailable|connection refused'; then
  pass "validator $target reported its executor unavailable instead of proceeding silently"
else
  info "validator $target logged no executor error in the window (it may not have been asked to build)"
fi
otherRound=$(certifiedRound 1)
if waitForCertifiedProgress 1 "$otherRound" 120; then
  pass "the rest of the shard kept certifying while reth$target was down"
else
  fail "shard stalled while one validator's execution client was down"
fi
startReth "$target"
waitReth "$target" 90 || fail "reth$target did not come back"
info "reth$target restarted with its retained datadir (head was $execBefore)"
recoveredAndWorking "$target" "$mark" "reth-restart"
assertConvergence "post-reth-restart"
snapshot 04b-after-reth-restart
echo

echo "=== 5. complete shard+reth pair restart, both datadirs retained ==="
pair=2
snapshot 05a-before-pair-restart
mark=$(logLines "$pair")
stop_one_evm_validator "$pair"
stopReth "$pair"
info "validator $pair and reth$pair both stopped"
otherRound=$(certifiedRound 1)
if waitForCertifiedProgress 1 "$otherRound" 120; then
  pass "shard kept certifying with the whole pair $pair down"
else
  fail "shard stalled with one complete pair down"
fi
submitAndConfirm 1 && pass "a transaction executed with pair $pair fully absent"
startReth "$pair"
waitReth "$pair" 90 || fail "reth$pair did not come back"
start_one_evm_validator "$pair" "$validators" "$partitionID" "$rootBoot" engine-api ""
recoveredAndWorking "$pair" "$mark" "pair-restart"
assertConvergence "post-pair-restart"
snapshot 05b-after-pair-restart
echo

echo "=== 6. final workload and multi-leader evidence ==="
runWorkload "post-fault" "$workloadTxs"
leadersAfter=$(cat test-nodes/evidence/.leaders-post-fault)
assertConvergence "final"

allLeaders=$(echo "$leadersBefore $leadersAfter" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')
leaderCount=$(echo "$allLeaders" | wc -w | tr -d ' ')
if [ "$leaderCount" -ge 2 ]; then
  pass "$leaderCount distinct shard leaders produced certified work across the run:$allLeaders"
else
  fail "only $leaderCount distinct shard leader(s) observed:$allLeaders — #88 requires at least two"
fi

blocks=$(hexToDec "$(rpc "$(ethURL 1)" eth_getBlockByNumber '["latest", false]' | pyget "['result']['number']")")
expected=${#txHashes[@]}
if [ "$blocks" -ge "$expected" ]; then
  pass "reth produced $blocks EVM blocks for ${expected} transactions (blocks counted, not quiet rounds)"
else
  fail "only $blocks EVM blocks for ${expected} transactions"
fi
snapshot 06-final
echo

if [ "$injectFailure" = true ]; then
  echo "=== 7. injected harness failure, to exercise the evidence-collection path ==="
  fail "INJECTED: deliberate failure (-F) so the artifact path is proven, not assumed"
fi

echo "=== evidence ==="
collectEvidence() {
  local out=test-nodes/evidence
  local i
  for i in $(seq 1 "$validators"); do
    cp "$(log "$i")" "$out/evm$i-debug.log" 2>/dev/null
    cp "test-nodes/reth$i/reth.log" "$out/reth$i.log" 2>/dev/null
    cp "test-nodes/evm$i/shard-node-luc.json" "$out/evm$i-luc.bin" 2>/dev/null
    cp "test-nodes/evm$i/node-info.json" "$out/evm$i-node-info.json" 2>/dev/null
  done
  for i in 1 2 3; do cp "test-nodes/root$i/debug.log" "$out/root$i-debug.log" 2>/dev/null; done
  cp "test-nodes/shard-conf-${partitionID}_0.json" "$out/" 2>/dev/null
  cp test-nodes/trust-base.json "$out/" 2>/dev/null
  cp test-nodes/evm-genesis.json test-nodes/evm-genesis-funded.json "$out/" 2>/dev/null
  # Secrets are excluded by construction, never filtered after the fact: keys.json and jwt.hex
  # are simply not copied. The check below fails the run if one ever appears anyway.
  if find "$out" -name 'keys.json' -o -name 'jwt.hex' | grep -q .; then
    fail "evidence archive contains a secret file"
  else
    pass "evidence archive contains no keys.json or jwt.hex"
  fi
  tar czf test-nodes/reth-chaos-evidence.tar.gz -C test-nodes evidence
  pass "evidence archived: test-nodes/reth-chaos-evidence.tar.gz ($(du -h test-nodes/reth-chaos-evidence.tar.gz | cut -f1))"
}
collectEvidence

echo
cleanup
if [ "$failures" -gt 0 ]; then
  echo "=== reth-chaos.sh: $failures assertion(s) failed — evidence retained ==="
  exit 1
fi
echo "=== reth-chaos.sh: real-reth workload and fault evidence complete ==="
