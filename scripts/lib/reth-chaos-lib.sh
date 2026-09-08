#!/bin/bash
# reth-chaos-lib.sh - DEFINITIONS ONLY for scripts/reth-chaos.sh.
#
# Sourcing this file must have NO side effects: it changes no directory, parses no options, starts
# no process, installs no trap and checks no prerequisite. That is the entire reason it exists.
#
# scripts/reth-chaos-selftest.sh used to source a PREFIX of reth-chaos.sh, which dragged `cd`,
# `getopts`, the reth prerequisite check and the INT/TERM trap along with the definitions. On a
# machine without reth the prerequisite check exited each case before a single assertion ran and
# the suite reported "0 ok, 6 bad" — a suite that tested nothing while looking as though it had
# failed honestly. Its `cd` also escaped the temporary work directory. Separating definitions from
# initialisation is what makes the assertion oracle testable with no reth, no devnet, no side
# effects and nothing written outside a temporary directory.
#
# Every tunable below is `: "${name:=default}"`, so a caller may set it before sourcing.

: "${validators:=4}"
: "${workloadTxs:=3}"
: "${keep:=false}"
: "${injectFailure:=false}"
: "${partitionID:=8}"
: "${chainID:=31337}"
: "${pinnedRethCommit:=189c0df32617afc488e0f091dbface1bd72cceb4}"   # ristik/ureth, branch unicity/main

: "${rethEngineBase:=18551}"
: "${rethEthBase:=18545}"
: "${rethP2PBase:=30401}"

: "${failures:=0}"
pass() { echo "  PASS: $1"; }
# Everything goes to stdout. Splitting pass/fail across stdout and stderr scrambles the order in
# a redirected log — stderr is unbuffered, stdout is block-buffered — which made an early run look
# as though cleanup had torn the devnet down mid-scenario when it had not. The exit code carries
# the failure signal; the log needs to read in the order things happened.
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
info() { echo "  ..   $1"; }

ethURL()    { echo "http://127.0.0.1:$((rethEthBase + $1 - 1))"; }
engineURL() { echo "http://127.0.0.1:$((rethEngineBase + $1 - 1))"; }

# --- RPC, strictly validated -------------------------------------------------------------------
#
# Every observation used in an assertion goes through rpcField. A transport failure, a JSON-RPC
# error object, a missing result or a missing field is a FAILED OBSERVATION and returns nonzero;
# it never yields a value an assertion can accidentally agree on.
#
# This matters more than it sounds. The first version returned "" on failure and compared the
# strings: with every block and receipt call erroring, all four nodes produced the same empty
# observation, so "all clients agree on the canonical head", "...on the sender nonce" and
# "...on every receipt" all PASSED with zero failures. A harness that reports agreement because
# nothing answered is worse than no harness. Reproduced by the reviewer and now pinned by
# scripts/reth-chaos-selftest.sh.
rpc() {
  curl -sS --max-time 15 -X POST "$1" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" 2>/dev/null
}

# rpcField <url> <method> <params> <python-index-expr>
# Prints the field on success. Returns 1 on transport failure, JSON-RPC error, null result, or a
# missing/null field, printing nothing.
rpcField() {
  local url=$1 method=$2 params=$3 expr=$4 body
  body=$(rpc "$url" "$method" "$params") || return 1
  [ -n "$body" ] || return 1
  python3 - "$body" "$expr" <<'PYEOF' 2>/dev/null || return 1
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
if not isinstance(d, dict) or d.get("error") is not None:
    sys.exit(1)
if "result" not in d or d["result"] is None:
    sys.exit(1)
cur = d
try:
    for key in json.loads(sys.argv[2]):
        cur = cur[key]
except Exception:
    sys.exit(1)
if cur is None:
    sys.exit(1)
print(cur)
PYEOF
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

# stopReth - stop a client and WAIT for it to actually exit before returning. Dropping the pid
# file immediately let a restart race the dying process for its datadir and ports.
stopReth() {
  local i=$1 pid waited=0
  [ -f "test-nodes/reth$i/pid" ] || return 0
  pid=$(cat "test-nodes/reth$i/pid")
  rm -f "test-nodes/reth$i/pid"
  kill "$pid" 2>/dev/null || return 0
  while ps -p "$pid" >/dev/null 2>&1; do
    if [ "$waited" -ge 30 ]; then
      kill -9 "$pid" 2>/dev/null
      break
    fi
    sleep 1; waited=$((waited + 1))
  done
  return 0
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
# finish - collect evidence, then tear down. Runs on success, on assertion failure, and on
# cancellation, so a run never ends without its evidence. Idempotent: an interrupt during the
# normal end-of-run path must not collect or tear down twice.
: "${finished:=}"
finish() {
  [ -z "$finished" ] || return 0
  finished=yes
  collectEvidence
  cleanup
}

# superviseResult <childStatus> <failuresFile> - the supervisor's verdict, as one function so it
# can be executed by scripts/reth-chaos-selftest.sh rather than only read.
#
# It collects evidence (finish), then combines TWO INDEPENDENT failure counts and prints the
# summary. Returns 0 only if both are zero.
#
# The two counts must stay separate, and conflating them was a real defect (#91 review 5144079322).
# finish -> collectEvidence reports through the same fail() the scenarios use, so it increments
# `failures` in THIS process: a failed copy, an archive tar could not write, or a secret file found
# in the archive. The supervisor then used to do `failures=$(cat "$failuresFile")`, overwriting its
# own count with the child's. A successful child plus a failed archive therefore printed the FAIL
# line and exited 0 with "evidence complete" — silently defeating the evidence-failure gate #88
# asks for, in the one direction that matters, since the evidence is the deliverable.
#
# Order is forced: finish must run before the child's count can be trusted anyway (it is what
# retains the evidence), so the fix is to snapshot the supervisor's own count immediately after it
# and add, never assign.
superviseResult() {
  local childStatus=$1 file=$2 childFailures supervisorFailures

  failures=0
  finish
  supervisorFailures=$failures

  if [ -s "$file" ]; then
    childFailures=$(cat "$file")
  else
    # The child never got far enough to record a count. That is itself a failure: the run did not
    # complete, and reporting 0 would read as success.
    echo "  FAIL: the scenario process ended without recording a result (exit $childStatus) — the run did not complete"
    childFailures=1
  fi
  # A result file that is not a number is not a result. Without this the arithmetic below fails at
  # runtime and the verdict is decided by whatever the shell does next, which is not a verdict.
  case "$childFailures" in
    "" | *[!0-9]*)
      echo "  FAIL: the scenario process recorded an unreadable result ('$childFailures') — the run did not complete"
      childFailures=1
      ;;
  esac
  if [ "$childStatus" -ne 0 ] && [ "$childFailures" -eq 0 ]; then
    echo "  FAIL: the scenario process exited $childStatus with no assertion failure recorded — treating as a harness failure"
    childFailures=1
  fi

  failures=$((childFailures + supervisorFailures))
  if [ "$failures" -gt 0 ]; then
    echo "=== reth-chaos.sh: $failures failure(s) — $childFailures from the run, $supervisorFailures from evidence collection — evidence retained ==="
    return 1
  fi
  echo "=== reth-chaos.sh: real-reth workload and fault evidence complete ==="
  return 0
}

# --- observation helpers ----------------------------------------------------------------------
log() { echo "test-nodes/evm$1/debug.log"; }
logLines() { wc -l <"$(log "$1")" 2>/dev/null | tr -d ' ' || echo 0; }

# certifiedRound - last partition round this validator logged ACCEPTING a certificate for.
certifiedRound() {
  local r
  r=$(grep -o 'partitionRound=[0-9]*' "$(log "$1")" 2>/dev/null | tail -1 | cut -d= -f2)
  echo "${r:-0}"
}

# execHead - the reth canonical head this validator's executor has applied, as "number:hash".
# Returns nonzero and prints nothing if the client cannot be observed: an unobservable head is not
# a head value, and must never flow into a comparison.
execHead() {
  local num hash
  num=$(rpcField "$(ethURL "$1")" eth_getBlockByNumber '["latest", false]' '["result","number"]') || return 1
  hash=$(rpcField "$(ethURL "$1")" eth_getBlockByNumber '["latest", false]' '["result","hash"]') || return 1
  case "$hash" in 0x*) ;; *) return 1 ;; esac
  echo "$(hexToDec "$num"):$hash"
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

# validatorForPeer - map a peer ID (as it appears in TechnicalRecord.Leader) to a validator index,
# using each node's own node-info.json. Prints nothing if unknown.
validatorForPeer() {
  local want=$1 i id
  for i in $(seq 1 "$validators"); do
    id=$(python3 -c "import json;print(json.load(open('test-nodes/evm$i/node-info.json'))['nodeId'])" 2>/dev/null)
    [ "$id" = "$want" ] && { echo "$i"; return 0; }
  done
  return 1
}

# currentShardLeader - the validator the shard's own latest accepted certificate names as leader
# for the NEXT round, i.e. the authenticated technical-record context rather than a guess from
# recent log lines. Prints "index peerID round" so the boundary can be recorded as evidence.
#
# The first version scanned for the lowest-index node whose last five submissions contained
# leader=true, which is neither the assigned nor the most recent leader; the reviewer was right
# that it made the scenario a shard-process restart rather than a leader experiment.
currentShardLeader() {
  local from=$1 line peer round idx
  line=$(grep 'accepted certificate' "$(log "$from")" 2>/dev/null | tail -1)
  [ -n "$line" ] || return 1
  peer=$(echo "$line" | grep -o 'nextLeader=[^ ]*' | cut -d= -f2)
  round=$(echo "$line" | grep -o 'nextRound=[0-9]*' | cut -d= -f2)
  [ -n "$peer" ] || return 1
  idx=$(validatorForPeer "$peer") || return 1
  echo "$idx $peer $round"
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
  local i h expected live=0 bad=0
  local heads="" nonces="" rcpts=""

  # Bounded wait for propagation before comparing. A block reaches the other clients over devp2p
  # and through their own forkchoice, which is not instant; comparing immediately would measure
  # delivery latency and report it as divergence.
  local waited=0 probe seen
  # Budget is overridable so scripts/reth-chaos-selftest.sh can drive the oracle without waiting
  # out a propagation window that will never be satisfied by stubs.
  while [ "$waited" -lt "${CONVERGE_WAIT_BUDGET:-60}" ]; do
    seen=""; probe=0
    for i in $(seq 1 "$validators"); do
      [ -f "test-nodes/reth$i/pid" ] || continue
      probe=$((probe + 1))
      seen="$seen$(execHead "$i" || echo UNOBSERVABLE)"$'\n'
    done
    [ "$(printf '%s' "$seen" | sort -u | grep -c .)" = "1" ] && ! printf '%s' "$seen" | grep -q UNOBSERVABLE && break
    sleep 2; waited=$((waited + 2))
  done

  # Collect. Every live participant MUST be observable, and every submitted transaction MUST have
  # a receipt with the block and status it was recorded with. A failed observation is a failure,
  # never an empty string that happens to match another empty string.
  for i in $(seq 1 "$validators"); do
    [ -f "test-nodes/reth$i/pid" ] || continue
    live=$((live + 1))

    local head nonce
    if ! head=$(execHead "$i"); then
      fail "$label: validator $i's execution head could not be observed"
      bad=$((bad + 1)); continue
    fi
    heads="$heads$head"$'\n'

    if ! nonce=$(rpcField "$(ethURL "$i")" eth_getTransactionCount "[\"$senderAcct\",\"latest\"]" '["result"]'); then
      fail "$label: validator $i's sender nonce could not be observed"
      bad=$((bad + 1)); continue
    fi
    nonces="$nonces$(hexToDec "$nonce")"$'\n'

    local per="" blk st
    for h in ${txHashes[@]+"${txHashes[@]}"}; do
      if ! blk=$(rpcField "$(ethURL "$i")" eth_getTransactionReceipt "[\"$h\"]" '["result","blockNumber"]'); then
        fail "$label: validator $i has no receipt for $h (it was executed and recorded earlier)"
        bad=$((bad + 1)); per=""; break
      fi
      if ! st=$(rpcField "$(ethURL "$i")" eth_getTransactionReceipt "[\"$h\"]" '["result","status"]'); then
        fail "$label: validator $i has no receipt status for $h"
        bad=$((bad + 1)); per=""; break
      fi
      # Cross-check against what was recorded when the transaction executed, so a client that
      # agrees with its peers but disagrees with history is still caught.
      expected=$(awk -v hh="$h" '$1==hh {print $3" "$4}' test-nodes/evidence/workload.txt | tail -1)
      if [ -n "$expected" ] && [ "$(hexToDec "$blk") $st" != "$expected" ]; then
        fail "$label: validator $i has $h at block $(hexToDec "$blk") status $st, recorded as $expected"
        bad=$((bad + 1))
      fi
      per="$per$(hexToDec "$blk"),$st;"
    done
    rcpts="$rcpts$per"$'\n'
  done

  {
    echo "--- $label (live=$live unobservable=$bad) ---"
    echo "heads:"; printf '%s' "$heads"
    echo "nonces:"; printf '%s' "$nonces"
    echo "receipts:"; printf '%s' "$rcpts"
  } >>test-nodes/evidence/convergence.txt

  if [ "$live" -eq 0 ]; then
    fail "$label: no live execution clients to compare — convergence is unproven, not satisfied"
    return 1
  fi
  if [ "$bad" -gt 0 ]; then
    fail "$label: $bad of $live live clients could not be observed; convergence NOT established"
    return 1
  fi

  # Only now is agreement meaningful: every live client answered, for every recorded transaction.
  local uniqHeads uniqNonces uniqRcpts nHeads
  nHeads=$(printf '%s' "$heads" | grep -c .)
  uniqHeads=$(printf '%s' "$heads" | sort -u | grep -c .)
  uniqNonces=$(printf '%s' "$nonces" | sort -u | grep -c .)
  uniqRcpts=$(printf '%s' "$rcpts" | sort -u | grep -c .)

  [ "$nHeads" = "$live" ] || { fail "$label: observed $nHeads heads for $live live clients"; return 1; }

  # Every mismatch sets mismatched, and the function RETURNS NONZERO. It used to return 0
  # unconditionally after printing FAIL lines, so a caller could not tell agreement from
  # disagreement and the next fault was injected into a cluster already known to have diverged.
  # Reproduced by review with valid but differing heads 4:0xabc / 4:0xdef: canonical-head FAIL,
  # return=0, recoveryFailed empty.
  local mismatched=0
  if [ "$uniqHeads" = "1" ]; then
    pass "$label: all $live live clients agree on the canonical head"
  else
    fail "$label: canonical heads disagree"; printf '%s' "$heads"; mismatched=1
  fi
  if [ "$uniqNonces" = "1" ]; then
    pass "$label: all $live live clients agree on the sender nonce (no duplicate execution)"
  else
    fail "$label: sender nonce disagrees"; printf '%s' "$nonces"; mismatched=1
  fi
  if [ "$uniqRcpts" = "1" ]; then
    pass "$label: all $live live clients agree on every one of ${#txHashes[@]} recorded receipts"
  else
    fail "$label: receipts disagree"; printf '%s' "$rcpts"; mismatched=1
  fi
  return "$mismatched"
}

# convergenceGate - assertConvergence, with its result actually consumed.
#
# Every scenario calls this rather than assertConvergence directly. A convergence failure is a
# prerequisite failure for everything after it: continuing would inject the next fault into a
# cluster already known to disagree, and the retained convergence.txt from the first run showed
# exactly that contamination (node 1 stuck at block 4 while the others advanced, across three
# "independent" scenarios).
# recoveredAndWorking - the returning node must (a) accept a certificate logged after its restart
# and (b) participate in executing a NEW transaction, agreeing with everyone else afterwards.
# A restart that merely re-reads an old certificate is not recovery.
# recoveryFailed is sticky. #88 requires that no further fault be injected until the returning node
# demonstrably executes and certifies new work, and the reviewer showed the consequence of ignoring
# it: after a failed recovery the next scenario ran against an already-degraded cluster, so its
# result said nothing about the fault it was supposed to isolate. Later scenarios are now marked
# NOT RUN instead of producing contaminated evidence.
: "${recoveryFailed:=}"

skipIfUnrecovered() {
  [ -n "$recoveryFailed" ] || return 1
  echo "  SKIP: $1 NOT RUN — the cluster never recovered from $recoveryFailed, so any result here"
  echo "        would be contaminated (#88: do not inject another fault until the returning node"
  echo "        demonstrably executes and certifies new work)."
  return 0
}

recoveredAndWorking() {
  local v=$1 mark=$2 label=$3 budget=${4:-120} waited=0
  while ! awk -v n="$mark" 'NR > n && /accepted certificate/ {f=1; exit} END{exit !f}' "$(log "$v")" 2>/dev/null; do
    if [ "$waited" -ge "$budget" ]; then
      fail "$label: validator $v accepted no NEW certificate within ${budget}s after returning"
      recoveryFailed="$label"
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
  headBefore=$(execHead "$v") || { fail "$label: validator $v's head is unobservable after returning"; recoveryFailed="$label"; return 1; }
  submitAndConfirm "$via" || { recoveryFailed="$label"; return 1; }
  # OBSERVATION SUCCESS IS CHECKED SEPARATELY FROM THE HEAD CHANGE.
  #
  # This loop used to be `while [ "$(execHead "$v" || echo UNOBSERVABLE)" = "$headBefore" ]`. A
  # failed observation substitutes UNOBSERVABLE, which differs from headBefore, so the loop exited
  # immediately and the node was declared recovered BECAUSE its client had stopped answering.
  # Review reproduced it: first observation 4:0xabc, every later one failing, two PASS lines,
  # return 0, failures 0. Only a VALID observed head that differs can establish recovery; a failed
  # observation is retried within the same bound and then fails.
  # The same budget bounds both waits. It used to be a hardcoded 120 here while the first loop used
  # $budget, so a caller could not bound this function at all — which made it untestable without
  # waiting out two minutes per case, and meant the two halves of one scenario had different
  # patience for no stated reason.
  waited=0
  local headAfter observed=false
  while [ "$waited" -lt "$budget" ]; do
    if headAfter=$(execHead "$v"); then
      observed=true
      [ "$headAfter" != "$headBefore" ] && break
    else
      observed=false
    fi
    sleep 2; waited=$((waited + 2))
  done
  if [ "$observed" != true ]; then
    fail "$label: validator $v's execution head was not observable within ${budget}s after returning — recovery is UNPROVEN, not established"
    recoveryFailed="$label"
    return 1
  fi
  if [ "$headAfter" = "$headBefore" ]; then
    fail "$label: validator $v's executor did not apply the new block (still $headBefore)"
    recoveryFailed="$label"
    return 1
  fi
  pass "$label: validator $v executed new work after returning ($headBefore -> $headAfter)"
  return 0
}

convergenceGate() {
  local label=$1
  if assertConvergence "$label"; then
    return 0
  fi
  recoveryFailed="${recoveryFailed:-$label}"
  info "$label did not converge — later scenarios will be marked NOT RUN rather than injected into a diverged cluster"
  return 1
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

collectEvidence() {
  local out=test-nodes/evidence
  local i missing=0 copied=0

  # copyRequired records whether each expected artefact actually arrived. Completeness used to be
  # inferred from "the archive has more than five entries", which cannot distinguish a complete run
  # from one where half the logs failed to copy but the genesis files made up the count.
  copyRequired() {
    local src=$1 dst=$2
    if [ ! -e "$src" ]; then
      return 0 # legitimately absent (a node that never started); not a copy failure
    fi
    if cp "$src" "$dst" 2>/dev/null; then
      copied=$((copied + 1))
    else
      missing=$((missing + 1))
      info "evidence: failed to copy $src"
    fi
  }

  for i in $(seq 1 "$validators"); do
    copyRequired "$(log "$i")" "$out/evm$i-debug.log"
    copyRequired "test-nodes/reth$i/reth.log" "$out/reth$i.log"
    copyRequired "test-nodes/evm$i/shard-node-luc.json" "$out/evm$i-luc.bin"
    copyRequired "test-nodes/evm$i/node-info.json" "$out/evm$i-node-info.json"
  done
  for i in 1 2 3; do copyRequired "test-nodes/root$i/debug.log" "$out/root$i-debug.log"; done
  copyRequired "test-nodes/shard-conf-${partitionID}_0.json" "$out/shard-conf-${partitionID}_0.json"
  copyRequired test-nodes/trust-base.json "$out/trust-base.json"
  copyRequired test-nodes/evm-genesis.json "$out/evm-genesis.json"
  copyRequired test-nodes/evm-genesis-funded.json "$out/evm-genesis-funded.json"

  # Secrets are excluded by construction, never filtered after the fact: keys.json and jwt.hex
  # are simply not copied. The check below fails the run if one ever appears anyway.
  if find "$out" -name 'keys.json' -o -name 'jwt.hex' | grep -q .; then
    fail "evidence archive contains a secret file"
  else
    pass "evidence archive contains no keys.json or jwt.hex"
  fi

  if [ "$missing" -gt 0 ]; then
    fail "evidence collection incomplete: $missing required artefact(s) present but not copied ($copied succeeded)"
  fi

  # The archive claim is made from tar's own exit status, not from counting what ended up inside.
  if tar czf test-nodes/reth-chaos-evidence.tar.gz -C test-nodes evidence 2>/dev/null &&
     [ -s test-nodes/reth-chaos-evidence.tar.gz ]; then
    if [ "$missing" -gt 0 ]; then
      info "archive written, but incomplete — see the failure above"
    elif [ "$copied" -eq 0 ]; then
      # An empty archive is not a successful collection. This happens when the run died before it
      # produced anything; saying PASS here would report an archive that contains nothing.
      info "archive written but EMPTY: the run produced no evidence to collect"
    else
      pass "evidence archived: test-nodes/reth-chaos-evidence.tar.gz ($(du -h test-nodes/reth-chaos-evidence.tar.gz | cut -f1), $copied artefact(s))"
    fi
  else
    fail "evidence archive was not produced — the run's evidence is only in test-nodes/evidence/"
  fi
}

