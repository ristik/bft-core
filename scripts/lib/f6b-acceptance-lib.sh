#!/bin/bash
# f6b-acceptance-lib.sh - DEFINITIONS ONLY, shared by the #92 acceptance lanes:
#
#   scripts/f6b-quiet-tail-recovery.sh    recovery across a quiet tail, no transaction at all
#   scripts/f6b-missed-block-recovery.sh  recovery after a genuinely missed block
#
# Sourcing this file must have NO side effects, exactly as scripts/lib/reth-chaos-lib.sh says and
# for the same reason: no `cd`, no option parsing, no process, no trap, no prerequisite check.
#
# WHY IT EXISTS. Every one of these helpers was a defect at least once, and every one of them is a
# guard on a NEGATIVE claim — "nothing executed", "the node never adopted", "the artifact exists".
# A second lane asking the same questions with a second copy of the answers is the argument
# anchorHeadIdentity settles in shardnode/anchor.go: two copies of a comparison that gates a
# conclusion is one copy too many, because the weaker of them becomes the one that matters. There
# is one implementation, and one self-test (f6bSelfTest) that exercises its failure paths.
#
# The caller owns the state these read and write:
#
#   failures        assertion counter. pass/fail must run in the PARENT shell to move it.
#   reached         how far the run got, for the manifest and for the required-log rule.
#   validators      how many validators the run started.
#   artifactDir     where the run artifact goes.
#   rethCommit      the reth actually on PATH; pinnedRethCommit what the lane baselines against.
#   manifestTitle   first line of the manifest.
#   manifestLogs    space-separated log paths the artifact must preserve.
#   manifestLines   extra "label: value" lines, one per array element.

: "${failures:=0}"
: "${reached:=startup}"
: "${validators:=3}"
: "${manifestTitle:=f6b acceptance run}"
: "${manifestLogs:=}"
: "${pinnedRethCommit:=}"

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
info() { echo "  info: $1"; }

rpc() { curl -sS --max-time 10 -X POST "$1" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"; }
pyget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)" 2>/dev/null; }

# rpcRequire is rpc that REPORTS a failure instead of returning empty, and it reports it on stderr
# with a non-zero status rather than by calling fail().
#
# Both halves matter, and review found both. `${c:-0}` over a failed read counted as zero
# transactions, so an unreachable node produced a PASS asserting nothing had executed — an assertion
# that cannot tell "I looked and saw none" from "I could not look" is not evidence, and these lanes'
# claims are negative ones. And calling fail() from here would increment $failures inside a COMMAND
# SUBSTITUTION, which is a subshell: the parent's counter never moved and the run exited 0 with
# failures on screen. Anything that must change $failures has to run in the parent shell.
rpcRequire() { # rpcRequire <url> <method> <params> <pyget-path> <what>
  local out value
  out=$(rpc "$1" "$2" "$3") || { echo "RPC $2 to $1 failed ($5)" >&2; return 1; }
  value=$(printf '%s' "$out" | pyget "$4")
  if [ -z "$value" ]; then
    echo "RPC $2 to $1 returned no $5: $(printf '%s' "$out" | head -c 200)" >&2
    return 1
  fi
  printf '%s' "$value"
}

# isQuantity is the one place that decides whether a string off the wire is a hex quantity this lane
# may compute with. It is deliberately STRICTER than "starts with 0x and has hex digits": that
# earlier form accepted "0x1-1", which then reached shell arithmetic as an EXPRESSION and evaluated
# to 0 — a malformed answer that read as "no transactions".
isQuantity() { [[ "$1" =~ ^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$ ]]; }

# isHash32 is the same rule for a 32-byte hash, which is fixed-width and may have leading zeros, so
# it is not a quantity and must not be validated as one.
isHash32() { [[ "$1" =~ ^0x[0-9a-fA-F]{64}$ ]]; }

# countTransactions echoes "<total> <headHex>" and returns non-zero if any read failed. It never
# touches $failures: see rpcRequire.
countTransactions() { # countTransactions <ethURL>
  local url=$1 headHex numbers total=0 n c
  headHex=$(rpcRequire "$url" eth_getBlockByNumber '["latest", false]' "['result']['number']" "head block number") || return 1

  # VALIDATE THE NUMBER BEFORE COUNTING FROM IT. A malformed head — "0x", a decimal, an error string
  # that json-decoded fine — made the python expansion below raise, which emptied the loop, which
  # left total at 0, which read as "no transactions". A range this lane could not construct is a
  # question it could not ask, and it must say so rather than answer it with a zero.
  if ! isQuantity "$headHex"; then
    echo "head block number from $url is not a hex quantity: '$headHex'" >&2
    return 1
  fi
  numbers=$(python3 -c "print(' '.join(hex(i) for i in range(0, int('$headHex', 16) + 1)))" 2>/dev/null) || {
    echo "could not enumerate blocks 0..$headHex from $url" >&2; return 1; }
  [ -n "$numbers" ] || { echo "no block numbers to check between 0 and $headHex from $url" >&2; return 1; }

  for n in $numbers; do
    c=$(rpcRequire "$url" eth_getBlockTransactionCountByNumber "[\"$n\"]" "['result']" "transaction count for block $n") || return 1
    if ! isQuantity "$c"; then
      echo "transaction count for block $n from $url is not a hex quantity: '$c'" >&2
      return 1
    fi
    # Do not interpret RPC text as shell arithmetic or allow machine-integer wraparound.
    total=$(python3 -c "print(int('$total') + int('$c', 16))") || return 1
  done
  echo "$total $headHex"
}

# assertTransactionCount is the general form and runs entirely in the PARENT shell, so its fail()
# actually counts. It is exact on both sides: a lane that expected three setup transactions and
# found four has had activity it did not authorise, which is the same defect as finding zero when
# the read failed.
assertTransactionCount() { # assertTransactionCount <label> <ethURL> <expected> [what]
  local label=$1 url=$2 want=$3 what=${4:-} out rc total headHex
  out=$(countTransactions "$url" 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$label: could not read the executor's blocks, so the transaction count is unproven: $(echo "$out" | tail -1)"
    return 1
  fi
  total=$(echo "$out" | tail -1 | cut -d' ' -f1)
  headHex=$(echo "$out" | tail -1 | cut -d' ' -f2)
  if [ "$total" = "$want" ]; then
    pass "$label: every canonical block, genesis through $headHex, holds exactly $want transaction(s)${what:+ — $what}"
    return 0
  fi
  fail "$label: $total transactions in genesis..$headHex, expected exactly $want${what:+ — $what}"
  return 1
}

assertNoTransactions() { # assertNoTransactions <label> <ethURL>
  local label=$1 url=$2 out rc total headHex
  out=$(countTransactions "$url" 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$label: could not read the executor's blocks, so 'no transactions' is unproven: $(echo "$out" | tail -1)"
    return 1
  fi
  total=$(echo "$out" | tail -1 | cut -d' ' -f1)
  headHex=$(echo "$out" | tail -1 | cut -d' ' -f2)
  if [ "$total" = "0" ]; then
    pass "$label: every canonical block, genesis through $headHex, contains zero transactions"
  else
    fail "$label: $total transactions executed — this lane must demonstrate recovery with no new activity"
  fi
}

# headBlock echoes "<numberHex> <hash> <stateRoot>" for the executor's canonical head, with every
# field validated, or fails on stderr with a non-zero status. It never touches $failures.
#
# The three fields are read from ONE response rather than three: a head that moved between reads
# would otherwise produce a number, a hash and a state root that never belonged to the same block,
# and a lane whose whole claim is "this exact block" cannot assemble its subject from three moments.
headBlock() { # headBlock <ethURL>
  blockAt "$1" latest
}

# blockAt is headBlock for a named block. `which` is "latest" or a hex quantity.
blockAt() { # blockAt <ethURL> <latest|0xN>
  local url=$1 which=$2 out num hash root sel
  case "$which" in
    latest) sel='"latest"' ;;
    *) isQuantity "$which" || { echo "block selector for $url is not a hex quantity: '$which'" >&2; return 1; }
       sel="\"$which\"" ;;
  esac
  out=$(rpc "$url" eth_getBlockByNumber "[$sel, false]") || { echo "RPC eth_getBlockByNumber($which) to $url failed" >&2; return 1; }
  num=$(printf '%s' "$out" | pyget "['result']['number']")
  hash=$(printf '%s' "$out" | pyget "['result']['hash']")
  root=$(printf '%s' "$out" | pyget "['result']['stateRoot']")
  if ! isQuantity "$num"; then echo "block $which from $url has no hex number: '$num'" >&2; return 1; fi
  if ! isHash32 "$hash"; then echo "block $which from $url has no 32-byte hash: '$hash'" >&2; return 1; fi
  if ! isHash32 "$root"; then echo "block $which from $url has no 32-byte state root: '$root'" >&2; return 1; fi
  echo "$num $hash $root"
}

# countIn is grep -c that always prints exactly one integer. `grep -c` exits 1 when the count is
# zero, so the obvious `$(grep -c ... || echo 0)` prints "0\n0" and every numeric test after it is a
# syntax error rather than a false — which is how a broken wait loop reads as "no certificates".
countIn() { local n; n=$(grep -c "$2" "$1" 2>/dev/null | head -1); echo "${n:-0}"; }

waitFor() { # waitFor <file> <pattern> <count> <seconds>
  for _ in $(seq 1 "$4"); do
    [ "$(countIn "$1" "$2")" -ge "$3" ] && return 0
    sleep 1
  done
  return 1
}

# waitForHead blocks until the executor's canonical head number reaches <hexOrDec>, or the deadline
# passes. It returns non-zero on timeout AND on an unreadable executor: "I could not look" is not
# "it did not get there", and it is not "it did".
waitForHead() { # waitForHead <ethURL> <decimalNumber> <seconds>
  local url=$1 want=$2 secs=$3 out num
  for _ in $(seq 1 "$secs"); do
    out=$(headBlock "$url" 2>/dev/null) && {
      num=$(python3 -c "print(int('$(echo "$out" | cut -d' ' -f1)', 16))" 2>/dev/null)
      [ -n "$num" ] && [ "$num" -ge "$want" ] && return 0
    }
    sleep 1
  done
  return 1
}

# --- quietness, measured as a TAIL rather than as a total ---------------------------------------
#
# A shard is quiet NOW or it is not, and "there are four quiet rounds in this log" does not say
# which. Counting cumulatively was a real defect: the missed-block lane waited for four quiet rounds
# in a log that already held nine from before the transactions were submitted, so the wait returned
# instantly and the node was restarted while the certificate naming the block it had missed was
# still the newest one. The root chain hands a returning node the LATEST certificate, so that node
# was handed the answer — which is precisely the F1 baseline's "recovery from new activity" (§1),
# arriving by accident inside the lane built to rule it out. One run in four lost that race.
#
# Both functions below therefore measure against the most recent NON-quiet round in any of the given
# logs, not against the start of the file. Both leaders and followers log "submitting block certification request". These helpers count
# request log entries, not distinct certified rounds; several logs are read together so a
# non-quiet request seen by any provider moves the boundary.
#
# Log lines begin `time=<RFC3339 with a fixed offset>`, which sorts lexically in timestamp order, and
# all of these logs are written by the same process family with the same format.
markNow() { date +time=%Y-%m-%dT%H:%M:%S; }

# nonQuietSince counts non-quiet rounds logged after <mark> across <log...>. A line from the same
# whole second as the mark counts as after it, which can only produce a false FAILURE, never a false
# pass — the direction an assertion about "nothing happened" has to err in.
nonQuietSince() { # nonQuietSince <mark> <log...>
  local mark=$1; shift
  grep -h "quiet=false" "$@" 2>/dev/null | awk -v t="$mark" '$1 > t' | wc -l | tr -d ' '
}

quietSince() { # quietSince <mark> <log...>
  local mark=$1; shift
  grep -h "quiet=true" "$@" 2>/dev/null | awk -v t="$mark" '$1 > t' | wc -l | tr -d ' '
}

# waitForQuietTail blocks until at least <want> quiet rounds have been logged across <log...> SINCE
# the most recent non-quiet round in any of them — that is, until the shard has a quiet tail of that
# length right now. If a block is certified while it waits, the boundary moves and the count starts
# again, which is the correct behaviour and not something the caller has to arrange. It echoes the
# tail length it settled on.
waitForQuietTail() { # waitForQuietTail <want> <seconds> <log...>
  local want=$1 secs=$2; shift 2
  local last n=0
  for _ in $(seq 1 "$secs"); do
    last=$(grep -h "quiet=false" "$@" 2>/dev/null | awk '{print $1}' | sort | tail -1)
    n=$(quietSince "${last:-time=0}" "$@")
    [ "${n:-0}" -ge "$want" ] && { echo "$n"; return 0; }
    sleep 1
  done
  echo "${n:-0}"
  return 1
}

# waitForLinesAfter blocks until <want> lines matching <after> have been logged in <file> AFTER the
# first line matching <mark>, and echoes how many there are.
#
# It exists because "wait for three more certificates, then count the ones after adoption" is not the
# same wait: if adoption happens near the end of that window, the three certificates are mostly
# BEFORE it and the assertion fails on its own timing rather than on the node's behaviour. One run
# reported "0 refusals over the 2 certificates that followed" — a passing property failed by an
# impatient wait, which is a false failure and the mirror image of every false pass above it.
waitForLinesAfter() { # waitForLinesAfter <file> <mark> <after> <want> <seconds>
  local f=$1 mark=$2 after=$3 want=$4 secs=$5 line n=0
  for _ in $(seq 1 "$secs"); do
    line=$(grep -n "$mark" "$f" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "$line" ]; then
      n=$(tail -n +"$line" "$f" | countIn /dev/stdin "$after")
      [ "$n" -ge "$want" ] && { echo "$n"; return 0; }
    fi
    sleep 1
  done
  echo "$n"
  return 1
}

# --- execution-layer peer connectivity, confirmed rather than assumed --------------------------
#
# `admin_removePeer` returns `true` for a peer that was never connected, for one that is already
# gone, and for one it will re-dial a second later. An experiment whose premise is "this client
# could not have obtained the block from anywhere" cannot rest on the return value of the call that
# was supposed to arrange that: it has to READ the connectivity afterwards, from both ends, and keep
# reading it while the window it matters in is open.

peerCount() { # peerCount <ethURL> — echoes a decimal count, non-zero status if it could not be read
  local n
  n=$(rpcRequire "$1" net_peerCount '[]' "['result']" "peer count") || return 1
  isQuantity "$n" || { echo "peer count from $1 is not a hex quantity: '$n'" >&2; return 1; }
  python3 -c "print(int('$n', 16))"
}

# peerIds echoes the peer ids this client currently holds, one per line — the second, independent
# reading of the same fact. net_peerCount and admin_peers are maintained separately, and a client
# that reports zero while still listing a session has not been isolated.
peerIds() { # peerIds <ethURL>
  local out
  out=$(rpc "$1" admin_peers '[]') || { echo "admin_peers to $1 failed" >&2; return 1; }
  printf '%s' "$out" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for p in d.get('result') or []:
    print(p.get('id', ''))
" 2>/dev/null
}

# nodeEnodeID echoes this client's own enode ID (the 128 hex chars between // and @), which is what
# a peer lists it as.
nodeEnodeID() { # nodeEnodeID <ethURL>
  local e
  e=$(rpcRequire "$1" admin_nodeInfo '[]' "['result']['enode']" "enode") || return 1
  printf '%s' "$e" | sed -n 's|^enode://\([0-9a-fA-F]*\)@.*|\1|p'
}

# holdsIsolation reads the isolation from BOTH ends and echoes "ok" or the reason it is not held.
# It never touches $failures — the caller asserts.
holdsIsolation() { # holdsIsolation <subjectEthURL> <subjectID> <peerEthURL...>
  local url=$1 id=$2; shift 2
  local n other ids
  n=$(peerCount "$url") || { echo "could not read the subject's peer count"; return 1; }
  [ "$n" = "0" ] || { echo "the subject still has $n execution peer(s)"; return 1; }
  ids=$(peerIds "$url") || { echo "could not read the subject's peer list"; return 1; }
  [ -z "$ids" ] || { echo "the subject reports no peer count but still lists sessions"; return 1; }
  for other in "$@"; do
    ids=$(peerIds "$other") || { echo "could not read $other's peer list"; return 1; }
    if printf '%s' "$ids" | grep -qi "$id"; then
      echo "$other still lists the subject as a peer"; return 1
    fi
  done
  echo ok
}

# waitForIsolation polls holdsIsolation until it holds, then keeps reading for <hold> more seconds to
# catch a client that re-dials a moment later. A single sample is not isolation.
waitForIsolation() { # waitForIsolation <subjectEthURL> <subjectID> <secs> <hold> <peerEthURL...>
  local url=$1 id=$2 secs=$3 hold=$4; shift 4
  local r
  for _ in $(seq 1 "$secs"); do
    r=$(holdsIsolation "$url" "$id" "$@")
    [ "$r" = "ok" ] && break
    sleep 1
  done
  [ "$r" = "ok" ] || { echo "$r"; return 1; }
  for _ in $(seq 1 "$hold"); do
    sleep 1
    r=$(holdsIsolation "$url" "$id" "$@")
    [ "$r" = "ok" ] || { echo "isolation did not hold: $r"; return 1; }
  done
  echo ok
}

waitForPeers() { # waitForPeers <ethURL> <want> <secs> — echoes the count it settled on
  local url=$1 want=$2 secs=$3 n=0
  for _ in $(seq 1 "$secs"); do
    n=$(peerCount "$url") || n=0
    [ "$n" -ge "$want" ] && { echo "$n"; return 0; }
    sleep 1
  done
  echo "$n"
  return 1
}

# receiptIdentity echoes "<blockNumber> <blockHash>" for a transaction, both validated. It is the
# identity check that head-hash equality cannot make: two clients agreeing on a head hash while
# disagreeing about which block a transaction landed in would be a client defect this lane should
# report rather than pass over.
receiptIdentity() { # receiptIdentity <ethURL> <txHash>
  local out num hash
  out=$(rpc "$1" eth_getTransactionReceipt "[\"$2\"]") || { echo "receipt RPC to $1 failed" >&2; return 1; }
  num=$(printf '%s' "$out" | pyget "['result']['blockNumber']")
  hash=$(printf '%s' "$out" | pyget "['result']['blockHash']")
  isQuantity "${num:-}" || { echo "receipt for $2 from $1 has no block number: '${num:-}'" >&2; return 1; }
  isHash32 "${hash:-}" || { echo "receipt for $2 from $1 has no block hash: '${hash:-}'" >&2; return 1; }
  echo "$num $hash"
}

manifestWritten=0
# writeManifest returns non-zero if it could not leave an artifact behind, and marks itself done
# only when it actually wrote one.
#
# It used to return SUCCESS when mkdir failed, having already set the once-flag — so a run with no
# artifact at all reported ALL CHECKS PASSED, no later attempt was made, and nothing said the
# provenance was missing. For a lane whose output IS the artifact, silently producing none is the
# same class of defect as counting a failed read as a zero.
writeManifest() {
  [ "$manifestWritten" -eq 1 ] && return 0
  if ! mkdir -p "$artifactDir/logs" 2>/dev/null; then
    echo "  FAIL: could not create the run artifact directory $artifactDir — this run leaves no provenance" >&2
    return 1
  fi
  # Copy first, then hash the copies: a digest of a file a running node is still appending to
  # describes nothing anybody can check later.
  local f digest logDigests="" line
  for f in $manifestLogs; do
    if [ ! -f "$f" ]; then
      if [ "${reached:-startup}" = "all sections" ]; then
        echo "  FAIL: required evidence log is missing: $f" >&2
        return 1
      fi
      continue # an early failure may precede this arm's startup
    fi
    if ! cp "$f" "$artifactDir/logs/$(echo "$f" | tr '/' '_')"; then
      echo "  FAIL: could not preserve evidence log: $f" >&2
      return 1
    fi
    digest=$(shasum -a 256 "$artifactDir/logs/$(echo "$f" | tr '/' '_')") || return 1
    logDigests="$logDigests  $digest
"
  done
  {
    echo "$manifestTitle"
    echo "finished:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "repository:      $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "worktree clean:  $([ -z "$(git status --porcelain 2>/dev/null)" ] && echo yes || echo "NO — this run is not reproducible from the recorded revision")"
    echo "ubft:            $( [ -x build/ubft ] && shasum -a 256 build/ubft | cut -d' ' -f1 || echo missing)"
    echo "reth:            ${rethCommit:-unknown}$([ "${rethCommit:-}" = "${pinnedRethCommit:-}" ] && echo " (pinned)" || echo " (NOT the pinned baseline)")"
    echo "validators:      $validators"
    for line in "${manifestLines[@]:-}"; do [ -n "$line" ] && echo "$line"; done
    echo "checks failed:   $failures"
    echo "reached:         ${reached:-startup}"
    echo
    echo "digests of the COPIED logs in $artifactDir/logs:"
    printf '%s' "$logDigests"
  } >"$artifactDir/manifest.txt" || {
    echo "  FAIL: could not write $artifactDir/manifest.txt — this run leaves no provenance" >&2
    return 1
  }
  manifestWritten=1
  return 0
}

# --- the lanes' own failure paths, tested without a devnet -------------------------------------
#
# WHY THIS EXISTS. Every defect review has found in this harness was in a path that only runs when
# something has ALREADY gone wrong: a read that failed, a number that was malformed, a directory that
# could not be created. Those paths never execute on a good run, so a passing acceptance run says
# nothing at all about them — and each one turned a failure into a PASS or a zero. So they are
# exercised deliberately, in a mode that needs no reth and no root chain:
#
#   ./scripts/f6b-quiet-tail-recovery.sh   --self-test
#   ./scripts/f6b-missed-block-recovery.sh --self-test
#
# Both invoke THIS function, because both lanes use these helpers and a failure path is not tested by
# being tested in one of the two callers.
#
# It asserts that each failure path FAILS, which is the only property that matters about them — the
# PROPERTY, not any particular guard. Several of the guards below are mutually redundant (a malformed
# head is caught by the pattern check, by the enumeration failing, and by the empty range), so
# removing any one of them individually changes nothing; removing all three makes this self-test fail
# by name. That is defence in depth, and it is worth stating rather than reporting per-guard coverage
# nobody has.
#
# It has already caught itself twice: helpers defined AFTER it made the checks inert, and they
# reported PASS while testing nothing — which is the same class of defect as everything below. That
# is now structural rather than a rule to remember: the checks live in the same file as the helpers,
# below all of them, and a lane can only reach this function by having sourced the whole library.
f6bSelfTest() {
  local selfFailures=0 desc before scratch
  echo "=== self-test: the lanes' failure paths ==="

  desc="an executor that cannot be reached is not zero transactions"
  before=$failures
  assertNoTransactions "unreachable" "http://127.0.0.1:9" >/dev/null 2>&1
  [ "$failures" -gt "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); }

  desc="a malformed head number is not zero transactions"
  before=$failures
  rpc() { echo '{"jsonrpc":"2.0","id":1,"result":{"number":"not-a-number"}}'; }
  assertNoTransactions "malformed head" "http://127.0.0.1:9" >/dev/null 2>&1
  [ "$failures" -gt "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); }

  desc="an empty head number is not zero transactions"
  before=$failures
  rpc() { echo '{"jsonrpc":"2.0","id":1,"result":{"number":"0x"}}'; }
  assertNoTransactions "empty head" "http://127.0.0.1:9" >/dev/null 2>&1
  [ "$failures" -gt "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); }

  desc="a malformed transaction count is not zero transactions"
  before=$failures
  rpc() {
    case "$2" in
      eth_getBlockByNumber) echo '{"jsonrpc":"2.0","id":1,"result":{"number":"0x1"}}' ;;
      *) echo '{"jsonrpc":"2.0","id":1,"result":"lots"}' ;;
    esac
  }
  assertNoTransactions "malformed count" "http://127.0.0.1:9" >/dev/null 2>&1
  [ "$failures" -gt "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); }

  desc="a hex-prefixed expression is not a transaction quantity"
  before=$failures
  rpc() {
    case "$2" in
      eth_getBlockByNumber) echo '{"result":{"number":"0x0"}}' ;;
      *) echo '{"result":"0x1-1"}' ;;
    esac
  }
  assertNoTransactions "expression count" unused >/dev/null 2>&1
  [ "$failures" -gt "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); }

  desc="a well-formed answer of zero still passes"
  before=$failures
  rpc() {
    case "$2" in
      eth_getBlockByNumber) echo '{"jsonrpc":"2.0","id":1,"result":{"number":"0x1"}}' ;;
      *) echo '{"jsonrpc":"2.0","id":1,"result":"0x0"}' ;;
    esac
  }
  assertNoTransactions "genuinely empty" "http://127.0.0.1:9" >/dev/null 2>&1
  [ "$failures" -eq "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc — a good answer was rejected"; selfFailures=$((selfFailures + 1)); }

  # THE MISSED-BLOCK LANE'S CLAIM IS NOT A ZERO. It asserts an EXACT count, because the setup
  # transactions are supposed to be there and nothing else is. Both directions are defects: fewer
  # than expected means the setup never happened and the lane is measuring an idle shard, more means
  # activity it did not authorise helped the recovery along.
  desc="an exact transaction count rejects too few"
  before=$failures
  rpc() {
    case "$2" in
      eth_getBlockByNumber) echo '{"result":{"number":"0x1"}}' ;;
      *) echo '{"result":"0x0"}' ;;
    esac
  }
  assertTransactionCount "too few" unused 3 >/dev/null 2>&1
  [ "$failures" -gt "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); }

  desc="an exact transaction count rejects too many"
  before=$failures
  rpc() {
    case "$2" in
      eth_getBlockByNumber) echo '{"result":{"number":"0x1"}}' ;;
      *) echo '{"result":"0x3"}' ;;
    esac
  }
  assertTransactionCount "too many" unused 3 >/dev/null 2>&1
  [ "$failures" -gt "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); }

  desc="an exact transaction count accepts the expected number"
  before=$failures
  rpc() {
    case "$2" in
      eth_getBlockByNumber) echo '{"result":{"number":"0x2"}}' ;;
      *) echo '{"result":"0x1"}' ;;
    esac
  }
  assertTransactionCount "just right" unused 3 >/dev/null 2>&1
  [ "$failures" -eq "$before" ] && echo "  PASS: $desc" || { echo "  FAIL: $desc — a good answer was rejected"; selfFailures=$((selfFailures + 1)); }

  desc="an unreadable executor is not a block identity"
  if blockAt "http://127.0.0.1:9" latest >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  # A TRUNCATED HASH IS NOT A HASH. The missed-block lane compares the adopted anchor against the
  # provider's canonical block hash, and a comparison of two values it never validated can agree by
  # both being empty — which is how a lane reports exact-block recovery having read nothing.
  desc="a short block hash is not a block identity"
  rpc() { echo '{"result":{"number":"0x3","hash":"0xdead","stateRoot":"0x'"$(printf '1%.0s' $(seq 1 64))"'"}}'; }
  if blockAt unused latest >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a complete block is read as one atomic identity"
  rpc() { echo '{"result":{"number":"0x3","hash":"0x'"$(printf 'a%.0s' $(seq 1 64))"'","stateRoot":"0x'"$(printf 'b%.0s' $(seq 1 64))"'"}}'; }
  if [ "$(blockAt unused latest 2>/dev/null)" = "0x3 0x$(printf 'a%.0s' $(seq 1 64)) 0x$(printf 'b%.0s' $(seq 1 64))" ]; then
    echo "  PASS: $desc"
  else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi

  # "I could not look" is not "it did not get there" and it is certainly not "it did".
  desc="an unreadable executor never satisfies a head wait"
  rpc() { echo '{"result":{"number":"garbage"}}'; }
  if waitForHead unused 1 1 >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi
  unset -f rpc

  # THE STALE-QUIETNESS DEFECT, reproduced. A log holding four quiet rounds followed by a block must
  # report a quiet TAIL of zero. Reading it as four is what restarted the recovering node while the
  # certificate naming its missed block was still the newest one.
  desc="quiet rounds before a block are not a quiet tail"
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/f6b-quiet.XXXXXX") || return 1
  {
    echo 'time=2026-01-01T00:00:01.0000+0000 msg="submitting block certification request" quiet=true'
    echo 'time=2026-01-01T00:00:02.0000+0000 msg="submitting block certification request" quiet=true'
    echo 'time=2026-01-01T00:00:03.0000+0000 msg="submitting block certification request" quiet=true'
    echo 'time=2026-01-01T00:00:04.0000+0000 msg="submitting block certification request" quiet=true'
    echo 'time=2026-01-01T00:00:05.0000+0000 msg="submitting block certification request" quiet=false'
  } >"$scratch/stale.log"
  if [ "$(waitForQuietTail 1 1 "$scratch/stale.log")" = "0" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — reported $(waitForQuietTail 1 1 "$scratch/stale.log")"; selfFailures=$((selfFailures + 1)); fi

  desc="quiet rounds after the last block are a quiet tail"
  echo 'time=2026-01-01T00:00:06.0000+0000 msg="submitting block certification request" quiet=true' >>"$scratch/stale.log"
  echo 'time=2026-01-01T00:00:07.0000+0000 msg="submitting block certification request" quiet=true' >>"$scratch/stale.log"
  if [ "$(waitForQuietTail 2 1 "$scratch/stale.log")" = "2" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi

  desc="a block after the mark is counted, one before it is not"
  a=$(nonQuietSince "time=2026-01-01T00:00:04" "$scratch/stale.log")
  b=$(nonQuietSince "time=2026-01-01T00:00:06" "$scratch/stale.log")
  if [ "$a" = "1" ] && [ "$b" = "0" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — since 00:00:04 saw $a, since 00:00:06 saw $b"; selfFailures=$((selfFailures + 1)); fi

  desc="the tail is read across every log, not just the first"
  cp "$scratch/stale.log" "$scratch/other.log"
  echo 'time=2026-01-01T00:00:08.0000+0000 msg="submitting block certification request" quiet=false' >>"$scratch/other.log"
  if [ "$(waitForQuietTail 1 1 "$scratch/stale.log" "$scratch/other.log")" = "0" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — a block seen only by the second validator did not move the boundary"; selfFailures=$((selfFailures + 1)); fi
  rm -rf "$scratch"

  # A WAIT ANCHORED ON THE WRONG POINT IS A FALSE FAILURE. Lines before the mark must not count
  # towards it, and a mark that has not appeared yet must not satisfy it at all.
  desc="lines before the mark do not count towards the wait"
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/f6b-after.XXXXXX") || return 1
  printf 'cert\ncert\ncert\nADOPTED\ncert\n' >"$scratch/after.log"
  if [ "$(waitForLinesAfter "$scratch/after.log" ADOPTED cert 1 1)" = "1" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — counted $(waitForLinesAfter "$scratch/after.log" ADOPTED cert 1 1)"; selfFailures=$((selfFailures + 1)); fi

  desc="a mark that never appears never satisfies the wait"
  printf 'cert\ncert\ncert\n' >"$scratch/none.log"
  if waitForLinesAfter "$scratch/none.log" ADOPTED cert 1 1 >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi
  rm -rf "$scratch"

  # ISOLATION IS READ, NEVER ASSUMED, AND READ FROM BOTH ENDS. Each of these is a way the premise
  # "this client could not have obtained the block from anywhere" fails while a single reading says
  # it holds.
  desc="a peer count that is not a quantity is not zero peers"
  rpc() { echo '{"result":"none"}'; }
  if peerCount unused >/dev/null 2>&1; then echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a client reporting no peers while still listing a session is not isolated"
  rpc() {
    case "$2" in
      net_peerCount) echo '{"result":"0x0"}' ;;
      admin_peers) echo '{"result":[{"id":"beef"}]}' ;;
    esac
  }
  if [ "$(holdsIsolation subject aaaa 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a survivor that still lists the subject means the subject is not isolated"
  rpc() {
    case "$1:$2" in
      subject:net_peerCount) echo '{"result":"0x0"}' ;;
      subject:admin_peers) echo '{"result":[]}' ;;
      *:admin_peers) echo '{"result":[{"id":"AAAA"}]}' ;;
    esac
  }
  if [ "$(holdsIsolation subject aaaa survivor 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc — the subject's own reading was taken as the whole answer"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="isolation confirmed from both ends reads as isolated"
  rpc() {
    case "$1:$2" in
      subject:net_peerCount) echo '{"result":"0x0"}' ;;
      *:admin_peers) echo '{"result":[]}' ;;
    esac
  }
  if [ "$(holdsIsolation subject aaaa survivor 2>/dev/null)" = "ok" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — a good isolation was rejected"; selfFailures=$((selfFailures + 1)); fi

  # A SINGLE SAMPLE IS NOT ISOLATION. A client that re-dials a second later was never isolated for
  # the window the experiment needs, and the whole result would rest on when the sample was taken.
  desc="a client that re-dials during the hold window is not isolated"
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/f6b-peers.XXXXXX") || return 1
  echo 0 >"$scratch/n"
  rpc() {
    local k; k=$(cat "$scratch/n"); echo $((k + 1)) >"$scratch/n"
    case "$1:$2" in
      subject:net_peerCount) [ "$k" -lt 4 ] && echo '{"result":"0x0"}' || echo '{"result":"0x1"}' ;;
      *:admin_peers) echo '{"result":[]}' ;;
    esac
  }
  if waitForIsolation subject aaaa 2 3 survivor >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi
  rm -rf "$scratch"

  desc="a receipt without a full block hash is not an identity"
  rpc() { echo '{"result":{"blockNumber":"0x3","blockHash":"0xdead"}}'; }
  if receiptIdentity unused 0xtx >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi
  unset -f rpc

  desc="an artifact directory that cannot be created fails the run"
  artifactDir=/dev/null/not-a-directory
  manifestWritten=0
  if writeManifest >/dev/null 2>&1; then
    echo "  FAIL: $desc — writeManifest reported success"
    selfFailures=$((selfFailures + 1))
  elif [ "$manifestWritten" -eq 1 ]; then
    echo "  FAIL: $desc — it marked itself done without writing anything"
    selfFailures=$((selfFailures + 1))
  else
    echo "  PASS: $desc"
  fi

  # Run the real writer in an isolated tree. A stale artifact must not mask a failed copy.
  desc="a required copy failure cannot produce a successful manifest"
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/f6b-selftest.XXXXXX") || return 1
  if (
    cd "$scratch" || exit 1
    validators=1; reached="all sections"; manifestWritten=0
    manifestLogs="test-nodes/evm1/control.log test-nodes/evm1/debug.log"
    artifactDir="$scratch/artifact"
    mkdir -p test-nodes/evm1 "$artifactDir/logs"
    printf control > test-nodes/evm1/control.log
    printf recovery > test-nodes/evm1/debug.log
    printf stale > "$artifactDir/logs/stale.log"
    # Inject a copy failure independently of user/root filesystem privileges.
    cp() { return 1; }
    if writeManifest >/dev/null 2>&1; then exit 1; fi
    [ "$manifestWritten" -eq 0 ]
  ); then echo "  PASS: $desc"; else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi

  desc="a completed run requires every assertion log"
  if (
    cd "$scratch" || exit 1
    validators=1; reached="all sections"; manifestWritten=0
    manifestLogs="test-nodes/evm1/control.log test-nodes/evm1/debug.log"
    artifactDir="$scratch/missing"
    rm test-nodes/evm1/debug.log
    if writeManifest >/dev/null 2>&1; then exit 1; fi
    [ "$manifestWritten" -eq 0 ]
  ); then echo "  PASS: $desc"; else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi

  desc="a complete artifact contains verifiable copied logs"
  if (
    cd "$scratch" || exit 1
    validators=1; reached="all sections"; manifestWritten=0
    manifestLogs="test-nodes/evm1/control.log test-nodes/evm1/debug.log"
    artifactDir="$scratch/complete"
    printf recovery > test-nodes/evm1/debug.log
    writeManifest >/dev/null 2>&1 || exit 1
    [ "$manifestWritten" -eq 1 ] || exit 1
    cmp test-nodes/evm1/control.log "$artifactDir/logs/test-nodes_evm1_control.log" || exit 1
    cmp test-nodes/evm1/debug.log "$artifactDir/logs/test-nodes_evm1_debug.log" || exit 1
    grep '^  [0-9a-f]' "$artifactDir/manifest.txt" | shasum -a 256 -c >/dev/null
  ); then echo "  PASS: $desc"; else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi
  rm -rf "$scratch"

  echo
  if [ "$selfFailures" -eq 0 ]; then
    echo "SELF-TEST PASSED"
  else
    echo "$selfFailures SELF-TEST CHECK(S) FAILED"
  fi
  return $((selfFailures > 0))
}
