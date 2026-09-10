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

f6bEvents="$(dirname "${BASH_SOURCE[0]}")/f6b_events.py"

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
# The offset is part of the mark. Without it the mark is a NAIVE instant while every log line
# carries one, and any real comparison between them raises rather than answers — so the mark has to
# be as well-formed as the thing it is compared against.
markNow() { date +time=%Y-%m-%dT%H:%M:%S%z; }

# nonQuietSince counts non-quiet rounds logged after <mark> across <log...>. A line from the same
# whole second as the mark counts as after it, which can only produce a false FAILURE, never a false
# pass — the direction an assertion about "nothing happened" has to err in.
nonQuietSince() { # nonQuietSince <mark> <log...>
  local mark=$1; shift
  python3 "$f6bEvents" --mode count --from "$mark" --pattern "quiet=false" "$@"
}

quietSince() { # quietSince <mark> <log...>
  local mark=$1; shift
  python3 "$f6bEvents" --mode count --from "$mark" --pattern "quiet=true" "$@"
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
    n=$(quietSince "${last:-time=1970-01-01T00:00:00+0000}" "$@")
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

# peerIds echoes the peer ids this client currently holds, one per line, lower-cased — the second,
# independent reading of the same fact. net_peerCount and admin_peers are maintained separately, and
# a client that reports zero while still listing a session has not been isolated.
#
# IT REFUSES ANYTHING THAT IS NOT A PEER LIST. The first version read the answer as
# `d.get('result') or []`, so a JSON-RPC error, a missing result, an explicit null and a malformed
# body were all rendered as "this client has no peers" — and with net_peerCount also unreadable,
# holdsIsolation printed `ok` for a client nobody could see at all. That is the same defect as
# counting a failed transaction read as a zero, in the one place where the whole experiment's
# premise is a negative. An entry without a usable id is refused for the same reason: it used to
# become the empty string, which matches nothing and therefore proves nothing.
peerIds() { # peerIds <ethURL>
  local out
  out=$(rpc "$1" admin_peers '[]') || { echo "admin_peers to $1 failed" >&2; return 1; }
  printf '%s' "$out" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception as e:
    sys.stderr.write('admin_peers returned no JSON: %s\n' % e); sys.exit(1)
if not isinstance(d, dict):
    sys.stderr.write('admin_peers returned %s, not a JSON-RPC object\n' % type(d).__name__); sys.exit(1)
if d.get('error') is not None:
    sys.stderr.write('admin_peers returned an error: %r\n' % (d['error'],)); sys.exit(1)
if 'result' not in d:
    sys.stderr.write('admin_peers returned no result field\n'); sys.exit(1)
r = d['result']
if not isinstance(r, list):
    sys.stderr.write('admin_peers result is %s, not a list\n' % type(r).__name__); sys.exit(1)
for p in r:
    if not isinstance(p, dict):
        sys.stderr.write('admin_peers entry is not an object\n'); sys.exit(1)
    i = p.get('id')
    if not isinstance(i, str) or not i.strip():
        sys.stderr.write('admin_peers entry has no usable id\n'); sys.exit(1)
    print(i.strip().lower())
" || { echo "admin_peers from $1 was not a readable peer list" >&2; return 1; }
}

# nodeAdminID echoes the id this client is listed as BY ITS PEERS, lower-cased.
#
# NOT the enode public key. At the pinned reth commit the admin API reports a peer as
# hex(keccak256(remote_id)) — 64 hex characters — while the enode URL carries the 128-character
# public key, and the two are measured here to be exactly that: a 128-character key and a
# 64-character id. An earlier revision compared the key against the peer list, which cannot match
# anything, so the survivor-side half of the isolation check was inert while reading as PASS. Both
# sides of a comparison have to be the same kind of thing.
nodeAdminID() { # nodeAdminID <ethURL>
  local id
  id=$(rpcRequire "$1" admin_nodeInfo '[]' "['result']['id']" "node id") || return 1
  id=$(printf '%s' "$id" | tr 'A-Z' 'a-z')
  [[ "$id" =~ ^[0-9a-f]{64}$ ]] || { echo "node id from $1 is not a 32-byte hex id: '$id'" >&2; return 1; }
  printf '%s' "$id"
}

# holdsIsolation reads the isolation from BOTH ends and echoes "ok" or the reason it is not held.
# It never touches $failures — the caller asserts.
holdsIsolation() { # holdsIsolation <subjectEthURL> <subjectAdminID> <peerEthURL...>
  local url=$1 id=$2; shift 2
  local n other ids
  n=$(peerCount "$url" 2>/dev/null) || { echo "could not read the subject's peer count"; return 1; }
  [ "$n" = "0" ] || { echo "the subject still has $n execution peer(s)"; return 1; }
  ids=$(peerIds "$url" 2>/dev/null) || { echo "could not read the subject's peer list"; return 1; }
  [ -z "$ids" ] || { echo "the subject reports no peer count but still lists sessions"; return 1; }
  for other in "$@"; do
    ids=$(peerIds "$other" 2>/dev/null) || { echo "could not read $other's peer list"; return 1; }
    # Exact equality on a whole line, both sides lower-cased by peerIds and nodeAdminID. A substring
    # match would also have accepted a prefix, which is how an id of the wrong length can look
    # absent when the harness never had a comparable value to look for.
    if printf '%s\n' "$ids" | grep -qx "$id"; then
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

# --- observation over a WINDOW, not at its endpoints ---------------------------------------------
#
# Two samples either side of an interval say nothing about the interval. A connection that opens and
# closes between them passes both, and the whole premise of the isolation experiment is that no
# connection existed at any point while the missed blocks were being created. Review found exactly
# that gap: the ten-second hold finished before the transactions were submitted and the next reading
# was taken after both receipts.
#
# Two independent records cover it, and the lane requires both. The MONITOR samples connectivity on
# a fixed interval and records every sample, including the ones it could not take — a window with
# too few samples, or with one unreadable sample, is not an observed window. The client's own
# SESSION EVENTS are the complete record: reth logs every session it establishes, so their absence
# over the window is evidence of a different kind from a sample, and neither substitutes for the
# other.

peerMonitorPID=""
startPeerMonitor() { # startPeerMonitor <ethURL> <outfile> <intervalSecs>
  : >"$2"
  (
    while :; do
      pmN=$(peerCount "$1" 2>/dev/null) || pmN=""
      pmIDs=$(peerIds "$1" 2>/dev/null) || pmIDs="__unreadable__"
      if [ -z "$pmN" ] || [ "$pmIDs" = "__unreadable__" ]; then
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) status=unreadable"
      else
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) status=ok peers=$pmN sessions=$(printf '%s' "$pmIDs" | tr '\n' ',')"
      fi
      sleep "$3"
    done
  ) >>"$2" 2>/dev/null &
  peerMonitorPID=$!
}

stopPeerMonitor() {
  [ -n "$peerMonitorPID" ] && kill "$peerMonitorPID" 2>/dev/null
  peerMonitorPID=""
}

# monitorClean echoes "ok", or the reason the window is not an observed window of no connectivity.
# An unreadable sample is a failure, not a gap: "I could not look" is not "there was nothing there".
monitorClean() { # monitorClean <file> <fromTS> <toTS> <minSamples>
  local f=$1 from=$2 to=$3 want=$4 r
  r=$(awk -v a="$from" -v b="$to" '
    $1 >= a && $1 <= b {
      n++
      if ($0 !~ /status=ok/) { unread++ }
      else if ($0 !~ /peers=0 sessions=$/) { conn++ }
    }
    END { printf "%d %d %d", n+0, unread+0, conn+0 }
  ' "$f" 2>/dev/null)
  set -- $r
  [ "${1:-0}" -ge "$want" ] || { echo "only ${1:-0} connectivity samples cover the window, at least $want were required"; return 1; }
  [ "${2:-1}" = "0" ] || { echo "${2} sample(s) in the window could not read the client"; return 1; }
  [ "${3:-1}" = "0" ] || { echo "${3} sample(s) in the window show an execution peer or a session"; return 1; }
  echo ok
}

# blockPresence answers whether a client HOLDS a block, by hash, independently of what its head is:
# "present" or "absent", and a non-zero status for anything it could not read. A null result is a
# real answer — the client does not have it — while an error, a missing result field or a body that
# is neither a block nor null is not an answer at all. The whole point of the unhelpful-peer
# experiment is a checked claim that a peer does NOT hold something, so "I could not ask" must never
# read as "it does not have it".
blockPresence() { # blockPresence <ethURL> <blockHash>
  local out
  out=$(rpc "$1" eth_getBlockByHash "[\"$2\", false]") || { echo "eth_getBlockByHash to $1 failed" >&2; return 1; }
  printf '%s' "$out" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception as e:
    sys.stderr.write('eth_getBlockByHash returned no JSON: %s\n' % e); sys.exit(1)
if not isinstance(d, dict):
    sys.stderr.write('eth_getBlockByHash returned %s, not a JSON-RPC object\n' % type(d).__name__); sys.exit(1)
if d.get('error') is not None:
    sys.stderr.write('eth_getBlockByHash returned an error: %r\n' % (d['error'],)); sys.exit(1)
if 'result' not in d:
    sys.stderr.write('eth_getBlockByHash returned no result field\n'); sys.exit(1)
r = d['result']
if r is None:
    print('absent')
elif isinstance(r, dict) and isinstance(r.get('hash'), str) and r['hash']:
    print('present')
else:
    sys.stderr.write('eth_getBlockByHash result is neither a block nor null\n'); sys.exit(1)
"
}

# monitorConnectedWithout is monitorClean's opposite for the arm where the subject is deliberately
# CONNECTED: every sample in the window must be readable, must show at least one execution peer, and
# must not list any of the forbidden ids. It is what makes "connected to peers that cannot help"
# a measured condition rather than a description of how the script was written.
monitorConnectedWithout() { # monitorConnectedWithout <file> <fromTS> <toTS> <minSamples> <forbiddenID...>
  local f=$1 from=$2 to=$3 want=$4; shift 4
  python3 - "$f" "$from" "$to" "$want" "$@" <<'PYMON'
import sys
from datetime import datetime, timedelta
path, from_ts, to_ts, want, *forbidden = sys.argv[1:]
def instant(v):
    return datetime.fromisoformat(v.replace('Z', '+00:00'))
try:
    start, end = instant(from_ts), instant(to_ts)
    if '.' not in to_ts:
        end += timedelta(seconds=1)
    n = unread = lonely = tainted = 0
    with open(path) as src:
        for line in src:
            parts = line.split()
            if not parts:
                continue
            stamp = instant(parts[0])
            if not (start <= stamp < end):
                continue
            n += 1
            if 'status=ok' not in line:
                unread += 1
                continue
            peers = 0
            for field in parts:
                if field.startswith('peers='):
                    peers = int(field.split('=', 1)[1])
            if peers < 1:
                lonely += 1
            if any(bad and bad in line for bad in forbidden):
                tainted += 1
    if n < int(want):
        print('only %d connectivity samples cover the window, at least %s were required' % (n, want)); sys.exit(1)
    if unread:
        print('%d sample(s) in the window could not read the client' % unread); sys.exit(1)
    if lonely:
        print('%d sample(s) in the window show no execution peer at all' % lonely); sys.exit(1)
    if tainted:
        print('%d sample(s) in the window list a peer this arm forbids' % tainted); sys.exit(1)
    print('ok')
except (OSError, ValueError, IndexError, TypeError) as err:
    print('cannot read connectivity window: %s' % err); sys.exit(1)
PYMON
}

# linesSince counts lines matching <pattern> logged after <mark> across <file...>. The mark must be
# in the same form as the log's first field: `time=...` for the node's own logs (markNow), a bare
# RFC3339 stamp for the execution client's.
linesSince() { # linesSince <mark> <pattern> <file...>
  local mark=$1 pat=$2; shift 2
  python3 "$f6bEvents" --mode count --from "$mark" --pattern "$pat" "$@"
}

# linesBetween counts lines matching <pattern> logged in [from, to] across <file...>. A whole-second
# end marker covers that complete second; see f6b_events.py.
linesBetween() { # linesBetween <from> <to> <pattern> <file...>
  local from=$1 to=$2 pat=$3; shift 3
  python3 "$f6bEvents" --mode count --from "$from" --to "$to" --pattern "$pat" "$@"
}

# blockPresence answers whether a client HOLDS a block, by hash, independently of what its head is:
# "present" or "absent", and a non-zero status for anything it could not read. A null result is a
# real answer — the client does not have it — while an error, a missing result field or a body that
# is neither a block nor null is not an answer at all. The whole point of the unhelpful-peer
# experiment is a checked claim that a peer does NOT hold something, so "I could not ask" must never
# read as "it does not have it".
blockPresence() { # blockPresence <ethURL> <blockHash>
  local out
  out=$(rpc "$1" eth_getBlockByHash "[\"$2\", false]") || { echo "eth_getBlockByHash to $1 failed" >&2; return 1; }
  printf '%s' "$out" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception as e:
    sys.stderr.write('eth_getBlockByHash returned no JSON: %s\n' % e); sys.exit(1)
if not isinstance(d, dict):
    sys.stderr.write('eth_getBlockByHash returned %s, not a JSON-RPC object\n' % type(d).__name__); sys.exit(1)
if d.get('error') is not None:
    sys.stderr.write('eth_getBlockByHash returned an error: %r\n' % (d['error'],)); sys.exit(1)
if 'result' not in d:
    sys.stderr.write('eth_getBlockByHash returned no result field\n'); sys.exit(1)
r = d['result']
if r is None:
    print('absent')
elif isinstance(r, dict) and isinstance(r.get('hash'), str) and r['hash']:
    print('present')
else:
    sys.stderr.write('eth_getBlockByHash result is neither a block nor null\n'); sys.exit(1)
"
}

# monitorConnectedWithout is monitorClean's opposite for the arm where the subject is deliberately
# CONNECTED: every sample in the window must be readable, must show at least one execution peer, and
# must not list any of the forbidden ids. It is what makes "connected to peers that cannot help"
# a measured condition rather than a description of how the script was written.
monitorConnectedWithout() { # monitorConnectedWithout <file> <fromTS> <toTS> <minSamples> <forbiddenID...>
  local f=$1 from=$2 to=$3 want=$4; shift 4
  python3 - "$f" "$from" "$to" "$want" "$@" <<'PYMON'
import sys
from datetime import datetime, timedelta
path, from_ts, to_ts, want, *forbidden = sys.argv[1:]
def instant(v):
    return datetime.fromisoformat(v.replace('Z', '+00:00'))
try:
    start, end = instant(from_ts), instant(to_ts)
    if '.' not in to_ts:
        end += timedelta(seconds=1)
    n = unread = lonely = tainted = 0
    with open(path) as src:
        for line in src:
            parts = line.split()
            if not parts:
                continue
            stamp = instant(parts[0])
            if not (start <= stamp < end):
                continue
            n += 1
            if 'status=ok' not in line:
                unread += 1
                continue
            peers = 0
            for field in parts:
                if field.startswith('peers='):
                    peers = int(field.split('=', 1)[1])
            if peers < 1:
                lonely += 1
            if any(bad and bad in line for bad in forbidden):
                tainted += 1
    if n < int(want):
        print('only %d connectivity samples cover the window, at least %s were required' % (n, want)); sys.exit(1)
    if unread:
        print('%d sample(s) in the window could not read the client' % unread); sys.exit(1)
    if lonely:
        print('%d sample(s) in the window show no execution peer at all' % lonely); sys.exit(1)
    if tainted:
        print('%d sample(s) in the window list a peer this arm forbids' % tainted); sys.exit(1)
    print('ok')
except (OSError, ValueError, IndexError, TypeError) as err:
    print('cannot read connectivity window: %s' % err); sys.exit(1)
PYMON
}

# linesFrom counts, and printLinesFrom echoes, the lines of <file...> at or after <mark>.
# linesBetween counts those inside [from, to]. All three are one implementation — see
# scripts/lib/f6b_events.py for why comparing RFC3339 as text is wrong, why a banner line is not
# corruption, and why an unreadable stream is a failed observation rather than a zero.
linesFrom() { # linesFrom <mark> <pattern> <file...>
  local mark=$1 pat=$2; shift 2
  python3 "$f6bEvents" --mode count --from "$mark" --pattern "$pat" "$@"
}

printLinesFrom() { # printLinesFrom <mark> <file...>
  local mark=$1; shift
  python3 "$f6bEvents" --mode show --from "$mark" "$@"
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
  a=$(nonQuietSince "time=2026-01-01T00:00:04+0000" "$scratch/stale.log")
  b=$(nonQuietSince "time=2026-01-01T00:00:06+0000" "$scratch/stale.log")
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
  # it holds. The identities below are REAL-SHAPED and distinct: a 64-hex admin id, which is what a
  # peer list contains, and the 128-hex enode public key for the same node, which is not. An earlier
  # fixture used `aaaa`/`AAAA` for both, and that is precisely why it hid a comparison between two
  # representations that can never be equal.
  local subjID="7abda841d17f3b44f9c5365b18529d5777cfc70928da8cb129760f601b6a1866"
  local subjKey="6ae135ef47ede8f445f7$(printf '0%.0s' $(seq 1 108))"
  local otherID="c0ffee11d17f3b44f9c5365b18529d5777cfc70928da8cb129760f601b6a9999"

  desc="a peer count that is not a quantity is not zero peers"
  rpc() { echo '{"result":"none"}'; }
  if peerCount unused >/dev/null 2>&1; then echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  # THE DEFECT REVIEW REPRODUCED. With net_peerCount answering 0 and admin_peers answering a
  # JSON-RPC error on BOTH ends, the earlier holdsIsolation printed `ok` and exited 0 — a client
  # nobody could see at all, reported as a client provably alone.
  desc="an admin_peers error is not an empty peer list"
  rpc() {
    case "$2" in
      net_peerCount) echo '{"jsonrpc":"2.0","id":1,"result":"0x0"}' ;;
      admin_peers) echo '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}' ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" survivor 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a null admin_peers result is not an empty peer list"
  rpc() {
    case "$2" in
      net_peerCount) echo '{"result":"0x0"}' ;;
      admin_peers) echo '{"result":null}' ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" survivor 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="an admin_peers response with no result field is not an empty peer list"
  rpc() {
    case "$2" in
      net_peerCount) echo '{"result":"0x0"}' ;;
      admin_peers) echo '{"jsonrpc":"2.0","id":1}' ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" survivor 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a peer entry with no id is not a readable peer list"
  rpc() {
    case "$1:$2" in
      subject:net_peerCount) echo '{"result":"0x0"}' ;;
      subject:admin_peers) echo '{"result":[]}' ;;
      *:admin_peers) echo '{"result":[{"name":"reth","id":""}]}' ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" survivor 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc — an unusable id was read as 'not the subject'"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a client reporting no peers while still listing a session is not isolated"
  rpc() {
    case "$2" in
      net_peerCount) echo '{"result":"0x0"}' ;;
      admin_peers) echo "{\"result\":[{\"id\":\"$otherID\"}]}" ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  # THE SECOND DEFECT REVIEW REPRODUCED, with values of the real shapes. The survivor lists the
  # subject by its 64-hex admin id; a check comparing the 128-hex enode key finds nothing and reads
  # as isolated.
  desc="a survivor that lists the subject's admin id means the subject is not isolated"
  rpc() {
    case "$1:$2" in
      subject:net_peerCount) echo '{"result":"0x0"}' ;;
      subject:admin_peers) echo '{"result":[]}' ;;
      *:admin_peers) echo "{\"result\":[{\"id\":\"$subjID\"}]}" ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" survivor 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc — the subject's own reading was taken as the whole answer"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  # CASE IS NOT IDENTITY. A survivor that reports the id in another case still lists the subject,
  # and a comparison that misses it reads as isolated — a false pass in the direction that matters.
  desc="a survivor listing the subject's id in another case still means it is not isolated"
  rpc() {
    case "$1:$2" in
      subject:net_peerCount) echo '{"result":"0x0"}' ;;
      subject:admin_peers) echo '{"result":[]}' ;;
      *:admin_peers) echo "{\"result\":[{\"id\":\"$(printf '%s' "$subjID" | tr 'a-f' 'A-F')\"}]}" ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" survivor 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  # A DIFFERENT PEER IS NOT THE SUBJECT. Ids are fixed-width, so one that merely CONTAINS the
  # subject's belongs to somebody else; a substring or prefix comparison would call that a lapsed
  # isolation and stop a valid run. Exact, whole-line equality is what the check is entitled to.
  desc="a peer whose id merely contains the subject's is a different peer"
  rpc() {
    case "$1:$2" in
      subject:net_peerCount) echo '{"result":"0x0"}' ;;
      subject:admin_peers) echo '{"result":[]}' ;;
      *:admin_peers) echo "{\"result\":[{\"id\":\"${subjID}0\"}]}" ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" survivor 2>/dev/null)" = "ok" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — the comparison is not exact"; selfFailures=$((selfFailures + 1)); fi

  desc="the enode public key is not the identity a peer list can be searched for"
  if [ "$(holdsIsolation subject "$subjKey" survivor 2>/dev/null)" = "ok" ]; then
    echo "  PASS: $desc"   # searching for the key finds nothing — which is exactly why the key must never be used
  else
    echo "  FAIL: $desc — the fixture no longer distinguishes the two representations"; selfFailures=$((selfFailures + 1))
  fi
  desc="and nodeAdminID refuses a value of the enode key's shape"
  rpc() { echo "{\"result\":{\"id\":\"$subjKey\"}}"; }
  if nodeAdminID unused >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi
  desc="nodeAdminID accepts a 32-byte id and lower-cases it"
  rpc() { echo "{\"result\":{\"id\":\"$(printf '%s' "$subjID" | tr 'a-f' 'A-F')\"}}"; }
  if [ "$(nodeAdminID unused 2>/dev/null)" = "$subjID" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi

  desc="isolation confirmed from both ends, with a genuinely empty list, reads as isolated"
  rpc() {
    case "$1:$2" in
      subject:net_peerCount) echo '{"result":"0x0"}' ;;
      *:admin_peers) echo '{"jsonrpc":"2.0","id":1,"result":[]}' ;;
    esac
  }
  if [ "$(holdsIsolation subject "$subjID" survivor 2>/dev/null)" = "ok" ]; then echo "  PASS: $desc"
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
  if waitForIsolation subject "$subjID" 2 3 survivor >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi
  unset -f rpc

  # THE THIRD DEFECT REVIEW REPRODUCED: endpoint samples do not cover an interval. A connection that
  # opens and closes between the ends passes both readings, and the whole premise is that none
  # existed at any point.
  desc="a connection that opens and closes mid-window is not an isolated window"
  {
    echo "2026-01-01T00:00:01Z status=ok peers=0 sessions="
    echo "2026-01-01T00:00:02Z status=ok peers=0 sessions="
    echo "2026-01-01T00:00:03Z status=ok peers=1 sessions=$otherID,"
    echo "2026-01-01T00:00:04Z status=ok peers=0 sessions="
    echo "2026-01-01T00:00:05Z status=ok peers=0 sessions="
  } >"$scratch/mon.log"
  if [ "$(monitorClean "$scratch/mon.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:05Z 3 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a sample that could not read the client is not a sample of no connectivity"
  {
    echo "2026-01-01T00:00:01Z status=ok peers=0 sessions="
    echo "2026-01-01T00:00:02Z status=unreadable"
    echo "2026-01-01T00:00:03Z status=ok peers=0 sessions="
  } >"$scratch/mon2.log"
  if [ "$(monitorClean "$scratch/mon2.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z 3 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a window with too few samples is not an observed window"
  if [ "$(monitorClean "$scratch/mon2.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z 10 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="samples outside the window do not fill it in"
  {
    echo "2026-01-01T00:00:01Z status=ok peers=0 sessions="
    echo "2026-01-01T00:00:02Z status=ok peers=0 sessions="
    echo "2026-01-01T00:00:03Z status=ok peers=0 sessions="
    echo "2026-01-01T00:09:00Z status=ok peers=0 sessions="
    echo "2026-01-01T00:09:01Z status=ok peers=0 sessions="
  } >"$scratch/mon3.log"
  if [ "$(monitorClean "$scratch/mon3.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z 5 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc — readings from outside the interval were counted towards covering it"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a fully covered, readable, unconnected window reads as isolated"
  if [ "$(monitorClean "$scratch/mon3.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z 3 2>/dev/null)" = "ok" ]; then
    echo "  PASS: $desc"
  else echo "  FAIL: $desc — a good window was rejected"; selfFailures=$((selfFailures + 1)); fi

  desc="a session event inside the window is found by the event trace"
  {
    echo "2026-01-01T00:00:00.5Z DEBUG net: Session established remote_addr=1"
    echo "2026-01-01T00:00:02.5Z DEBUG net: Session established remote_addr=2"
    echo "2026-01-01T00:09:30.0Z DEBUG net: Session established remote_addr=3"
  } >"$scratch/reth.log"
  a=$(linesBetween 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z "Session established" "$scratch/reth.log")
  b=$(linesBetween 2026-01-01T00:00:03Z 2026-01-01T00:09:00Z "Session established" "$scratch/reth.log")
  if [ "$a" = "1" ] && [ "$b" = "0" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — in-window=$a (want 1), out-of-window=$b (want 0)"; selfFailures=$((selfFailures + 1)); fi

  desc="a session in the first fractional second is inside the window"
  echo "2026-01-01T00:00:01.500Z DEBUG net: Session established" >"$scratch/fraction.log"
  if [ "$(linesBetween 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z "Session established" "$scratch/fraction.log")" = "1" ]; then
    echo "  PASS: $desc"
  else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi

  desc="a session in the final marked second is still inside the snapshot"
  echo "2026-01-01T00:00:03.500Z DEBUG net: Session established" >"$scratch/fraction.log"
  if [ "$(linesBetween 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z "Session established" "$scratch/fraction.log")" = "1" ]; then
    echo "  PASS: $desc"
  else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi

  desc="a missing session trace is not zero session events"
  if linesBetween 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z "Session established" "$scratch/absent.log" >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  # THE SAME BOUNDARY, IN THE OTHER DIRECTION. An event inside the marked second is at or after that
  # second's start; string comparison puts it before, and a trace extraction written that way
  # produced no lines at all for a run in which everything happened inside one second.
  desc="an event in the marked second is at or after the mark"
  {
    echo "2026-09-10T22:03:20.000000Z DEBUG net: Session established"
    echo "2026-09-10T22:03:24.575417Z DEBUG net: Session established"
  } >"$scratch/from.log"
  a=$(linesFrom 2026-09-10T22:03:24Z "Session established" "$scratch/from.log")
  b=$(linesFrom 2026-09-10T22:03:20Z "Session established" "$scratch/from.log")
  if [ "$a" = "1" ] && [ "$b" = "2" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — from the marked second counted $a (want 1), from earlier $b (want 2)"; selfFailures=$((selfFailures + 1)); fi

  desc="a missing event stream is not an empty one"
  if linesFrom 2026-09-10T22:03:24Z "x" "$scratch/absent-stream.log" >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi
  if printLinesFrom 2026-09-10T22:03:24Z "$scratch/absent-stream.log" >/dev/null 2>&1; then
    echo "  FAIL: $desc (printLinesFrom)"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc (printLinesFrom)"; fi

  # A LOG HAS LINES THAT ARE NOT EVENTS. reth prints its chain-spec banner before anything
  # timestamped; a parser that treats those as corruption declares the file unreadable and every
  # window over it fails. A file with NO timestamped line at all is a different thing and is refused.
  desc="a banner before the first event does not make the log unreadable"
  {
    echo "Pre-merge hard forks (block based):"
    echo "2026-01-01T00:00:02.500Z DEBUG net: Session established"
  } >"$scratch/banner.log"
  if [ "$(linesFrom 2026-01-01T00:00:01Z "Session established" "$scratch/banner.log" 2>/dev/null)" = "1" ]; then
    echo "  PASS: $desc"
  else echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1)); fi

  desc="a file with no timestamped line at all is not an event log"
  printf 'Pre-merge hard forks (block based):\nMerge hard forks:\n' >"$scratch/nostamps.log"
  if linesFrom 2026-01-01T00:00:01Z "" "$scratch/nostamps.log" >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a phase-bound count ignores what happened in the phase before it"
  {
    echo "time=2026-01-01T00:00:01.0+0000 outcome=payload-unavailable"
    echo "time=2026-01-01T00:00:02.0+0000 outcome=payload-unavailable"
    echo "time=2026-01-01T00:00:09.0+0000 outcome=payload-unavailable"
  } >"$scratch/node.log"
  a=$(linesSince "time=2026-01-01T00:00:05+0000" "outcome=payload-unavailable" "$scratch/node.log")
  if [ "$a" = "1" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — counted $a, want 1"; selfFailures=$((selfFailures + 1)); fi

  # A CLAIM THAT A PEER DOES NOT HOLD SOMETHING IS A NEGATIVE, so an unreadable answer must never
  # become it. Only an explicit null is "absent".
  desc="an eth_getBlockByHash error is not an absent block"
  rpc() { echo '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nope"}}'; }
  if blockPresence unused 0xabc >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a missing result field is not an absent block"
  rpc() { echo '{"jsonrpc":"2.0","id":1}'; }
  if blockPresence unused 0xabc >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a null result is an absent block, and a block is a present one"
  rpc() { echo '{"jsonrpc":"2.0","id":1,"result":null}'; }
  a=$(blockPresence unused 0xabc 2>/dev/null)
  rpc() { echo '{"jsonrpc":"2.0","id":1,"result":{"hash":"0xabc","number":"0x3"}}'; }
  b=$(blockPresence unused 0xabc 2>/dev/null)
  if [ "$a" = "absent" ] && [ "$b" = "present" ]; then echo "  PASS: $desc"
  else echo "  FAIL: $desc — got '$a' and '$b'"; selfFailures=$((selfFailures + 1)); fi
  unset -f rpc

  # THE CONNECTED WINDOW, which is monitorClean's opposite and fails in the opposite directions.
  desc="a window with a sample showing no peer is not a connected window"
  {
    echo "2026-01-01T00:00:01Z status=ok peers=2 sessions=aa,bb,"
    echo "2026-01-01T00:00:02Z status=ok peers=0 sessions="
    echo "2026-01-01T00:00:03Z status=ok peers=2 sessions=aa,bb,"
  } >"$scratch/conn.log"
  if [ "$(monitorConnectedWithout "$scratch/conn.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z 3 cc 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a window listing a forbidden peer is not a window without it"
  {
    echo "2026-01-01T00:00:01Z status=ok peers=2 sessions=aa,bb,"
    echo "2026-01-01T00:00:02Z status=ok peers=3 sessions=aa,bb,cc,"
    echo "2026-01-01T00:00:03Z status=ok peers=2 sessions=aa,bb,"
  } >"$scratch/conn2.log"
  if [ "$(monitorConnectedWithout "$scratch/conn2.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z 3 cc 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc — a peer the arm forbids passed unnoticed"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="an unreadable sample is not a connected sample either"
  {
    echo "2026-01-01T00:00:01Z status=ok peers=2 sessions=aa,bb,"
    echo "2026-01-01T00:00:02Z status=unreadable"
    echo "2026-01-01T00:00:03Z status=ok peers=2 sessions=aa,bb,"
  } >"$scratch/conn3.log"
  if [ "$(monitorConnectedWithout "$scratch/conn3.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z 3 cc 2>/dev/null)" = "ok" ]; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a missing connectivity record is not a connected window"
  if monitorConnectedWithout "$scratch/absent-monitor.log" 2026-01-01T00:00:01Z 2026-01-01T00:00:03Z 3 cc >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi

  desc="a fully covered, readable, connected window without the forbidden peer reads as ok"
  if [ "$(monitorConnectedWithout "$scratch/conn.log" 2026-01-01T00:00:03Z 2026-01-01T00:00:03Z 1 cc 2>/dev/null)" = "ok" ]; then
    echo "  PASS: $desc"
  else echo "  FAIL: $desc — a good window was rejected"; selfFailures=$((selfFailures + 1)); fi

  desc="a receipt without a full block hash is not an identity"
  rpc() { echo '{"result":{"blockNumber":"0x3","blockHash":"0xdead"}}'; }
  if receiptIdentity unused 0xtx >/dev/null 2>&1; then
    echo "  FAIL: $desc"; selfFailures=$((selfFailures + 1))
  else echo "  PASS: $desc"; fi
  unset -f rpc
  rm -rf "$scratch"

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
