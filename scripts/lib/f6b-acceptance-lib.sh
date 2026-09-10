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
