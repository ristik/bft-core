#!/usr/bin/env bash
# scripts/lane-slot.sh selftest (bft-core#1218): the port table, the lock protocol, and process scoping between trees.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); repo=$(cd "$here/.." && pwd)
source "$here/lib/lane-slot.sh"
fails=0
pass() { echo "  selftest PASS: $1"; }
fail() { echo "  selftest FAIL: $1" >&2; fails=$((fails + 1)); }
tmp=$(mktemp -d); fake='import time; time.sleep(120)'
cleanup() {
  local p
  for p in $(pids_under "$tmp"); do kill "$p" 2>/dev/null; done
  rm -rf "$tmp"
}
# the processes whose working directory is under $1: this selftest's own fakes, found by directory, never by name
pids_under() { local d p; for d in /proc/[0-9]*; do p=${d#/proc/}; case "$(readlink "$d/cwd" 2>/dev/null)" in "$1" | "$1"/*) echo "$p" ;; esac; done; }
trap cleanup EXIT

# 1. the table
lane_slot_selftest || fails=$((fails + 1))

# 2. no raw historical port literal in a lane script: every port goes through the slot offset (lane_port / LANE_PORT_OFFSET). A line that needs one
# (a fixture, data that is never dialed) says why with "lane-port-ok".
ports=$(lane_slot_ports 0 | awk '{print $2}' | sort -u | paste -sd'|' -)
lit=$(cd "$repo" && grep -rnwE "$ports" helper.sh scripts start.sh stop.sh start-evm.sh stop-evm.sh setup-nodes.sh setup-evm-nodes.sh \
  --include='*.sh' --include='*.py' 2>/dev/null | grep -v 'scripts/lib/lane-slot.sh' | grep -vE 'LANE_PORT_OFFSET|lane_port|lane-port-ok' | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)
if [ -z "$lit" ]; then pass "no raw historical port literal in the lane scripts"; else fail "raw historical port literals (route them through LANE_PORT_OFFSET):"; echo "$lit" >&2; fi

# 3. a lookup of processes by name alone is never used by the lane libraries and steps (use owned_pids: command AND cwd)
w1=pg; w2=rep; w3=pi; w4=dof
bare=$(cd "$repo" && grep -nE "(^|[^_a-z])${w1}${w2} -f|${w3}${w4}|ps -e|ps aux" helper.sh scripts/lib/{h3,q3,vr,h3-q3,q3-flow,m2-handoff,utb,agg,p85}-lib.sh scripts/*steps.sh scripts/vr-*.sh 2>/dev/null \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#|^helper.sh:7[0-9][0-9]:|^scripts/lib/q3-lib.sh:2[67][0-9]:' || true)
if [ -z "$bare" ]; then pass "no bare name-pattern process lookup in the lane libraries and steps"; else fail "bare process lookups (use owned_pids):"; echo "$bare" >&2; fi

# 4. two trees with the same relative layout see only their own processes
mkdir -p "$tmp/a" "$tmp/b"
for t in a b; do
  ( cd "$tmp/$t" && python3 -c "$fake" ubft root-node run --home test-nodes/root1 >/dev/null 2>&1 & )
  ( cd "$tmp/$t" && python3 -c "$fake" reth node --datadir test-nodes/reth5/dd --home test-nodes/evm5 >/dev/null 2>&1 & )
done
sleep 1
for pat in 'ubft root-node run --home test-nodes/root1' '--home test-nodes/evm5( |$)|test-nodes/reth5/dd'; do
  for t in a b; do
    mine=$(cd "$tmp/$t" && source "$repo/helper.sh" && owned_pids "$pat" | wc -l | tr -d ' ')
    own=$(pids_under "$tmp/$t" | wc -l | tr -d ' ')
    if [ "$mine" = 1 ] && [ "$own" -ge 1 ]; then pass "tree $t sees only its own process for '$pat'"; else fail "tree $t sees $mine processes for '$pat'"; fi
  done
done

# 5. the lock: one winner, the ephemeral-range refusal, exact owner and claim on release, atomic against a delayed duplicate
export LANE_LOCK_DIR="$tmp/locks"; ls_=$here/lane-slot.sh
a=$(LANE_OWNER=x "$ls_" acquire --slot 1 --token t1 2>/dev/null) && [ "$a" = 1 ] && pass "acquire takes a free slot" || fail "acquire of a free slot"
LANE_OWNER=y "$ls_" acquire --slot 1 >/dev/null 2>&1 && fail "an occupied slot was acquired" || pass "an occupied slot is refused"
LANE_OWNER=y "$ls_" release 1 >/dev/null 2>&1 && fail "release by a non-owner" || pass "release by a non-owner is refused"
LANE_OWNER=x "$ls_" release 1 --token other >/dev/null 2>&1 && fail "release under another claim's token" || pass "release under another claim's token is refused"
LANE_OWNER=x "$ls_" release 1 --token t1 >/dev/null 2>&1 && pass "release by the claim" || fail "release by the claim"
LANE_OWNER=x "$ls_" acquire --slot 1 --token t2 >/dev/null 2>&1   # a replacement claim by the same owner
LANE_OWNER=x "$ls_" release 1 --token t1 >/dev/null 2>&1   # the delayed duplicate release of the first claim
[ -f "$LANE_LOCK_DIR/slot-1.txt" ] && pass "a delayed duplicate release leaves the replacement claim's lock" || fail "a delayed duplicate release removed the replacement claim's lock"
LANE_OWNER=x "$ls_" release 1 --token t2 >/dev/null 2>&1
echo "32768 60999" >"$tmp/range"
if LANE_PORT_RANGE_FILE="$tmp/range" LANE_PORT_RESERVED_FILE=/nonexistent LANE_OWNER=x "$ls_" acquire --slot 3 >/dev/null 2>&1; then fail "slot 3 acquired with its core listeners in the ephemeral range"; else pass "slot 3 is refused while its core listeners are in the ephemeral range"; fi
s=$(LANE_PORT_RANGE_FILE="$tmp/range" LANE_PORT_RESERVED_FILE=/nonexistent LANE_OWNER=x "$ls_" acquire 2>/dev/null); [ "$s" = 0 ] && pass "an unspecific acquire skips to a usable slot" || fail "unspecific acquire gave '$s'"
LANE_OWNER=x "$ls_" release 0 >/dev/null 2>&1
n=0; for i in 1 2 3 4 5 6; do ( LANE_OWNER=o$i "$ls_" acquire --slot 2 >/dev/null 2>&1 && echo won ) & done | grep -c won | { read -r n; [ "$n" = 1 ] && pass "six simultaneous acquires of one slot: one winner" || fail "six simultaneous acquires gave $n winners"; }
wait

[ "$fails" = 0 ] || exit 1
echo "lane-slot selftest: all passed"
