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

# 5. the lock: one winner, tokens, exact claim on release, atomic against a delayed duplicate, profile-aware ephemeral-range refusal, orphaned mutex
export LANE_LOCK_DIR="$tmp/locks"; ls_=$here/lane-slot.sh
acq() { LANE_OWNER=${OWN:-x} "$ls_" acquire "$@" 2>/dev/null; }          # acq --slot N --token T ...: prints the slot
rel() { LANE_OWNER=${OWN:-x} "$ls_" release "$@" >/dev/null 2>&1; }
a=$(acq --slot 1 --token t1); [ "$a" = 1 ] && pass "acquire takes a free slot" || fail "acquire of a free slot gave '$a'"
acq --slot 1 --token t9 >/dev/null && fail "an occupied slot was acquired" || pass "an occupied slot is refused"
acq --slot 0 >/dev/null && fail "a tokenless claim was accepted" || pass "a claim without a token is refused"
acq --slot 0 --token t1 >/dev/null && fail "a token already held was accepted" || pass "a token held by another lock is refused"
OWN=y rel 1 --token t1 && fail "release by a non-owner" || pass "release by a non-owner is refused"
rel 1 --token other && fail "release under another claim's token" || pass "release under another claim's token is refused"
rel 1 && fail "release without a token" || pass "release without a token is refused"
rel 1 --token t1 && pass "release by the claim" || fail "release by the claim"
acq --slot 1 --token t2 >/dev/null     # the replacement claim by the same owner
rel 1 --token t1                        # the delayed duplicate release of the first claim
[ -f "$LANE_LOCK_DIR/slot-1.txt" ] && pass "a delayed duplicate release leaves the replacement claim's lock" || fail "a delayed duplicate release removed the replacement claim's lock"
rel 1 --token t2
# the launcher's owner: acquire and release with the same --owner, whatever LANE_OWNER and USER say
a=$(LANE_OWNER=other "$ls_" acquire --slot 1 --owner VT-07 --token tv 2>/dev/null)
LANE_OWNER=other USER=other "$ls_" release 1 --owner VT-07 --token tv >/dev/null 2>&1 && [ ! -f "$LANE_LOCK_DIR/slot-1.txt" ] && pass "release with the acquire's --owner and token works for any user" || fail "release with the acquire's --owner and token"
# ephemeral range, by profile: slot 3 needs unreserved core ports; slot 2's section-3 negative clients are inside the default profile
echo "32768 60999" >"$tmp/range"; export LANE_PORT_RESERVED_FILE=/nonexistent
for pair in "3 paired-default" "3 f6b"; do set -- $pair
  LANE_PORT_RANGE_FILE="$tmp/range" acq --slot "$1" --profile "$2" --token "e$1$2" >/dev/null && fail "slot $1 profile $2 accepted with listeners in the ephemeral range" || pass "slot $1 profile $2 is refused: its listeners are in the ephemeral range"
done
echo "20000 30000" >"$tmp/range2"
LANE_PORT_RANGE_FILE="$tmp/range2" acq --slot 2 --profile paired-default --token e2 >/dev/null && pass "slot 2 paired-default is accepted when no listener is in the range" || fail "slot 2 paired-default refused with no listener in the range"
rel 2 --token e2
printf '32768 60999\n' >"$tmp/range3"
r2=$(lane_slot_ephemeral_conflicts 2 "$(lane_profile_classes paired-default)" 2>/dev/null; LANE_PORT_RANGE_FILE="$tmp/range3" lane_slot_ephemeral_conflicts 2 "$(lane_profile_classes paired-default)")
[ -z "$r2" ] && pass "slot 2's default paired profile (section-3 negative clients included) has no listener in 32768..60999" || fail "slot 2 paired-default has listeners in the ephemeral range: $r2"
r0=$(LANE_PORT_RANGE_FILE="$tmp/range3" lane_slot_ephemeral_conflicts 0 "$(lane_profile_classes f6c)")
[ -n "$r0" ] && s0=$(LANE_PORT_RANGE_FILE="$tmp/range3" acq --slot 0 --profile f6c --token e0) && [ "$s0" = 0 ] && pass "slot 0 is exempt from the hard check (its historical ports): accepted with a note" || fail "slot 0 f6c: conflicts='$r0' acquire='$s0'"
rel 0 --token e0
# the bind preflight refuses a port something listens on
lane_port_listening 1 && fail "port 1 reported as listening" || pass "lane_port_listening is false on a closed port"
# an orphaned mutex: a dead holder's pid is reported by status and broken by acquire
mkdir -p "$LANE_LOCK_DIR/.slot-1.mutex"; echo 999999 >"$LANE_LOCK_DIR/.slot-1.mutex/pid"
st=$("$ls_" status 2>&1 | grep -c "orphaned mutex"); [ "$st" = 1 ] && [ ! -d "$LANE_LOCK_DIR/.slot-1.mutex" ] && pass "status reports and clears an orphaned mutex" || fail "status on an orphaned mutex"
mkdir -p "$LANE_LOCK_DIR/.slot-1.mutex"; echo 999999 >"$LANE_LOCK_DIR/.slot-1.mutex/pid"
a=$(acq --slot 1 --token tm); [ "$a" = 1 ] && pass "acquire breaks an orphaned mutex" || fail "acquire with an orphaned mutex gave '$a'"
rel 1 --token tm
# six simultaneous acquires of one slot: one winner, counted in this shell
for i in 1 2 3 4 5 6; do ( OWN=o$i acq --slot 2 --token "w$i" >"$tmp/win.$i" ) & done
wait
n=$(cat "$tmp"/win.* 2>/dev/null | grep -c '^2$')
[ "$n" = 1 ] && pass "six simultaneous acquires of one slot: one winner" || fail "six simultaneous acquires gave $n winners"

[ "$fails" = 0 ] || { echo "lane-slot selftest: $fails FAILED" >&2; exit 1; }
echo "lane-slot selftest: all passed"
