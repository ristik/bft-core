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

# 5. the lock (one host-wide flock): one winner, generated and unique tokens, exact claim on release, atomic against a delayed duplicate, a killed holder frees it,
# profile-aware ephemeral-range refusal
export LANE_LOCK_DIR="$tmp/locks"; ls_=$here/lane-slot.sh
acq() { LANE_OWNER=${OWN:-x} "$ls_" acquire "$@" 2>/dev/null; }          # prints "SLOT TOKEN"
rel() { LANE_OWNER=${OWN:-x} "$ls_" release "$@" >/dev/null 2>&1; }
a=$(acq --slot 1 --token t1); [ "${a%% *}" = 1 ] && pass "acquire takes a free slot" || fail "acquire of a free slot gave '$a'"
acq --slot 1 --token t9 >/dev/null && fail "an occupied slot was acquired" || pass "an occupied slot is refused"
acq --slot 0 --token t1 >/dev/null && fail "a token already held was accepted" || pass "a token held by another lock is refused"
acq --slot 0 --token 't[0-9]' >/dev/null && { acq --slot 2 --token 't[0-9]' >/dev/null && fail "a bracket token was acquired twice" || pass "tokens are compared literally (a bracket token cannot be acquired twice)"; rel 0 --token 't[0-9]'; } || fail "a bracket token was refused"
OWN=y rel 1 --token t1 && fail "release by a non-owner" || pass "release by a non-owner is refused"
rel 1 --token other && fail "release under another claim's token" || pass "release under another claim's token is refused"
rel 1 && fail "release without a token" || pass "release without a token is refused"
rel 1 --token t1 && pass "release by the claim" || fail "release by the claim"
acq --slot 1 --token t2 >/dev/null     # the replacement claim by the same owner
rel 1 --token t1                        # the delayed duplicate release of the first claim
[ -f "$LANE_LOCK_DIR/slot-1.txt" ] && pass "a delayed duplicate release leaves the replacement claim's lock" || fail "a delayed duplicate release removed the replacement claim's lock"
rel 1 --token t2
# a generated token: printed, unique, and the launcher's owner (the same --owner on acquire and release, whatever LANE_OWNER and USER say)
claim=$(LANE_OWNER=other "$ls_" acquire --slot 1 --owner VT-07 2>/dev/null); read -r gs gt <<<"$claim"
[ "$gs" = 1 ] && [ -n "$gt" ] && pass "acquire without --token generates and prints one" || fail "generated token: '$claim'"
LANE_OWNER=other USER=other "$ls_" release 1 --owner VT-07 --token "$gt" >/dev/null 2>&1 && [ ! -f "$LANE_LOCK_DIR/slot-1.txt" ] && pass "release with the printed token and the acquire's --owner works for any user" || fail "release with the generated token"
# the same token raced over two different slots: exactly one wins, every time
for i in 1 2 3 4 5 6 7 8; do
  ( OWN=r1 acq --slot 1 --token "race$i" >"$tmp/ra" ) & ( OWN=r2 acq --slot 2 --token "race$i" >"$tmp/rb" ) & wait
  w=$(cat "$tmp/ra" "$tmp/rb" | grep -c .)
  [ "$w" = 1 ] || { fail "the token race$i won on $w slots"; break; }
  rm -f "$tmp/ra" "$tmp/rb"; OWN=r1 rel 1 --token "race$i"; OWN=r2 rel 2 --token "race$i"
  [ "$i" != 8 ] || pass "one token raced over two slots eight times: always exactly one winner"
done
# a helper killed while it holds the lock leaves nothing behind: the kernel drops the flock
( exec 9>"$LANE_LOCK_DIR/.lanes.lock"; flock -x 9; sleep 60 ) & holder=$!
sleep 0.5; kill -9 "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
a=$(acq --slot 1 --token tk); [ "${a%% *}" = 1 ] && pass "a killed lock holder leaves no stale state: acquire proceeds" || fail "acquire after a killed holder gave '$a'"
rel 1 --token tk
# ephemeral range, by profile: slot 3 needs unreserved core ports; slot 2's section-3 negative clients are inside the default profile
echo "32768 60999" >"$tmp/range"; export LANE_PORT_RESERVED_FILE=/nonexistent
for pair in "3 paired-default" "3 f6b"; do set -- $pair
  LANE_PORT_RANGE_FILE="$tmp/range" acq --slot "$1" --profile "$2" --token "e$1$2" >/dev/null && fail "slot $1 profile $2 accepted with listeners in the ephemeral range" || pass "slot $1 profile $2 is refused: its listeners are in the ephemeral range"
done
echo "50000 60000" >"$tmp/range2"
LANE_PORT_RANGE_FILE="$tmp/range2" acq --slot 2 --profile paired-default --token e2 >/dev/null && pass "slot 2 paired-default is accepted when no listener is in the range" || fail "slot 2 paired-default refused with no listener in the range"
rel 2 --token e2
r2=$(LANE_PORT_RANGE_FILE="$tmp/range" lane_slot_ephemeral_conflicts 2 "$(lane_profile_classes paired-default)")
[ -z "$r2" ] && pass "slot 2's default paired profile (section-3 negative clients included) has no listener in 32768..60999" || fail "slot 2 paired-default has listeners in the ephemeral range: $r2"
r0=$(LANE_PORT_RANGE_FILE="$tmp/range" lane_slot_ephemeral_conflicts 0 "$(lane_profile_classes f6c)")
s0=$(LANE_PORT_RANGE_FILE="$tmp/range" acq --slot 0 --profile f6c --token e0)
[ -n "$r0" ] && [ "${s0%% *}" = 0 ] && pass "slot 0 is exempt from the hard check (its historical ports): accepted with a note" || fail "slot 0 f6c: conflicts='$r0' acquire='$s0'"
rel 0 --token e0

# 6. the bind preflight probes by an actual bind: it refuses a port held by a listening socket AND one that is only bound, and does not need LANE_SLOT (set -u)
hold() { python3 -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", int(sys.argv[1])))
if sys.argv[2] == "listen": s.listen(1)
time.sleep(30)' "$1" "$2" & }
for mode in listen bound; do
  port=$((38000 + RANDOM % 1000)); hold "$port" "$mode"; hp=$!; sleep 0.7
  if out=$(env -u LANE_SLOT bash -uc "source '$here/lib/lane-slot.sh'; lane_port_preflight $port selftest" 2>&1); then fail "preflight passed a port held by a $mode socket"
  else case "$out" in *"cannot be bound"*) pass "preflight refuses a port held by a $mode socket, with a clear message (no unbound-variable error)" ;; *) fail "preflight message for a $mode socket: $out" ;; esac; fi
  kill "$hp" 2>/dev/null; wait "$hp" 2>/dev/null
done
free=$((39000 + RANDOM % 900)); env -u LANE_SLOT bash -uc "source '$here/lib/lane-slot.sh'; lane_port_preflight $free selftest" >/dev/null 2>&1 && pass "preflight passes a free port" || fail "preflight refused a free port"

[ "$fails" = 0 ] || { echo "lane-slot selftest: $fails FAILED" >&2; exit 1; }
echo "lane-slot selftest: all passed"
