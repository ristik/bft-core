#!/usr/bin/env bash
# Lane slots on a shared host (bft-core#1218). A lane takes one slot (0..3), exports LANE_SLOT=N, and every port of scripts/reth-paired-devnet.sh and its
# libraries moves by N*1000 (scripts/lib/lane-slot.sh holds the table). The lock is ~/host-lock/slot-N.txt (LANE_LOCK_DIR to move it).
#   scripts/lane-slot.sh acquire --token T [--slot N] [--owner NAME] [--tmux SESSION] [--tree DIR] [--profile P[,P]]
#        pick the lowest free slot (or N), write the lock, print the slot number. T is a unique claim token (required; a token already held by another lock is refused).
#        Refuses an occupied slot, and (slots 1..3) a slot whose listeners for the profile fall in the host's ephemeral port range and are not reserved. Profiles:
#        paired-default (default: the paired devnet with its section-3 negative clients), f6b, f6c, seed, f8. Slot 0 keeps its historical ports and is not refused: it is covered by the bind preflight.
#   scripts/lane-slot.sh release [N] --token T [--owner NAME] [--force]   remove the lock of the claim with token T, owned by NAME (default $LANE_OWNER, else $USER); --force skips both checks. N defaults to $LANE_SLOT
#   scripts/lane-slot.sh status                                           every slot: free, or its lock; a stale tmux session or an orphaned mutex is flagged
#   scripts/lane-slot.sh ports [N]                                        "name port" of every port of slot N
#   scripts/lane-slot.sh mongo up|down [LOG_DIR]                          the slot's MongoDB replica set (LANE_SLOT=N), for lanes with the aggregator
#   scripts/lane-slot.sh selftest                                         ports, literals, lock protocol, process scoping
# Launcher (same owner and token on acquire and release; abort when acquire fails; mongo down before release; assignment apart from the export):
#   owner=VT-07; token=$owner-$$-$(date +%s)
#   slot=$(scripts/lane-slot.sh acquire --owner "$owner" --token "$token" --tmux vt07) || exit 1; export LANE_SLOT=$slot
#   trap 'scripts/lane-slot.sh mongo down "$HOME/lane-mongo" || true; scripts/lane-slot.sh release --owner "$owner" --token "$token"' EXIT
# The lock records the owner, tmux session, tree, ports and start time. It does not kill anything and does not detect a dead owner: `status` shows the tree and
# start, and a stale lock is released by hand (release --force) after checking the owner's processes.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lockdir=${LANE_LOCK_DIR:-$HOME/host-lock}
cmd=${1:-}; [ $# -eq 0 ] || shift

lockfile() { echo "$lockdir/slot-$1.txt"; }
whoami_tag() { echo "${LANE_OWNER:-${USER:-unknown}}"; }

# One mutex per slot serializes acquire, release and the ownership check of release (mkdir is atomic): a release can never remove the lock of
# a claim made after the one it was meant for, and an acquire never sees a half-removed lock.
mutex_dir() { echo "$lockdir/.slot-$1.mutex"; }
# an orphaned mutex (its holder's pid is dead: the helper was killed between taking it and dropping it) is reported and broken, never left hidden
mutex_orphan() { local d p; d=$(mutex_dir "$1"); [ -d "$d" ] || return 1; p=$(cat "$d/pid" 2>/dev/null) || return 1; [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null && echo "$p"; }
mutex_take() {
  local i d o; d=$(mutex_dir "$1"); mkdir -p "$lockdir"
  for i in $(seq 1 100); do
    if mkdir "$d" 2>/dev/null; then echo $$ >"$d/pid"; held_mutex=$1; trap 'mutex_drop "$held_mutex"' EXIT; trap 'exit 130' INT TERM HUP; return 0; fi
    if o=$(mutex_orphan "$1"); then echo "slot $1: breaking an orphaned mutex (holder pid $o is dead)" >&2; rm -rf "$d"; continue; fi
    sleep 0.1
  done
  echo "slot $1: the lock mutex is held by pid $(cat "$d/pid" 2>/dev/null || echo '?')" >&2; return 1
}
mutex_drop() { [ -n "${1:-}" ] || return 0; rm -rf "$(mutex_dir "$1")"; held_mutex=; }
held_mutex=

case "$cmd" in
  acquire)
    source "$here/lib/lane-slot.sh"
    slot= owner=$(whoami_tag) tmuxs=${TMUX_SESSION:-} tree=$PWD token=${LANE_SLOT_TOKEN:-} profile=paired-default
    if [ -z "$tmuxs" ] && [ -n "${TMUX:-}" ]; then tmuxs=$(tmux display-message -p '#S' 2>/dev/null || true); fi
    while [ $# -gt 0 ]; do
      case "$1" in
        --slot) slot=${2:?--slot N}; shift 2 ;;
        --owner) owner=${2:?--owner NAME}; shift 2 ;;
        --tmux) tmuxs=${2:?--tmux SESSION}; shift 2 ;;
        --tree) tree=${2:?--tree DIR}; shift 2 ;;
        --token) token=${2:?--token T}; shift 2 ;;
        --profile) profile=${2:?--profile P}; shift 2 ;;
        *) echo "acquire: unknown argument $1" >&2; exit 2 ;;
      esac
    done
    [ -n "$token" ] || { echo "acquire: --token T is required (a unique claim token; release must present it)" >&2; exit 2; }
    classes=$(lane_profile_classes "$profile") || exit 2
    mkdir -p "$lockdir"
    if [ -n "$slot" ]; then candidates=$slot; else candidates="0 1 2 3"; fi
    for s in $candidates; do
      case "$s" in 0 | 1 | 2 | 3) ;; *) echo "slot must be 0..3" >&2; exit 2 ;; esac
      f=$(lockfile "$s")
      mutex_take "$s" || exit 1
      if [ -e "$f" ]; then
        mutex_drop "$s"
        [ -z "$slot" ] || { echo "slot $s is occupied:" >&2; sed 's/^/  /' "$f" >&2; exit 1; }
        continue
      fi
      if grep -qsx "token: $token" "$lockdir"/slot-[0-3].txt 2>/dev/null; then mutex_drop "$s"; echo "acquire: token '$token' is already held by another lock: a claim token must be unique" >&2; exit 1; fi
      bad=$(lane_slot_ephemeral_conflicts "$s" "$classes" | tr '\n' ' ')
      if [ -n "$bad" ] && [ "$s" != 0 ]; then
        mutex_drop "$s"
        [ -z "$slot" ] || { echo "slot $s refused: its core listeners fall in this host's ephemeral port range (ip_local_port_range), where an outgoing connection can take the port first: $bad" >&2; exit 1; }
        continue
      fi
      [ -z "$bad" ] || echo "note: slot 0 keeps its historical ports; these listeners of profile $profile are in the ephemeral range (the bind preflight refuses a start on a taken port): $bad" >&2
      {
        echo "owner: $owner"
        echo "tmux: ${tmuxs:-none}"
        echo "tree: $tree"
        echo "slot: $s"
        echo "token: $token"
        echo "profile: $profile"
        echo "ports: $(lane_slot_ports "$s" | awk '$3=="core"{n[$1]++; if(!($1 in lo)||$2<lo[$1])lo[$1]=$2; if($2>hi[$1])hi[$1]=$2} END{for(k in lo) printf "%s %d-%d; ", k, lo[k], hi[k]}' | sed 's/; $//')"
        echo "start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      } >"$f"
      mutex_drop "$s"
      echo "$s"; exit 0
    done
    echo "no free lane slot (0..3 all locked or refused); see: $0 status" >&2; exit 1 ;;
  release)
    slot=${LANE_SLOT:-} force=0 token=${LANE_SLOT_TOKEN:-} rowner=$(whoami_tag)
    while [ $# -gt 0 ]; do case "$1" in --force) force=1; shift ;; --token) token=${2:?--token T}; shift 2 ;; --owner) rowner=${2:?--owner NAME}; shift 2 ;; [0-3]) slot=$1; shift ;; *) echo "release: unknown argument $1" >&2; exit 2 ;; esac; done
    [ -n "$slot" ] || { echo "release: give the slot (or set LANE_SLOT)" >&2; exit 2; }
    f=$(lockfile "$slot")
    mutex_take "$slot" || exit 1
    if [ ! -f "$f" ]; then mutex_drop "$slot"; echo "slot $slot is not locked"; exit 0; fi
    owner=$(sed -n 's/^owner: //p' "$f"); held=$(sed -n 's/^token: //p' "$f")
    if [ "$force" != 1 ]; then
      if [ "$owner" != "$rowner" ] || [ -z "$token" ] || [ "$held" != "$token" ]; then
        mutex_drop "$slot"; echo "slot $slot is held by '$owner' under another claim (release needs the claim's --owner and --token); use --force after checking its processes" >&2; exit 1
      fi
    fi
    rm -f "$f"; mutex_drop "$slot"; echo "released slot $slot" ;;
  status)
    for s in 0 1 2 3; do
      f=$(lockfile "$s")
      if o=$(mutex_orphan "$s"); then rm -rf "$(mutex_dir "$s")"; echo "slot $s: orphaned mutex of dead pid $o cleared (an acquire or release was interrupted)"; elif [ -d "$(mutex_dir "$s")" ]; then echo "slot $s: mutex held by pid $(cat "$(mutex_dir "$s")/pid" 2>/dev/null || echo '?') (an acquire or release is running)"; fi
      if [ -f "$f" ]; then
        # a lock names its tmux session (either "tmux: NAME" or "tmux=NAME"): a session that no longer exists is a stale lock. The exact name: -t "=NAME" (a bare NAME also matches a prefix)
        t=$(sed -n -E 's/^tmux: *([^ ]+).*/\1/p; s/.* tmux=([^ ]+).*/\1/p' "$f" | head -n 1)
        note=
        if [ -n "$t" ] && [ "$t" != none ] && command -v tmux >/dev/null 2>&1 && ! tmux has-session -t "=$t" 2>/dev/null; then
          note=" (STALE? tmux session '$t' does not exist; check the owner's processes, then release --force)"
        fi
        echo "slot $s: LOCKED$note"; sed 's/^/  /' "$f"
      else echo "slot $s: free"; fi
    done ;;
  ports) LANE_SLOT=${1:-${LANE_SLOT:-0}}; source "$here/lib/lane-slot.sh"; lane_slot_ports "$LANE_SLOT" | awk '{print $1, $2}' ;;
  mongo) [ "${1:-}" = up ] || [ "${1:-}" = down ] || { echo "usage: $0 mongo up|down [LOG_DIR]" >&2; exit 2; }
    action=$1; shift; exec "$here/ci/mongo-up.sh" "$action" "${1:-${TMPDIR:-/tmp}/lane-mongo-slot${LANE_SLOT:-0}}" ;;
  selftest) exec "$here/lane-slot-selftest.sh" ;;
  *) sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
