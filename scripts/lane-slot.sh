#!/usr/bin/env bash
# Lane slots on a shared host (bft-core#1218). A lane takes one slot (0..3), exports LANE_SLOT=N, and every port of scripts/reth-paired-devnet.sh and its
# libraries moves by N*1000 (scripts/lib/lane-slot.sh holds the table). The lock is ~/host-lock/slot-N.txt (LANE_LOCK_DIR to move it).
#   scripts/lane-slot.sh acquire [--slot N] [--owner NAME] [--tmux SESSION] [--tree DIR] [--token T]   pick the lowest free slot (or N), write the lock, print the slot number; refuses an occupied slot and a slot whose core listeners fall in the host's ephemeral port range (slot 3 on a default Linux host)
#   scripts/lane-slot.sh release [N] [--force] [--token T]                    remove the lock (only the owner's, and only the claim with token T when the lock has one, unless --force); N defaults to $LANE_SLOT
#   scripts/lane-slot.sh status                                                 every slot: free, or its lock
#   scripts/lane-slot.sh ports [N]                                              "name port" of every port of slot N
#   scripts/lane-slot.sh mongo up|down [LOG_DIR]                                the slot's MongoDB replica set (LANE_SLOT=N), for lanes with the aggregator
#   scripts/lane-slot.sh selftest                                               no collision across slots 0..3 or with the docker package
# Launcher (abort when acquire fails; keep the assignment apart from the export, which would hide its status):
#   slot=$(scripts/lane-slot.sh acquire --owner VT-07 --token "$$") || exit 1; export LANE_SLOT=$slot
#   trap 'scripts/lane-slot.sh release --token "$$"' EXIT
# status flags a lock whose tmux session no longer exists.
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
mutex_take() { local i; mkdir -p "$lockdir"; for i in $(seq 1 100); do mkdir "$lockdir/.slot-$1.mutex" 2>/dev/null && return 0; sleep 0.1; done; echo "slot $1: the lock mutex is held (a crashed holder? remove $lockdir/.slot-$1.mutex by hand)" >&2; return 1; }
mutex_drop() { rmdir "$lockdir/.slot-$1.mutex" 2>/dev/null || true; }

case "$cmd" in
  acquire)
    source "$here/lib/lane-slot.sh"
    slot= owner=$(whoami_tag) tmuxs=${TMUX_SESSION:-} tree=$PWD token=${LANE_SLOT_TOKEN:-}
    if [ -z "$tmuxs" ] && [ -n "${TMUX:-}" ]; then tmuxs=$(tmux display-message -p '#S' 2>/dev/null || true); fi
    while [ $# -gt 0 ]; do
      case "$1" in
        --slot) slot=${2:?--slot N}; shift 2 ;;
        --owner) owner=${2:?--owner NAME}; shift 2 ;;
        --tmux) tmuxs=${2:?--tmux SESSION}; shift 2 ;;
        --tree) tree=${2:?--tree DIR}; shift 2 ;;
        --token) token=${2:?--token T}; shift 2 ;;
        *) echo "acquire: unknown argument $1" >&2; exit 2 ;;
      esac
    done
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
      bad=$(lane_slot_ephemeral_conflicts "$s" core | tr '\n' ' ')
      if [ -n "$bad" ]; then
        mutex_drop "$s"
        [ -z "$slot" ] || { echo "slot $s refused: its core listeners fall in this host's ephemeral port range (ip_local_port_range), where an outgoing connection can take the port first: $bad" >&2; exit 1; }
        continue
      fi
      aux=$(lane_slot_ephemeral_conflicts "$s" aux | awk '{print $1}' | sort -u | tr '\n' ' ')
      [ -z "$aux" ] || echo "note: slot $s auxiliary listeners in the ephemeral range (one lane's each, as on slot 0): $aux" >&2
      {
        echo "owner: $owner"
        echo "tmux: ${tmuxs:-none}"
        echo "tree: $tree"
        echo "slot: $s"
        [ -z "$token" ] || echo "token: $token"
        echo "ports: $(lane_slot_ports "$s" | awk '$3=="core"{n[$1]++; if(!($1 in lo)||$2<lo[$1])lo[$1]=$2; if($2>hi[$1])hi[$1]=$2} END{for(k in lo) printf "%s %d-%d; ", k, lo[k], hi[k]}' | sed 's/; $//')"
        echo "start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      } >"$f"
      mutex_drop "$s"
      echo "$s"; exit 0
    done
    echo "no free lane slot (0..3 all locked or refused); see: $0 status" >&2; exit 1 ;;
  release)
    slot=${LANE_SLOT:-} force=0 token=${LANE_SLOT_TOKEN:-}
    while [ $# -gt 0 ]; do case "$1" in --force) force=1; shift ;; --token) token=${2:?--token T}; shift 2 ;; [0-3]) slot=$1; shift ;; *) echo "release: unknown argument $1" >&2; exit 2 ;; esac; done
    [ -n "$slot" ] || { echo "release: give the slot (or set LANE_SLOT)" >&2; exit 2; }
    f=$(lockfile "$slot")
    mutex_take "$slot" || exit 1
    if [ ! -f "$f" ]; then mutex_drop "$slot"; echo "slot $slot is not locked"; exit 0; fi
    owner=$(sed -n 's/^owner: //p' "$f"); held=$(sed -n 's/^token: //p' "$f")
    if [ "$force" != 1 ]; then
      if [ "$owner" != "$(whoami_tag)" ] || { [ -n "$held" ] && [ "$held" != "$token" ]; }; then
        mutex_drop "$slot"; echo "slot $slot is held by '$owner'${held:+ under another claim}, not by this claim; use --force after checking its processes" >&2; exit 1
      fi
    fi
    rm -f "$f"; mutex_drop "$slot"; echo "released slot $slot" ;;
  status)
    for s in 0 1 2 3; do
      f=$(lockfile "$s")
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
  *) sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
