#!/usr/bin/env bash
# Lane slots on a shared host (bft-core#1218). A lane takes one slot (0..3), exports LANE_SLOT=N, and every port of scripts/reth-paired-devnet.sh and its
# libraries moves by N*1000 (scripts/lib/lane-slot.sh holds the table). The lock is ~/host-lock/slot-N.txt (LANE_LOCK_DIR to move it).
#   scripts/lane-slot.sh acquire [--slot N] [--owner NAME] [--tmux SESSION] [--tree DIR]   pick the lowest free slot (or N), write the lock, print the slot number; refuses an occupied one
#   scripts/lane-slot.sh release [N] [--force]                                  remove the lock (only the owner's, unless --force); N defaults to $LANE_SLOT
#   scripts/lane-slot.sh status                                                 every slot: free, or its lock
#   scripts/lane-slot.sh ports [N]                                              "name port" of every port of slot N
#   scripts/lane-slot.sh mongo up|down [LOG_DIR]                                the slot's MongoDB replica set (LANE_SLOT=N), for lanes with the aggregator
#   scripts/lane-slot.sh selftest                                               no collision across slots 0..3 or with the docker package
# status flags a lock whose tmux session no longer exists. Typical use:  export LANE_SLOT=$(scripts/lane-slot.sh acquire --owner VT-07) && ./scripts/reth-paired-devnet.sh 4 10 ...; scripts/lane-slot.sh release
# The lock records the owner, tmux session, tree, ports and start time. It does not kill anything and does not detect a dead owner: `status` shows the tree and
# start, and a stale lock is released by hand (release --force) after checking the owner's processes.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lockdir=${LANE_LOCK_DIR:-$HOME/host-lock}
cmd=${1:-}; [ $# -eq 0 ] || shift

lockfile() { echo "$lockdir/slot-$1.txt"; }
whoami_tag() { echo "${LANE_OWNER:-${USER:-unknown}}"; }

case "$cmd" in
  acquire)
    slot= owner=$(whoami_tag) tmuxs=${TMUX_SESSION:-} tree=$PWD
    if [ -z "$tmuxs" ] && [ -n "${TMUX:-}" ]; then tmuxs=$(tmux display-message -p '#S' 2>/dev/null || true); fi
    while [ $# -gt 0 ]; do
      case "$1" in
        --slot) slot=${2:?--slot N}; shift 2 ;;
        --owner) owner=${2:?--owner NAME}; shift 2 ;;
        --tmux) tmuxs=${2:?--tmux SESSION}; shift 2 ;;
        --tree) tree=${2:?--tree DIR}; shift 2 ;;
        *) echo "acquire: unknown argument $1" >&2; exit 2 ;;
      esac
    done
    mkdir -p "$lockdir"
    if [ -n "$slot" ]; then candidates=$slot; else candidates="0 1 2 3"; fi
    for s in $candidates; do
      case "$s" in 0 | 1 | 2 | 3) ;; *) echo "slot must be 0..3" >&2; exit 2 ;; esac
      f=$(lockfile "$s")
      # noclobber makes the create atomic: two lanes acquiring at once cannot both win
      if ( set -o noclobber; : >"$f" ) 2>/dev/null; then
        off=$((s * 1000))
        {
          echo "owner: $owner"
          echo "tmux: ${tmuxs:-none}"
          echo "tree: $tree"
          echo "slot: $s"
          echo "ports: reth eth $((18545 + off)), engine $((18551 + off)), p2p $((30401 + off)); root p2p $((26662 + off)), rpc $((25866 + off)); shard rpc $((28311 + off)); aggregator $((3001 + off)); mongo $((27117 + off))"
          echo "start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        } >"$f"
        echo "$s"; exit 0
      fi
      [ -z "$slot" ] || { echo "slot $s is occupied:" >&2; sed 's/^/  /' "$f" >&2; exit 1; }
    done
    echo "no free lane slot (0..3 all locked); see: $0 status" >&2; exit 1 ;;
  release)
    slot=${LANE_SLOT:-} force=0
    while [ $# -gt 0 ]; do case "$1" in --force) force=1; shift ;; [0-3]) slot=$1; shift ;; *) echo "release: unknown argument $1" >&2; exit 2 ;; esac; done
    [ -n "$slot" ] || { echo "release: give the slot (or set LANE_SLOT)" >&2; exit 2; }
    f=$(lockfile "$slot")
    [ -f "$f" ] || { echo "slot $slot is not locked"; exit 0; }
    owner=$(sed -n 's/^owner: //p' "$f")
    if [ "$force" != 1 ] && [ "$owner" != "$(whoami_tag)" ]; then echo "slot $slot is held by '$owner', not '$(whoami_tag)'; use --force after checking its processes" >&2; exit 1; fi
    rm -f "$f"; echo "released slot $slot" ;;
  status)
    for s in 0 1 2 3; do
      f=$(lockfile "$s")
      if [ -f "$f" ]; then
        # a lock names its tmux session (either "tmux: NAME" or "tmux=NAME"): a session that no longer exists is a stale lock
        t=$(sed -n -E 's/^tmux: *([^ ]+).*/\1/p; s/.* tmux=([^ ]+).*/\1/p' "$f" | head -n 1)
        note=
        if [ -n "$t" ] && [ "$t" != none ] && command -v tmux >/dev/null 2>&1 && ! tmux has-session -t "$t" 2>/dev/null; then
          note=" (STALE? tmux session '$t' does not exist; check the owner's processes, then release --force)"
        fi
        echo "slot $s: LOCKED$note"; sed 's/^/  /' "$f"
      else echo "slot $s: free"; fi
    done ;;
  ports) LANE_SLOT=${1:-${LANE_SLOT:-0}}; source "$here/lib/lane-slot.sh"; lane_slot_ports "$LANE_SLOT" ;;
  mongo) [ "${1:-}" = up ] || [ "${1:-}" = down ] || { echo "usage: $0 mongo up|down [LOG_DIR]" >&2; exit 2; }
    action=$1; shift; exec "$here/ci/mongo-up.sh" "$action" "${1:-${TMPDIR:-/tmp}/lane-mongo-slot${LANE_SLOT:-0}}" ;;
  selftest) source "$here/lib/lane-slot.sh"; lane_slot_selftest ;;
  *) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
