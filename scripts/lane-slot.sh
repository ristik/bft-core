#!/usr/bin/env bash
# Lane slots on a shared host (bft-core#1218). A lane takes one slot (0..3), exports LANE_SLOT=N, and every port of scripts/reth-paired-devnet.sh and its
# libraries moves by N*1000 (scripts/lib/lane-slot.sh holds the table). The lock is ~/host-lock/slot-N.txt (LANE_LOCK_DIR to move it).
#   scripts/lane-slot.sh acquire [--slot N] [--owner NAME] [--tmux SESSION] [--tree DIR] [--profile P[,P]] [--token T]
#        pick the lowest free slot (or N), write the lock, print "SLOT TOKEN". The claim token is generated (uuid) unless --token gives one; it is unique across all locks.
#        Exits 75 if an explicitly requested slot is occupied. Refuses slots 1..3 when listeners for the profile fall in the host's ephemeral port range and are not reserved. Profiles:
#        paired-default (default: the paired devnet with its section-3 negative clients), f6b, f6c, seed, f8. Slot 0 keeps its historical ports and is not refused: it is covered by the bind preflight.
#   scripts/lane-slot.sh release [N] --token T [--owner NAME] [--force]   remove the lock of the claim with token T, owned by NAME (default $LANE_OWNER, else $USER); --force skips both checks. N defaults to $LANE_SLOT, else the slot the token names
#   scripts/lane-slot.sh status                                           every slot: free, or its lock; a lock whose tmux session is gone is flagged
#   scripts/lane-slot.sh ports [N]                                        "name port" of every port of slot N
#   scripts/lane-slot.sh mongo up|down [LOG_DIR]                          the slot's MongoDB replica set (LANE_SLOT=N), for lanes with the aggregator
#   scripts/lane-slot.sh selftest                                         ports, literals, lock protocol, process scoping
# Every acquire, release and status runs under one host-wide flock(1) on $LANE_LOCK_DIR/.lanes.lock (the kernel drops it when the holder dies: nothing to clean up).
# Launcher (same owner and token on acquire and release; an aborting acquire; the lane runs as a child, a TERM/INT/HUP of the launcher is forwarded to it and waited
# for before the mongo teardown and the release; the assignment apart from the export): see docs/lane-slots.md, which scripts/lane-slot-selftest.sh runs.
# The lock records the owner, tmux session, tree, ports and start time. It does not kill anything and does not detect a dead owner: `status` shows the tree and
# start, and a stale lock is released by hand (release --force) after checking the owner's processes.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lockdir=${LANE_LOCK_DIR:-$HOME/host-lock}
cmd=${1:-}; [ $# -eq 0 ] || shift

lockfile() { echo "$lockdir/slot-$1.txt"; }
whoami_tag() { echo "${LANE_OWNER:-${USER:-unknown}}"; }

# One host-wide lock around the whole critical section of acquire, release and status, including the cross-slot token scan. flock(1) holds it for the life of
# this process: a killed helper leaves nothing behind. The slow children (tmux, the port-table subshells, the test stall) run with fd 9 closed, so they cannot keep the
# lock past the holder's death; a claim is written to a temp file and renamed into place, so an interrupted acquire leaves at most a temp file, which the next
# acquire or status (both under the lock) removes.
lanes_lock() {
  command -v flock >/dev/null 2>&1 || { echo "lane-slot.sh needs flock(1) (util-linux)" >&2; exit 2; }
  mkdir -p "$lockdir"; exec 9>"$lockdir/.lanes.lock"
  flock -x -w 30 9 || { echo "lane-slot.sh: could not take $lockdir/.lanes.lock within 30 s" >&2; exit 1; }
  rm -f "$lockdir"/slot-[0-3].txt.tmp.* 9>&-   # a partial claim of an interrupted acquire (every writer holds the lock, so none is in flight)
}
new_token() { cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || mktemp -u XXXXXXXXXXXXXXXXXXXXXXXX; }

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
    [ -n "$token" ] || token=$(new_token)
    classes=$(lane_profile_classes "$profile") || exit 2
    lanes_lock
    if [ -n "$slot" ]; then candidates=$slot; else candidates="0 1 2 3"; fi
    for s in $candidates; do
      case "$s" in 0 | 1 | 2 | 3) ;; *) echo "slot must be 0..3" >&2; exit 2 ;; esac
      f=$(lockfile "$s")
      if [ -e "$f" ]; then
        [ -z "$slot" ] || { echo "slot $s is occupied:" >&2; sed 's/^/  /' "$f" >&2; exit 75; }
        continue
      fi
      if grep -qsxF "token: $token" "$lockdir"/slot-[0-3].txt 2>/dev/null; then echo "acquire: token '$token' is already held by another lock: a claim token must be unique" >&2; exit 1; fi
      bad=$(exec 9>&-; lane_slot_ephemeral_conflicts "$s" "$classes" | tr '\n' ' ')
      if [ -n "$bad" ] && [ "$s" != 0 ]; then
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
        echo "ports: $(exec 9>&-; lane_slot_ports "$s" | awk '$3=="core"{n[$1]++; if(!($1 in lo)||$2<lo[$1])lo[$1]=$2; if($2>hi[$1])hi[$1]=$2} END{for(k in lo) printf "%s %d-%d; ", k, lo[k], hi[k]}' | sed 's/; $//')"
        echo "start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      } >"$f.tmp.$$"
      [ -z "${LANE_SLOT_TEST_STALL:-}" ] || sleep "$LANE_SLOT_TEST_STALL" 9>&-   # a test hook: a window to interrupt an acquire between writing and publishing
      mv "$f.tmp.$$" "$f"
      echo "$s $token"; exit 0
    done
    echo "no free lane slot (0..3 all locked or refused); see: $0 status" >&2; exit 1 ;;
  release)
    slot=${LANE_SLOT:-} force=0 token=${LANE_SLOT_TOKEN:-} rowner=$(whoami_tag)
    while [ $# -gt 0 ]; do case "$1" in --force) force=1; shift ;; --token) token=${2:?--token T}; shift 2 ;; --owner) rowner=${2:?--owner NAME}; shift 2 ;; [0-3]) slot=$1; shift ;; *) echo "release: unknown argument $1" >&2; exit 2 ;; esac; done
    lanes_lock
    # the claim token names its own lock: without a slot (and without LANE_SLOT), find it by token, so a trap that lost the slot still releases the right claim
    if [ -z "$slot" ] && [ -n "$token" ]; then
      for c in 0 1 2 3; do grep -qsxF "token: $token" "$(lockfile "$c")" && { slot=$c; break; }; done
    fi
    [ -n "$slot" ] || { echo "release: give the slot (or set LANE_SLOT), or a --token that names a held claim" >&2; exit 2; }
    f=$(lockfile "$slot")
    if [ ! -f "$f" ]; then echo "slot $slot is not locked"; exit 0; fi
    owner=$(sed -n 's/^owner: //p' "$f"); held=$(sed -n 's/^token: //p' "$f")
    if [ "$force" != 1 ]; then
      if [ "$owner" != "$rowner" ] || [ -z "$token" ] || [ "$held" != "$token" ]; then
        echo "slot $slot is held by '$owner' under another claim (release needs the claim's --owner and --token); use --force after checking its processes" >&2; exit 1
      fi
    fi
    rm -f "$f"; echo "released slot $slot" ;;
  status)
    lanes_lock
    for s in 0 1 2 3; do
      f=$(lockfile "$s")
      if [ -f "$f" ]; then
        # a lock names its tmux session (either "tmux: NAME" or "tmux=NAME"): a session that no longer exists is a stale lock. The exact name: -t "=NAME" (a bare NAME also matches a prefix)
        t=$(sed -n -E 's/^tmux: *([^ ]+).*/\1/p; s/.* tmux=([^ ]+).*/\1/p' "$f" | head -n 1)
        note=
        if [ -n "$t" ] && [ "$t" != none ] && command -v tmux >/dev/null 2>&1 && ! tmux has-session -t "=$t" 9>&- 2>/dev/null; then
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
