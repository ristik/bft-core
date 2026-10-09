#!/usr/bin/env bash
# M2 acceptance lane on the fresh-B1 layout (the one registry layout): a four-validator paired devnet, one paid certified block, then two root handoffs through
# the Q3 flow (V3 candidate, a readiness receipt from every entity, propose, install, activation, authority advance, paid transaction) with the same members,
# and the M2a restore of a validator across both epochs (the H4 restore probe), under the D1 monitor. Every step prints PASS or FAIL.
#
#   M2_URETH_BIN=<ureth build with the fresh-B1 profile> M2_URETH_COMMIT=<its commit> scripts/m2-lane.sh
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${M2_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/m2-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

[ -n "${M2_URETH_BIN:-}" ] && [ -x "$M2_URETH_BIN" ] || fail "set M2_URETH_BIN to a ureth build carrying the fresh-B1 profile (--unicity.* bindings)"
[ -n "${M2_URETH_COMMIT:-}" ] || fail "set M2_URETH_COMMIT to the ureth source commit"
"$M2_URETH_BIN" --version 2>&1 | grep -Fq "Commit SHA: $M2_URETH_COMMIT" || fail "M2_URETH_BIN does not report the commit $M2_URETH_COMMIT"

if [ "${M2_LANE_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "M2 acceptance lane (fresh-B1)" env M2_LANE_LOCKED=1 M2_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; evidence directory $EVIDENCE_DIR"
[ -x build/ubft ] || fail "build/ubft is missing (make build)"
echo "bft-core head=$(git rev-parse HEAD) ureth=$M2_URETH_COMMIT ubft sha256=$(shasum -a 256 build/ubft | cut -d' ' -f1)" | tee "$EVIDENCE_DIR/heads.txt"

# A signal to the lane stops the scenario child and waits for its own teardown (an orphaned child keeps restarting nodes in this checkout).
DEVNET_PIDFILE=
stop_devnet() {
  local pid i
  [ -n "$DEVNET_PIDFILE" ] && [ -s "$DEVNET_PIDFILE" ] || return 0
  pid=$(cat "$DEVNET_PIDFILE")
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
  kill -KILL "$pid" 2>/dev/null || true
}
trap stop_devnet EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# the single B1 layout: one B1 profile derived from the shard configuration and the root trust base; the registry slots are read under the layout-3 names;
# every shard node exposes its operator endpoint (the readiness check asks it what it has staged)
export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1

set +e
DEVNET_PIDFILE="$EVIDENCE_DIR/.devnet-pid"; rm -f "$DEVNET_PIDFILE"
( set -o pipefail
  EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256} M2_PROFILE2=1 M2A_FINAL_RESTORE=${M2A_FINAL_RESTORE:-1} SIGNING=authority \
    POST_M2A_URETH_BIN="$M2_URETH_BIN" POST_M2A_URETH_COMMIT="$M2_URETH_COMMIT" \
    M2_RUN_LOG_DIR="$EVIDENCE_DIR/nodes" \
    bash -c 'echo $$ >"$0"; exec bash ./scripts/reth-paired-devnet.sh 4 10' "$DEVNET_PIDFILE" 2>&1 | tee "$EVIDENCE_DIR/lane.log" ) &
wait "$!"
status=$?
set -e
rm -f "$DEVNET_PIDFILE"
cp -R test-nodes/q3 "$EVIDENCE_DIR/q3" 2>/dev/null || true
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "M2 acceptance lane failed (exit $status); see $EVIDENCE_DIR/lane.log"
fi
grep -q 'two profile-2 handoffs (same members, Q3 flow) certified paid transactions' "$EVIDENCE_DIR/lane.log" || fail "lane ended without completing the two handoffs"
pass "M2 acceptance lane complete; evidence in $EVIDENCE_DIR"
