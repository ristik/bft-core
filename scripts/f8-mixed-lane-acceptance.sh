#!/usr/bin/env bash
# F8 mixed-lane acceptance on the fresh-B1 layout (the one registry layout): the EVM partition and three independent rugregator aggregator shards (a split
# partition A and an unsharded B) under one root committee. The aggregators certify alongside the EVM; the EVM is delayed, stopped and resumed, a non-default
# aggregator shard reconnects, an EVM proposal certifies during a root leader rotation, and one root handoff (same members, through the Q3 flow) leaves every
# aggregator shard live with root coverage. Every step prints PASS or FAIL.
#
#   F8_URETH_BIN=<ureth build with the fresh-B1 profile> F8_URETH_COMMIT=<its commit> \
#   RUGREGATOR_BIN=<binary built from the F8 pin> RUGREGATOR_SOURCE=<checkout at the F8 pin> scripts/f8-mixed-lane-acceptance.sh
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${F8_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/f8-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
cd "$REPO_ROOT"
source scripts/f8-rugregator-pin.sh

[ -n "${F8_URETH_BIN:-}" ] && [ -x "$F8_URETH_BIN" ] || fail "set F8_URETH_BIN to a ureth build carrying the fresh-B1 profile (--unicity.* bindings)"
[ -n "${F8_URETH_COMMIT:-}" ] || fail "set F8_URETH_COMMIT to the ureth source commit"
"$F8_URETH_BIN" --version 2>&1 | grep -Fq "Commit SHA: $F8_URETH_COMMIT" || fail "F8_URETH_BIN does not report the commit $F8_URETH_COMMIT"
[ -n "${RUGREGATOR_BIN:-}" ] && [ -x "$RUGREGATOR_BIN" ] || fail "set RUGREGATOR_BIN to the binary built from $F8_RUGREGATOR_PIN"
[ -n "${RUGREGATOR_SOURCE:-}" ] || fail "set RUGREGATOR_SOURCE to the pinned rugregator checkout"
[ "$(git -C "$RUGREGATOR_SOURCE" rev-parse HEAD)" = "$F8_RUGREGATOR_PIN" ] || fail "RUGREGATOR_SOURCE is not at the F8 pinned revision $F8_RUGREGATOR_PIN"

if [ "${F8_LANE_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "F8 mixed-lane acceptance (fresh-B1)" env F8_LANE_LOCKED=1 F8_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; evidence directory $EVIDENCE_DIR"
[ -x build/ubft ] || fail "build/ubft is missing (make build)"
echo "bft-core head=$(git rev-parse HEAD) ureth=$F8_URETH_COMMIT rugregator=$F8_RUGREGATOR_PIN ubft sha256=$(shasum -a 256 build/ubft | cut -d' ' -f1)" | tee "$EVIDENCE_DIR/heads.txt"

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
  EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256} F8_MIXED_LANE=1 M2_PROFILE2=1 SIGNING=authority \
    POST_M2A_URETH_BIN="$F8_URETH_BIN" POST_M2A_URETH_COMMIT="$F8_URETH_COMMIT" \
    M2_RUN_LOG_DIR="$EVIDENCE_DIR/nodes" F8_LOG_DIR="$EVIDENCE_DIR/f8" \
    bash -c 'echo $$ >"$0"; exec bash ./scripts/reth-paired-devnet.sh 4 10' "$DEVNET_PIDFILE" 2>&1 | tee "$EVIDENCE_DIR/lane.log" ) &
wait "$!"
status=$?
set -e
rm -f "$DEVNET_PIDFILE"
cp -R test-nodes/q3 "$EVIDENCE_DIR/q3" 2>/dev/null || true
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "F8 mixed-lane acceptance failed (exit $status); see $EVIDENCE_DIR/lane.log"
fi
for want in 'three aggregator shards certified alongside the EVM partition' 'aggregators continued through delayed/stopped EVM; reconnect and in-flight EVM proposal passed' \
  'one root handoff (same members, Q3 flow) certified paid transactions' 'all three aggregator shards remained live through the root handoff'; do
  grep -Fq "$want" "$EVIDENCE_DIR/lane.log" || fail "lane ended without: $want"
done
pass "F8 mixed-lane acceptance complete; evidence in $EVIDENCE_DIR"
