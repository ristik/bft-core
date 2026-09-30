#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${M2_261_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/m2-replacement-client-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

if [ "${M2_261_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  timeout_bin=
  if command -v timeout >/dev/null 2>&1; then timeout_bin=$(command -v timeout)
  elif command -v gtimeout >/dev/null 2>&1; then timeout_bin=$(command -v gtimeout)
  else fail "GNU timeout is required to bound the live lane"
  fi
  exec "$LOCK_SCRIPT" "M2 #261 replacement-client comparison" "$timeout_bin" 7200s \
    env M2_261_LOCKED=1 M2_261_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi

cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired; evidence output is $EVIDENCE_DIR"

URETH_SRC=${URETH_SRC:-$AGRE_ROOT/ureth}
URETH_BIN=${POST_M2A_URETH_BIN:-}
URETH_COMMIT=${POST_M2A_URETH_COMMIT:-}
[ -x "$URETH_BIN" ] || fail "set POST_M2A_URETH_BIN to the pinned ureth binary"
[ -n "$URETH_COMMIT" ] || fail "set POST_M2A_URETH_COMMIT to the source commit used to build ureth"
latestUreth=$(git -C "$URETH_SRC" rev-parse origin/unicity/main) || fail "cannot resolve ureth origin/unicity/main"
[ "$URETH_COMMIT" = "$latestUreth" ] || fail "ureth binary pin $URETH_COMMIT differs from current origin/unicity/main $latestUreth"
git -C "$URETH_SRC" merge-base --is-ancestor 0f0fc029 "$URETH_COMMIT" || fail "ureth pin predates the retention-default change 0f0fc029"
version=$("$URETH_BIN" --version 2>&1) || fail "pinned ureth --version failed"
printf '%s\n' "$version" | grep -Fq "Commit SHA: $URETH_COMMIT" || fail "ureth binary does not report its declared source commit"
urethHash=$(shasum -a 256 "$URETH_BIN" | awk '{print $1}')
printf 'ureth commit=%s binary sha256=%s\n' "$URETH_COMMIT" "$urethHash" | tee "$EVIDENCE_DIR/ureth-pin.txt"

if [ ! -x build/ubft ]; then
  mkdir -p build
  go build -o build/ubft ./cli/ubft || fail "could not build ubft from this lane branch"
fi
go build -o "$EVIDENCE_DIR/m2-replacement-client-compare" ./scripts/m2-replacement-client-compare || fail "could not build archive comparison tool"

laneLog=$EVIDENCE_DIR/lane.log
laneStatus=0
if POST_M2A_MODE=f7 POST_M2A_CHAIN_ID=31337 M2_PROFILE2=1 SIGNING=authority M2A_FINAL_RESTORE=1 \
  POST_M2A_URETH_BIN="$URETH_BIN" POST_M2A_URETH_COMMIT="$URETH_COMMIT" \
  M2_RUN_LOG_DIR="$EVIDENCE_DIR/lane-nodes" D1_MONITOR_TIMEOUT=1800 \
  bash ./scripts/reth-paired-devnet.sh 4 20 2>&1 | tee "$laneLog"; then
  pass "paid and idle paired-validator history completed both root handoffs and archive restore"
else
  laneStatus=$?
  printf 'WARN: paired lane exited %d; retaining and comparing any complete certified history in %s\n' \
    "$laneStatus" "$laneLog" >&2
fi

sourceArchive=$EVIDENCE_DIR/source-v2-archive
replacementArchive=$EVIDENCE_DIR/replacement-v2-archive
cp -R test-nodes/h4-archives/evm2 "$sourceArchive" || fail "could not retain source validator archive"
cp -R test-nodes/h4-replaced/archive "$replacementArchive" || fail "could not retain restored validator archive"
cp test-nodes/post-m2a-evidence/f7-lock-pin.json "$EVIDENCE_DIR/f7-paid-receipt-pin.json" || fail "F7 typed paid-receipt pin is missing"
cp test-nodes/post-m2a-evidence/operator-status.json "$EVIDENCE_DIR/operator-status.json" || fail "post-handoff operator status is missing"

"$EVIDENCE_DIR/m2-replacement-client-compare" \
  --source-archive "$sourceArchive" --replacement-archive "$replacementArchive" \
  --source-log "$EVIDENCE_DIR/lane-nodes/evm2/debug.log" \
  --replacement-log "$EVIDENCE_DIR/lane-nodes/h4-replaced/restore.log" \
  --out "$EVIDENCE_DIR/comparison.json" | tee "$EVIDENCE_DIR/comparison.log" || fail "source/replacement history comparison failed"

pass "comparison report includes per-block BFT certificate and canonical input digests"
if [ "$laneStatus" -ne 0 ]; then
  fail "paired restore lane had an ancillary failure; comparison evidence is preserved in $EVIDENCE_DIR"
fi
pass "M2 #261 integrated replacement-client lane complete"
