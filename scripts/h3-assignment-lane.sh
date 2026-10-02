#!/usr/bin/env bash
# H3 acceptance lane (briefs/h3-evm-assignment-design.md section 8, amended: validator-set changes are always coupled): a fresh
# M3-shaped genesis (registry layout 2, validator_coupling=true) with F8's three aggregator shards; a configuration-only epoch
# advance as the baseline, a refused bad-PoP coupled proposal, a coupled rotation (root entity and its delegated EVM validator)
# during an in-flight old proposal with a held acknowledgement and a root quorum restart, retired-key rejection (hard
# assertions), the F7 inclusion proof verified offline with the new-epoch trust base, the H4 restore at s=1, and a coupled s=2 ->
# s=3 supersession whose late ack is refused. Every step prints PASS or FAIL; the first FAIL exits nonzero. Local signing
# (successor keys must sign PoPs): the signing-authority-backed rotation is not exercised.
#
#   H3_URETH_BIN=<ureth build with the layout-2 registry> H3_URETH_COMMIT=<its commit> \
#   RUGREGATOR_BIN=<F8-pinned binary> RUGREGATOR_SOURCE=<F8-pinned checkout> scripts/h3-assignment-lane.sh
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${H3_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/h3-assignment-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

[ -n "${H3_URETH_BIN:-}" ] && [ -x "$H3_URETH_BIN" ] || fail "set H3_URETH_BIN to a ureth build carrying the layout-2 SealRegistry"
[ -n "${H3_URETH_COMMIT:-}" ] || fail "set H3_URETH_COMMIT to the ureth source commit"
[ -n "${RUGREGATOR_BIN:-}" ] && [ -n "${RUGREGATOR_SOURCE:-}" ] || fail "set RUGREGATOR_BIN and RUGREGATOR_SOURCE (the F8 pin)"

if [ "${H3_LANE_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "H3 EVM assignment acceptance lane" env H3_LANE_LOCKED=1 H3_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
echo "NOTE: local signing only (SIGNING=local): the signing-authority-backed rotation is not exercised by this lane."
pass "devnet lock acquired by the queued runner; evidence directory $EVIDENCE_DIR"
[ -x build/ubft ] || fail "build/ubft is missing (make build)"
echo "bft-core head=$(git rev-parse HEAD) ureth=$H3_URETH_COMMIT ubft sha256=$(shasum -a 256 build/ubft | cut -d' ' -f1)" | tee "$EVIDENCE_DIR/heads.txt"

set +e
EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256} H3_ASSIGNMENT_LANE=1 F8_MIXED_LANE=1 M2_PROFILE2=1 SIGNING=local \
  POST_M2A_URETH_BIN="$H3_URETH_BIN" POST_M2A_URETH_COMMIT="$H3_URETH_COMMIT" \
  M2_RUN_LOG_DIR="$EVIDENCE_DIR/nodes" F8_LOG_DIR="$EVIDENCE_DIR/f8" \
  bash ./scripts/reth-paired-devnet.sh 4 10 2>&1 | tee "$EVIDENCE_DIR/lane.log"
status=${PIPESTATUS[0]}
set -e
cp -R test-nodes/h3 "$EVIDENCE_DIR/h3" 2>/dev/null || true
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "H3 acceptance lane failed (exit $status); see $EVIDENCE_DIR/lane.log"
fi
grep -q 'H3 acceptance lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "lane ended without completing every step"
pass "H3 acceptance lane complete; evidence in $EVIDENCE_DIR"
