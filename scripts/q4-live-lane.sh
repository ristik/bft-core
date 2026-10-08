#!/usr/bin/env bash
# Q4 #51 (B) live lane (briefs/q4-design-v2.md section 6): REAL-PROCESS representatives of the weighted fault matrix on the paired
# devnet with F8's three aggregator shards, through the root fault shim and F8's callbacks. It is gated: it runs only in an activated
# weighted epoch (Q4_WEIGHTED_CHECK) and otherwise stops BLOCKED (exit 3). Serialized with every other devnet run by
# briefs/devnet-lock.sh (the Q3 lane has priority; this lane takes its turn).
#
#   Q4_URETH_BIN=<ureth build> Q4_URETH_COMMIT=<commit> RUGREGATOR_BIN=<F8 pin> RUGREGATOR_SOURCE=<F8 checkout> \
#   Q4_EPOCH=<installed epoch> Q4_WEIGHTED_CHECK='<command that exits 0 in the weighted epoch>' scripts/q4-live-lane.sh
#   scripts/q4-live-lane.sh --dry-run     # no lock, no process: pins, steps and the self-test of the helpers
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${Q4_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/q4-live-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

if [ "${1:-}" = "--dry-run" ]; then
  cd "$REPO_ROOT"
  source scripts/lib/q4-lib.sh
  d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
  q4_selftest_docs "$d"
  [ "$(ls "$d" | wc -l)" -eq 4 ] || fail "self-test: the control documents were not written"
  for f in "$d"/*.json; do jq -e . "$f" >/dev/null || fail "self-test: $f is not JSON"; done
  bash -n scripts/q4-live-steps.sh scripts/q4-live-lane.sh scripts/lib/q4-lib.sh || fail "syntax"
  python3 scripts/q4-trace-check.py --help >/dev/null || fail "trace checker does not run"
  grep -c '^q4_step ' scripts/q4-live-steps.sh | sed 's/^/steps: /'
  pass "dry run: nothing started, no lock taken"
  exit 0
fi

[ -n "${Q4_URETH_BIN:-}" ] && [ -x "$Q4_URETH_BIN" ] || fail "set Q4_URETH_BIN to the pinned ureth build"
[ -n "${Q4_URETH_COMMIT:-}" ] || fail "set Q4_URETH_COMMIT"
[ -n "${RUGREGATOR_BIN:-}" ] && [ -n "${RUGREGATOR_SOURCE:-}" ] || fail "set RUGREGATOR_BIN and RUGREGATOR_SOURCE (the F8 pin)"
[ -n "${Q4_EPOCH:-}" ] || fail "set Q4_EPOCH"
[ -n "${Q4_BFT_COMMIT:-}" ] || fail "set Q4_BFT_COMMIT: the lane refuses an unpinned or dirty checkout"

if [ "${Q4_LANE_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "Q4 live lane (dev3)" env Q4_LANE_LOCKED=1 Q4_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
export Q4_EVIDENCE_DIR="$EVIDENCE_DIR"
[ "$(git rev-parse HEAD)" = "$Q4_BFT_COMMIT" ] || fail "HEAD is not the pinned Q4_BFT_COMMIT"
[ -z "$(git status --porcelain --untracked-files=no)" ] || fail "tracked files are modified: prebuilt or dirty development builds are not acceptance evidence"
[ -x build/ubft ] || fail "build/ubft is missing (make build)"
make build-q4shim >/dev/null || fail "make build-q4shim"
[ -x build/q4shim/ubft ] || fail "build/q4shim/ubft is missing"
{
  echo "bft-core head=$(git rev-parse HEAD) ureth=$Q4_URETH_COMMIT"
  echo "ubft sha256=$(shasum -a 256 build/ubft | cut -d' ' -f1)"
  echo "ubft-q4shim sha256=$(shasum -a 256 build/q4shim/ubft | cut -d' ' -f1)"
  go version
} | tee "$EVIDENCE_DIR/heads.txt"

export Q4_SHIM_DIR="$PWD/test-nodes/q4/shim" Q4_ROOT_BIN="$PWD/build/q4shim/ubft"
rm -rf "$Q4_SHIM_DIR"; mkdir -p "$Q4_SHIM_DIR"
set +e
EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256} Q4_LIVE_LANE=1 F8_MIXED_LANE=1 M2_PROFILE2=1 SIGNING=authority \
  POST_M2A_URETH_BIN="$Q4_URETH_BIN" POST_M2A_URETH_COMMIT="$Q4_URETH_COMMIT" \
  M2_RUN_LOG_DIR="$EVIDENCE_DIR/nodes" F8_LOG_DIR="$EVIDENCE_DIR/f8" \
  bash ./scripts/reth-paired-devnet.sh 4 10 2>&1 | tee "$EVIDENCE_DIR/lane.log"
status=${PIPESTATUS[0]}
set -e
cp -R "$Q4_SHIM_DIR" "$EVIDENCE_DIR/shim" 2>/dev/null || true
cp -R test-nodes/q4 "$EVIDENCE_DIR/q4" 2>/dev/null || true
if [ "$status" -eq 3 ]; then
  echo "BLOCKED: the weighted-epoch gate was not met; no fault was injected" | tee -a "$EVIDENCE_DIR/lane.log"
  exit 3
fi
if [ "$status" -ne 0 ] || grep -q '^ *FAIL:' "$EVIDENCE_DIR/lane.log"; then
  fail "Q4 live lane failed (exit $status); see $EVIDENCE_DIR/lane.log"
fi
grep -q 'Q4 live lane: all steps PASSED' "$EVIDENCE_DIR/lane.log" || fail "lane ended without completing every step"
pass "Q4 live lane complete; evidence in $EVIDENCE_DIR"
