#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${POST_M2A_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/post-m2a-f7-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

if [ "${POST_M2A_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "post-M2a F7 MintReason evidence" env POST_M2A_LOCKED=1 POST_M2A_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; F7 evidence output is $EVIDENCE_DIR"

if POST_M2A_MODE=f7 POST_M2A_CHAIN_ID=31337 M2_PROFILE2=1 M2_RUN_LOG_DIR="$EVIDENCE_DIR/lane-nodes" \
  bash ./scripts/reth-paired-devnet.sh 4 20 2>&1 | tee "$EVIDENCE_DIR/lane.log"; then
  pass "paired ureth lane completed the typed lock, root handoff and D1 pruning rounds"
else
  fail "paired ureth lane failed; inspect $EVIDENCE_DIR/lane.log"
fi

pin=test-nodes/post-m2a-evidence/f7-lock-pin.json
status=test-nodes/post-m2a-evidence/operator-status.json
[ -s "$pin" ] || fail "certified lock receipt pin is missing"
[ -s "$status" ] || fail "operator frontier status is missing"
cp "$pin" "$EVIDENCE_DIR/lock-pin.json"
cp "$status" "$EVIDENCE_DIR/operator-status.json"
pass "retained lock receipt pin and post-handoff archive/frontier status"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/f7-mintproof.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
GOFLAGS=${GOFLAGS:-} go build -o "$tmp/extract" ./scripts/f7-mintproof-extract || fail "could not build archive extractor"
GOFLAGS=${GOFLAGS:-} go build -o "$tmp/verify-offline" ./scripts/f7-mintproof-verify || fail "could not build pure offline verifier"
block_hash=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["blockHash"])' "$pin")
tx_index=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["txIndex"])' "$pin")
log_index=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["logIndex"])' "$pin")
emitter=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["contract"])' "$pin")
topic=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["topic"])' "$pin")
archive_dir=test-nodes/post-m2a-archives/evm1
trust_base=test-nodes/trust-base-epoch1.json
"$tmp/extract" extract --archive "$archive_dir" --block-hash "$block_hash" --tx-index "$tx_index" \
  --log-index "$log_index" --emitter "$emitter" --topic "$topic" --out "$EVIDENCE_DIR/locked.cbor" || fail "archive inclusion extraction failed"
pass "MintReasonBundleV1 inclusion extracted from receipt-complete archive v2"
"$tmp/extract" extract --archive "$archive_dir" --block-hash "$block_hash" --absence \
  --out "$EVIDENCE_DIR/unlocked-absence.cbor" || fail "archive absence extraction failed"
pass "complete receipt-list absence bundle extracted for the distinct Unlocked(uint256) predicate"
[ -s "$trust_base" ] || fail "epoch-1 root trust base is missing"
# The verifier has no RPC/archive dependency, and sandbox-exec additionally denies all network
# operations for each fresh process. Keep an explicit stripped-environment fallback for hosts
# without macOS sandbox-exec; the evidence log labels that weaker mode precisely.
sandboxExec=$(command -v sandbox-exec || true)
if [ -n "$sandboxExec" ]; then
  offlineProfile='(version 1) (allow default) (deny network*)'
  run_offline_verifier() {
    env -i PATH="$PATH" "$sandboxExec" -p "$offlineProfile" "$tmp/verify-offline" "$@"
  }
  pass "F7 verifier network sandbox enabled (deny network*)"
else
  run_offline_verifier() {
    env -i PATH="$PATH" HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
      ALL_PROXY=http://127.0.0.1:9 "$tmp/verify-offline" "$@"
  }
  pass "F7 verifier uses network-stripped env, not sandboxed"
fi
run_offline_verifier --bundle "$EVIDENCE_DIR/locked.cbor" \
  --trust-base "$trust_base" --mode locked >"$EVIDENCE_DIR/verify-locked.json" || fail "offline inclusion verification failed"
pass "separate offline process verified the lock receipt using only bundle and epoch trust base"
run_offline_verifier --bundle "$EVIDENCE_DIR/unlocked-absence.cbor" \
  --trust-base "$trust_base" --mode absent >"$EVIDENCE_DIR/verify-absence.json" || fail "offline absence verification failed"
pass "separate offline process verified absence of the distinct event predicate"
cp test-nodes/post-m2a-evidence/f7-lock-pin.json "$EVIDENCE_DIR/lock-pin.json"
pass "F7 evidence run complete"
