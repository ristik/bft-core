#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${POST_M2A_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/post-m2a-t1-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

if [ "${POST_M2A_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "post-M2a T1 vesting acceptance" env POST_M2A_LOCKED=1 POST_M2A_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; T1 evidence output is $EVIDENCE_DIR"

if POST_M2A_MODE=t1 POST_M2A_CHAIN_ID=1337 M2_PROFILE2=1 M2_RUN_LOG_DIR="$EVIDENCE_DIR/lane-nodes" \
  bash ./scripts/reth-paired-devnet.sh 4 20 2>&1 | tee "$EVIDENCE_DIR/lane.log"; then
  pass "fresh paired lane compiled and started the default manifest genesis"
else
  fail "paired T1 lane failed; inspect $EVIDENCE_DIR/lane.log"
fi

claim=test-nodes/post-m2a-evidence/t1-claim.json
[ -s "$claim" ] || fail "claim receipt and balance record is missing"
python3 - "$claim" <<'PY' || fail "saved receipt/balances do not show the successful due-at-start claim"
import json,sys
record=json.load(open(sys.argv[1],encoding="utf-8"))
r=record["receipt"]
if r.get("status") != "0x1" or r.get("type") != "0x2" or not r.get("blockHash"):
    raise SystemExit("claim receipt is not successful, typed, and block-bound")
b=record["balances"]
if int(b["beneficiaryAfter"],16)-int(b["beneficiaryBefore"],16) != 300000000000000000000000000:
    raise SystemExit("beneficiary did not receive the exact due tranche")
if int(b["feeCollectorAfter"],16) <= int(b["feeCollectorBefore"],16):
    raise SystemExit("FeeCollector did not receive the priority fee")
PY
cp "$claim" "$EVIDENCE_DIR/t1-claim.json"
pass "receipt and before/after balances prove the first claim and real fee credit"
cp test-nodes/evm-genesis-finalized-funded.json "$EVIDENCE_DIR/genesis.json"
cp test-nodes/post-m2a-allocation-build-v1.json "$EVIDENCE_DIR/effective-default-manifest.json"
pass "retained finalized genesis and the effective default manifest parameters"
pass "T1 evidence run complete"
