#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${POST_M2A_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/post-m2a-t4-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

if [ "${POST_M2A_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "post-M2a T4 full-state audit" env POST_M2A_LOCKED=1 POST_M2A_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; T4 evidence output is $EVIDENCE_DIR"

if POST_M2A_MODE=t4 POST_M2A_CHAIN_ID=1337 M2_PROFILE2=1 POST_M2A_SKIP_HANDOFF=1 M2_RUN_LOG_DIR="$EVIDENCE_DIR/lane-nodes" \
  bash ./scripts/reth-paired-devnet.sh 4 20 2>&1 | tee "$EVIDENCE_DIR/lane.log"; then
  pass "fresh default-manifest T4 lane certified transfers and vesting claim without handoffs"
else
  fail "paired T4 lane failed; inspect $EVIDENCE_DIR/lane.log"
fi

genesis=test-nodes/evm-genesis-finalized-funded.json
snapshot=test-nodes/post-m2a-evidence/t4-rpc-accounting.json
receipt=test-nodes/post-m2a-evidence/t1-claim.json
[ -s "$genesis" ] || fail "compiled default-manifest genesis is missing"
[ -s "$snapshot" ] || fail "full certified-state snapshot is missing"
[ -s "$receipt" ] || fail "successful vesting claim receipt is missing"

mkdir -p "$EVIDENCE_DIR/build"
go build -o "$EVIDENCE_DIR/build/pos-supply-auditor" ./cmd/pos-supply-auditor || fail "could not build #298 supply auditor"
if "$EVIDENCE_DIR/build/pos-supply-auditor" --genesis "$genesis" --state-dump "$snapshot" \
  >"$EVIDENCE_DIR/audit-result.json"; then
  python3 - "$EVIDENCE_DIR/audit-result.json" "$receipt" <<'PY' || fail "the audit did not reconcile the claim block and fee burn exactly"
import json,sys
result=json.load(open(sys.argv[1],encoding="utf-8")); claim=json.load(open(sys.argv[2],encoding="utf-8"))
if result.get("status") != "pass": raise SystemExit("auditor result is not pass")
if not result.get("nativeSupply",{}).get("matches"): raise SystemExit("native supply did not reconcile exactly")
if int(result.get("nativeSupply",{}).get("ordinaryGasUsed","0")) <= 0: raise SystemExit("no ordinary receipt gas was observed")
if int(result.get("nativeSupply",{}).get("baseFeeBurn","0")) <= 0: raise SystemExit("no base-fee burn from ordinary receipts was observed")
if int(result["certifiedBlock"]["number"]) < int(claim["claimBlockNumber"],16):
    raise SystemExit("audit snapshot predates the vesting claim")
PY
  pass "#298 auditor reconciled full state, transfers, base-fee burn and claim at the certified tip"
else
  fail "#298 auditor rejected the unmodified full-state snapshot"
fi

python3 - "$snapshot" "$receipt" "$EVIDENCE_DIR/injected-accounting-error.json" <<'PY' || fail "could not prepare the isolated injected accounting error"
import json,sys
snapshot=json.load(open(sys.argv[1],encoding="utf-8")); claim=json.load(open(sys.argv[2],encoding="utf-8"))
address=claim["sender"].lower()
if address not in snapshot["accounts"]: raise SystemExit(f"bootstrap sender {address} is absent from full state")
account=snapshot["accounts"][address]
account["balance"]="0x"+format(int(account["balance"],16)+1,"x")
json.dump(snapshot,open(sys.argv[3],"w",encoding="utf-8"),indent=2); print()
PY
set +e
"$EVIDENCE_DIR/build/pos-supply-auditor" --genesis "$genesis" \
  --state-dump "$EVIDENCE_DIR/injected-accounting-error.json" >"$EVIDENCE_DIR/injected-audit-result.json"
injected_status=$?
set -e
[ "$injected_status" -eq 1 ] || fail "auditor did not return violation exit 1 for the injected +1 wei state"
python3 - "$EVIDENCE_DIR/injected-audit-result.json" <<'PY' || fail "the injected error was not reported as a native-supply mismatch"
import json,sys
result=json.load(open(sys.argv[1],encoding="utf-8"))
if result.get("status") != "fail" or not any(v.get("check")=="native_supply_mismatch" for v in result.get("violations",[])):
    raise SystemExit("native_supply_mismatch violation missing")
PY
pass "injected +1 wei accounting error was detected by the auditor with nonzero exit"
cp "$genesis" "$EVIDENCE_DIR/genesis.json"
cp "$snapshot" "$EVIDENCE_DIR/certified-state.json"
pass "T4 evidence run complete"
