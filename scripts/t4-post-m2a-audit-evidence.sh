#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
AGRE_ROOT=$(cd "$REPO_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
EVIDENCE_DIR=${POST_M2A_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/t4-full-$(date -u +%Y%m%dT%H%M%SZ)}
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

if [ "${POST_M2A_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || fail "devnet lock helper is missing at $LOCK_SCRIPT"
  exec "$LOCK_SCRIPT" "T4 full Cancun supply audit" env POST_M2A_LOCKED=1 POST_M2A_EVIDENCE_DIR="$EVIDENCE_DIR" "$0" "$@"
fi
cd "$REPO_ROOT"
mkdir -p "$EVIDENCE_DIR"
pass "devnet lock acquired by the queued runner; T4 evidence output is $EVIDENCE_DIR"

artifact_dir="$EVIDENCE_DIR/solidity"
bash ./scripts/t4/compile-fixtures.sh "$artifact_dir" >"$EVIDENCE_DIR/solidity-compile.log" 2>&1 || {
  cat "$EVIDENCE_DIR/solidity-compile.log" >&2
  fail "could not compile pinned Cancun Solidity fixtures"
}
cat "$EVIDENCE_DIR/solidity-compile.log"
POST_M2A_T4_ARTIFACT_DIR="$artifact_dir" POST_M2A_MODE=t4 POST_M2A_CHAIN_ID=1337 \
  M2_PROFILE2=1 POST_M2A_SKIP_HANDOFF=1 M2_RUN_LOG_DIR="$EVIDENCE_DIR/lane-nodes" \
  bash ./scripts/reth-paired-devnet.sh 4 20 2>&1 | tee "$EVIDENCE_DIR/lane.log" || \
  fail "paired T4 lane failed; inspect $EVIDENCE_DIR/lane.log"
pass "fresh T4 lane certified the full scenario, including the Cancun fixture transactions"

genesis=test-nodes/evm-genesis-finalized-funded.json
snapshot=test-nodes/post-m2a-evidence/t4-rpc-accounting.json
claim_receipt=test-nodes/post-m2a-evidence/t1-claim.json
actions=test-nodes/post-m2a-evidence/t4-contract-actions.json
observations=test-nodes/post-m2a-evidence/t4-observations.json
[ -s "$genesis" ] || fail "compiled default-manifest genesis is missing"
[ -s "$snapshot" ] || fail "full certified-state snapshot is missing"
[ -s "$claim_receipt" ] || fail "successful vesting claim receipt is missing"
[ -s "$actions" ] || fail "certified T4 contract action manifest is missing"
[ -s "$observations" ] || fail "T4 supplemental observations are missing"

mkdir -p "$EVIDENCE_DIR/build"
go build -o "$EVIDENCE_DIR/build/pos-supply-auditor" ./cmd/pos-supply-auditor || fail "could not build T4 supply auditor"
if "$EVIDENCE_DIR/build/pos-supply-auditor" --genesis "$genesis" --state-dump "$snapshot" >"$EVIDENCE_DIR/audit-result.json"; then
  python3 - "$EVIDENCE_DIR/audit-result.json" "$claim_receipt" "$actions" "$snapshot" "$observations" <<'PY' || fail "full T4 audit assertions did not reconcile"
import json,sys
r,c,a,s,o=(json.load(open(p,encoding="utf-8")) for p in sys.argv[1:])
n=r.get("nativeSupply",{}); cov=r.get("coverage",{})
if r.get("status")!="pass" or not n.get("matches"): raise SystemExit("auditor/native supply did not pass")
if int(n.get("ordinaryGasUsed","0"))<=0 or int(n.get("baseFeeBurn","0"))<=0: raise SystemExit("ordinary gas/base-fee burn not observed")
if int(n.get("selfdestructBurnObserved","0"))!=int(a["selfdestructToSelf"]["valueWei"]): raise SystemExit("same-tx burn did not match fixture value")
for k in ("fullState","headersComplete","receiptsComplete","selfdestructTracesComplete"):
    if cov.get(k) is not True: raise SystemExit(f"coverage.{k} incomplete")
if int(r["certifiedBlock"]["number"])<int(c["claimBlockNumber"],16): raise SystemExit("snapshot predates vesting claim")
w=r["wuct"]; supply=int(a["wuct"]["expectedTotalSupplyWei"])
if supply<=0 or int(w["totalSupply"])!=supply or int(w["nativeBalance"])<supply: raise SystemExit("WUCT supply/custody mismatch")
f=r["feeCollector"]; due=int(f["totalLiabilities"])
if due<=0 or due>int(f["nativeBalance"]): raise SystemExit("FeeCollector liabilities absent or unbacked")
o=o["t4Observations"]
if o["ordinarySelfdestruct"]["codeAtTip"]=="0x" or o["ordinarySelfdestruct"]["balanceAtTipWei"]!="0": raise SystemExit("ordinary SELFDESTRUCT did not transfer and retain code")
if o["burnedNewContract"]["codeAtTip"]!="0x" or o["burnedNewContract"]["balanceAtTipWei"]!="0": raise SystemExit("same-tx SELFDESTRUCT did not remove new contract")
PY
  pass "full-state audit reconciled both Cancun SELFDESTRUCT cases, WUCT and FeeCollector liabilities"
else
  status=$?
  cat "$EVIDENCE_DIR/audit-result.json" >&2 || true
  fail "unmodified T4 snapshot audit exited $status instead of passing"
fi

python3 - "$snapshot" "$claim_receipt" "$EVIDENCE_DIR" <<'PY' || fail "could not prepare isolated +1 mint and -1 burn mutations"
import copy,json,sys
s=json.load(open(sys.argv[1],encoding="utf-8")); c=json.load(open(sys.argv[2],encoding="utf-8")); d=sys.argv[3]
address=c["sender"].lower()
if address not in s["accounts"]: raise SystemExit(f"bootstrap sender {address} is absent from full state")
for name,delta in (("mint-plus-one-wei",1),("burn-minus-one-wei",-1)):
    v=copy.deepcopy(s); b=int(v["accounts"][address]["balance"],16)
    if delta<0 and b<1: raise SystemExit("mutation account has insufficient test balance")
    v["accounts"][address]["balance"]="0x"+format(b+delta,"x")
    with open(f"{d}/{name}.json","w",encoding="utf-8") as f: json.dump(v,f,indent=2); f.write("\n")
PY

for label in mint-plus-one-wei burn-minus-one-wei; do
  set +e
  "$EVIDENCE_DIR/build/pos-supply-auditor" --genesis "$genesis" --state-dump "$EVIDENCE_DIR/$label.json" >"$EVIDENCE_DIR/$label-result.json"
  result=$?
  set -e
  [ "$result" -eq 1 ] || fail "$label mutation returned $result, wanted exit 1"
  python3 - "$EVIDENCE_DIR/$label-result.json" <<'PY' || fail "$label did not report native_supply_mismatch"
import json,sys
r=json.load(open(sys.argv[1],encoding="utf-8"))
if r.get("status")!="fail" or not any(v.get("check")=="native_supply_mismatch" for v in r.get("violations",[])): raise SystemExit("native_supply_mismatch absent")
PY
done
pass "injected +1 wei mint and -1 wei burn errors were each detected with exit 1"

python3 - "$snapshot" "$EVIDENCE_DIR" <<'PY' || fail "could not prepare incomplete-coverage cases"
import copy,json,sys
s=json.load(open(sys.argv[1],encoding="utf-8")); d=sys.argv[2]
def write(name,mutate):
    v=copy.deepcopy(s); mutate(v)
    with open(f"{d}/inconclusive-missing-{name}.json","w",encoding="utf-8") as f: json.dump(v,f,indent=2); f.write("\n")
write("header",lambda v:v["blocks"][0].pop("hash",None))
number=next((b["number"] for b in s["blocks"] if int(b["transactionCount"])>0),None)
if number is None: raise SystemExit("no block with a receipt to remove")
write("receipt",lambda v:next(b for b in v["blocks"] if b["number"]==number).pop("feeReceipts",None))
write("trace",lambda v:(v["blocks"][0].pop("selfdestructTracesComplete",None),v["blocks"][0].pop("selfdestructs",None)))
PY

for missing in header receipt trace; do
  set +e
  "$EVIDENCE_DIR/build/pos-supply-auditor" --genesis "$genesis" --state-dump "$EVIDENCE_DIR/inconclusive-missing-$missing.json" >"$EVIDENCE_DIR/inconclusive-missing-$missing-result.json"
  result=$?
  set -e
  [ "$result" -eq 2 ] || fail "missing $missing returned $result, wanted inconclusive exit 2"
  python3 - "$EVIDENCE_DIR/inconclusive-missing-$missing-result.json" "$missing" <<'PY' || fail "missing $missing did not return inconclusive"
import json,sys
r=json.load(open(sys.argv[1],encoding="utf-8")); k={"header":"headersComplete","receipt":"receiptsComplete","trace":"selfdestructTracesComplete"}[sys.argv[2]]
if r.get("status")!="inconclusive" or r.get("coverage",{}).get(k) is not False or not r.get("coverage",{}).get("incompleteReasons"): raise SystemExit("status/coverage/reason mismatch")
PY
done
pass "missing header, receipt and trace each returned inconclusive with exit 2"

cp "$genesis" "$EVIDENCE_DIR/genesis.json"
cp "$snapshot" "$EVIDENCE_DIR/certified-state.json"
cp "$claim_receipt" "$EVIDENCE_DIR/vesting-claim-receipt.json"
cp "$actions" "$EVIDENCE_DIR/t4-contract-actions.json"
cp "$observations" "$EVIDENCE_DIR/t4-observations.json"
cp -R test-nodes/post-m2a-evidence/t4-contract-actions "$EVIDENCE_DIR/"
cp -R test-nodes/post-m2a-evidence/t4-traces "$EVIDENCE_DIR/"
cp -R "$EVIDENCE_DIR/lane-nodes" "$EVIDENCE_DIR/node-logs"
pass "T4 evidence run complete"
