#!/usr/bin/env bash
# The wallet-evidence stage of the NB2-09 (bft-core#1105) run (bft-core#1102): against a running devnet, build a Deposited receipt
# proof and a SegmentSealed seal receipt through the public gateway's RPC only, and verify both with the Go reference (nb2ref).
#
#   scripts/nb2-evidence/stage.sh GATEWAY_URL TRUST_BUNDLE PIN_FILE [--seed CHAIN_ID | VAULT DEPOSIT_TX DEPLOYMENT_BLOCK]
#
# GATEWAY_URL is the gateway's JSON-RPC root (for example http://127.0.0.1:18600/ or https://HOST/rpc). TRUST_BUNDLE and PIN_FILE are
# the trust-base release bundle and its genesis EntryID (dnb-tool trust-bundle). --seed deploys a two-topic log emitter with the
# public Anvil key and emits one event of each shape (until the NB2-04 vault exists); otherwise VAULT, a deposit transaction and the
# vault's deployment block name a real deployment, and the newest seal is searched from that block. EVM_PARTITION (8), EVM_SHARD
# (0x80) and K (4 with --seed, else 64) select Γ's values. Output goes to NB2_EVIDENCE_OUT (default test-nodes/nb2-evidence).
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
url=${1:?gateway URL} bundle=${2:?trust bundle} pin=$(tr -d '[:space:]' <"${3:?pin file}")
shift 3
out=${NB2_EVIDENCE_OUT:-test-nodes/nb2-evidence}
mkdir -p "$out"
tool=$out/nb2-evidence
go build -o "$tool" ./scripts/nb2-evidence
partition=${EVM_PARTITION:-8} shard=${EVM_SHARD:-0x80}
if [ "${1:-}" = --seed ]; then
  k=${K:-4}
  "$tool" seed -rpc "$url" -chain-id "${2:?chain id}" -k "$k" | tee "$out/seed.json"
  vault=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['emitter'])" "$out/seed.json")
  tx=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['depositTx'])" "$out/seed.json")
  from=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['deploymentBlock'])" "$out/seed.json")
else
  k=${K:-64} vault=${1:?vault} tx=${2:?deposit tx} from=${3:?deployment block}
fi
echo "stage: deposit receipt proof (tx $tx)"
"$tool" receipt -rpc "$url" -tx "$tx" -emitter "$vault" -out "$out/deposit-proof.cbor"
"$tool" verify -proof "$out/deposit-proof.cbor" -emitter "$vault" -partition "$partition" -shard "$shard" -trust-bundle "$bundle" -pin "$pin" -event deposited -k "$k"
echo "stage: newest SegmentSealed seal receipt (from block $from)"
"$tool" newest-seal -rpc "$url" -emitter "$vault" -from "$from" -out "$out/seal-proof.cbor"
"$tool" verify -proof "$out/seal-proof.cbor" -emitter "$vault" -partition "$partition" -shard "$shard" -trust-bundle "$bundle" -pin "$pin" -event sealed -k "$k"
"$tool" segments -rpc "$url" -emitter "$vault" -from "$from" -start 0 >"$out/segments.txt"
echo "stage: wallet evidence verified through $url only"
