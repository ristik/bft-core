#!/usr/bin/env bash
# X4 PoS step check (reconcile): read-only; the reconcile record shows a replayed, conserved, refilled pool.
set -euo pipefail
cd "$(dirname "$0")/../../.."
: "${X4_STEP_DIR:?run under the lane or scripts/x4pos/driver.py}"
min=$(jq -r '.minIntervals // 2' <<<"${X4_STEP_ARGS:-{\}}" 2>/dev/null || echo 2)   # 4 in the campaign (x4f_reconcile passes it)
jq -e --argjson min "$min" '.conserved == true and .intervals >= $min and .zeroBudget >= 1 and .fundings >= 1 and .refilledAfterExhaustion == true' "$X4_STEP_DIR/reconcile.json" >/dev/null
echo "reconcile.check: ok"
