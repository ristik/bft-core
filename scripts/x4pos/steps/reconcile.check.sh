#!/usr/bin/env bash
# X4 PoS step check (reconcile): read-only; the reconcile record shows a replayed, conserved, refilled pool.
set -euo pipefail
cd "$(dirname "$0")/../../.."
: "${X4_STEP_DIR:?run under the lane or scripts/x4pos/driver.py}"
jq -e '.conserved == true and .intervals >= 2 and .zeroBudget >= 1 and .fundings >= 1 and .refilledAfterExhaustion == true' "$X4_STEP_DIR/reconcile.json" >/dev/null
echo "reconcile.check: ok"
