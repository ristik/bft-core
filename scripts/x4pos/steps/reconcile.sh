#!/usr/bin/env bash
# X4 PoS step (reconcile): the reward pool's whole life replayed against the chain at the end of the campaign, and its conservation. Run by x4f_reconcile from the lane (x4e_run).
set -euo pipefail
cd "$(dirname "$0")/../../.."
source scripts/x4pos/lib.sh
out=$X4_STEP_DIR/replay.txt
x4p_reward_replay "$out"
x4p_reward_conserved
jq -n --argjson i "$(x4p_replay_field "$out" intervals)" --argjson p "$(x4p_replay_field "$out" paid)" --argjson z "$(x4p_replay_field "$out" zeroBudget)" --argjson f "$(x4p_replay_field "$out" fundings)" \
  --argjson r "$(x4p_replay_field "$out" refilledAfterExhaustion)" '{intervals: $i, paid: $p, zeroBudget: $z, fundings: $f, refilledAfterExhaustion: $r, conserved: true}' >"$X4_STEP_DIR/reconcile.json"
x4p_log "reconciled: $(cat "$X4_STEP_DIR/reconcile.json")"
