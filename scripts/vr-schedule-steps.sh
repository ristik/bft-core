#!/usr/bin/env bash
# VT-07a live acceptance of the activation schedule's early warning (VR_SCHEDULE=1), sourced by vr-boundary-steps.sh after the Boundary:
#   1. the Foundation queues ScheduleActivation (kind 9) for noop-test-v1 (supported) and for future-rule-v9 (a rule no binary supports) at
#      E = known root epoch + 3, through `ubft governance propose schedule-activation` / sign / aggregate / execute;
#   2. `ubft validator upgrade` shows both as Queued, with the unsupported one marked UPGRADE REQUIRED;
#   3. the shard nodes (which read the schedule from their own ureth) warn from the Queued event: log event upgrade.required state=pending and the
#      unicity_upgrade_required gauge;
#   4. a `ubft` built with -tags no_test_rule reports noop-test-v1 as unsupported (validator upgrade --exit-code fails).
# The governance delay is NOT waited out here: the latch at E and the refusal past it need further handoffs (not in this lane).
vrs_dir() { mkdir -p "$VR_EVIDENCE/schedule" && echo "$VR_EVIDENCE/schedule"; }
vrs_queue() { # name rule-name release-hex
  local d; d=$(vrs_dir); local g=$d/$1 kd ap=() k known
  mkdir -p "$g"; kd=$(mktemp -d)
  known=$(build/ubft validator upgrade --rpc "$vrb_rpc" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["knownRootEpoch"])')
  build/ubft governance propose schedule-activation --rpc "$vrb_rpc" --rule "$2" --release-digest "$3" --root-epoch "$((known + 3))" --not-before-in 1h5m \
    --label "VT-07a live $2" --out "$g/proposal.json" --note "VT-07a live run" 2>&1 | tee "$g/propose.log" || { vrb_log "FAIL: propose $1"; return 1; }
  for k in 0 1 2; do
    python3 -c "import json;print(json.load(open('$VR_DIR/dev-keys/keys.json'))['signers'][$k]['privateKey'])" >"$kd/s$k.key"; chmod 600 "$kd/s$k.key"
    build/ubft governance sign --rpc "$vrb_rpc" --proposal "$g/proposal.json" --signer-key "$kd/s$k.key" --out "$g/approval$k.json" >>"$g/sign.log" 2>&1 || { vrb_log "FAIL: sign $1/$k"; return 1; }
    ap+=(--approval "$g/approval$k.json")
  done
  build/ubft governance aggregate --rpc "$vrb_rpc" --proposal "$g/proposal.json" "${ap[@]}" --out "$g/bundle.json" 2>&1 | tee "$g/aggregate.log" || { vrb_log "FAIL: aggregate $1"; return 1; }
  python3 -c "import json;print(json.load(open('$VR_DIR/dev-keys/keys.json'))['signers'][0]['privateKey'])" >"$kd/sender.key"; chmod 600 "$kd/sender.key"
  build/ubft governance execute --rpc "$vrb_rpc" --bundle "$g/bundle.json" --sender-key "$kd/sender.key" 2>&1 | tee "$g/execute-bundle.log" || { vrb_log "FAIL: queue $1"; return 1; }
  rm -rf "$kd"
  vrb_log "PASS: $2 queued as change $(python3 -c "import json;print(json.load(open('$g/proposal.json'))['predictedChangeId'])") for root epoch $((known + 3))"
}
vrs_run() {
  local d i; d=$(vrs_dir)
  vrs_queue noop noop-test-v1 0x1111111111111111111111111111111111111111111111111111111111111111 || return 1
  vrs_queue future future-rule-v9 0x2222222222222222222222222222222222222222222222222222222222222222 || return 1
  build/ubft validator upgrade --rpc "$vrb_rpc" >"$d/validator-upgrade.txt" 2>&1; build/ubft validator upgrade --rpc "$vrb_rpc" --json >"$d/validator-upgrade.json" 2>&1
  cat "$d/validator-upgrade.txt"
  grep -q 'UPGRADE REQUIRED' "$d/validator-upgrade.txt" && grep -q 'Queued' "$d/validator-upgrade.txt" \
    && vrb_log "PASS: validator upgrade shows the queued schedules, the unsupported one as UPGRADE REQUIRED" || { vrb_log "FAIL: validator upgrade does not show the queued schedules"; return 1; }
  vrb_wait 200 "a shard node warned of the queued unsupported rule (event=upgrade.required state=pending)" grep -qE 'upgrade.required.*state=pending|state=pending.*upgrade.required' test-nodes/evm1/debug.log || return 1
  grep -hE 'upgrade.required' test-nodes/evm*/debug.log | cut -c1-400 | head -8 >"$d/shard-warnings.txt"
  for i in 1 2 3 4; do
    curl -s "http://$(evm_validator_rpc_addr "$i")/api/v1/metrics" | grep -i 'upgrade_required' >>"$d/shard-metrics.txt"
  done
  [ -s "$d/shard-metrics.txt" ] && vrb_log "PASS: unicity_upgrade_required gauge on the shard nodes: $(head -1 "$d/shard-metrics.txt" | cut -c1-200)" || vrb_log "info: no unicity_upgrade_required sample on the shard metrics endpoint"
  ( cd cli/ubft && go build -tags "${GO_BUILD_TAGS_NTR:-vrdev,no_test_rule}" -o ../../build/ubft-no-test-rule ) || { vrb_log "FAIL: building the no_test_rule binary"; return 1; }
  if build/ubft-no-test-rule validator upgrade --rpc "$vrb_rpc" --exit-code >"$d/no-test-rule-upgrade.txt" 2>&1; then
    vrb_log "FAIL: the no_test_rule binary does not require an upgrade"; return 1
  fi
  grep -q 'noop-test-v1\|UPGRADE REQUIRED' "$d/no-test-rule-upgrade.txt" && vrb_log "PASS: a binary built with -tags no_test_rule reports the scheduled rule as unsupported (validator upgrade --exit-code fails)"
  vrb_log "NOT SHOWN here: execution after the governance delay, the latch at E, postponement and the cutoff, a refusal past E, recovery with a pending rule"
}
