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

# ---- VR_SCHEDULE=2: the latch at E and a no_test_rule root refusing past it (SIGNING=local; a long run: one 3600 s governance wait) ----------------------
#   1. shard node 4 is restarted with a `-tags no_test_rule` ubft (it lacks noop-test-v1) while the schedule is only queued (a root of the
#      committee could not be used: design 7.3 asks every successor member's support, so a root without the rule blocks the handoff, by design);
#   2. noop-test-v1 is queued for E = known root epoch + 3 and executed after the governance delays;
#   3. `ubft validator rotate` (a new payee for identity 4) drives one handoff per epoch up to E: the schedule is carried by the first handoff, the
#      warning and ab_unicity_upgrade_required fire on shard node 4 ahead of E, and at the commit into E VR latches the entry and shard node 4 refuses the switch
#      with UpgradeRequired; ureth's unicity_rulesV1 shows the rule before and after E.
vrs_roots_at() { # epoch: at least 3 roots report this active epoch
  local r n=0; for r in $(vrb_root_rpcs); do curl -sf -X POST -H 'Content-Type: application/json' -d '{}' "$r/api/v1/q3/status" | grep -q "\"activeEpoch\": *$1" && n=$((n+1)); done; [ "$n" -ge 3 ]
}
vrs_rules() { curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"unicity_rulesV1","params":[]}' "$vrb_rpc"; }
vrs_upgrade_state() { build/ubft validator upgrade --rpc "$vrb_rpc" 2>&1; }
vrs_rotate() { # a new payee for identity 4 (local keys): the next election is due
  local keys=$VR_DIR/dev-keys/keys.json owner payee cfg rid ehome= rhome= h
  owner=$(python3 -c "import json;print(json.load(open('$keys'))['owners'][3]['privateKey'])")
  payee=0x$(openssl rand -hex 20)
  rid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[3]['rootNodeId'])")
  local eid; eid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[3]['evmNodeId'])")
  for h in test-nodes/root*/; do [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$rid" ] && rhome=${h%/}; done
  for h in test-nodes/evm*/; do [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$eid" ] && ehome=${h%/}; done
  cfg=$(mktemp -d); printf '%s\n' "$owner" >"$cfg/operator.key"; chmod 600 "$cfg/operator.key"; openssl rand -hex 32 >"$cfg/ureth.key"
  cat >"$cfg/validator.json" <<JSON
{"format":"unicity.validator.config.v1","rpc":"$vrb_rpc","registry":"$vrb_vr","rootKeys":"$PWD/$rhome/keys.json",
 "evmKeys":"$PWD/$ehome/keys.json","urethKey":"$cfg/ureth.key","jwt":"$cfg/none","operatorKey":"$cfg/operator.key",
 "payee":"$(python3 -c "import json;print(json.load(open('$keys'))['owners'][3]['address'])")","id":4}
JSON
  build/ubft validator rotate --validator-config "$cfg/validator.json" --new-payee "$payee" 2>&1 | tail -3
  rm -rf "$cfg"
}
vrs_handoff() { # target epoch: rotate, wait for the new output, the roots' switch and VR's Boundary
  local n=$1
  vrs_rotate || return 1
  vrb_wait 900 "VR's open output is Published (towards epoch $n)" vrb_published || return 1
  vrb_result=$(vrb_open_output)
  vrb_wait 900 "the roots switched to epoch $n" vrs_roots_at "$n" || return 1
  vrb_wait 900 "the EVM shard acknowledged and VR applied the Boundary into epoch $n" vrb_acked || return 1
}
vrs_long() {
  local d i known E g change waited=0 kd; d=$(vrs_dir)
  known=$(build/ubft validator upgrade --rpc "$vrb_rpc" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["knownRootEpoch"])'); E=$((known + 3))
  vrs_rules >"$d/ureth-rules-before.json"; vrb_log "ureth rules before: $(cut -c1-300 "$d/ureth-rules-before.json")"
  # 1. shard node 4 as a binary without the test rule
  ( cd cli/ubft && go build -tags "${GO_BUILD_TAGS_NTR:-vrdev,no_test_rule}" -o ../../build/ubft-ntr ) || { vrb_log "FAIL: building the no_test_rule binary"; return 1; }
  cp build/ubft build/ubft.default && mv build/ubft-ntr build/ubft
  declare -F m2_start_root >/dev/null || source scripts/lib/m2-handoff-lib.sh
  local rootBoot bootnodes online; rootBoot=$(m2_root_addr 1); online=$(m2_online_validators)
  stop_one_evm_validator 4 || { mv build/ubft build/ubft-ntr; mv build/ubft.default build/ubft; return 1; }
  bootnodes=$(evm_bootnodes_for_peers "$rootBoot" 4 $online)
  start_one_evm_validator 4 "${validators:-4}" "$partitionID" "$rootBoot" engine-api rpc "$bootnodes" >/dev/null 2>&1; local rc=$?
  [ "$rc" != 0 ] || vrb_log "PASS: shard node 4 restarted as a no_test_rule binary"
  mv build/ubft build/ubft-ntr && mv build/ubft.default build/ubft
  [ "$rc" = 0 ] || return 1
  # 2. queue and execute the schedule
  vrs_queue noop noop-test-v1 0x1111111111111111111111111111111111111111111111111111111111111111 || return 1
  g=$d/noop; change=$(python3 -c "import json;print(json.load(open('$g/proposal.json'))['predictedChangeId'])")
  kd=$(mktemp -d); python3 -c "import json;print(json.load(open('$VR_DIR/dev-keys/keys.json'))['signers'][0]['privateKey'])" >"$kd/sender.key"; chmod 600 "$kd/sender.key"
  vrb_log "waiting out the governance delays (3600 s of certified time) for change $change"
  while ! build/ubft governance execute --rpc "$vrb_rpc" --change "$change" --sender-key "$kd/sender.key" >"$g/execute-change.log" 2>&1; do
    sleep 60; waited=$((waited + 60))
    [ "$waited" -lt 9000 ] || { vrb_log "FAIL: the delays did not pass within 150 minutes"; tail -3 "$g/execute-change.log"; return 1; }
  done
  rm -rf "$kd"; cat "$g/execute-change.log"
  vrb_log "PASS: the schedule (change $change, E=$E) was executed after ${waited}s"
  vrs_upgrade_state >"$d/upgrade-after-execute.txt"; cat "$d/upgrade-after-execute.txt"
  # 3. one handoff per epoch up to E
  for i in $(seq $((known + 1)) "$E"); do
    vrs_handoff "$i" || { vrb_log "FAIL: the handoff into epoch $i"; return 1; }
    vrb_log "PASS: handoff into epoch $i committed"
    vrs_upgrade_state >"$d/upgrade-epoch$i.txt"; vrs_rules >"$d/ureth-rules-epoch$i.json"
    grep -hE 'upgrade\.required|upgrade\.refused|UpgradeRequired' test-nodes/evm4/debug.log | cut -c1-420 | tail -5 >"$d/evm4-upgrade-lines-epoch$i.txt"
  done
  curl -s "http://$(evm_validator_rpc_addr 4)/api/v1/metrics" | grep -i 'upgrade_required' >"$d/evm4-metric.txt" 2>/dev/null
  grep -q 'Latched' "$d/upgrade-epoch$E.txt" && vrb_log "PASS: VR latched the schedule at the Boundary into epoch $E" || vrb_log "FAIL: the schedule is not Latched after epoch $E"
  grep -q 'UpgradeRequired' test-nodes/evm4/debug.log && vrb_log "PASS: the no_test_rule shard node 4 refused epoch $E: $(grep -h 'UpgradeRequired' test-nodes/evm4/debug.log | tail -1 | cut -c1-300)" || vrb_log "FAIL: shard node 4 did not refuse with UpgradeRequired"
  vrb_log "ureth rules at epoch $E: $(cut -c1-400 "$d/ureth-rules-epoch$E.json")"
}
