#!/usr/bin/env bash
# VT-07a live acceptance of the activation schedule's early warning (VR_SCHEDULE=1), sourced by vr-boundary-steps.sh after the Boundary:
#   1. the Foundation queues ScheduleActivation (kind 9) for noop-test-v1 (supported) and for future-rule-v9 (a rule no binary supports) at
#      E = known root epoch + 3, through `ubft governance propose schedule-activation` / sign / aggregate / execute;
#   2. `ubft validator upgrade` shows both as Queued, with the unsupported one marked UPGRADE REQUIRED;
#   3. the shard nodes (which read the schedule from their own ureth) warn from the Queued event: log event upgrade.required state=pending and the
#      unicity_upgrade_required gauge;
#   4. a `ubft` built with -tags no_test_rule reports noop-test-v1 as unsupported (validator upgrade --exit-code fails).
# The governance delay is NOT waited out here: the latch at E and the refusal past it need further handoffs (not in this lane).
# ---- the acceptance checks, as pure functions of evidence files: each returns non-zero when the evidence is missing or wrong ------------------------
# (scripts/vr-schedule-checks-test.sh feeds them canned evidence, so they are proven to fail when it is absent)
vrs_rule_id() { cast keccak "unicity.rule/$1"; }   # 0x-hex ruleId

# vrs_check_events <file> <ruleId 0x-hex> <epoch> <event>: the file holds a line of that event for exactly this rule and epoch
vrs_check_events() {
  local rid=${2#0x}
  grep -E "(event=)?$4" "$1" 2>/dev/null | grep -E "rule=(0x)?$rid" | grep -qE "epoch=$3([^0-9]|$)"
}
# vrs_check_active <file> <ruleId> <E>: one activation.active record for the rule (activation epoch E) whose CURRENT epoch is >= E
vrs_check_active() {
  grep -E 'activation\.active' "$1" 2>/dev/null | grep -E "rule=(0x)?${2#0x}" | grep -E "(^|[ ,{])epoch=$3([ ,}\"]|$)" \
    | sed -n 's/.*currentEpoch=\([0-9][0-9]*\).*/\1/p' | awk -v e="$3" '$1 >= e { ok = 1 } END { exit ok ? 0 : 1 }'
}
# vrs_check_all_roots <dir> <ruleId> <epoch> <roots...>: every listed root logged activation.latched AND activation.active for the rule at E
vrs_check_all_roots() {
  local d=$1 rid=$2 e=$3 i; shift 3
  [ "$#" -gt 0 ] || return 1
  for i in "$@"; do
    vrs_check_events "$d/root$i-activation-events.txt" "$rid" "$e" 'activation\.latched' || { echo "root$i did not log activation.latched for rule $rid epoch $e" >&2; return 1; }
    vrs_check_active "$d/root$i-activation-events.txt" "$rid" "$e" || { echo "root$i did not log activation.active for rule $rid epoch $e" >&2; return 1; }
  done
}
# vrs_check_refusal <log> <ruleId> <epoch>: ONE log record is the structured refusal (event=upgrade.refused) whose ATTEMPTED epoch (its epoch key) is E
# and whose UpgradeRequired error names this rule (the greps are filters over the same line: nothing is matched across records, and the rule's own
# scheduled epoch in the message text is not what decides)
vrs_check_refusal() {
  grep -E 'event=upgrade\.refused' "$1" 2>/dev/null | grep -E "(^|[ ,{])epoch=$3([ ,}\"]|$)" | grep "UpgradeRequired" | grep -q "rule ${2#0x}"
}
# vrs_check_warning <log> <ruleId> <E>: ONE record is the pending warning (event=upgrade.required state=pending) for this rule with activationEpoch=E and a
# currentEpoch below E (a warning AHEAD of the activation)
vrs_check_warning() {
  grep -E 'event=upgrade\.required' "$1" 2>/dev/null | grep -E 'state=pending' | grep -E "rule=(0x)?${2#0x}" | grep -E "activationEpoch=$3([^0-9]|$)" \
    | sed -n 's/.*currentEpoch=\([0-9][0-9]*\).*/\1/p' | awk -v e="$3" '$1 < e { ok = 1 } END { exit ok ? 0 : 1 }'
}
# vrs_check_metric <metrics text> <ruleId> <E> <state>: a SAMPLE line (not HELP/TYPE) of unicity_upgrade_required with the labels rule, epoch and state and the value 1
vrs_check_metric() {
  # the EXACT exported name, anchored (ab_ is the exporter's prefix), the label keys inside the braces, and the value field = 1
  grep -E '^(ab_)?unicity_upgrade_required\{' "$1" 2>/dev/null | grep -E "[{,]rule=\"(0x)?${2#0x}\"" | grep -E "[{,]epoch=\"$3\"" | grep -E "[{,]state=\"$4\"" \
    | grep -qE '\} 1(\.0+)?[[:space:]]*$'
}
# vrs_require_roots: THIS lane's roots only (scoped discovery), exactly the expected count, each root's status saved as evidence
vrs_require_roots() {
  local want=${validators:-4} r n=0 d; d=$(vrs_dir)
  local rpcs; rpcs=$(vrb_root_rpcs)
  for r in $rpcs; do
    n=$((n+1)); curl -sf -X POST -H 'Content-Type: application/json' -d '{}' "$r/api/v1/q3/status" >"$d/root-status-$n.json" || { vrb_log "FAIL: root $r does not answer"; return 1; }
  done
  [ "$n" = "$want" ] || { vrb_log "FAIL: this lane's root discovery found $n roots ($(echo $rpcs)), expected $want"; return 1; }
  vrb_log "PASS: exactly $want roots of this lane: $(echo $rpcs)"
}
# vrs_check_rules <unicity_rulesV1 response> <ruleId> <epoch> <latched true|false> <known true|false>: ureth reports the rule scheduled for E
vrs_check_rules() {
  python3 - "$@" <<'PY'
import json, sys
f, rid, epoch, latched, known = sys.argv[1], sys.argv[2].lower(), int(sys.argv[3]), sys.argv[4] == "true", sys.argv[5] == "true"
try:
    r = json.load(open(f))["result"]
except Exception as e:
    sys.exit("no unicity_rulesV1 result: %s" % e)
if not r.get("observed"):
    sys.exit("ureth has observed no canonical head")
if known and not any(k["id"].lower() == rid for k in r.get("known", [])):
    sys.exit("the rule is not among the rules this binary knows")
hit = [e for e in r.get("scheduled", []) if e["ruleId"].lower() == rid and e["rootEpoch"] == epoch and e["latched"] == latched and e["known"] == known]
sys.exit(0 if hit else "no scheduled entry for the rule at epoch %d (latched=%s known=%s): %s" % (epoch, latched, known, r.get("scheduled")))
PY
}
# vrs_check_rules_absent <unicity_rulesV1 response> <ruleId>: a VALID response (result present, observed=true, lists well formed) that has no scheduled entry for the rule;
# a missing, malformed, error or observed=false response is a failure, never "absent"
vrs_check_rules_absent() {
  python3 - "$@" <<'PY'
import json, re, sys
f, rid = sys.argv[1], sys.argv[2].lower()
hexid = re.compile(r"^0x[0-9a-fA-F]{64}$")
try:
    r = json.load(open(f))["result"]
    observed = r["observed"]
    known, scheduled, lacking = r["known"], r["scheduled"], r["lacking"]
    assert isinstance(r["genesisSpec"], str)
    assert isinstance(known, list) and isinstance(scheduled, list) and isinstance(lacking, list)
    for k in known:
        assert isinstance(k["name"], str) and hexid.match(k["id"])
    for e in scheduled:   # every entry well formed: an empty object or a missing field is a malformed response, not an absence
        assert hexid.match(e["ruleId"]) and hexid.match(e["releaseDigest"]) and type(e["rootEpoch"]) is int and 0 <= e["rootEpoch"] < 2**64
        assert type(e["latched"]) is bool and type(e["known"]) is bool
    for e in lacking:
        assert hexid.match(e["ruleId"]) and hexid.match(e["releaseDigest"]) and type(e["rootEpoch"]) is int and 0 <= e["rootEpoch"] < 2**64
except Exception as e:
    sys.exit("not a valid unicity_rulesV1 response: %r" % (e,))
if observed is not True:
    sys.exit("ureth has observed no canonical head")
bad = [e for e in scheduled + lacking if e["ruleId"].lower() == rid]
sys.exit("the rule is already scheduled: %s" % bad if bad else 0)
PY
}
# vrs_check_latched_row <validator upgrade --json> <ruleId> <epoch>: ONE schedule row has this rule, this root epoch and the state Latched
vrs_check_latched_row() {
  python3 - "$@" <<'PY'
import json, sys
f, rid, epoch = sys.argv[1], sys.argv[2].lower(), int(sys.argv[3])
try:
    rows = json.load(open(f))["schedule"]
except Exception as e:
    sys.exit("no schedule in %s: %s" % (f, e))
sys.exit(0 if any(r.get("ruleId", "").lower() == rid and r.get("rootEpoch") == epoch and r.get("state") == "Latched" for r in rows) else "no Latched row for the rule at epoch %d" % epoch)
PY
}

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
  vrs_require_roots || return 1
  vrs_queue noop noop-test-v1 0x1111111111111111111111111111111111111111111111111111111111111111 || return 1
  vrs_queue future future-rule-v9 0x2222222222222222222222222222222222222222222222222222222222222222 || return 1
  build/ubft validator upgrade --rpc "$vrb_rpc" >"$d/validator-upgrade.txt" 2>&1; build/ubft validator upgrade --rpc "$vrb_rpc" --json >"$d/validator-upgrade.json" 2>&1
  cat "$d/validator-upgrade.txt"
  if grep -q 'UPGRADE REQUIRED' "$d/validator-upgrade.txt" && grep -q 'Queued' "$d/validator-upgrade.txt"; then
    vrb_log "PASS: validator upgrade shows the queued schedules, the unsupported one as UPGRADE REQUIRED"
  else vrb_log "FAIL: validator upgrade does not show the queued schedules"; return 1; fi
  local frid known fE; frid=$(vrs_rule_id future-rule-v9)
  known=$(build/ubft validator upgrade --rpc "$vrb_rpc" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["knownRootEpoch"])'); fE=$((known + 3))
  vrb_wait 240 "every shard node logged ONE pending warning for the queued unsupported rule (rule, activationEpoch=$fE, currentEpoch below it)" vrs_nodes_warned "$frid" "$fE" || return 1
  grep -hE 'event=upgrade\.required' test-nodes/evm*/debug.log | cut -c1-400 | head -8 >"$d/shard-warnings.txt"
  vrb_wait 240 "every shard node exports unicity_upgrade_required{rule,epoch=$fE,state=pending} = 1" vrs_nodes_metric pending "$frid" "$fE" || return 1
  ( cd cli/ubft && GOMAXPROCS=4 nice -n 10 go build -tags "${GO_BUILD_TAGS_NTR:-vrdev,no_test_rule}" -o ../../build/ubft-no-test-rule ) || { vrb_log "FAIL: building the no_test_rule binary"; return 1; }
  if build/ubft-no-test-rule validator upgrade --rpc "$vrb_rpc" --exit-code >"$d/no-test-rule-upgrade.txt" 2>&1; then
    vrb_log "FAIL: the no_test_rule binary does not require an upgrade"; return 1
  fi
  grep -q 'UPGRADE REQUIRED' "$d/no-test-rule-upgrade.txt" || { vrb_log "FAIL: the no_test_rule binary's report does not say UPGRADE REQUIRED"; return 1; }
  vrb_log "PASS: a binary built with -tags no_test_rule reports the scheduled rule as unsupported (validator upgrade --exit-code fails)"
  vrb_log "NOT SHOWN here: execution after the governance delay, the latch at E, postponement and the cutoff, a refusal past E, recovery with a pending rule"
}

# ---- VR_SCHEDULE=2: the latch at E and a no_test_rule root refusing past it (SIGNING=local; a long run: one 3600 s governance wait) ----------------------
#   1. shard node 4 is restarted with a `-tags no_test_rule` ubft (it lacks noop-test-v1) while the schedule is only queued (a root of the
#      committee could not be used: design 7.3 asks every successor member's support, so a root without the rule blocks the handoff, by design);
#   2. noop-test-v1 is queued for E = known root epoch + 3 and executed after the governance delays;
#   3. `ubft validator rotate` (a new payee for identity 4) drives one handoff per epoch up to E: the schedule is carried by the first handoff, the
#      warning and ab_unicity_upgrade_required fire on shard node 4 ahead of E, and at the commit into E VR latches the entry and shard node 4 refuses the switch
#      with UpgradeRequired; ureth's unicity_rulesV1 shows the rule before and after E.
# vrs_check_status_epoch <q3/status JSON> <E>: activeEpoch is a JSON integer EQUAL to E (no substring or >= matching)
vrs_check_status_epoch() {
  python3 - "$@" <<'PY'
import json, sys
try:
    v = json.load(open(sys.argv[1]))["activeEpoch"]
except Exception as e:
    sys.exit("no activeEpoch: %r" % (e,))
sys.exit(0 if type(v) is int and v == int(sys.argv[2]) else "activeEpoch %r is not %s" % (v, sys.argv[2]))
PY
}
vrs_roots_at() { # epoch: at least 3 of this lane's roots report exactly this active epoch
  local r n=0 f; f=$(mktemp)
  for r in $(vrb_root_rpcs); do
    curl -sf -X POST -H 'Content-Type: application/json' -d '{}' "$r/api/v1/q3/status" >"$f" 2>/dev/null && vrs_check_status_epoch "$f" "$1" 2>/dev/null && n=$((n+1))
  done
  rm -f "$f"; [ "$n" -ge 3 ]
}
vrs_rules() { curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"unicity_rulesV1","params":[]}' "$vrb_rpc"; }
vrs_nodes_warned() { local i; for i in 1 2 3 4; do vrs_check_warning "test-nodes/evm$i/debug.log" "$1" "$2" || return 1; done; }
vrs_nodes_metric() { local i d; d=$(vrs_dir); for i in 1 2 3 4; do
  curl -s "http://$(evm_validator_rpc_addr "$i")/api/v1/metrics" >"$d/evm$i-metric-$1.txt" 2>/dev/null
  vrs_check_metric "$d/evm$i-metric-$1.txt" "$2" "$3" "$1" || return 1; done; }
vrs_scrape_check() { # state ruleId E: scrape shard node 4's metrics endpoint, keep the text as evidence and check for the sample
  local d; d=$(vrs_dir)
  curl -s "http://$(evm_validator_rpc_addr 4)/api/v1/metrics" >"$d/evm4-metric-$1.txt" 2>/dev/null
  vrs_check_metric "$d/evm4-metric-$1.txt" "$2" "$3" "$1"
}
vrs_upgrade_state() { build/ubft validator upgrade --rpc "$vrb_rpc" 2>&1; }
vrs_upgrade_json() { build/ubft validator upgrade --rpc "$vrb_rpc" --json 2>/dev/null; }
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
  vrs_require_roots || return 1
  known=$(build/ubft validator upgrade --rpc "$vrb_rpc" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["knownRootEpoch"])'); E=$((known + 3))
  vrs_rules >"$d/ureth-rules-before.json"; vrb_log "ureth rules before: $(cut -c1-300 "$d/ureth-rules-before.json")"
  # 1. shard node 4 as a binary without the test rule
  ( cd cli/ubft && GOMAXPROCS=4 nice -n 10 go build -tags "${GO_BUILD_TAGS_NTR:-vrdev,no_test_rule}" -o ../../build/ubft-ntr ) || { vrb_log "FAIL: building the no_test_rule binary"; return 1; }
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
  vrb_wait 240 "shard node 4 exports unicity_upgrade_required{state=pending} for the queued rule" vrs_scrape_check pending "$(vrs_rule_id noop-test-v1)" "$E" || return 1
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
  local rid; rid=$(vrs_rule_id noop-test-v1)
  vrs_check_rules_absent "$d/ureth-rules-before.json" "$rid" || { vrb_log "FAIL: ureth's baseline unicity_rulesV1 is not a valid response without the rule"; return 1; }
  vrb_log "PASS: baseline: ureth observed the head and lists no schedule for the rule"
  for i in $(seq $((known + 1)) "$E"); do
    vrs_handoff "$i" || { vrb_log "FAIL: the handoff into epoch $i"; return 1; }
    vrb_log "PASS: handoff into epoch $i committed"
    vrs_upgrade_state >"$d/upgrade-epoch$i.txt"; vrs_upgrade_json >"$d/upgrade-epoch$i.json"; vrs_rules >"$d/ureth-rules-epoch$i.json"
  done
  # the evidence, then the checks: any missing piece fails the step (and so the lane)
  local r
  for r in 1 2 3 4; do grep -hE 'activation\.latched|activation\.active' "test-nodes/root$r/debug.log" | cut -c1-400 >"$d/root$r-activation-events.txt"; done
  grep -hE 'upgrade\.required|upgrade\.refused|UpgradeRequired' test-nodes/evm4/debug.log | cut -c1-500 >"$d/evm4-upgrade-lines.txt"
  vrs_check_all_roots "$d" "$rid" "$E" 1 2 3 4 || { vrb_log "FAIL: not every root logged activation.latched and activation.active for the rule at epoch $E"; return 1; }
  vrb_log "PASS: all 4 roots logged activation.latched and activation.active for rule $rid at epoch $E"
  vrs_check_latched_row "$d/upgrade-epoch$E.json" "$rid" "$E" || { vrb_log "FAIL: VR does not list the schedule as Latched after epoch $E"; return 1; }
  vrb_log "PASS: VR latched the schedule at the Boundary into epoch $E"
  vrs_check_rules "$d/ureth-rules-epoch$E.json" "$rid" "$E" true true || { vrb_log "FAIL: ureth's unicity_rulesV1 does not show the rule latched at epoch $E"; return 1; }
  vrb_log "PASS: ureth unicity_rulesV1 lists the rule at epoch $E as latched and known"
  vrs_check_warning "$d/evm4-upgrade-lines.txt" "$rid" "$E" || { vrb_log "FAIL: shard node 4 logged no pending upgrade.required warning for the rule ahead of E"; return 1; }
  vrb_log "PASS: shard node 4 warned (upgrade.required state=pending) ahead of E"
  vrs_scrape_check effective "$rid" "$E" || { vrb_log "FAIL: no unicity_upgrade_required sample (value 1, rule, epoch $E, state=effective) on shard node 4"; return 1; }
  vrb_log "PASS: unicity_upgrade_required{state=effective} on shard node 4: $(grep -h 'state="effective"' "$d/evm4-metric-effective.txt" | head -1 | cut -c1-300)"
  vrs_check_refusal "$d/evm4-upgrade-lines.txt" "$rid" "$E" || { vrb_log "FAIL: shard node 4 did not refuse with UpgradeRequired for rule $rid at epoch $E"; return 1; }
  vrb_log "PASS: the no_test_rule shard node 4 refused epoch $E with UpgradeRequired for rule $rid"
  return 0
}
