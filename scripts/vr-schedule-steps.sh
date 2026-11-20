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
  vrs_validate_rules "$1" || return 1
  python3 - "$@" <<'PY'
import json, sys
f, rid, epoch, latched, known = sys.argv[1], sys.argv[2].lower(), int(sys.argv[3]), sys.argv[4] == "true", sys.argv[5] == "true"
r = json.load(open(f))["result"]
if r["observed"] is not True:
    sys.exit("ureth has observed no canonical head")
if known and not any(k["id"].lower() == rid for k in r["known"]):
    sys.exit("the rule is not among the rules this binary knows")
hit = [e for e in r["scheduled"] if e["ruleId"].lower() == rid and e["rootEpoch"] == epoch and e["latched"] is latched and e["known"] is known]
sys.exit(0 if hit else "no scheduled entry for the rule at epoch %d (latched=%s known=%s): %s" % (epoch, latched, known, r["scheduled"]))
PY
}
# vrs_check_rules_absent <unicity_rulesV1 response> <ruleId>: a VALID response (result present, observed=true, lists well formed) that has no scheduled entry for the rule;
# a missing, malformed, error or observed=false response is a failure, never "absent"
# vrs_validate_rules <unicity_rulesV1 response>: the STRICT structure every rules check starts from (u64 JSON integer epochs, 64-hex ids and digests, boolean flags)
vrs_validate_rules() {
  python3 - "$@" <<'PY'
import json, re, sys
hexid = re.compile(r"^0x[0-9a-fA-F]{64}$")
def invalid(why):   # explicit exits, never `assert`: asserts vanish under PYTHONOPTIMIZE=1
    sys.exit("not a valid unicity_rulesV1 response: %s" % why)
def is_u64(v):
    return type(v) is int and 0 <= v < 2**64
def row_ok(e, flags):
    if not isinstance(e, dict):
        return False
    if not (isinstance(e.get("ruleId"), str) and hexid.match(e["ruleId"]) and isinstance(e.get("releaseDigest"), str) and hexid.match(e["releaseDigest"])):
        return False
    if not is_u64(e.get("rootEpoch")):
        return False
    return all(type(e.get(f)) is bool for f in flags)
try:
    r = json.load(open(sys.argv[1]))["result"]
    observed, known, scheduled, lacking, spec = r["observed"], r["known"], r["scheduled"], r["lacking"], r["genesisSpec"]
except Exception as e:
    invalid(repr(e))
if type(observed) is not bool:
    invalid("observed is not a boolean")
if not isinstance(spec, str):
    invalid("genesisSpec")
if not (isinstance(known, list) and isinstance(scheduled, list) and isinstance(lacking, list)):
    invalid("known, scheduled and lacking must be lists")
for k in known:   # every entry well formed: an empty object, a float epoch, integer flags or a short digest is a malformed response
    if not (isinstance(k, dict) and isinstance(k.get("name"), str) and isinstance(k.get("id"), str) and hexid.match(k["id"])):
        invalid("a known entry: %r" % (k,))
for e in scheduled:
    if not row_ok(e, ("latched", "known")):
        invalid("a scheduled entry: %r" % (e,))
for e in lacking:
    if not row_ok(e, ()):
        invalid("a lacking entry: %r" % (e,))
PY
}
vrs_check_rules_absent() {
  vrs_validate_rules "$1" || return 1
  python3 - "$@" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))["result"]
rid = sys.argv[2].lower()
if r["observed"] is not True:
    sys.exit("ureth has observed no canonical head")
bad = [e for e in r["scheduled"] + r["lacking"] if e["ruleId"].lower() == rid]
sys.exit("the rule is already scheduled: %s" % bad if bad else 0)
PY
}
# vrs_check_postponed <validator status --json> <ruleId> <oldE> <newE>: VR lists the rule's OLD entry (root epoch oldE) as Superseded and a NEW entry (root epoch newE) as Active,
# each in ONE activations line of that rule
vrs_check_postponed() {
  python3 - "$@" <<'PY'
import json, re, sys
f, rid, old, new = sys.argv[1], sys.argv[2].lower().removeprefix("0x"), sys.argv[3], sys.argv[4]
try:
    acts = json.load(open(f))["activations"]
except Exception as e:
    sys.exit("no activations: %r" % (e,))
if not isinstance(acts, list) or not all(isinstance(a, str) for a in acts):
    sys.exit("activations is not a list of strings")
def has(epoch, state):
    pat = re.compile(r"^rule %s release [0-9a-f]{64} at root epoch %s, not before UC time [0-9]+: %s$" % (rid, epoch, state))
    return any(pat.match(a) for a in acts)
sys.exit(0 if has(old, "Superseded") and has(new, "Active") else "no Superseded(%s)+Active(%s) pair for the rule in %r" % (old, new, acts))
PY
}
# vrs_check_change_state <governance list text> <state> [reason number]: the change is in that state (Rejected with that reason), on ONE line
vrs_check_change_state() {
  if [ -n "${3:-}" ]; then grep -qE "^[[:space:]]+state $2 \\(reason $3\\)\$" "$1" 2>/dev/null
  else grep -qE "^[[:space:]]+state $2\$" "$1" 2>/dev/null; fi
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
vrs_queue() { # name rule-name release-hex [absolute root epoch E; default: known root epoch + 3]
  local d; d=$(vrs_dir); local g=$d/$1 kd ap=() k known
  mkdir -p "$g"; kd=$(mktemp -d)
  known=$(build/ubft validator upgrade --rpc "$vrb_rpc" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["knownRootEpoch"])')
  build/ubft governance propose schedule-activation --rpc "$vrb_rpc" --rule "$2" --release-digest "$3" --root-epoch "${4:-$((known + 3))}" --not-before-in 1h5m \
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
  vrb_log "PASS: $2 queued as change $(python3 -c "import json;print(json.load(open('$g/proposal.json'))['predictedChangeId'])") for root epoch ${4:-$((known + 3))}"
}
vrs_change_id() { python3 -c "import json;print(json.load(open('$(vrs_dir)/$1/proposal.json'))['predictedChangeId'])"; }
vrs_sender_key() { local f; f=$(mktemp); python3 -c "import json;print(json.load(open('$VR_DIR/dev-keys/keys.json'))['signers'][0]['privateKey'])" >"$f"; chmod 600 "$f"; echo "$f"; }
# vrs_execute <name> [max seconds]: execute the queued change once its governance delays have passed (retrying until they do)
vrs_execute() {
  local g; g=$(vrs_dir)/$1; local id waited=0 kf; id=$(vrs_change_id "$1"); kf=$(vrs_sender_key)
  while ! build/ubft governance execute --rpc "$vrb_rpc" --change "$id" --sender-key "$kf" >"$g/execute-change.log" 2>&1; do
    sleep 30; waited=$((waited + 30))
    [ "$waited" -lt "${2:-9000}" ] || { vrb_log "FAIL: change $id ($1) could not be executed within ${2:-9000}s"; tail -3 "$g/execute-change.log"; rm -f "$kf"; return 1; }
  done
  rm -f "$kf"; vrb_log "PASS: change $id ($1) executed after ${waited}s of retries"
}
vrs_gov_list() { build/ubft governance list --rpc "$vrb_rpc" --change "$(vrs_change_id "$1")" 2>&1; }
vrs_status_json() { build/ubft validator status --rpc "$vrb_rpc" --json 2>/dev/null; }
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
vrs_rot=0
vrs_rotate() { # a new payee for identity 4: the next election is due (SIGNING=authority: the payee is the next one the authority's policy lists)
  local keys=$VR_DIR/dev-keys/keys.json owner payee cfg rid ehome= rhome= h evmHolder
  owner=$(python3 -c "import json;print(json.load(open('$keys'))['owners'][3]['privateKey'])")
  payee=0x$(openssl rand -hex 20)
  rid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[3]['rootNodeId'])")
  local eid; eid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[3]['evmNodeId'])")
  for h in test-nodes/root*/; do [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$rid" ] && rhome=${h%/}; done
  for h in test-nodes/evm*/; do [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$eid" ] && ehome=${h%/}; done
  cfg=$(mktemp -d); printf '%s\n' "$owner" >"$cfg/operator.key"; chmod 600 "$cfg/operator.key"; openssl rand -hex 32 >"$cfg/ureth.key"
  evmHolder="\"evmKeys\":\"$PWD/$ehome/keys.json\""
  if [ "${SIGNING:-local}" = authority ]; then
    local an=${ehome#test-nodes/evm}
    evmHolder="\"evmAuthority\":{\"socket\":\"$PWD/test-nodes/auth$an/operator.sock\",\"credential\":\"$PWD/test-nodes/auth$an/operator.cred\",\"nodeInfo\":\"$PWD/test-nodes/auth$an/node-info.json\"}"
    vrs_rot=$((vrs_rot + 1))   # index 0 is the Boundary step's own rotation
    payee=$(python3 -c "import json;print(json.load(open('$VR_DIR/rotate-payees-all.json'))['$an'][$vrs_rot])") || { vrb_log "FAIL: the authority policy lists no payee number $vrs_rot (VR_ROTATIONS)"; return 1; }
  fi
  cat >"$cfg/validator.json" <<JSON
{"format":"unicity.validator.config.v1","rpc":"$vrb_rpc","registry":"$vrb_vr","rootKeys":"$PWD/$rhome/keys.json",
 $evmHolder,"urethKey":"$cfg/ureth.key","jwt":"$cfg/none","operatorKey":"$cfg/operator.key",
 "payee":"$(python3 -c "import json;print(json.load(open('$keys'))['owners'][3]['address'])")","id":4}
JSON
  build/ubft validator rotate --validator-config "$cfg/validator.json" --new-payee "$payee" 2>&1 | tail -3
  rm -rf "$cfg"
}
# vrs_advance_authorities <epoch> <E>: each authority signs for one scope, so the authorities advance into root epoch n (advance-with-proof) and their shard
# nodes restart under the new sessions before the shard can acknowledge. Shard node 4 is the no_test_rule node: it restarts as that binary, and at E it
# is expected to refuse the epoch (it is neither awaited nor advanced).
vrs_advance_authorities() {
  local n=$1 E=$2 i root1 pdr
  [ -n "$(type -t vrj_advance_authorities)" ] || source scripts/vr-joiner-steps.sh
  vrj_source_libs || return 1
  root1="http://127.0.0.1:$(m2_rpc_port 1)"
  for i in 1 2 3 4; do
    [ "$i" = 4 ] && [ "$n" = "$E" ] && continue
    vrb_wait 300 "evm$i activated root epoch $n" grep -Fq "msg=\"handoff activated\" rootEpoch=$n" "test-nodes/evm$i/debug.log" || return 1
  done
  build/ubft q3 trust-base --root-rpc "$root1" --epoch "$n" --out "test-nodes/trust-base-epoch$n.json" || { vrb_log "FAIL: the trust base of epoch $n"; return 1; }
  for i in 1 2 3; do
    H3_ONLINE="1 2 3 4" M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities "$n" 1 "$i" || { vrb_log "FAIL: the advance of authority $i into epoch $n"; return 1; }
  done
  if [ "$n" != "$E" ]; then
    cp build/ubft build/ubft.default && mv build/ubft-ntr build/ubft   # shard node 4 restarts as the no_test_rule binary
    H3_ONLINE="1 2 3 4" M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities "$n" 1 4; local rc=$?
    mv build/ubft build/ubft-ntr && mv build/ubft.default build/ubft
    [ "$rc" = 0 ] || { vrb_log "FAIL: the advance of authority 4 into epoch $n"; return 1; }
  fi
}
vrs_handoff() { # target epoch, E: rotate, wait for the new output, the roots' switch, the authorities' advance (SIGNING=authority) and VR's Boundary
  local n=$1 E=$2
  vrs_rotate || return 1
  vrb_wait 900 "VR's open output is Published (towards epoch $n)" vrb_published || return 1
  vrb_result=$(vrb_open_output)
  vrb_wait 900 "the roots switched to epoch $n" vrs_roots_at "$n" || return 1
  if [ "${SIGNING:-local}" = authority ]; then vrs_advance_authorities "$n" "$E" || return 1; fi
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
  # 2. queue the schedule A (noop-test-v1, E), a second rule B (postpone-test-v1, E_B=8) and two postponements together, so one 3600 s governance wait serves all:
  #    P1 postpones B to 10 (executed before the handoff into 4: B's cutoff is epoch 6, so it is accepted), P2 postpones A to 9 (executed before the handoff into E:
  #    successor E > E-2, past A's cutoff, so VR rejects it with PastCutoff)
  local ridB Eb=8 Eb2=10 Ea2=9; ridB=$(vrs_rule_id postpone-test-v1)
  vrs_queue noop noop-test-v1 0x1111111111111111111111111111111111111111111111111111111111111111 || return 1
  vrs_queue ruleb postpone-test-v1 0x3333333333333333333333333333333333333333333333333333333333333333 "$Eb" || return 1
  vrs_queue postb postpone-test-v1 0x4444444444444444444444444444444444444444444444444444444444444444 "$Eb2" || return 1
  vrs_queue posta noop-test-v1 0x5555555555555555555555555555555555555555555555555555555555555555 "$Ea2" || return 1
  vrb_wait 240 "shard node 4 exports unicity_upgrade_required{state=pending} for the queued rule" vrs_scrape_check pending "$(vrs_rule_id noop-test-v1)" "$E" || return 1
  g=$d/noop; change=$(vrs_change_id noop)
  vrb_log "waiting out the governance delays (3600 s of certified time) for the queued changes"
  vrs_execute noop 9000 || return 1
  vrs_execute ruleb 600 || return 1
  vrb_log "PASS: the schedules A (change $change, E=$E) and B (E=$Eb) were executed"
  vrs_upgrade_state >"$d/upgrade-after-execute.txt"; cat "$d/upgrade-after-execute.txt"
  # 3. one handoff per epoch up to E
  local rid; rid=$(vrs_rule_id noop-test-v1)
  vrs_check_rules_absent "$d/ureth-rules-before.json" "$rid" || { vrb_log "FAIL: ureth's baseline unicity_rulesV1 is not a valid response without the rule"; return 1; }
  vrb_log "PASS: baseline: ureth observed the head and lists no schedule for the rule"
  for i in $(seq $((known + 1)) "$E"); do
    if [ "$i" = $((known + 2)) ]; then vrs_execute postb 600 || return 1; fi     # P1, accepted: committed in the handoff into 4 (<= B's E-2 = 6)
    if [ "$i" = "$E" ]; then vrs_execute posta 600 || return 1; fi              # P2, past A's cutoff: committed in the handoff into E
    vrs_handoff "$i" "$E" || { vrb_log "FAIL: the handoff into epoch $i"; return 1; }
    vrb_log "PASS: handoff into epoch $i committed"
    vrs_upgrade_state >"$d/upgrade-epoch$i.txt"; vrs_upgrade_json >"$d/upgrade-epoch$i.json"; vrs_rules >"$d/ureth-rules-epoch$i.json"
    vrs_status_json >"$d/status-epoch$i.json"; vrs_gov_list postb >"$d/gov-postb-epoch$i.txt"; vrs_gov_list posta >"$d/gov-posta-epoch$i.txt"
  done
  # the evidence, then the checks: any missing piece fails the step (and so the lane)
  local r
  for r in 1 2 3 4; do grep -hE 'activation\.latched|activation\.active' "test-nodes/root$r/debug.log" | cut -c1-400 >"$d/root$r-activation-events.txt"; done
  grep -hE 'upgrade\.required|upgrade\.refused|UpgradeRequired' test-nodes/evm4/debug.log | cut -c1-500 >"$d/evm4-upgrade-lines.txt"
  # (a) the postponement of B before its cutoff was accepted at the handoff into epoch 4: the old entry is Superseded and the new one Active
  vrs_check_postponed "$d/status-epoch$((known + 2)).json" "$ridB" "$Eb" "$Eb2" || { vrb_log "FAIL: VR does not list B as Superseded(E=$Eb) + Active(E=$Eb2) after the handoff into epoch $((known + 2))"; return 1; }
  vrb_log "PASS: the postponement of rule B (E $Eb -> $Eb2) before its cutoff was accepted: old entry Superseded, new Active"
  # (b) the postponement of A after its cutoff (successor $E > $E-2) was refused: the change is Rejected, reason 6 (PastCutoff), and A is unchanged
  vrs_check_change_state "$d/gov-posta-epoch$E.txt" Rejected 6 || { vrb_log "FAIL: the postponement of A past its cutoff is not Rejected (reason 6, PastCutoff): $(grep -E 'state' "$d/gov-posta-epoch$E.txt" | head -2)"; return 1; }
  vrb_log "PASS: the postponement of rule A after its cutoff was refused: change Rejected (PastCutoff)"
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
