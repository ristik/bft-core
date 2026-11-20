#!/usr/bin/env bash
# Proves the live-acceptance checks of vr-schedule-steps.sh pass on the right evidence and fail on wrong evidence, on canned data.
#
# Every must-fail case is a DIFFERENTIAL test: a good input for the predicate's family is built by a literal builder; the bad input is that good input
# with ONE explicit edit (a sed on the line, or a different builder argument); the harness then asserts that (1) the bad input DIFFERS from the good one,
# (2) the predicate PASSES on the good one, and (3) it FAILS on the bad one, for the python predicates with a failure message matching the intended
# reason. So a case cannot pass vacuously (an edit that changed nothing, or an input that was bad for some other reason).
set -u
cd "$(dirname "$0")/.." || exit 2
source scripts/vr-schedule-steps.sh
fails=0 cases=0
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
rid=0xabababababababababababababababababababababababababababababababab
other=0xcd$(printf 'cd%.0s' $(seq 31))
E=5
fail() { echo "FAIL: $*"; fails=$((fails+1)); }

# mf <label> <predicate> <good> <bad> [reason-regex]: predicate <file> must pass on good, fail on bad (and say why, when a reason is given)
mf() {
  local label=$1 pred=$2 good=$3 bad=$4 reason=${5:-} err
  cases=$((cases+1))
  if [ -d "$good" ]; then diff -r "$good" "$bad" >/dev/null 2>&1 && { fail "$label: the bad input equals the good one (vacuous case)"; return; }
  else cmp -s "$good" "$bad" && { fail "$label: the bad input equals the good one (vacuous case)"; return; }; fi
  "$pred" "$good" 2>/dev/null || { fail "$label: the good input does not pass"; return; }
  err=$("$pred" "$bad" 2>&1 >/dev/null) && { fail "$label: the bad input passes"; return; }
  [ -z "$reason" ] || echo "$err" | grep -qE "$reason" || fail "$label: failed for another reason: $err"
  return 0
}
ok() { cases=$((cases+1)); "$@" 2>/dev/null || fail "expected pass: $*"; }   # a good input that must pass

# ---- builders: each writes the GOOD evidence of its family ------------------------------------------------------------------------------------------
act() { echo "time=x level=INFO msg=\"$2\" event=$1 rule=${rid#0x} epoch=$E digest=1111 currentEpoch=$3"; }
mkroots() { local dir=$1 i; rm -rf "$dir"; mkdir -p "$dir"; for i in 1 2 3 4; do { act activation.latched latched $E; act activation.active active $E; } >"$dir/root$i-activation-events.txt"; done; }
refusal() { echo "time=x level=ERROR msg=\"refusing\" event=upgrade.refused epoch=5 error=\"UpgradeRequired: this binary does not support rule ${rid#0x}, active from root epoch 5 (release digest 11)\""; }
warning() { echo "level=WARN msg=\"UPGRADE REQUIRED\" event=upgrade.required state=pending rule=${rid#0x} release=11 activationEpoch=5 currentEpoch=2 notBeforeUcTime=1"; }
metric() { { echo "# HELP ab_unicity_upgrade_required 1 for each rule"; echo "# TYPE ab_unicity_upgrade_required gauge"; echo "ab_unicity_upgrade_required{epoch=\"5\",rule=\"${rid#0x}\",state=\"pending\",otel_scope_name=\"x\"} 1"; }; }
rpc() { echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":$1}"; }
row='{"ruleId":"'$rid'","releaseDigest":"'$rid'","rootEpoch":5,"latched":true,"known":true}'
rules() { rpc '{"genesisSpec":"Cancun","known":[{"name":"noop-test-v1","id":"'$rid'"}],"observed":true,"scheduled":['"$1"'],"lacking":[]}'; }
status() { echo "{\"activeEpoch\": $1, \"follower\": false}"; }
upgrade() { printf '{"schedule":[%s]}' "$1"; }
urow() { echo '{"ruleId":"'$1'","rootEpoch":'$2',"state":"'$3'"}'; }

# ---- the roots' activation events: every root, rule, epoch E, latched AND active with currentEpoch >= E ------------------------------------------------
mkroots "$d/rg"; roots_pred() { vrs_check_all_roots "$1" "$rid" $E 1 2 3 4; }
edit() { mkroots "$d/rb"; "$@"; }   # a bad copy: a fresh good set, then ONE edit
edit sed -i.bak 's/epoch=5 /epoch=6 /' "$d/rb/root2-activation-events.txt";                    mf "roots: another activation epoch on one root" roots_pred "$d/rg" "$d/rb"
edit sed -i.bak "s/rule=${rid#0x}/rule=${other#0x}/" "$d/rb/root4-activation-events.txt";      mf "roots: another rule on one root" roots_pred "$d/rg" "$d/rb"
edit sed -i.bak 's/currentEpoch=5/currentEpoch=4/' "$d/rb/root3-activation-events.txt";        mf "roots: active record with a CURRENT epoch below E" roots_pred "$d/rg" "$d/rb"
edit sed -i.bak 's/ currentEpoch=5//' "$d/rb/root1-activation-events.txt";                     mf "roots: no currentEpoch at all" roots_pred "$d/rg" "$d/rb"
edit sed -i.bak '/activation.latched/d' "$d/rb/root3-activation-events.txt";                   mf "roots: latched missing on one root" roots_pred "$d/rg" "$d/rb"
edit sed -i.bak '/activation.active/d' "$d/rb/root3-activation-events.txt";                    mf "roots: active missing on one root" roots_pred "$d/rg" "$d/rb"
edit sh -c ": >'$d/rb/root3-activation-events.txt'";                                           mf "roots: one root silent" roots_pred "$d/rg" "$d/rb"
edit rm "$d/rb/root4-activation-events.txt";                                                   mf "roots: one root with no file" roots_pred "$d/rg" "$d/rb"
mkroots "$d/rb6"; for i in 1 2 3 4; do sed -i.bak 's/currentEpoch=5/currentEpoch=6/' "$d/rb6/root$i-activation-events.txt"; done; ok vrs_check_all_roots "$d/rb6" "$rid" $E 1 2 3 4   # current epoch 6 >= E is fine
cases=$((cases+1)); vrs_check_all_roots "$d/rg" "$rid" $E 2>/dev/null && fail "no roots listed passes"
cases=$((cases+1)); vrs_check_all_roots "$d/rg" "$rid" 6 1 2 3 4 2>/dev/null && fail "the right evidence for another expected epoch passes"
cases=$((cases+1)); vrs_check_all_roots "$d/rg" "$other" $E 1 2 3 4 2>/dev/null && fail "the right evidence for another expected rule passes"

# ---- the shard refusal: ONE record, event=upgrade.refused, the attempted epoch key = E, UpgradeRequired naming the rule ----------------------------------
refusal >"$d/rf.txt"; ref_pred() { vrs_check_refusal "$1" "$rid" $E; }
refusal | sed 's/ epoch=5 / epoch=6 /' >"$d/rb.txt";                          mf "refusal: attempted epoch 6 (rule active from 5)" ref_pred "$d/rf.txt" "$d/rb.txt"
refusal | sed "s/rule ${rid#0x}/rule ${other#0x}/" >"$d/rb.txt";               mf "refusal: another rule" ref_pred "$d/rf.txt" "$d/rb.txt"
refusal | sed 's/event=upgrade.refused/event=other/' >"$d/rb.txt";             mf "refusal: not the structured event" ref_pred "$d/rf.txt" "$d/rb.txt"
refusal | sed 's/UpgradeRequired/SomethingElse/' >"$d/rb.txt";                 mf "refusal: no UpgradeRequired" ref_pred "$d/rf.txt" "$d/rb.txt"
{ refusal | sed 's/ epoch=5 / epoch=6 /'; echo "level=INFO msg=other epoch=5"; } >"$d/rb.txt"; mf "refusal: epoch E on another record" ref_pred "$d/rf.txt" "$d/rb.txt"
{ refusal | sed 's/ epoch=5 / epoch=6 /'; refusal | sed "s/rule ${rid#0x}/rule ${other#0x}/"; } >"$d/rb.txt"; mf "refusal: rule and epoch spread over two records" ref_pred "$d/rf.txt" "$d/rb.txt"
refusal | sed 's/root epoch 5/root epoch 9/' >"$d/rg9.txt"; ok ref_pred "$d/rg9.txt"                                 # the attempted epoch decides, not the text's scheduled epoch
cases=$((cases+1)); vrs_check_refusal "$d/none.txt" "$rid" $E 2>/dev/null && fail "a missing refusal log passes"

# ---- the pending warning: ONE record, rule, activationEpoch=E, currentEpoch < E ---------------------------------------------------------------------------
warning >"$d/wg.txt"; warn_pred() { vrs_check_warning "$1" "$rid" $E; }
warning | sed 's/currentEpoch=2/currentEpoch=5/' >"$d/wb.txt";                 mf "warning: currentEpoch = E (not ahead)" warn_pred "$d/wg.txt" "$d/wb.txt"
warning | sed 's/currentEpoch=2/currentEpoch=7/' >"$d/wb.txt";                 mf "warning: currentEpoch > E" warn_pred "$d/wg.txt" "$d/wb.txt"
warning | sed 's/state=pending/state=effective/' >"$d/wb.txt";                 mf "warning: wrong state" warn_pred "$d/wg.txt" "$d/wb.txt"
warning | sed 's/activationEpoch=5/activationEpoch=6/' >"$d/wb.txt";           mf "warning: another activation epoch" warn_pred "$d/wg.txt" "$d/wb.txt"
warning | sed "s/rule=${rid#0x}/rule=${other#0x}/" >"$d/wb.txt";              mf "warning: another rule" warn_pred "$d/wg.txt" "$d/wb.txt"
warning | sed 's/ currentEpoch=2//' >"$d/wb.txt";                              mf "warning: no currentEpoch" warn_pred "$d/wg.txt" "$d/wb.txt"
warning | sed 's/event=upgrade.required/event=other/' >"$d/wb.txt";            mf "warning: not the structured event" warn_pred "$d/wg.txt" "$d/wb.txt"
{ warning | sed 's/activationEpoch=5/activationEpoch=6/'; warning | sed "s/rule=${rid#0x}/rule=${other#0x}/"; warning | sed 's/state=pending/state=effective/'; } >"$d/wb.txt"; mf "warning: the pieces on three different records" warn_pred "$d/wg.txt" "$d/wb.txt"
echo 'level=WARN msg="upgrade required"' >"$d/wb.txt";                         mf "warning: a bare warning" warn_pred "$d/wg.txt" "$d/wb.txt"

# ---- the metric: an exact-name SAMPLE line with labels rule/epoch/state and the value 1 as the last field --------------------------------------------------
metric >"$d/mg.txt"; met_pred() { vrs_check_metric "$1" "$rid" $E pending; }
metric | sed '/^ab_/d' >"$d/mb.txt";                                           mf "metric: HELP/TYPE only" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/} 1$/} 0/' >"$d/mb.txt";                                       mf "metric: value 0" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/state=\"pending\"/state=\"effective\"/' >"$d/mb.txt";          mf "metric: wrong state" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/epoch=\"5\"/epoch=\"6\"/' >"$d/mb.txt";                        mf "metric: wrong epoch" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed "s/rule=\"${rid#0x}\"/rule=\"${other#0x}\"/" >"$d/mb.txt";        mf "metric: another rule" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/^ab_unicity/other_unicity/' >"$d/mb.txt";                      mf "metric: another metric name (other_unicity_upgrade_required)" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/^ab_unicity/x_ab_unicity/' >"$d/mb.txt";                       mf "metric: prefixed name" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/unicity_upgrade_required{/unicity_upgrade_required_total{/' >"$d/mb.txt"; mf "metric: another metric family (_total)" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/} 1$/} 1 1795000000/' >"$d/mb.txt";                            mf "metric: value is not the last field" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/rule=/rulez=/' >"$d/mb.txt";                                   mf "metric: label key rule missing" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/,state=/,statez=/' >"$d/mb.txt";                               mf "metric: label key state missing" met_pred "$d/mg.txt" "$d/mb.txt"
{ metric | sed 's/epoch=\"5\"/epoch=\"6\"/'; metric | sed "s/rule=\"${rid#0x}\"/rule=\"${other#0x}\"/"; metric | sed 's/state=\"pending\"/state=\"effective\"/'; } | grep -v '^#' >"$d/mb.txt"; mf "metric: labels spread over three samples" met_pred "$d/mg.txt" "$d/mb.txt"
metric | sed 's/^ab_//' >"$d/mg2.txt"; ok met_pred "$d/mg2.txt"                                                          # the unprefixed exact name is accepted

# ---- ureth's unicity_rulesV1: the latch assertion (vrs_check_rules) and the baseline (vrs_check_rules_absent) both start from the strict validation ----------
rules "$row" >"$d/ug.json"; lat_pred() { vrs_check_rules "$1" "$rid" $E true true; }
bad_row() { rules "$(echo "$row" | sed "$1")" >"$d/ub.json"; }
bad_row 's/"rootEpoch":5/"rootEpoch":5.0/';       mf "rules: float epoch 5.0" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row 's/"rootEpoch":5/"rootEpoch":-5/';        mf "rules: negative epoch" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row 's/"rootEpoch":5/"rootEpoch":18446744073709551616/'; mf "rules: epoch 2^64" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row 's/"rootEpoch":5/"rootEpoch":"5"/';       mf "rules: string epoch" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row 's/"latched":true/"latched":1/';          mf "rules: integer latched" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row 's/"known":true/"known":1/';              mf "rules: integer known" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row 's/"releaseDigest":"[^"]*",//';           mf "rules: no release digest" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row 's/"releaseDigest":"0x[0-9a-f]*"/"releaseDigest":"0x11"/'; mf "rules: short release digest" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row "s/\"ruleId\":\"$rid\"/\"ruleId\":\"0x11\"/"; mf "rules: short rule id" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
rules "$row,{}" >"$d/ub.json";                    mf "rules: a valid row plus an empty entry" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
bad_row 's/"latched":true/"latched":false/';      mf "rules: the rule is not latched" lat_pred "$d/ug.json" "$d/ub.json" 'no scheduled entry'
bad_row 's/"rootEpoch":5/"rootEpoch":6/';         mf "rules: another epoch" lat_pred "$d/ug.json" "$d/ub.json" 'no scheduled entry'
bad_row 's/"known":true/"known":false/';         mf "rules: not known" lat_pred "$d/ug.json" "$d/ub.json" 'no scheduled entry'
bad_row "s/\"ruleId\":\"$rid\"/\"ruleId\":\"$other\"/"; mf "rules: another rule scheduled" lat_pred "$d/ug.json" "$d/ub.json" 'no scheduled entry'
sed 's/"observed":true/"observed":false/' "$d/ug.json" >"$d/ub.json";            mf "rules: observed=false" lat_pred "$d/ug.json" "$d/ub.json" 'observed'
sed 's/"result"/"resultz"/' "$d/ug.json" >"$d/ub.json";                         mf "rules: no result" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
echo '{"error":{"code":-32601,"message":"method not found"}}' >"$d/ub.json";     mf "rules: an error response" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'
echo garbage >"$d/ub.json";                                                      mf "rules: garbage" lat_pred "$d/ug.json" "$d/ub.json" 'not a valid'

# the baseline: absence is a VALID response without the rule
oentry='{"ruleId":"'$other'","releaseDigest":"'$other'","rootEpoch":9,"latched":false,"known":false}'
rules "$oentry" >"$d/bg.json"; abs_pred() { vrs_check_rules_absent "$1" "$rid"; }
rules "$oentry,$row" >"$d/bb.json";               mf "baseline: the rule IS scheduled" abs_pred "$d/bg.json" "$d/bb.json" 'already scheduled'
rules "$oentry,{}" >"$d/bb.json";                 mf "baseline: scheduled:[.., {}]" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
rules "{}" >"$d/bb.json";                         mf "baseline: scheduled:[{}]" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
rules "null" >"$d/bb.json";                       mf "baseline: scheduled:[null]" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
rules "$(echo "$oentry" | sed 's/"rootEpoch":9/"rootEpoch":-1/')" >"$d/bb.json";   mf "baseline: unrelated entry with rootEpoch -1" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
rules "$(echo "$oentry" | sed 's/"rootEpoch":9/"rootEpoch":18446744073709551616/')" >"$d/bb.json"; mf "baseline: unrelated entry with rootEpoch 2^64" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
rules "$(echo "$oentry" | sed 's/"rootEpoch":9/"rootEpoch":9.0/')" >"$d/bb.json"; mf "baseline: unrelated entry with float epoch" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
rules "$(echo "$oentry" | sed 's/"latched":false/"latched":0/')" >"$d/bb.json"; mf "baseline: unrelated entry with integer flag" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
rules "$(echo "$oentry" | sed 's/"releaseDigest":"[^"]*",//')" >"$d/bb.json"; mf "baseline: unrelated entry without a digest" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
sed 's/"scheduled":\[[^]]*\]/"scheduled":"none"/' "$d/bg.json" >"$d/bb.json";   mf "baseline: scheduled is not a list" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
sed 's/"lacking":\[\]/"lacking":[{}]/' "$d/bg.json" >"$d/bb.json";               mf "baseline: lacking:[{}]" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
sed 's/"known":\[{[^}]*}\]/"known":[{}]/' "$d/bg.json" >"$d/bb.json";            mf "baseline: known:[{}]" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
sed 's/"genesisSpec":"Cancun",//' "$d/bg.json" >"$d/bb.json";                    mf "baseline: no genesisSpec" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
sed 's/"observed":true/"observed":false/' "$d/bg.json" >"$d/bb.json";            mf "baseline: observed=false" abs_pred "$d/bg.json" "$d/bb.json" 'observed'
sed 's/"observed":true/"observed":1/' "$d/bg.json" >"$d/bb.json";                mf "baseline: observed is not a boolean" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
echo '{"error":{"code":-32601}}' >"$d/bb.json";                                  mf "baseline: an error response" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
: >"$d/bb.json";                                                                 mf "baseline: an empty file" abs_pred "$d/bg.json" "$d/bb.json" 'not a valid'
rules "" >"$d/bg0.json"; ok abs_pred "$d/bg0.json"                                                                  # a valid response with no entry at all is an absence

# ---- the roots' status: activeEpoch is a JSON integer EQUAL to E ---------------------------------------------------------------------------------------
status 5 >"$d/sg.json"; st_pred() { vrs_check_status_epoch "$1" $E; }
status 50 >"$d/sb.json";   mf "status: activeEpoch 50 for E=5 (astra r8)" st_pred "$d/sg.json" "$d/sb.json" 'not 5'
status 4 >"$d/sb.json";    mf "status: 4" st_pred "$d/sg.json" "$d/sb.json" 'not 5'
status 6 >"$d/sb.json";    mf "status: 6 (not >=)" st_pred "$d/sg.json" "$d/sb.json" 'not 5'
status '"5"' >"$d/sb.json"; mf "status: the string \"5\"" st_pred "$d/sg.json" "$d/sb.json" 'not 5'
status 5.0 >"$d/sb.json";  mf "status: 5.0" st_pred "$d/sg.json" "$d/sb.json" 'not 5'
status null >"$d/sb.json"; mf "status: null" st_pred "$d/sg.json" "$d/sb.json" 'not 5'
echo '{"epoch":5}' >"$d/sb.json"; mf "status: no activeEpoch key" st_pred "$d/sg.json" "$d/sb.json" 'no activeEpoch'
echo garbage >"$d/sb.json"; mf "status: garbage" st_pred "$d/sg.json" "$d/sb.json" 'no activeEpoch'

# ---- VR's schedule row (validator upgrade --json): rule, epoch and the state Latched in ONE row -------------------------------------------------------------
upgrade "$(urow "$rid" 5 Latched)" >"$d/lg.json"; lr_pred() { vrs_check_latched_row "$1" "$rid" $E; }
upgrade "$(urow "$other" 5 Latched),$(urow "$rid" 5 Active)" >"$d/lb.json";       mf "latched row: another rule Latched, the target not (astra)" lr_pred "$d/lg.json" "$d/lb.json" 'no Latched row'
upgrade "$(urow "$rid" 6 Latched)" >"$d/lb.json";                                 mf "latched row: another epoch" lr_pred "$d/lg.json" "$d/lb.json" 'no Latched row'
upgrade "$(urow "$rid" 5 Queued)" >"$d/lb.json";                                  mf "latched row: Queued" lr_pred "$d/lg.json" "$d/lb.json" 'no Latched row'
upgrade "" >"$d/lb.json";                                                         mf "latched row: empty schedule" lr_pred "$d/lg.json" "$d/lb.json" 'no Latched row'
echo garbage >"$d/lb.json";                                                       mf "latched row: garbage" lr_pred "$d/lg.json" "$d/lb.json" 'no schedule'
upgrade "$(urow "$rid" 5 Latched | sed 's/"rootEpoch":5/"rootEpoch":"5"/')" >"$d/lb.json"; mf "latched row: string epoch" lr_pred "$d/lg.json" "$d/lb.json" 'no Latched row'

if [ "$fails" = 0 ]; then echo "vr-schedule checks: all $cases cases pass"; else echo "vr-schedule checks: $fails failing of $cases"; exit 1; fi
