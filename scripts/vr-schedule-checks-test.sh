#!/usr/bin/env bash
# Proves the live-acceptance checks of vr-schedule-steps.sh fail when the evidence is missing or wrong (and pass on the right evidence), on canned data.
set -u
cd "$(dirname "$0")/.." || exit 2
source scripts/vr-schedule-steps.sh
fails=0
ok()   { if "$@"; then :; else echo "FAIL (expected pass): $*"; fails=$((fails+1)); fi; }
bad()  { if "$@" 2>/dev/null; then echo "FAIL (expected failure): $*"; fails=$((fails+1)); fi; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
rid=0xabababababababababababababababababababababababababababababababab
E=5
line() { echo "time=x level=INFO msg=\"$2\" event=$1 rule=${rid#0x} epoch=$3 digest=1111 currentEpoch=${4:-$3}"; }
for i in 1 2 3 4; do { line activation.latched "latched" $E; line activation.active "active" $E; } >"$d/root$i-activation-events.txt"; done
ok  vrs_check_all_roots "$d" "$rid" $E 1 2 3 4
bad vrs_check_all_roots "$d" "$rid" 6 1 2 3 4                       # another epoch
bad vrs_check_all_roots "$d" 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd 5 1 2 3 4   # another rule
bad vrs_check_all_roots "$d" "$rid" $E                              # no roots
{ line activation.latched l $E; line activation.active a $E 4; } >"$d/root1-activation-events.txt"; bad vrs_check_all_roots "$d" "$rid" $E 1   # active record whose CURRENT epoch (4) is below E
{ line activation.latched l $E; line activation.active a $E 6; } >"$d/root1-activation-events.txt"; ok  vrs_check_all_roots "$d" "$rid" $E 1   # current epoch 6 >= E
{ line activation.latched l $E; echo "event=activation.active rule=${rid#0x} epoch=$E"; } >"$d/root1-activation-events.txt"; bad vrs_check_all_roots "$d" "$rid" $E 1   # no currentEpoch at all
for i in 1 2 3 4; do { line activation.latched "latched" $E; line activation.active "active" $E; } >"$d/root$i-activation-events.txt"; done
: >"$d/root3-activation-events.txt";                  bad vrs_check_all_roots "$d" "$rid" $E 1 2 3 4   # one root silent
line activation.latched l $E >"$d/root3-activation-events.txt"; bad vrs_check_all_roots "$d" "$rid" $E 1 2 3 4   # latched but never active
bad vrs_check_all_roots "$d" "$rid" $E 1 2 3 4 5                    # a root with no file at all
# the shard refusal: ONE record carries event=upgrade.refused, epoch=E and an UpgradeRequired naming the rule and E
ref() { echo "time=x level=ERROR msg=\"refusing\" event=upgrade.refused epoch=$1 error=\"UpgradeRequired: this binary does not support rule ${2#0x}, active from root epoch $3 (release digest 11)\""; }
ref 5 "$rid" 5 >"$d/ref.txt"
ok  vrs_check_refusal "$d/ref.txt" "$rid" $E
ref 6 "$rid" 5 >"$d/ref6.txt";       bad vrs_check_refusal "$d/ref6.txt" "$rid" $E      # astra: a refusal at epoch 6 for a rule active from 5
{ ref 6 "$rid" 5; ref 5 0xcd$(printf 'cd%.0s' $(seq 31)) 5; } >"$d/split.txt"; bad vrs_check_refusal "$d/split.txt" "$rid" $E   # the right rule on one line, epoch E on another
{ ref 6 "$rid" 5; echo "level=INFO msg=other epoch=5"; } >"$d/split2.txt";      bad vrs_check_refusal "$d/split2.txt" "$rid" $E
bad vrs_check_refusal "$d/ref.txt" "$rid" 6
ref 5 "$rid" 9 >"$d/ref59.txt"; ok vrs_check_refusal "$d/ref59.txt" "$rid" $E      # attempted epoch 5 decides, not the text's scheduled epoch
bad vrs_check_refusal "$d/ref.txt" 0xcd$(printf 'cd%.0s' $(seq 31)) $E
sed 's/event=upgrade.refused/event=other/' "$d/ref.txt" >"$d/noevent.txt"; bad vrs_check_refusal "$d/noevent.txt" "$rid" $E
bad vrs_check_refusal "$d/none.txt" "$rid" $E
# the pending warning: ONE record with the rule, activationEpoch=E and currentEpoch<E
warn() { echo "level=WARN msg=\"UPGRADE REQUIRED\" event=upgrade.required state=$1 rule=${2#0x} release=11 activationEpoch=$3 currentEpoch=$4 notBeforeUcTime=1"; }
warn pending "$rid" 5 2 >"$d/warn.txt";                        ok  vrs_check_warning "$d/warn.txt" "$rid" $E
warn pending "$rid" 5 5 >"$d/w.txt";                           bad vrs_check_warning "$d/w.txt" "$rid" $E      # currentEpoch not below E: not ahead
warn pending "$rid" 5 7 >"$d/w.txt";                           bad vrs_check_warning "$d/w.txt" "$rid" $E
warn effective "$rid" 5 2 >"$d/w.txt";                         bad vrs_check_warning "$d/w.txt" "$rid" $E      # wrong state
warn pending "$rid" 6 2 >"$d/w.txt";                           bad vrs_check_warning "$d/w.txt" "$rid" $E      # another activation epoch
warn pending 0xcd$(printf 'cd%.0s' $(seq 31)) 5 2 >"$d/w.txt"; bad vrs_check_warning "$d/w.txt" "$rid" $E      # another rule
{ warn pending "$rid" 6 2; warn pending 0xcd$(printf 'cd%.0s' $(seq 31)) 5 2; warn effective "$rid" 5 2; } >"$d/w.txt"; bad vrs_check_warning "$d/w.txt" "$rid" $E   # the pieces on different records
echo "event=upgrade.required state=pending rule=${rid#0x} activationEpoch=5" >"$d/w.txt";   bad vrs_check_warning "$d/w.txt" "$rid" $E      # no currentEpoch
bad vrs_check_warning "$d/ref.txt" "$rid" $E
bad vrs_check_warning "$d/none.txt" "$rid" $E
# the metric: a SAMPLE line, value 1, labels rule/epoch/state (not HELP/TYPE)
other=0xcd$(printf 'cd%.0s' $(seq 31))
m() { echo "ab_unicity_upgrade_required{epoch=\"$2\",rule=\"${1#0x}\",state=\"$3\",otel_scope_name=\"x\"} $4"; }
{ echo "# HELP ab_unicity_upgrade_required 1 for each rule"; echo "# TYPE ab_unicity_upgrade_required gauge"; m "$rid" 5 pending 1; } >"$d/m.txt"; ok  vrs_check_metric "$d/m.txt" "$rid" $E pending
{ echo "# HELP ab_unicity_upgrade_required rule=\"${rid#0x}\" epoch=\"5\" state=\"pending\" 1"; echo "# TYPE ab_unicity_upgrade_required gauge"; } >"$d/m.txt";  bad vrs_check_metric "$d/m.txt" "$rid" $E pending   # HELP/TYPE only
m "$rid" 5 pending 0 >"$d/m.txt";             bad vrs_check_metric "$d/m.txt" "$rid" $E pending   # value 0
m "$rid" 5 effective 1 >"$d/m.txt";           bad vrs_check_metric "$d/m.txt" "$rid" $E pending   # wrong state
m "$rid" 6 pending 1 >"$d/m.txt";             bad vrs_check_metric "$d/m.txt" "$rid" $E pending   # wrong epoch
m "$other" 5 pending 1 >"$d/m.txt";           bad vrs_check_metric "$d/m.txt" "$rid" $E pending   # another rule
{ m "$rid" 6 pending 1; m "$other" 5 pending 1; m "$rid" 5 effective 1; } >"$d/m.txt"; bad vrs_check_metric "$d/m.txt" "$rid" $E pending   # labels spread over samples
: >"$d/m.txt";                                bad vrs_check_metric "$d/m.txt" "$rid" $E pending
bad vrs_check_metric "$d/missing.txt" "$rid" $E pending
# ureth's unicity_rulesV1
r() { echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":$1}"; }
good='{"genesisSpec":"Cancun","known":[{"name":"noop-test-v1","id":"'$rid'"}],"observed":true,"scheduled":[{"ruleId":"'$rid'","releaseDigest":"'$rid'","rootEpoch":5,"latched":true,"known":true}],"lacking":[]}'
r "$good" >"$d/u.json";                                              ok  vrs_check_rules "$d/u.json" "$rid" $E true true
r "${good/\"latched\":true/\"latched\":false}" >"$d/u.json";         bad vrs_check_rules "$d/u.json" "$rid" $E true true
r "${good/\"rootEpoch\":5/\"rootEpoch\":6}" >"$d/u.json";            bad vrs_check_rules "$d/u.json" "$rid" $E true true
r "${good/\"observed\":true/\"observed\":false}" >"$d/u.json";       bad vrs_check_rules "$d/u.json" "$rid" $E true true
r "${good/\"scheduled\":[*]/\"scheduled\":[]}" >"$d/u.json";         bad vrs_check_rules "$d/u.json" 0xcd$(printf 'cd%.0s' $(seq 31)) $E true true
echo '{"error":{"code":-32601}}' >"$d/u.json";                       bad vrs_check_rules "$d/u.json" "$rid" $E true true
echo 'not json' >"$d/u.json";                                       bad vrs_check_rules "$d/u.json" "$rid" $E true true
# the VR schedule row: rule, epoch and state in ONE row
other=0xcd$(printf 'cd%.0s' $(seq 31))
row() { echo "{\"ruleId\":\"$1\",\"rootEpoch\":$2,\"state\":\"$3\"}"; }
printf '{"schedule":[%s]}' "$(row $rid 5 Latched)" >"$d/up.json";                          ok  vrs_check_latched_row "$d/up.json" "$rid" $E
printf '{"schedule":[%s,%s]}' "$(row $other 5 Latched)" "$(row $rid 5 Active)" >"$d/up.json"; bad vrs_check_latched_row "$d/up.json" "$rid" $E   # astra: another rule Latched, the target not
printf '{"schedule":[%s]}' "$(row $rid 6 Latched)" >"$d/up.json";                          bad vrs_check_latched_row "$d/up.json" "$rid" $E
printf '{"schedule":[%s]}' "$(row $rid 5 Queued)" >"$d/up.json";                           bad vrs_check_latched_row "$d/up.json" "$rid" $E
printf '{"schedule":[]}' >"$d/up.json";                                                    bad vrs_check_latched_row "$d/up.json" "$rid" $E
echo 'garbage' >"$d/up.json";                                                              bad vrs_check_latched_row "$d/up.json" "$rid" $E
# the baseline: a valid response without the entry passes; anything else fails
base='{"genesisSpec":"Cancun","known":[{"name":"noop-test-v1","id":"'$rid'"}],"observed":true,"scheduled":[],"lacking":[]}'
r "$base" >"$d/b.json";                                         ok  vrs_check_rules_absent "$d/b.json" "$rid"
r "${base/\"observed\":true/\"observed\":false}" >"$d/b.json";   bad vrs_check_rules_absent "$d/b.json" "$rid"
echo '{"error":{"code":-32601,"message":"method not found"}}' >"$d/b.json"; bad vrs_check_rules_absent "$d/b.json" "$rid"
echo 'garbage' >"$d/b.json";                                      bad vrs_check_rules_absent "$d/b.json" "$rid"
: >"$d/b.json";                                                 bad vrs_check_rules_absent "$d/b.json" "$rid"
bad vrs_check_rules_absent "$d/missing.json" "$rid"
echo '{"result":{"observed":true}}' >"$d/b.json";                bad vrs_check_rules_absent "$d/b.json" "$rid"   # lists missing: malformed
r "$good" >"$d/b.json";                                         bad vrs_check_rules_absent "$d/b.json" "$rid"   # the rule IS scheduled
r "${base/\"scheduled\":[]/\"scheduled\":[{}]}" >"$d/b.json";    bad vrs_check_rules_absent "$d/b.json" "$rid"   # astra: scheduled:[{}]
r "${base/\"scheduled\":[]/\"scheduled\":[{\"ruleId\":\"0x11\"}]}" >"$d/b.json"; bad vrs_check_rules_absent "$d/b.json" "$rid"   # truncated id, missing fields
r "${base/\"scheduled\":[]/\"scheduled\":[null]}" >"$d/b.json";  bad vrs_check_rules_absent "$d/b.json" "$rid"
r "${base/\"scheduled\":[]/\"scheduled\":\"none\"}" >"$d/b.json"; bad vrs_check_rules_absent "$d/b.json" "$rid"
r "${base/\"lacking\":[]/\"lacking\":[{}]}" >"$d/b.json";        bad vrs_check_rules_absent "$d/b.json" "$rid"
r "${base/\"known\":[{\"name\":\"noop-test-v1\",\"id\":\"$rid\"}]/\"known\":[{}]}" >"$d/b.json"; bad vrs_check_rules_absent "$d/b.json" "$rid"
r "${base/\"genesisSpec\":\"Cancun\",/}" >"$d/b.json";           bad vrs_check_rules_absent "$d/b.json" "$rid"   # genesisSpec missing
okentry='{"ruleId":"'$other'","releaseDigest":"'$other'","rootEpoch":9,"latched":false,"known":false}'
r "${base/\"scheduled\":[]/\"scheduled\":[$okentry]}" >"$d/b.json"; ok vrs_check_rules_absent "$d/b.json" "$rid"   # a well-formed entry for ANOTHER rule is still an absence
[ "$fails" = 0 ] && echo "vr-schedule checks: all pass" || { echo "vr-schedule checks: $fails failing"; exit 1; }
