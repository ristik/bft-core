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
line() { echo "time=x level=INFO msg=\"$2\" event=$1 rule=${rid#0x} epoch=$3 digest=1111"; }
for i in 1 2 3 4; do { line activation.latched "latched" $E; line activation.active "active" $E; } >"$d/root$i-activation-events.txt"; done
ok  vrs_check_all_roots "$d" "$rid" $E 1 2 3 4
bad vrs_check_all_roots "$d" "$rid" 6 1 2 3 4                       # another epoch
bad vrs_check_all_roots "$d" 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd 5 1 2 3 4   # another rule
bad vrs_check_all_roots "$d" "$rid" $E                              # no roots
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
bad vrs_check_refusal "$d/ref.txt" 0xcd$(printf 'cd%.0s' $(seq 31)) $E
sed 's/event=upgrade.refused/event=other/' "$d/ref.txt" >"$d/noevent.txt"; bad vrs_check_refusal "$d/noevent.txt" "$rid" $E
bad vrs_check_refusal "$d/none.txt" "$rid" $E
# the pending warning
echo "level=WARN msg=\"UPGRADE REQUIRED\" event=upgrade.required state=pending rule=${rid#0x} activationEpoch=5" >"$d/warn.txt"
ok  vrs_check_warning "$d/warn.txt" "$rid"
bad vrs_check_warning "$d/ref.txt" "$rid"
sed 's/state=pending/state=effective/' "$d/warn.txt" >"$d/warn2.txt"; bad vrs_check_warning "$d/warn2.txt" "$rid"
# ureth's unicity_rulesV1
r() { echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":$1}"; }
good='{"genesisSpec":"Cancun","known":[{"name":"noop-test-v1","id":"'$rid'"}],"observed":true,"scheduled":[{"ruleId":"'$rid'","releaseDigest":"0x11","rootEpoch":5,"latched":true,"known":true}],"lacking":[]}'
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
[ "$fails" = 0 ] && echo "vr-schedule checks: all pass" || { echo "vr-schedule checks: $fails failing"; exit 1; }
