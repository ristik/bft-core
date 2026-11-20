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
# the shard refusal
echo "time=x level=ERROR msg=refusing event=upgrade.refused epoch=5 error=\"UpgradeRequired: this binary does not support rule ${rid#0x}, active from root epoch $E (release digest 11)\"" >"$d/ref.txt"
ok  vrs_check_refusal "$d/ref.txt" "$rid" $E
bad vrs_check_refusal "$d/ref.txt" "$rid" 6
bad vrs_check_refusal "$d/ref.txt" 0xcd$(printf 'cd%.0s' $(seq 31)) $E
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
echo "Latched rule x" >"$d/up.txt"; ok vrs_check_upgrade_state "$d/up.txt" Latched; bad vrs_check_upgrade_state "$d/up.txt" Queued
[ "$fails" = 0 ] && echo "vr-schedule checks: all pass" || { echo "vr-schedule checks: $fails failing"; exit 1; }
