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

# ---- the activation source port of an authority: the slot's own reth eth port, never slot 0's by accident ----------------------------------------------------
cases=$((cases+1)); [ "$(unset rethEthBase; LANE_SLOT=2 bash -c 'source scripts/lib/lane-slot.sh; lane_reth_eth_port 1')" = 20545 ] || fail "slot 2 validator 1 is not on 20545"
cases=$((cases+1)); [ "$(unset rethEthBase; LANE_SLOT=2 bash -c 'source scripts/lib/lane-slot.sh; lane_reth_eth_port 3')" = 20547 ] || fail "slot 2 validator 3 is not on 20547"
cases=$((cases+1)); [ "$(unset rethEthBase; LANE_SLOT=0 bash -c 'source scripts/lib/lane-slot.sh; lane_reth_eth_port 1')" = 18545 ] || fail "slot 0 validator 1 is not on 18545"
cases=$((cases+1)); [ "$(unset LANE_SLOT rethEthBase; bash -c 'source scripts/lib/lane-slot.sh; lane_reth_eth_port 2')" = 18546 ] || fail "the default slot validator 2 is not on 18546"
cases=$((cases+1)); [ "$(LANE_SLOT=2 rethEthBase=20545 bash -c 'source scripts/lib/lane-slot.sh; lane_reth_eth_port 4')" = 20548 ] || fail "an explicit rethEthBase is not honoured"
cases=$((cases+1)); grep -q 'lane_reth_eth_port' helper.sh && ! grep -q 'rethEthBase:-18545' helper.sh || fail "helper.sh still falls back to slot 0's port"  # lane-port-ok: static rejection check
# A paired VR launch enables archive proofs without an opt-in. Ordinary lanes keep the proof window.
source scripts/lib/reth-pin.sh
archive_preflight() { VR_LANE=1 urethPinRequireStateProofs "$1"; }
printf '#!/usr/bin/env bash\necho "  --unicity.archive-state-proofs"\n' >"$d/archive-reth"
printf '#!/usr/bin/env bash\necho "  --rpc.eth-proof-window <BLOCKS>"\n' >"$d/window-reth"
chmod +x "$d/archive-reth" "$d/window-reth"
mf "paired VR: old ureth is refused in preflight" archive_preflight "$d/archive-reth" "$d/window-reth" 'VR_LANE=1 requires .*--unicity.archive-state-proofs'
proof_flags_are() {
  [ "$(urethPinStateProofFlags)" = "$1" ]
}
ok env -u VR_ARCHIVE_STATE_PROOFS VR_LANE=1 bash -c 'source scripts/lib/reth-pin.sh; [ "$(urethPinStateProofFlags)" = --unicity.archive-state-proofs ]'
ok env VR_LANE=1 VR_ARCHIVE_STATE_PROOFS=0 bash -c 'source scripts/lib/reth-pin.sh; [ "$(urethPinStateProofFlags)" = --unicity.archive-state-proofs ]'
cases=$((cases+1)); VR_LANE=0 VR_ARCHIVE_STATE_PROOFS=1 proof_flags_are '--rpc.eth-proof-window 64' || fail "ordinary paired lane lost its 64-block window"
# Another lane may resolve its own pin while the first lane still needs an archive-capable restart.
pinned_restarts() (
  unset URETH_BIN
  export URETH_PIN_CACHE_DIR=$d/ureth-cache
  local vr=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ordinary=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  local vr_cache ordinary_cache vr_binary
  vr_cache=$(urethPinCacheEntry "$URETH_PIN_CACHE_DIR" "$vr")
  ordinary_cache=$(urethPinCacheEntry "$URETH_PIN_CACHE_DIR" "$ordinary")
  mkdir -p "$URETH_PIN_CACHE_DIR" || return 1
  printf '#!/usr/bin/env bash\ncase "$*" in --version) echo "Commit SHA: %s";; "node --help") echo "  --unicity.archive-state-proofs";; esac\n' "$vr" >"$vr_cache"
  printf '#!/usr/bin/env bash\necho "Commit SHA: %s"\n' "$ordinary" >"$ordinary_cache"
  chmod +x "$vr_cache" "$ordinary_cache" || return 1
  URETH_PIN_COMMIT=$vr
  urethPinResolve || return 1
  vr_binary=$URETH_BIN
  unset URETH_BIN
  URETH_PIN_COMMIT=$ordinary
  urethPinResolve || return 1
  [ "$vr_binary" != "$URETH_BIN" ] &&
    urethPinVerifyBinary "$vr_binary" "$vr" &&
    VR_LANE=1 urethPinRequireStateProofs "$vr_binary"
)
ok pinned_restarts

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

# the predicates run under PYTHONOPTIMIZE=1 (which strips `assert`) and still reject the bad inputs
cases=$((cases+1)); grep -nE '(^|[^A-Za-z0-9_])assert([^A-Za-z0-9_]|$)' scripts/vr-schedule-steps.sh | grep -vE '^[0-9]+:[[:space:]]*#' >/dev/null && fail "an assert statement is left in vr-schedule-steps.sh"
export PYTHONOPTIMIZE=1
rules "$row" >"$d/pg.json"; rules "$(echo "$row" | sed 's/"latched":true/"latched":1/')" >"$d/pb.json"
cases=$((cases+1)); vrs_check_rules "$d/pg.json" "$rid" $E true true 2>/dev/null || fail "PYTHONOPTIMIZE: the good row no longer passes"
cases=$((cases+1)); vrs_check_rules "$d/pb.json" "$rid" $E true true 2>/dev/null && fail "PYTHONOPTIMIZE: the integer-flag row passes (an assert-based predicate)"
cases=$((cases+1)); rules "{}" >"$d/pb.json"; vrs_check_rules_absent "$d/pb.json" "$rid" 2>/dev/null && fail "PYTHONOPTIMIZE: scheduled:[{}] passes"
for f in 's/"rootEpoch":5/"rootEpoch":-5/' 's/"rootEpoch":5/"rootEpoch":5.0/' 's/"known":true/"known":1/' 's/"releaseDigest":"[^"]*",//'; do
  cases=$((cases+1)); rules "$(echo "$row" | sed "$f")" >"$d/pb.json"; vrs_check_rules "$d/pb.json" "$rid" $E true true 2>/dev/null && fail "PYTHONOPTIMIZE: $f passes"
done
unset PYTHONOPTIMIZE
# ---- the no-assert guard matches `assert` followed by ANY non-identifier character: a space, a tab, a parenthesis ----------------------------------------
noassert() { ! grep -nE '(^|[^A-Za-z0-9_])assert([^A-Za-z0-9_]|$)' "$1" | grep -vE '^[0-9]+:[[:space:]]*#' >/dev/null; }
printf 'x = 1\n' >"$d/as_good.py"; cases=$((cases+1)); noassert "$d/as_good.py" || fail "the guard flags a file without assert"
printf 'x = 1\n# an assert in a comment is not code\nassertion = 2\nreassert(x)\n' >"$d/as_good2.py"; cases=$((cases+1)); noassert "$d/as_good2.py" || fail "the guard flags a comment or a longer identifier"
for body in '    assert x' '    assert(x)' $'    assert\tx' 'assert x, "m"' 'if y: assert(x)' '    assert'; do
  printf '%s\n' "$body" >"$d/as_bad.py"; cases=$((cases+1)); noassert "$d/as_bad.py" && fail "the guard misses: $body"
done
# ---- a command's failure survives vrs_logged (no `| tee`/`| tail` masking) ----------------------------------------------------------------------------
cases=$((cases+1)); vrs_logged "$d/l1.log" sh -c 'echo boom >&2; exit 7' >/dev/null 2>&1; [ "$?" = 7 ] || fail "vrs_logged lost the failing command's status"
cases=$((cases+1)); vrs_logged "$d/l2.log" sh -c 'echo fine' >/dev/null 2>&1 || fail "vrs_logged failed a succeeding command"
cases=$((cases+1)); grep -q boom "$d/l1.log" || fail "vrs_logged did not keep the output"
cases=$((cases+1)); grep -nE '\|[[:space:]]*(tee|tail|head)[^|]*\|\|' scripts/vr-schedule-steps.sh | grep -vE 'node-id|cut -c' >/dev/null && fail "a command's status is masked by a pipe to tee/tail/head in vr-schedule-steps.sh"
# ---- postponement: VR lists B's old entry Superseded and the new one Active, each in one activations line of the rule ------------------------------------
sline() { echo "rule ${1#0x} release $(printf 'ab%.0s' $(seq 32)) at root epoch $2, not before UC time 1795187438: $3"; }
sstat() { python3 -c 'import json,sys; print(json.dumps({"activations": sys.argv[1:]}))' "$@"; }
sstat "$(sline "$rid" 8 Superseded)" "$(sline "$rid" 10 Active)" >"$d/pg.json"; pp_pred() { vrs_check_postponed "$1" "$rid" 8 10; }
sstat "$(sline "$rid" 8 Active)" "$(sline "$rid" 10 Active)" >"$d/pb.json";       mf "postponed: the old entry is not Superseded" pp_pred "$d/pg.json" "$d/pb.json" 'no Superseded'
sstat "$(sline "$rid" 8 Superseded)" "$(sline "$rid" 10 Latched)" >"$d/pb.json";  mf "postponed: the new entry is not Active" pp_pred "$d/pg.json" "$d/pb.json" 'no Superseded'
sstat "$(sline "$rid" 8 Superseded)" "$(sline "$rid" 11 Active)" >"$d/pb.json";   mf "postponed: another new epoch" pp_pred "$d/pg.json" "$d/pb.json" 'no Superseded'
sstat "$(sline "$rid" 8 Superseded)" "$(sline "$other" 10 Active)" >"$d/pb.json"; mf "postponed: the Active entry is another rule's" pp_pred "$d/pg.json" "$d/pb.json" 'no Superseded'
sstat "$(sline "$other" 8 Superseded)" "$(sline "$rid" 10 Active)" >"$d/pb.json"; mf "postponed: the Superseded entry is another rule's" pp_pred "$d/pg.json" "$d/pb.json" 'no Superseded'
sstat "$(sline "$rid" 10 Active)" >"$d/pb.json";                                  mf "postponed: no old entry" pp_pred "$d/pg.json" "$d/pb.json" 'no Superseded'
sstat "$(sline "$rid" 8 Superseded)" >"$d/pb.json";                               mf "postponed: no new entry" pp_pred "$d/pg.json" "$d/pb.json" 'no Superseded'
echo '{"activations": "none"}' >"$d/pb.json";                                      mf "postponed: activations is not a list" pp_pred "$d/pg.json" "$d/pb.json" 'not a list'
echo '{}' >"$d/pb.json";                                                           mf "postponed: no activations" pp_pred "$d/pg.json" "$d/pb.json" 'no activations'
sstat "$(sline "$rid" 8 Superseded) and Active at root epoch 10: Active" >"$d/pb.json"; mf "postponed: both facts in ONE line" pp_pred "$d/pg.json" "$d/pb.json" 'no Superseded'
# The registry records a generic rejection. The committed candidate names the exact fold verdict.
gl() { printf '  #7 schedule\n      state %s\n' "$1"; }
gl "Rejected (reason 1)" >"$d/cg.txt"; cs_pred() { vrs_check_change_state "$1" Rejected; }
gl "Active" >"$d/cb.txt"; mf "change: accepted" cs_pred "$d/cg.txt" "$d/cb.txt"
gl "Queued" >"$d/cb.txt"; mf "change: still queued" cs_pred "$d/cg.txt" "$d/cb.txt"
printf '  #7 schedule\n      note Rejected (reason 1)\n' >"$d/cb.txt"; mf "change: the words on another line" cs_pred "$d/cg.txt" "$d/cb.txt"
: >"$d/cb.txt"; mf "change: empty output" cs_pred "$d/cg.txt" "$d/cb.txt"
vdoc() { printf '{"epoch":%s,"registryChanges":[{"ID":%s,"Kind":%s,"Verdict":%s}]}\n' "$@"; }
vdoc 5 7 9 6 >"$d/vg.json"; cv_pred() { vrs_check_candidate_verdict "$1" 5 7 6; }
vdoc 5 7 9 1 >"$d/vb.json"; mf "verdict: generic rejection is not PastCutoff" cv_pred "$d/vg.json" "$d/vb.json" 'no matching'
vdoc 4 7 9 6 >"$d/vb.json"; mf "verdict: wrong epoch" cv_pred "$d/vg.json" "$d/vb.json" 'wrong activation epoch'
vdoc 5 8 9 6 >"$d/vb.json"; mf "verdict: wrong change" cv_pred "$d/vg.json" "$d/vb.json" 'no matching'
vdoc 5 7 7 6 >"$d/vb.json"; mf "verdict: wrong change kind" cv_pred "$d/vg.json" "$d/vb.json" 'no matching'
vdoc 5 7 9 '"6"' >"$d/vb.json"; mf "verdict: string verdict" cv_pred "$d/vg.json" "$d/vb.json" 'no matching'
if [ "$fails" = 0 ]; then echo "vr-schedule checks: all $cases cases pass"; else echo "vr-schedule checks: $fails failing of $cases"; exit 1; fi
