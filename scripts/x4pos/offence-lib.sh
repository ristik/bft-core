# X4 B4: the second offence of the PoS campaign, on dev3's S4 library (scripts/lib/s4-lib.sh). Definitions only: sourcing this file starts nothing.
#
# Offence 1 is the S4 lane as it is (the joiner's root5, delivered in epoch 2, evicted by the recovery). Offence 2 is a member that STAYS: root4, a member of K. It is delivered AFTER
# the recovery, in root epoch 3 (S4_EPOCH=3, scripts/lib/s4-lib.sh), so that it has its own full evidence window: the policy window is 1000 rounds from the offence round (~8 min),
# which offence 1's whole flow (collect, request, controls, admission, settlement, checks) would otherwise use up (run 39882356004: "too-late: ordinary evidence window elapsed").
# After the recovery a LATER election result (Reserved from K, so root4 is a frozen member) opens by itself and stays open; the contracts' coverageChanged (ElectionPolicy.sol)
# marks such a result LOST when a frozen member is admitted as an offender (permanent, designed), and the running K assignment never reads it (dev3's reading of the pinned
# contracts): x4o_second asserts that, with offence 1 (root5, not a member of the K result) as the negative control.
# The reporter is one throw-away key for both offences: it claims once, at the end, exactly the sum of the two bounties (s4_claim removes the key).

X4O_DIR=${X4O_DIR:-test-nodes/p85/s4b}
X4O_OFFENDER_ROOT=${X4O_OFFENDER_ROOT:-4}
X4O_ZERO=0x0000000000000000000000000000000000000000000000000000000000000000

# The election's publication(bytes32) is a static struct, one 32-byte word per field; word 13 is `lost` (ElectionPolicy.sol:147-161; word 10 `published` is read the same way in p85_recovery)
x4o_lost() { p85_call "$(p85_election)" 'publication(bytes32)' "$1" | python3 -c "import sys;w=sys.stdin.read().strip()[2:];print(int(w[64*13:64*14],16))"; }

# between the admission and the settlement of offence 2 (S4_ADMITTED_HOOK): the designed effect on the LATER election result, if one is open
x4o_admitted() {
  local lost
  [ "${X4O_R:-}" != "$X4O_ZERO" ] || return 0
  lost=$(x4o_lost "$X4O_R") || return 1
  echo "$lost" >"$X4O_DIR/lost-after-admission.txt"
  [ "$lost" = 1 ] || { echo "x4o: the later election result $X4O_R is not marked lost after the admission of a frozen member (lost=$lost)" >&2; return 1; }
  s4_pass "x4o: admitted: the later election result $X4O_R is marked lost (coverage lost), as designed"
}

# offence 2, after offence 1 is done: deliver in epoch 3, collect, submit, settle, check. A LATER election (Reserved from K, so root4 is a frozen member) opens right after the recovery resolves and nothing in
# the lane drives it: the admission marks that result lost (permanent, designed; ElectionPolicy.coverageChanged), the running K assignment never reads it. Asserted, with offence 1
# (root5, not a member of the K result) as the negative control: lost must still be 0 before offence 2.
x4o_second() {
  local zero=$X4O_ZERO r res acked0 lost0 state0 e r0 r1 pre
  mkdir -p "$X4O_DIR"
  # delivery in epoch 3 (the offender is a member of K, signing there) and collection: its own window starts at its round
  ( export S4_OFFENDER_ROOT=$X4O_OFFENDER_ROOT S4_DIR=$X4O_DIR S4_EXPECT_EVICTED=0 S4_EPOCH=3
    s4_equivocate && s4_collect_after_rotation ) || return 1
  [ -n "${P85_K:-}" ] || p85_scenario_ids "$H3_DIR/registry-log.txt" || return 1   # K's assignment id (the lane's scenario ids), when a step runs in its own shell
  r=$(p85_open_result) || { echo "x4o: cannot read the election's open result" >&2; return 1; }
  acked0=$(p85_last_acked) || return 1
  pre=$(jq -n --arg open "$r" --arg acked "$acked0" --argjson epoch "$(s4_epoch 1)" --argjson round "$(s4_round 1)" '{openResult: $open, lastAcked: $acked, epoch: $epoch, round: $round}')
  if [ "$r" != "$zero" ]; then
    res=$(p85_call "$(p85_election)" 'result(bytes32)' "$r" | p85_dec result) || return 1
    lost0=$(x4o_lost "$r") || return 1
    pre=$(jq -c --argjson res "$res" --argjson lost "$lost0" --arg k "$P85_K" '. + {state: $res.state, predecessorIsK: (($res.predecessor | ascii_downcase) == ($k | ascii_downcase)), lostBefore: $lost}' <<<"$pre")
    [ "$(jq -r .state <<<"$pre")" = 1 ] && [ "$(jq -r .predecessorIsK <<<"$pre")" = true ] || { echo "x4o: the open result is not a Reserved result from K: $pre" >&2; return 1; }
    [ "$lost0" = 0 ] || { echo "x4o: the later result is already marked lost before offence 2 (offence 1 is not a member of it): $pre" >&2; return 1; }
  fi
  echo "$pre" >"$X4O_DIR/pre-submit.json"
  X4O_R=$r
  ( export S4_OFFENDER_ROOT=$X4O_OFFENDER_ROOT S4_DIR=$X4O_DIR S4_EXPECT_EVICTED=0 S4_EPOCH=3 S4_ADMITTED_HOOK=x4o_admitted X4O_R
    s4_submit_settle && s4_check ) || return 1
  # the running K assignment is untouched: the same acknowledged assignment, epoch 3, and a paid transaction certifies after the settlement
  local acked1 lost1 open1 state1; e=$(s4_epoch 1); r0=$(s4_round 1)
  acked1=$(p85_last_acked) || return 1
  # one paid transaction, waited for in the root epoch the lane is in (m2_send_paid matches `certificate admitted ... rootEpoch=<arg>`; epoch 1 never matches in epoch 3, bft-core#796)
  local paid=1
  p85_paid "$e" >/dev/null || { echo "x4o: a paid transaction (root epoch $e) did not go through after the second settlement" >&2; return 1; }
  sleep 10; r1=$(s4_round 1)
  open1=$(p85_open_result) || return 1
  if [ "$r" != "$zero" ]; then lost1=$(x4o_lost "$r") || return 1; state1=$(p85_result_state "$r"); else lost1=; state1=; fi
  jq -n --argjson epoch "$e" --argjson r0 "$r0" --argjson r1 "$r1" --arg acked0 "$acked0" --arg acked1 "$acked1" --arg open1 "$open1" --arg r "$r" --arg lost1 "$lost1" --arg state1 "$state1" --argjson paid "$paid" \
    '{epoch: $epoch, roundBefore: $r0, roundAfter: $r1, lastAckedUnchanged: ($acked0 == $acked1), paidTxOk: true, paidAttempt: $paid, openResultUnchanged: ($open1 == $r), lostAfterSettlement: (if $lost1 == "" then null else ($lost1 | tonumber) end), laterResultStateAfter: (if $state1 == "" then null else ($state1 | tonumber) end)}' >"$X4O_DIR/post-settle.json"
  jq -e '.epoch == 3 and .roundAfter > .roundBefore and .lastAckedUnchanged and .openResultUnchanged' "$X4O_DIR/post-settle.json" >/dev/null || { echo "x4o: the K assignment moved after the second admission: $(cat "$X4O_DIR/post-settle.json")" >&2; return 1; }
  if [ "$r" != "$zero" ]; then
    [ "$lost1" = 1 ] && [ "$state1" = 1 ] || { echo "x4o: after the settlement the later result is lost=$lost1 state=$state1 (wanted lost, still Reserved)" >&2; return 1; }
  fi
  s4_pass "x4o: offence 2 (root $X4O_OFFENDER_ROOT, a staying member) settled; later result ${r} lost=${lost1:-n/a}; the K assignment keeps running (epoch $e, round $r0 -> $r1, last acknowledged unchanged)"
}

# one claim for both offences: the reporter's credit is exactly offence 1's bounty plus offence 2's, then the usual exact claim (S4_DIR = offence 2's directory)
x4o_claim() {
  local a=${S4_DIR:-test-nodes/p85/s4} b=$X4O_DIR
  python3 - "$a" "$b" <<'PY' || return 1
import json, sys
a, b = sys.argv[1], sys.argv[2]
j = lambda d, n: json.load(open("%s/snapshot-%s.json" % (d, n)))
d1 = j(a, "settled")["creditReporter"] - j(a, "before")["creditReporter"]
d2 = j(b, "settled")["creditReporter"] - j(b, "before")["creditReporter"]
got = j(b, "final")["creditReporter"]
want = j(a, "before")["creditReporter"] + d1 + d2
if got != want or d1 <= 0 or d2 <= 0:
    sys.exit("FAIL: x4o: the reporter's credit is %d, the two bounties are %d + %d (from %d)" % (got, d1, d2, j(a, "before")["creditReporter"]))
print("PASS: x4o: the reporter's credit %d = bounty 1 %d + bounty 2 %d" % (got, d1, d2))
PY
  S4_DIR=$b s4_claim
}
