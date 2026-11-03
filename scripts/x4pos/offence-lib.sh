# X4 B4: the second offence of the PoS campaign, on dev3's S4 library (scripts/lib/s4-lib.sh). Definitions only: sourcing this file starts nothing.
#
# Offence 1 is the S4 lane as it is (the joiner's root5, delivered in epoch 2, evicted by the recovery). Offence 2 is a member that STAYS: root4, a member of K and of K'. It is delivered after
# offence 1 settled and, in the X4 campaign (X4_H2_LANE), after the second handoff (scripts/x4pos/handoff-lib.sh), in root epoch 4 (S4_EPOCH=4, scripts/lib/s4-lib.sh), so that it has its own
# full evidence window: the policy window is 1000 rounds from the offence round (~8 min), which offence 1's whole flow (collect, request, controls, admission, settlement, checks) would otherwise
# use up (run 39882356004: "too-late: ordinary evidence window elapsed"). The election result that is open then (Reserved from the last acknowledged assignment, so root4 is a frozen member) is marked
# LOST by the contracts' coverageChanged (ElectionPolicy.sol) when a frozen member is admitted as an offender (permanent, designed), the running assignment never reads it, and the roots REJECT it by
# themselves (rootchain/posreject, bft-core#857 and #871: a result proven lost is due at once): the campaign's RejectResult of an unpublishable result. x4o_second asserts that as a before/after of offence 2
# alone (lost is 0 immediately before its submission and 1 after its admission; Closed, 5, after the settlement) and that the running assignment is untouched. The run does NOT show that offence 1
# leaves such a result unmarked: views are taken at the end of each step, and the later result may open after offence 1's admission (dev3, bft-core#800). Offence 2 excludes a fourth identity, and the
# election needs four eligible ones (nMin 4): no result is reserved after this one, which is why the second handoff comes first. The reporter is one throw-away key for both offences: it claims once,
# at the end, exactly the sum of the two bounties (s4_claim removes the key).

X4O_DIR=${X4O_DIR:-test-nodes/p85/s4b}
X4O_OFFENDER_ROOT=${X4O_OFFENDER_ROOT:-4}
X4O_ZERO=0x0000000000000000000000000000000000000000000000000000000000000000

# The election's publication(bytes32) is a static struct, one 32-byte word per field; word 13 is `lost` (ElectionPolicy.sol:147-161; word 10 `published` is read the same way in p85_recovery)
x4o_lost() { p85_call "$(p85_election)" 'publication(bytes32)' "$1" | python3 -c "import sys;w=sys.stdin.read().strip()[2:];print(int(w[64*13:64*14],16))"; }

# between the admission and the settlement of offence 2 (S4_ADMITTED_HOOK): the designed effect on the LATER election result, if one is open
x4o_admitted() {
  local lost
  lost=$(x4o_lost "$X4O_R") || return 1
  echo "$lost" >"$X4O_DIR/lost-after-admission.txt"
  [ "$lost" = 1 ] || { echo "x4o: the later election result $X4O_R is not marked lost after the admission of a frozen member (lost=$lost)" >&2; return 1; }
  s4_pass "x4o: admitted: the later election result $X4O_R is marked lost (coverage lost), as designed"
}

# The root epoch offence 2 is delivered in: the recovery's epoch 3, or epoch 4 after the campaign's second handoff (X4_H2_LANE, scripts/x4pos/handoff-lib.sh)
X4O_EPOCH=${X4O_EPOCH:-$([ "${X4_H2_LANE:-0}" = 1 ] && echo 4 || echo 3)}

# The roots reject an election result that is proven lost by themselves (rootchain/posreject, bft-core#857 and #871: due as soon as the loss is proven, no age needed): the result becomes
# Closed (5) through a root-ordered SessionClosed record. Waited for here, then the open result is read again: it must not be the rejected one.
x4o_wait_rejected() { # result seconds
  local i st
  for i in $(seq 1 "$2"); do
    st=$(p85_result_state "$1" 2>/dev/null); [ "$st" = 5 ] && { echo "$i"; return 0; }
    sleep 1
  done
  echo "x4o: the lost result $1 was not rejected by the roots in $2 s (state ${st:-unreadable})" >&2
  return 1
}

# offence 2, after offence 1 is done (and, in the X4 campaign, after the second handoff): wait for the election result that is open, deliver in epoch $X4O_EPOCH, collect, submit, settle,
# check. That result is Reserved from the last acknowledged assignment, so root4 is a frozen member: the admission marks it lost (permanent, designed; ElectionPolicy.coverageChanged), the
# running assignment never reads it, and the roots then REJECT it (the campaign's RejectResult of an unpublishable result). Asserted before/after offence 2 alone: lost is 0 immediately before
# its submission and 1 after its admission; after the settlement the result is Closed and no longer the open one. A pack without an open result is refused: the lost evidence is the point
# of this step.
x4o_second() {
  local zero=$X4O_ZERO r res acked0 lost0 state0 e r0 r1 pre rej
  mkdir -p "$X4O_DIR"
  # the result opens a few minutes after the last acknowledgement (the election's cadence): waited for BEFORE the offence is delivered, so that its evidence window is not spent waiting
  for e in $(seq 1 1200); do r=$(p85_open_result 2>/dev/null) && [ -n "$r" ] && [ "$r" != "$zero" ] && break; sleep 1; done
  [ -n "${r:-}" ] && [ "$r" != "$zero" ] || { echo "x4o: no later election result opened in 1200 s: offence 2 would show no lost marking and no rejection" >&2; return 1; }
  # delivery in the epoch (the offender is a member of the running assignment, signing there) and collection: its own window starts at its round
  ( export S4_OFFENDER_ROOT=$X4O_OFFENDER_ROOT S4_DIR=$X4O_DIR S4_EXPECT_EVICTED=0 S4_EPOCH=$X4O_EPOCH
    s4_equivocate && s4_collect_after_rotation ) || return 1
  [ -n "${P85_K:-}" ] || p85_scenario_ids "$H3_DIR/registry-log.txt" || return 1   # K's assignment id (the lane's scenario ids), when a step runs in its own shell
  r=$(p85_open_result) || { echo "x4o: cannot read the election's open result" >&2; return 1; }
  [ "$r" != "$zero" ] || { echo "x4o: no later election result is open after the delivery: offence 2 would show no lost marking" >&2; return 1; }
  acked0=$(p85_last_acked) || return 1
  pre=$(jq -n --arg open "$r" --arg acked "$acked0" --argjson epoch "$(s4_epoch 1)" --argjson round "$(s4_round 1)" '{openResult: $open, lastAcked: $acked, epoch: $epoch, roundBeforeSubmit: $round}')
  res=$(p85_call "$(p85_election)" 'result(bytes32)' "$r" | p85_dec result) || return 1
  lost0=$(x4o_lost "$r") || return 1
  pre=$(jq -c --argjson res "$res" --argjson lost "$lost0" '. + {state: $res.state, predecessorIsLastAcked: (($res.predecessor | ascii_downcase) == (.lastAcked | ascii_downcase)), lostBefore: $lost}' <<<"$pre")
  [ "$(jq -r .state <<<"$pre")" = 1 ] && [ "$(jq -r .predecessorIsLastAcked <<<"$pre")" = true ] || { echo "x4o: the open result is not a Reserved result from the last acknowledged assignment: $pre" >&2; return 1; }
  [ "$lost0" = 0 ] || { echo "x4o: the later result is already marked lost before offence 2: $pre" >&2; return 1; }
  echo "$pre" >"$X4O_DIR/pre-submit.json"
  X4O_R=$r
  ( export S4_OFFENDER_ROOT=$X4O_OFFENDER_ROOT S4_DIR=$X4O_DIR S4_EXPECT_EVICTED=0 S4_EPOCH=$X4O_EPOCH S4_ADMITTED_HOOK=x4o_admitted X4O_R
    s4_submit_settle && s4_check ) || return 1
  # the roots reject the lost result by themselves; the running assignment is untouched: the same acknowledged assignment and a paid transaction certifies after the settlement
  rej=$(x4o_wait_rejected "$r" 1500) || return 1
  local acked1 lost1 open1 state1 closed; e=$(s4_epoch 1); r0=$(s4_round 1)
  acked1=$(p85_last_acked) || return 1
  # one paid transaction, waited for in the root epoch the lane is in (m2_send_paid matches `certificate admitted ... rootEpoch=<arg>`; epoch 1 never matches in epoch 3, bft-core#796)
  # paidTxOk is true and paidAttempt 1 by construction: the function returned before writing post-settle.json if the transaction was not certified
  local paid=1
  p85_paid "$e" >/dev/null || { echo "x4o: a paid transaction (root epoch $e) did not go through after the second settlement" >&2; return 1; }
  sleep 10; r1=$(s4_round 1)
  for e in $(seq 1 120); do [ "$(p85_cursor)" = "$(p85_log_count)" ] && break; sleep 1; done
  open1=$(p85_open_result) || return 1
  lost1=$(x4o_lost "$r") || return 1; state1=$(p85_result_state "$r")
  closed=$(p85_log_dump | awk -v r="$r" '$2==1 && (tolower($5)==tolower(r) || tolower($6)==tolower(r)){n++} END{print n+0}')   # SessionClosed records naming the result (informational: the word layout is the registry's)
  e=$(s4_epoch 1)
  jq -n --argjson epoch "$e" --argjson r0 "$r0" --argjson r1 "$r1" --arg acked0 "$acked0" --arg acked1 "$acked1" --arg open1 "$open1" --arg r "$r" --arg lost1 "$lost1" --arg state1 "$state1" --argjson paid "$paid" \
    --argjson rej "$rej" --argjson closed "$closed" --argjson cur "$(p85_cursor)" --argjson cnt "$(p85_log_count)" \
    '{epoch: $epoch, roundAfterSettle: $r0, roundAfterPaidTx: $r1, lastAckedUnchanged: ($acked0 == $acked1), paidTxOk: true, paidAttempt: $paid, openResultIsNotTheRejected: ($open1 != $r), openResultAfter: $open1, rejectedAfterSeconds: $rej, sessionClosedRecords: $closed, cursor: $cur, count: $cnt, lostAfterSettlement: (if $lost1 == "" then null else ($lost1 | tonumber) end), laterResultStateAfter: (if $state1 == "" then null else ($state1 | tonumber) end)}' >"$X4O_DIR/post-settle.json"
  jq -e --argjson want "$X4O_EPOCH" '.epoch == $want and .roundAfterPaidTx > .roundAfterSettle and .lastAckedUnchanged and .openResultIsNotTheRejected and .cursor == .count' "$X4O_DIR/post-settle.json" >/dev/null || { echo "x4o: the running assignment moved after the second admission: $(cat "$X4O_DIR/post-settle.json")" >&2; return 1; }
  [ "$lost1" = 1 ] && [ "$state1" = 5 ] || { echo "x4o: after the settlement the later result is lost=$lost1 state=$state1 (wanted lost and Closed by the roots' rejection)" >&2; return 1; }
  s4_pass "x4o: offence 2 (root $X4O_OFFENDER_ROOT, a staying member) settled in epoch $e; later result ${r} lost=$lost1, REJECTED by the roots after ${rej} s (Closed); the running assignment keeps going (round $r0 -> $r1, last acknowledged unchanged)"
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
