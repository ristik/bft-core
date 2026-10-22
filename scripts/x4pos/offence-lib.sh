# X4 B4: the second offence of the PoS campaign, on dev3's S4 library (scripts/lib/s4-lib.sh). Definitions only: sourcing this file starts nothing.
#
# Offence 1 is the S4 lane as it is (the joiner's root5, evicted by the recovery). Offence 2 is a member that STAYS: root4, a member of K and of J. Both statements pairs are
# delivered while epoch 2 is current (x4o_equivocate, right after s4_equivocate); offence 2 is collected, submitted and settled only after the recovery, and only when no
# election result is open: the contracts' coverageChanged (ElectionPolicy.sol) marks an open Reserved result LOST when a member of it is admitted as an offender, which would
# block the recovery's result; after the result is resolved an admission touches no result and no running assignment, root4 is only ineligible for the NEXT election
# (dev3's reading of the pinned contracts; the lane records the open result it saw). The lane ends before the election cadence can fire again.
# The reporter is one throw-away key for both offences: it claims once, at the end, exactly the sum of the two bounties (s4_claim removes the key).

X4O_DIR=${X4O_DIR:-test-nodes/p85/s4b}
X4O_OFFENDER_ROOT=${X4O_OFFENDER_ROOT:-4}

# offence 2, delivery (epoch 2 is current)
x4o_equivocate() { S4_OFFENDER_ROOT=$X4O_OFFENDER_ROOT S4_DIR=$X4O_DIR S4_EXPECT_EVICTED=0 s4_equivocate; }

# offence 2, after the recovery: collect, submit, settle, check
x4o_second() {
  local open zero=0x0000000000000000000000000000000000000000000000000000000000000000
  mkdir -p "$X4O_DIR"
  open=$(p85_open_result) || { echo "x4o: cannot read the election's open result" >&2; return 1; }
  jq -n --arg open "$open" --argjson epoch "$(s4_epoch 1)" --argjson round "$(s4_round 1)" '{openResult: $open, epoch: $epoch, round: $round}' >"$X4O_DIR/pre-submit.json"
  [ "$open" = "$zero" ] || { echo "x4o: election result $open is still open: admitting a member of it would mark it lost" >&2; return 1; }
  ( export S4_OFFENDER_ROOT=$X4O_OFFENDER_ROOT S4_DIR=$X4O_DIR S4_EXPECT_EVICTED=0 S4_ADMITTED_HOOK=
    s4_collect_after_rotation && s4_submit_settle && s4_check ) || return 1
  # the running K assignment is untouched: the roots are still in epoch 3 and certify
  local e r0 r1
  e=$(s4_epoch 1); r0=$(s4_round 1); sleep 10; r1=$(s4_round 1)
  { [ "$e" = 3 ] && [ "$r1" -gt "$r0" ]; } || { echo "x4o: after the second admission the roots are in epoch $e and round $r0 -> $r1 (not advancing in epoch 3)" >&2; return 1; }
  jq -n --argjson epoch "$e" --argjson r0 "$r0" --argjson r1 "$r1" '{epoch: $epoch, roundBefore: $r0, roundAfter: $r1}' >"$X4O_DIR/post-settle.json"
  s4_pass "x4o: offence 2 (root $X4O_OFFENDER_ROOT, a staying member) settled after the recovery; the K assignment keeps running (epoch $e, round $r0 -> $r1)"
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
