# X4 #856: the second handoff of the PoS campaign, on the ACCUMULATED chain. Definitions only: sourcing this file starts nothing. Lane step (p85_step): x4h_second.
#
# WHAT IT DRIVES. After the recovery the election reserves a second result R2 from K (the committee the recovery returned to: entities 1-4). The first campaign run never drove
# it, so a result stayed open for the rest of the run, which held back the reward tail and the governance activation (contracts#73). x4h_second drives R2 through the whole
# handoff exactly as the lane's primary handoff does (proofs of possession, publication, the root-ordered plan with readiness receipts, the root install of epoch 4, the committed
# activation record, the validators' authorities into the new scope) until custody acknowledges it: K' is K's four members under a new assignment, root epoch 4, shard epoch 3.
# It runs AFTER offence 1 settled (its evidence window is short) and BEFORE offence 2: offence 2 excludes a fourth identity, and the genesis election needs at least four eligible
# ones (nMin 4), so no result can be reserved after it. Offence 2 is then delivered in epoch 4, marks the result that opens after this handoff lost, and the roots reject that
# result (scripts/x4pos/offence-lib.sh): the campaign's RejectResult of an unpublishable result.
#
# NEEDS (scripts/p85-recovery-steps.sh, X4_H2_LANE=1): entity 4's signing authority and execution client alive and its node back in K's scope (p85_j_stalls, p85_recovery keep it),
# so that K' can name it. The roots 1-4 are K's committee; root 5 (the joiner's) is a follower and is not restarted.

X4H_DIR=${X4H_DIR:-$H3_DIR/x4pos/steps/handoff2}
X4H_ENTITIES="1 2 3 4"

# the four execution clients report the same head (a returned node has caught up) before the readiness receipts, which check each client against the roots' certified state
x4h_synced() {
  local i h first= j ok
  for i in $(seq 1 300); do
    ok=1; first=
    for j in $X4H_ENTITIES; do
      h=$("$P85_CAST" block-number --rpc-url "http://127.0.0.1:$((rethEthBase + j - 1))" 2>/dev/null) || { ok=0; break; }
      if [ -z "$first" ]; then first=$h; elif [ "$h" != "$first" ] && [ "$((h > first ? h - first : first - h))" -gt 1 ]; then ok=0; break; fi
    done
    [ "$ok" = 1 ] && return 0
    sleep 1
  done
  echo "x4h: the execution clients of $X4H_ENTITIES did not reach one head in 300 s" >&2
  return 1
}

# the open election result, waited for: R2 opens a few minutes after the RecoveryAck (the cadence), offence 1's flow usually outlasts that
x4h_wait_open() { # seconds
  local i r zero=0x0000000000000000000000000000000000000000000000000000000000000000
  for i in $(seq 1 "$1"); do
    r=$(p85_open_result 2>/dev/null) && [ -n "$r" ] && [ "$r" != "$zero" ] && { echo "$r"; return 0; }
    sleep 1
  done
  echo "x4h: no election result opened in $1 s" >&2
  return 1
}

x4h_second() {
  local r k acked0 res lost frozen ids i epoch0 log="$H3_DIR/registry-log.txt" k2 st rec_ok cursor count target
  mkdir -p "$X4H_DIR"
  H3_ROOTS="1 2 3 4"; H3_ONLINE="1 2 3 4"
  epoch0=$(p85_root_epoch) || return 1
  [ "$epoch0" = 3 ] || { echo "x4h: the roots are in epoch $epoch0, the second handoff starts from the recovery's epoch 3" >&2; return 1; }
  [ -n "${P85_K:-}" ] || { p85_log_dump >"$log" && p85_scenario_ids "$log"; } || return 1
  acked0=$(p85_last_acked | tr 'A-F' 'a-f') || return 1
  [ "$acked0" = "$P85_K" ] || { echo "x4h: custody's last acknowledged assignment $acked0 is not the recovery's K ($P85_K)" >&2; return 1; }

  # 1. the result: Reserved, from K, not lost, naming exactly K's four members
  r=$(x4h_wait_open 1200) || return 1
  res=$(p85_call "$(p85_election)" 'result(bytes32)' "$r" | p85_dec result) || return 1
  lost=$(x4o_lost "$r") || return 1
  frozen=$(p85_call "$(p85_election)" "frozenMembers(bytes32)((uint64,uint64,uint64,uint64,bytes32)[])" "$r") || return 1
  echo "$frozen" >"$X4H_DIR/frozen-members.txt"
  ids=$(grep -o '([0-9]*,' <<<"$frozen" | tr -d '(,' | tr '\n' ' ' | sed 's/ $//')
  jq -e '.state == 1 and ((.predecessor | ascii_downcase) == $k)' --arg k "$P85_K" <<<"$res" >/dev/null || { echo "x4h: the open result is not a Reserved result from K: $res" >&2; return 1; }
  [ "$lost" = 0 ] || { echo "x4h: the open result is already marked lost: $res" >&2; return 1; }
  [ "$ids" = "$X4H_ENTITIES" ] || { echo "x4h: the open result names members '$ids', not K's '$X4H_ENTITIES' (a member that cannot be handed to is not in this lane's reach): $frozen" >&2; return 1; }
  cp "$H3_DIR/result-id.txt" "$H3_DIR/result-id-1.txt" 2>/dev/null || true
  echo "$r" >"$H3_DIR/result-id.txt"; echo "$r" >"$X4H_DIR/result-id.txt"
  echo "$res" >"$X4H_DIR/result-before.json"
  x4h_synced || return 1

  # 2. proofs of possession, publication, the plan: the lane's primary handoff for these four members, epoch 3 -> 4
  Q3_WEIGHTS="1 1 1 1" q3_trust_base_v3 4 || return 1
  P85_PROOF_TAG=sign2 P85_PROOF_ENTITIES="$X4H_ENTITIES" P85_PROOF_TB_EPOCH=4 P85_PROOF_ROOTS="1 2 3 4" p85_proofs || return 1
  P85_PROOF_ENTITIES="$X4H_ENTITIES" Q3_PROPOSE_ROOTS="1 2 3 4" Q3_ENTITIES="$X4H_ENTITIES" Q3_TOTAL_WEIGHT=4 Q3_ROOT_QUORUM=3 Q3_EVM_QUORUM=3 Q3_WEIGHTS_1="1 1 1 1" \
    q3_handoff_n 3 4 "1 1 1 1" 0 "$P85_DIR/genesis-identities.json" || return 1

  # 3. the root install of epoch 4 and its committed activation record (the Commit is K's: W=4, quorum 3)
  H3_ROOTS="1 2 3 4" q3_install_n 4 || return 1
  H3_ROOTS="1 2 3 4" Q3_TOTAL_WEIGHT=4 Q3_ROOT_QUORUM=3 q3_activation_n 3 4 || return 1

  # 4. the validators into the new scope (root epoch 4, shard epoch 3); K' certifies once a quorum of them is there
  M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 4 3 $X4H_ENTITIES || { echo "x4h: authority advance into the second handoff's scope failed" >&2; return 1; }
  for i in $(seq 1 180); do h3_registry_is 3 4 && break; sleep 1; done
  h3_registry_is 3 4 || { echo "x4h: the registry did not reach shard epoch 3 / root epoch 4 (shard epoch $(h3_slot "$h3_slot_shard"), root epoch $(h3_slot "$h3_slot_root"))" >&2; return 1; }
  p85_paid 4 || { echo "x4h: a paid transaction was not certified at root epoch 4" >&2; return 1; }

  # 5. custody acknowledges K': the result is Acknowledged, K' is the last acknowledged assignment, K is closed, K' open
  for i in $(seq 1 900); do [ "$(p85_result_state "$r")" = 3 ] && break; sleep 1; done
  st=$(p85_result_state "$r")
  [ "$st" = 3 ] || { echo "x4h: the result $r is in state $st, not Acknowledged" >&2; p85_stuck_report; return 1; }
  k2=$(p85_last_acked | tr 'A-F' 'a-f') || return 1
  [ "$k2" = "$(jq -r '.assignmentID | ascii_downcase' <<<"$res")" ] && [ "$k2" != "$P85_K" ] && [ "$k2" != "$P85_J" ] && [ "$k2" != "$P85_G" ] || { echo "x4h: custody's last acknowledged assignment $k2 is not the result's new assignment" >&2; return 1; }
  jq -e '.closed == 1' <<<"$(p85_assignment "$P85_K")" >/dev/null || { echo "x4h: K is not closed by the acknowledgement of K'" >&2; return 1; }
  jq -e '.state == 2 and .closed == 0 and .offsetSet == 1' <<<"$(p85_assignment "$k2")" >/dev/null || { echo "x4h: K' is not Active and open: $(p85_assignment "$k2")" >&2; return 1; }
  for i in $(seq 1 180); do [ "$(p85_cursor)" = "$(p85_log_count)" ] && [ "$(p85_log_count)" = "$(p85_log_target)" ] && break; sleep 1; done
  cursor=$(p85_cursor); count=$(p85_log_count); target=$(p85_log_target)
  [ "$cursor" = "$count" ] && [ "$count" = "$target" ] || { echo "x4h: reconciliation incomplete after the acknowledgement: cursor=$cursor count=$count target=$target" >&2; return 1; }
  p85_log_dump >"$log" || return 1
  rec_ok=$(awk -v r="$r" '$2==2 && (tolower($5)==tolower(r) || tolower($6)==tolower(r)){n++} END{print n+0}' "$log")   # an Ack record naming the result (informational: the word layout is the registry's)
  P85_K2=$k2; export P85_K2
  jq -n --arg r "$r" --arg k "$P85_K" --arg k2 "$k2" --argjson e0 "$epoch0" --argjson e1 "$(p85_root_epoch)" --argjson cur "$cursor" --argjson cnt "$count" --argjson tgt "$target" --argjson ack "$rec_ok" \
    --argjson ents "$(printf '%s\n' $X4H_ENTITIES | jq -s .)" \
    '{result: $r, resultState: 3, entities: $ents, lastAckedBefore: $k, lastAckedAfter: $k2, rootEpochBefore: $e0, rootEpochAfter: $e1, kClosed: true, k2Open: true, cursor: $cur, count: $cnt, target: $tgt, ackRecordsNamingTheResult: $ack}' >"$X4H_DIR/second-handoff.json" || return 1
  jq -e '.rootEpochAfter == 4 and .lastAckedAfter != .lastAckedBefore' "$X4H_DIR/second-handoff.json" >/dev/null || { echo "x4h: the record of the second handoff is not one: $(cat "$X4H_DIR/second-handoff.json")" >&2; return 1; }
  echo "PASS: x4h: the election result ${r:0:12} was driven to its Ack: K ${P85_K:0:12} -> K' ${k2:0:12} (the same four members), root epoch $epoch0 -> $(p85_root_epoch), shard epoch 2 -> 3"
}
