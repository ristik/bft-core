# Sourced by reth-paired-devnet.sh (Q3_WEIGHT_LANE=1, H3_ASSIGNMENT_LANE=1, F8_MIXED_LANE=1, M2_PROFILE2=1, SIGNING=authority) after the first paid
# certified block, in place of m2-profile2-handoffs.sh. Q3 #50 slice E (briefs/q3-design-v2.md section 5 item 3, section 6 row E): ONE coupled
# handoff from the layout-2 unit PoA to mirrored weights 6,1,1,1 that activates Q1 scheme 2, Q2 weighted EVM requests and the #399 selector through
# the committed activation record, then progress, a real TC, a heavy-validator crash across E, negative controls, and the evidence pack.
# Every step prints PASS or FAIL; a FAIL tears down what the lane started and exits nonzero. Roots and shard nodes run with --q3-lane (their own
# verified Q3 history from the pinned genesis); Ureth is pinned to the deployment's network id and root genesis identity (ureth#52).
#
# Entities: root i and its delegated EVM validator i (i=1..4), the SAME keys before and after (a weight change, not a key change). Entity 1 is the
# heavy one (weight 6). Root epochs: 1 genesis (unit, scheme 1), 2 the V3 epoch E. Shard (EVM) epochs: 0, then 1 (the coupled assignment).
# Pair A is entity 1's BFT node and Ureth. Pair B is entity 4's node and Ureth after a fresh restore (q3_start_second_pair): a new home and a new execution
# client whose own Go reconstructs the verified history from the pinned root genesis. It shares no store, cache or verification result with pair A.
#
# Definitions first; the lane runs from q3_run_lane unless Q3_LANE_DEFINE_ONLY=1 (the runner's --dry-run sources this file that way).
source scripts/lib/m2-handoff-lib.sh
H3_DIR=${Q3_DIR:-test-nodes/q3}
Q3_DIR=$H3_DIR
source scripts/lib/h3-lib.sh
source scripts/lib/q3-lib.sh
source scripts/lib/q3-flow-lib.sh

q3_pass() { echo "  PASS: $*"; }
q3_die() {
  local i
  echo "  FAIL: $*" >&2
  for i in 1 2 3 4; do [ -f "test-nodes/root$i/debug.log" ] && { echo "--- tail of root$i/debug.log" >&2; tail -n 6 "test-nodes/root$i/debug.log" | cut -c1-300 >&2; }; done
  q3_teardown
  exit 1
}
q3_step() { local name=$1; shift; echo "--- Q3 step: $name"; "$@" || q3_die "$name"; q3_pass "$name"; }

# ---- weights -----------------------------------------------------------------------------------------------------------------------------------
q3_validators_json() { # out ids...: sorted successor node infos with the entity's mirrored weight as stake
  local out=$1 id files=; shift
  for id in "$@"; do files+=" test-nodes/auth$id/node-info.json"; done
  local w=; for id in "$@"; do w+="${w:+,}\"$(jq -r .nodeId "test-nodes/auth$id/node-info.json")\":$(q3_weight_of "$id")"; done
  # shellcheck disable=SC2086
  jq -s --argjson w "{$w}" 'map({nodeId, sigKey, stake: $w[.nodeId]}) | sort_by(.nodeId)' $files >"$out"
}

# The successor committee's identity records (#85 lifecycle): the genesis records of the same four entities with the mirrored weights. The
# staking id, payee and exposure digest are the entity's own and do not change with its weight.
q3_successor_identities() { # out ids...
  local out=$1 id w= ; shift
  for id in "$@"; do w+="${w:+,}\"$(h3_root_id "$id")\":$(q3_weight_of "$id")"; done
  # the committed weight q is the quantization of the raw bonded weight x (#508: rawWeight >= weight, and q = quant(x over the set, B)); with the mirrored weights well
  # inside the profile cap B the quantization is the identity, so both carry the mirrored weight
  jq --argjson w "{$w}" 'map(.weight = $w[.rootNodeId] | .rawWeight = $w[.rootNodeId])' "$Q3_GENESIS_IDENTITIES" >"$out"
}

# The coupled assignment (the same four entities, mirrored weights): h3_build_assignment with the mirrored stakes, the successor identity
# records every possession proof signs, and the recovery authorization whose K is the genesis committee the root recorded at genesis.
q3_build_assignment() { # tag ids...  (Q3_RECOVERY=1: the derived recovery of the pending primary, exactly K, no validators, proofs, identities or authorization)
  local tag=$1 id pops=; shift
  if [ -n "${Q3_RECOVERY:-}" ]; then
    build/ubft root handoff evm-context --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$Q3_DIR/$tag-context.json" || return 1
    build/ubft root handoff evm-assemble --context "$Q3_DIR/$tag-context.json" --recovery --supersede --out "$Q3_DIR/$tag-assignment.json" || return 1
    return 0
  fi
  q3_validators_json "$Q3_DIR/$tag-validators.json" "$@" || return 1
  build/ubft root handoff evm-context --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$Q3_DIR/$tag-context.json" || return 1
  q3_successor_identities "$Q3_DIR/$tag-identities.json" "$@" || return 1
  q3_x build/ubft root handoff evm-authorization --context "$Q3_DIR/$tag-context.json" --incumbent "${Q3_INCUMBENT:-$Q3_GENESIS_IDENTITIES}" \
    --chain "${M2_CHAIN_ID:-31337}" --out "$Q3_DIR/$tag-authorization.json" || return 1
  for id in "$@"; do
    build/ubft root handoff evm-pop --context "$Q3_DIR/$tag-context.json" --validators "$Q3_DIR/$tag-validators.json" \
      --identities "$Q3_DIR/$tag-identities.json" \
      --node-id "$(evm_validator_id "$id")" --authority-socket "test-nodes/auth$id/operator.sock" \
      --authority-credential "test-nodes/auth$id/operator.cred" >"$Q3_DIR/$tag-pop-$id.json" || return 1
    pops+="${pops:+,}$Q3_DIR/$tag-pop-$id.json"
  done
  H3_BIND_ROOTS="$*" h3_bindings_json "$Q3_DIR/$tag-bindings.json" "$@" || return 1
  build/ubft root handoff evm-assemble --context "$Q3_DIR/$tag-context.json" --validators "$Q3_DIR/$tag-validators.json" \
    --identities "$Q3_DIR/$tag-identities.json" --authorization "$Q3_DIR/$tag-authorization.json" \
    --pops "$pops" --bindings "$Q3_DIR/$tag-bindings.json" --out "$Q3_DIR/$tag-assignment.json" ${Q3_SUPERSEDE:+--supersede} || return 1
}

q3_rec() { jq -r "$1" "$Q3_DIR/activation-record.json"; }

q3_wait_grep_since() { # seconds file first-line-after regex: the pattern appears in the file beyond the mark
  local limit=$1 file=$2 mark=$3 re=$4 i
  for i in $(seq 1 "$limit"); do
    tail -n +"$((mark + 1))" "$file" 2>/dev/null | grep -aEq -- "$re" && return 0
    sleep 1
  done
  echo "timed out after ${limit}s waiting for /$re/ in $file after line $mark" >&2
  return 1
}

# ---- steps ------------------------------------------------------------------------------------------------------------------------------------
q3_baseline() {
  local sg
  h3_progress baseline 8 || return 1
  h3_registry_is 0 1 || return 1
  if [ "${Q3_B1:-0}" = 1 ]; then
    # the fresh-B1 registry (layout 3): the profile that defines it is the one the genesis, ureth and the shard nodes were all given
    [ -s "${EVM_B1_PROFILE:-}" ] || { echo "no B1 profile: the lane runs on the fresh-B1 stack" >&2; return 1; }
    { echo "layout=3 (fresh B1)"; echo "profileHash=$(python3 -c "import json;print(json.load(open('$EVM_B1_PROFILE')).get('profileHash',''))")"; echo "ureth flags: $(sed -n 's/^ureth flags: *//p' test-nodes/b1-profile.out)"; } >"$Q3_DIR/registry-layout.txt"
    cp "$EVM_B1_PROFILE" "$Q3_DIR/b1-profile.json"
  else
    [ "$(registry_layout)" = 2 ] || { echo "registry layout is not 2" >&2; return 1; }
    registry_layout >"$Q3_DIR/registry-layout.txt"
    cp "$Q3_DIR/registry-layout.txt" "$Q3_DIR/b1-profile.json"   # no B1 profile on the historical stack: the evidence file records the layout
  fi
  rpc "http://127.0.0.1:$rethEthBase" eth_getCode "[\"$H3_REGISTRY\",\"latest\"]" | pyget "['result']" | tr -d '\n' | shasum -a 256 | cut -d' ' -f1 >"$Q3_DIR/registry-hash.txt"
  q3_execution_pins || return 1
  cp "$Q3_GENESIS_IDENTITIES" "$Q3_DIR/genesis-identities.json" || return 1
  # unit PoA on scheme 1 before the handoff, read from the root's own verified state: epoch 1, scheme 1, unit weights, W=4 / Q=3
  sg=$(q3_signers_of "$(h3_first_root)") || return 1
  printf '%s\n' "$sg" | jq -c . >"$Q3_DIR/scheme-before.txt"
  [ "$(printf '%s' "$sg" | jq -r '[.epoch, .scheme] | join(",")')" = 1,1 ] || { echo "baseline certificate is not epoch 1 / scheme 1: $sg" >&2; return 1; }
  printf '%s' "$sg" | jq '.signers' >"$Q3_DIR/signers-before.json"
  q3_check_weights cert "$Q3_DIR/signers-before.json" 4 3 >/dev/null || return 1
  h3_root_info | jq -c '[.partitionShards[] | select(.partitionId != 8) | {partitionId} + (del(.partitionId, .roundNumber, .trRound, .trLeader) | with_entries(select(.value | type != "number")))]' >"$Q3_DIR/aggregator-before.json"
}

q3_candidate() {
  cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
  q3_trust_base_v3 2 || return 1
  q3_build_assignment cand 1 2 3 4 || return 1
  q3_derive_candidate || return 1
  [ "$(jq -r '.signingScheme' "$Q3_DIR/candidate-config.json")" = 2 ] || { echo "candidate tuple does not select scheme 2" >&2; return 1; }
  # the mirrored weights are in BOTH the root trust base and the EVM assignment, entity for entity: the heavy entity's key carries the heavy stake
  [ "$(jq -c '[.[].stake] | sort' "$Q3_DIR/cand-validators.json")" = "$(echo "$Q3_WEIGHTS" | tr ' ' '\n' | sort -n | paste -sd, - | sed 's/^/[/;s/$/]/')" ] || { echo "assignment stakes differ from $Q3_WEIGHTS" >&2; return 1; }
  [ "$(jq -r --arg id "$(jq -r .nodeId test-nodes/auth1/node-info.json)" '.[] | select(.nodeId == $id) | .stake' "$Q3_DIR/cand-validators.json")" = "$(q3_weight_of 1)" ] || { echo "entity 1 does not carry weight $(q3_weight_of 1)" >&2; return 1; }
  q3_check_weights set "$Q3_DIR/root-weights.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM" >/dev/null || return 1
  q3_check_weights set-evm "$Q3_DIR/evm-weights.json" "$Q3_TOTAL_WEIGHT" "$Q3_EVM_QUORUM" >/dev/null || return 1
}

q3_handoff() {
  # no pre-restart certificate may be at epoch 2: the roots only install epoch 2 at the restart below
  h3_retry_handoff 1 q3_attempt || return 1
  echo "activating handoff committed at root epoch 1"
}

# The installation barrier: every root restarts with the install epoch (M2/H3 pattern); this restart sits between the Commit and the first ordinary
# round (E,A*). No epoch-2 certificate may exist before it (the root's verified state still reports epoch 1), and the first one after it is read in
# q3_activation against A*.
q3_install_epoch2() {
  local before r
  for r in $H3_ROOTS; do
    before=$(q3_signers_of "$r" | jq -r .epoch) || return 1
    [ "$before" = 1 ] || { echo "root $r already reports a certificate of epoch $before before its install restart" >&2; return 1; }
  done
  h3_restart_roots 2 || { echo "root restart into epoch 2 failed" >&2; return 1; }
  for r in $(seq 1 120); do
    [ "$(q3_signers_of "$(h3_first_root)" 2>/dev/null | jq -r .epoch 2>/dev/null)" = 2 ] && break
    sleep 1
  done
  q3_signers_of "$(h3_first_root)" | jq -c . >"$Q3_DIR/first-epoch2-certificate.json"
  [ "$(jq -r .epoch "$Q3_DIR/first-epoch2-certificate.json")" = 2 ] || { echo "no epoch-2 certificate after the install restart" >&2; return 1; }
  q3_history_ids "$Q3_DIR/history-ids-pre-restart.txt"
}

q3_activation() {
  local astar amin first rounds
  q3_x build/ubft root handoff q3-activation --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --epoch 2 --out "$Q3_DIR/activation-record.json" || return 1
  [ "$(q3_rec .epoch)" = 2 ] || { echo "activation epoch is not E=2" >&2; return 1; }
  [ "$(q3_rec .signingScheme)" = 2 ] || { echo "activated scheme is not 2" >&2; return 1; }
  [ "$(q3_rec .v3BodyId)" = "$(tr -d '[:space:]' <"$Q3_DIR/v3-body-id.txt")" ] || { echo "activation record names a different V3BodyID than the candidate" >&2; return 1; }
  astar=$(q3_rec .activationRound); amin=$(q3_rec .minActivationRound)
  [ "$astar" -ge "$amin" ] || { echo "A*=$astar is below A_min=$amin" >&2; return 1; }
  first=$(jq -r .round "$Q3_DIR/first-epoch2-certificate.json")
  [ "$first" -ge "$astar" ] || { echo "first observed epoch-2 certificate round $first is below A*=$astar" >&2; return 1; }
  printf 'E=%s\nA_min=%s\nA*=%s\nactivationCommitId=%s\nv3BodyId=%s\nfirst observed epoch-2 certificate round=%s\n' "$(q3_rec .epoch)" "$amin" "$astar" "$(q3_rec .activationCommitId)" "$(q3_rec .v3BodyId)" "$first" >"$Q3_DIR/activation-coordinates.txt"
  # the old Commit proof is verified under the OLD epoch: unit weights, W=4, three signatures
  jq '.commit.signers' "$Q3_DIR/activation-record.json" >"$Q3_DIR/old-commit-signers.json"
  jq '.commit' "$Q3_DIR/activation-record.json" >"$Q3_DIR/old-commit-proof.json"
  [ "$(jq -r '.commit.scheme' "$Q3_DIR/activation-record.json")" = 1 ] || { echo "the activation's Commit is not a scheme-1 (old epoch) proof" >&2; return 1; }
  rounds=$(q3_check_weights cert "$Q3_DIR/old-commit-signers.json" 4 3) || return 1
  echo "old Commit proof signed by total weight $rounds under the old unit epoch (W=4, Q=3)"
}

q3_acknowledge() {
  local i
  M2_ADVANCE_NO_REPLICA_WAIT=0 h3_advance_authorities 2 1 1 2 3 4 || { echo "authority advance to root epoch 2 / shard epoch 1 failed" >&2; return 1; }
  for i in $(seq 1 180); do h3_registry_is 1 2 && break; sleep 1; done
  h3_registry_is 1 2 || { echo "registry did not reach shard epoch 1 / root epoch 2" >&2; return 1; }
  # the frozen parent and the acknowledgement are recorded BEFORE any user transaction of the new epoch
  jq -n --arg ack "$(h3_slot "$h3_slot_shard")" --arg root "$(h3_slot "$h3_slot_root")" --argjson row "$(h3_evm_row)" \
    '{registrySlotShardEpoch: $ack, registrySlotRootEpoch: $root, evmRow: $row}' >"$Q3_DIR/frozen-parent-ack.json"
  h3_paid 2 || { echo "post-ack paid transaction was not certified at root epoch 2" >&2; return 1; }
}

q3_progress_scheme2() {
  local root=$(h3_first_root) i sg prev=0 round
  : >"$Q3_DIR/scheme-after.txt"
  # consecutive root certificates under scheme 2 at epoch 2, each read from the root's verified state: strictly increasing rounds
  for i in 1 2 3 4; do
    for _ in $(seq 1 30); do
      sg=$(q3_signers_of "$root") || return 1
      round=$(printf '%s' "$sg" | jq -r .round)
      [ "$round" -gt "$prev" ] && break
      sleep 1
    done
    [ "$round" -gt "$prev" ] || { echo "no new root certificate after round $prev" >&2; return 1; }
    [ "$(printf '%s' "$sg" | jq -r '[.epoch, .scheme, .quorum] | join(",")')" = 2,2,true ] || { echo "certificate is not a quorum at epoch 2 / scheme 2: $sg" >&2; return 1; }
    printf '%s\n' "$sg" | jq -c . >>"$Q3_DIR/scheme-after.txt"
    prev=$round
  done
  h3_send_certified 2 || return 1
  h3_progress post-activation 8 || return 1
  q3_x build/ubft q3 signers --root-rpc "$(h3_rpc_url "$root")" --out "$Q3_DIR/signers-root.json" || return 1
  q3_check_weights cert "$Q3_DIR/signers-root.json" "$Q3_TOTAL_WEIGHT" "$Q3_ROOT_QUORUM" >/dev/null || return 1
  tail -n 3 "$Q3_DIR/scheme-after.txt" >"$Q3_DIR/commit-trace.txt"
}

# The EVM shard's requests are counted by the mirrored weights (W=9, Q=5): the root's consensus lines of the weighted view carry the weight of each
# counted request, which must reach the threshold. This is the observable evidence of the EVM request-weight quorum (the root's UC signatures are
# the root committee's, recorded by q3_progress_scheme2).
q3_evm_request_weights() {
  local out="$Q3_DIR/evm-request-weights.txt" i
  : >"$out"
  for i in 1 2 3 4; do
    q3_check_request_weights "$Q3_EVM_TOTAL_WEIGHT" "$Q3_EVM_QUORUM" "test-nodes/root$i/debug.log" >>"$out" 2>/dev/null || true
  done
  [ -s "$out" ] || { echo "no weighted EVM consensus line in any root log" >&2; return 1; }
  # every line must verify, not only the ones that did not fail the loop above
  q3_check_request_weights "$Q3_EVM_TOTAL_WEIGHT" "$Q3_EVM_QUORUM" test-nodes/root1/debug.log test-nodes/root2/debug.log test-nodes/root3/debug.log test-nodes/root4/debug.log >/dev/null || return 1
}

q3_aggregators_unchanged() {
  h3_root_info | jq -c '[.partitionShards[] | select(.partitionId != 8) | {partitionId} + (del(.partitionId, .roundNumber, .trRound, .trLeader) | with_entries(select(.value | type != "number")))]' >"$Q3_DIR/aggregator-after.json"
  cmp -s "$Q3_DIR/aggregator-before.json" "$Q3_DIR/aggregator-after.json" || { echo "aggregator configuration changed across the activation" >&2; return 1; }
  [ "$(jq 'length' "$Q3_DIR/aggregator-after.json")" = 3 ] || return 1
  h3_progress aggregators 8
}

# A real TC with the heavy validator alive: stop a light root; its leader rounds time out; heavy + two lights (8 >= 7) form the scheme-2 TC.
# Epoch 2 is the root's current epoch (the roots restarted into it), so every timeout vote signed from here on is an epoch-2 statement.
q3_real_tc() {
  local root=test-nodes/root1/debug.log mark
  mark=$(wc -l <"$root")
  h3_mark
  stop_pidfile test-nodes/root4/pid 'ubft root-node run' INT
  q3_wait_grep_since 180 "$root" "$mark" "$Q3_PAT_TC" || return 1
  q3_wait_grep_since 60 "$root" "$mark" "$(q3_pat "$Q3_PAT_SIGNED_TIMEOUT" 2)" || return 1
  h3_since_mark | grep -aE "$Q3_PAT_TC|$(q3_pat "$Q3_PAT_SIGNED_TIMEOUT" 2)" | tail -n 20 >"$Q3_DIR/tc-trace.txt"
  [ -s "$Q3_DIR/tc-trace.txt" ] || return 1
  # root 4 returns (same state, same epoch: a plain restart, no archive of its stores)
  m2_start_root 4 2 "$(m2_root_addr 1)" || return 1
  h3_progress after-tc 8
}

# The negative root boundary: the heavy root alone (weight 6 of W=9, Q=7) cannot form a certificate. The three light roots are killed; the heavy root
# keeps timing out (it signs timeout votes) but no timeout certificate forms and no root round commits. With ONE light root back the weight is 7 =
# Q and the chain commits again, so 6 fails and 7 passes at the same boundary.
q3_root_boundary() {
  local root1=test-nodes/root1/debug.log mark mark2 settled end i signed timeouts formed committed
  mark=$(wc -l <"$root1")
  for i in 2 3 4; do stop_pidfile "test-nodes/root$i/pid" 'ubft root-node run' KILL; done
  sleep 12     # what was in flight commits or dies out; the chain is then stuck
  settled=$(q3_signers_of 1 | jq -r .round)
  sleep 40     # four local timeouts (10 s each) of the heavy root alone
  end=$(q3_signers_of 1 | jq -r .round)
  signed=$(tail -n +"$((mark + 1))" "$root1" | grep -ac 'msg="signed timeout vote"')
  timeouts=$(tail -n +"$((mark + 1))" "$root1" | grep -ac 'msg="local timeout"')
  { echo "heavy root alone (weight 6 of 9, quorum 7)"; echo "last committed round after settling: $settled; after 40 s more: $end"; echo "timeout votes signed by the heavy root: $signed (re-broadcast at each of its $timeouts local timeouts)"
    echo "timeout certificates formed: $(tail -n +"$((mark + 1))" "$root1" | grep -ac 'timeout quorum for round')"; } >"$Q3_DIR/root-boundary.txt"
  [ "$end" = "$settled" ] || { echo "the heavy root alone committed rounds ($settled -> $end): weight 6 formed a certificate" >&2; return 1; }
  # it signs its timeout vote once for the stuck round and sends the same vote again at every local timeout
  [ "$signed" -ge 1 ] && [ "$timeouts" -ge 3 ] || { echo "the heavy root signed $signed timeout votes with $timeouts local timeouts in 52 s: it was not running its rounds" >&2; return 1; }
  [ "$(tail -n +"$((mark + 1))" "$root1" | grep -ac 'timeout quorum for round')" = 0 ] || { echo "a timeout certificate formed from weight 6" >&2; return 1; }
  # one light root back: 6 + 1 = 7 >= Q. The two other roots stay down, and the weighted proposer-priority selector (#489) gives the heavy root about
  # two thirds of the rounds, so consecutive live leaders occur and rounds COMMIT; the timeout certificates that bridge the dead leaders are counted too.
  mark2=$(wc -l <"$root1")
  m2_start_root 2 2 "$(m2_root_addr 1)" || return 1
  for i in $(seq 1 180); do
    [ "$(q3_signers_of 1 2>/dev/null | jq -r .round 2>/dev/null)" -gt "$end" ] 2>/dev/null && break
    sleep 1
  done
  committed=$(q3_signers_of 1 | jq -r .round)
  formed=$(tail -n +"$((mark2 + 1))" "$root1" | grep -ac 'timeout quorum for round')
  echo "heavy + one light root (weight 7 of 9): committed round $committed (was stuck at $end), $formed timeout certificates in the window" >>"$Q3_DIR/root-boundary.txt"
  [ "$committed" -gt "$end" ] || { echo "heavy plus one light (weight 7) did not commit a round ($end -> $committed)" >&2; return 1; }
  m2_start_root 3 2 "$(m2_root_addr 1)" || return 1
  m2_start_root 4 2 "$(m2_root_addr 1)" || return 1
  h3_progress root-boundary-restored 8
}

# The negative EVM boundary: three light EVM validators (weight 3 of W=9, Q=5) cannot get a shard certification accepted. The heavy entity's shard node is
# stopped (its Ureth and signing authority stay); the three lights keep sending requests and the root counts them, but never reaches consensus for the
# EVM partition, so its certified IR does not move. With the heavy shard node back, the shard certifies again.
q3_evm_boundary() {
  local heavy=1 i rounds_before rounds_after consensus notyet submitted rootBoot bootnodes
  [ "$(q3_weight_of "$heavy")" = 6 ] || { echo "entity $heavy is not the heavy one" >&2; return 1; }
  stop_one_evm_validator "$heavy" || return 1
  sleep 10     # a certification in flight when the heavy node stopped lands or dies out
  rounds_before=$(h3_root_info | jq -r '.partitionShards[] | select(.partitionId == 8) | .roundNumber')
  for i in 1 2 3 4; do q3_mark_log "test-nodes/root$i/debug.log" "boundary-root$i"; done
  for i in 2 3 4; do q3_mark_log "test-nodes/evm$i/debug.log" "boundary-evm$i"; done
  sleep 45
  rounds_after=$(h3_root_info | jq -r '.partitionShards[] | select(.partitionId == 8) | .roundNumber')
  consensus=0; notyet=0; submitted=0
  for i in 1 2 3 4; do
    consensus=$((consensus + $(q3_since_mark "test-nodes/root$i/debug.log" "boundary-root$i" | grep -ac 'partition 00000008 reached consensus')))
    notyet=$((notyet + $(q3_since_mark "test-nodes/root$i/debug.log" "boundary-root$i" | grep -ac 'partition 00000008 quorum not yet reached')))
  done
  for i in 2 3 4; do submitted=$((submitted + $(q3_since_mark "test-nodes/evm$i/debug.log" "boundary-evm$i" | grep -ac 'submitting block certification request'))); done
  { echo "heavy EVM entity $heavy stopped; three light EVM validators (weight 3 of 9, quorum 5) for 45 s"; echo "EVM partition IR round: $rounds_before -> $rounds_after"
    echo "light validators' certification requests submitted: $submitted"; echo "root lines 'quorum not yet reached' for the EVM partition: $notyet"; echo "root lines 'reached consensus' for the EVM partition: $consensus"; } >"$Q3_DIR/evm-boundary.txt"
  [ "$submitted" -ge 1 ] || { echo "the light validators submitted no certification request" >&2; return 1; }
  [ "$notyet" -ge 1 ] || { echo "the roots counted no request of the light validators" >&2; return 1; }
  [ "$consensus" = 0 ] || { echo "the roots reached consensus on the EVM partition from weight 3" >&2; return 1; }
  [ "$rounds_after" = "$rounds_before" ] || { echo "the EVM partition certified a state ($rounds_before -> $rounds_after) from weight 3" >&2; return 1; }
  rootBoot=$(m2_root_addr 1) || return 1
  bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$heavy" $(m2_online_validators)) || return 1
  start_one_evm_validator "$heavy" 4 "$partitionID" "$rootBoot" engine-api rpc "$bootnodes" || return 1
  h3_progress evm-boundary-restored 8
}

q3_ids() { grep -aoE 'messageID=[0-9a-f]+' | sort -u; }

# The heavy-validator crash across E. The three light roots are SIGKILLed first, so the heavy root (6 < 7) alone cannot form a timeout certificate and
# its signed timeout vote reaches no one; it is SIGKILLed right after signing (a kill that only waits for the log line races the 40 ms broadcast to the
# lights, whose own votes would complete a certificate and consume the vote: run 23). The lights and then the heavy restart; the safety module must recover the ORIGINAL message (its identity is the SHA-256 of the exact signed
# statement) and rebroadcast it, the TC must form, and commits must resume. No orderly stop and no retry of the module alone. Only the TIMEOUT is
# observable as a rebroadcast; the vote held again at start is logged with its identity ("recovered last vote") and compared with the signed one.
q3_heavy_crash() {
  local root1=test-nodes/root1/debug.log signed lastsigned recovered recov rebroadcast i mark
  mark=$(wc -l <"$root1")
  for i in 2 3 4; do stop_pidfile "test-nodes/root$i/pid" 'ubft root-node run' KILL; done   # the lights away: the heavy root cannot complete a certificate alone
  q3_wait_grep_since 180 "$root1" "$mark" "$(q3_pat "$Q3_PAT_SIGNED_TIMEOUT" 2)" || return 1
  stop_pidfile test-nodes/root1/pid 'ubft root-node run' KILL          # the heavy root dies right after signing
  signed=$(tail -n +"$((mark + 1))" "$root1" | grep -aE "$(q3_pat "$Q3_PAT_SIGNED_TIMEOUT" 2)" | q3_ids)
  [ -n "$signed" ] || { echo "no signed timeout identity to compare against" >&2; return 1; }
  lastsigned=$(tail -n +"$((mark + 1))" "$root1" | grep -aE "$(q3_pat "$Q3_PAT_SIGNED_TIMEOUT" 2)" | tail -n 1 | q3_ids | sed 's/messageID=//')
  printf '%s\n' "$signed" >"$Q3_DIR/signed-before-crash.txt"
  mark=$(wc -l <"$root1")
  # a cold network: the heavy root starts first without a bootnode (as at genesis), the lights follow with it as their bootnode
  m2_start_root 1 2 "" || return 1
  for i in 2 3 4; do m2_start_root "$i" 2 "$(m2_root_addr 1)" || return 1; done
  # the last vote the node stored before it died is held again at start under the identity it was signed with (independent of the timer path below)
  q3_wait_grep_since 60 "$root1" "$mark" "msg=\"recovered last vote\" .*kind=timeout round=[0-9]+ messageID=$lastsigned" || return 1
  # The original message comes back by one of two paths, both with its identity: the pacemaker is reset from the stored last vote (which a node that
  # stored its timeout vote before dying always holds), or the safety module returns the recorded timeout when no vote is held.
  recov="msg=\"recovered last vote\" .*kind=timeout .*messageID=[0-9a-f]{64}|$(q3_pat "$Q3_PAT_RECOVERED" 2)"
  q3_wait_grep_since 120 "$root1" "$mark" "$recov" || return 1
  recovered=$(tail -n +"$((mark + 1))" "$root1" | grep -aE "$recov")
  q3_wait_grep_since 120 "$root1" "$mark" "$Q3_PAT_REBROADCAST" || return 1
  rebroadcast=$(tail -n +"$((mark + 1))" "$root1" | grep -aE "$Q3_PAT_REBROADCAST")
  printf '%s\n' "$recovered" >"$Q3_DIR/recovered-message.txt"
  printf '%s\n' "$rebroadcast" >"$Q3_DIR/rebroadcast-trace.txt"
  # exact-statement reproduction: every recovered identity was signed before the crash, and a recovered one is rebroadcast unchanged
  for i in $(printf '%s\n' "$recovered" | q3_ids); do
    printf '%s\n' "$signed" | grep -qx "$i" || { echo "recovered $i was not signed before the crash" >&2; return 1; }
    printf '%s\n' "$rebroadcast" | q3_ids | grep -qx "$i" || { echo "recovered $i was not rebroadcast" >&2; return 1; }
  done
  # the TC forms and commits resume: the root reports quorum certificates of epoch 2 again
  q3_wait_grep_since 180 "$root1" "$mark" "$Q3_PAT_TC" || return 1
  h3_progress after-heavy-crash 8 "${H3_POST_RESTART_WINDOW:-}" || return 1
  [ "$(q3_signers_of 1 | jq -r '[.epoch, .scheme, .quorum] | join(",")')" = 2,2,true ] || { echo "no epoch-2 scheme-2 quorum certificate after the crash" >&2; return 1; }
  q3_history_ids "$Q3_DIR/history-ids-post-restart.txt" || return 1
  # no verified history identity was lost across the restart: every pre-restart ID is still retained
  [ -z "$(comm -23 <(sort "$Q3_DIR/history-ids-pre-restart.txt") <(sort "$Q3_DIR/history-ids-post-restart.txt"))" ] || { echo "history identities lost across the restart" >&2; return 1; }
  return 0
}

# ---- a subsequent scheme-2 handoff, and the supersession of an unacknowledged one ---------------------------------------------------------------
# Handoff 2 (root epoch 2 -> 3, the same four entities, weights (4,3,1,1): part of the heavy weight moves to entity 2) is committed by the weighted epoch-2 committee under
# scheme 2 (a heavy-plus-one-light Commit, 7 of 9) and activates, but its acknowledgement is withheld: the registry stays at shard epoch 1. Handoff 3
# (epoch 3 -> 4) is the RECOVERY of that pending primary (assembled with --recovery --supersede): a derived candidate that is exactly K, the committee of the last
# acknowledged assignment (6,1,1,1), on the same frozen parent. Its folded acknowledgement takes the registry from shard epoch 1 straight to 3 (the primary J and the
# recovery K fold into one acknowledgement), and the superseded primary is never acknowledged. A supersession cannot install a new committee: a primary over a pending
# primary is refused (evmassign.ErrPendingPrimary), and the recovery's K is the incumbent by construction.
Q3_WEIGHTS_1=$Q3_WEIGHTS
Q3_WEIGHTS_2="4 3 1 1"      # part of the way to a swap: distance 4/9 from (6,1,1,1)
Q3_WEIGHTS_3=$Q3_WEIGHTS_1 # the recovery returns to K, the last acknowledged committee (6,1,1,1); the epoch-4 root committee mirrors it
Q3_WEIGHTS_SWAP="1 6 1 1"   # the full heavy-weight swap: 10/9, refused

# The four shard services' operator endpoints (the candidate staging and the readiness check use them): which answer, and the process behind each port. Recorded before
# the late steps so a service that disappears is named at the step where it does, not later as a refused staging.
q3_services_report() { # label: appends to services.txt; fails naming every entity whose endpoint does not answer
  local label=$1 i addr down=() pid
  { echo "== $label"
    for i in $H3_ROOTS; do
      addr=$(evm_validator_rpc_addr "$i")
      pid=$(lsof -nP -iTCP:"${addr##*:}" -sTCP:LISTEN -t 2>/dev/null | head -1)
      if curl -fsS -m 5 -X POST -H 'content-type: application/json' -d '{}' "http://$addr/api/v1/q3/status" >/dev/null 2>&1; then
        echo "entity $i operator $addr: answers (pid ${pid:-?})"
      else
        echo "entity $i operator $addr: NOT answering (listener pid ${pid:-none}; node pid file: $(cat "test-nodes/evm$i/pid" 2>/dev/null || echo none), alive: $(kill -0 "$(cat "test-nodes/evm$i/pid" 2>/dev/null)" 2>/dev/null && echo yes || echo no))"
        down+=("$i")
      fi
    done; } >>"$Q3_DIR/services.txt"
  [ "${#down[@]}" -eq 0 ] || { echo "the shard operator endpoint of entity ${down[*]} does not answer at step '$label' (see $Q3_DIR/services.txt)" >&2; tail -n $((${#down[@]} + 1 + 4)) "$Q3_DIR/services.txt" >&2; return 1; }
}

# The negative continuity row: the full heavy-weight swap (6,1,1,1 -> 1,6,1,1) has weight distance 10/9, above the committed budget 1/1, and the root refuses to derive its
# candidate. Nothing is planned or ordered; the registry and the chain are unchanged. The positive rows are the handoffs that stay inside the budget.
q3_continuity_refusal() {
  q3_services_report "before the continuity refusal" || return 1
  local err budget out="$Q3_DIR/continuity-refusal.txt"
  budget=$(jq -r '.partitionParams.continuity_max_distance' "$fullShardConf")
  [ "$budget" = 1/1 ] || { echo "the genesis configuration commits continuity_max_distance=$budget, not 1/1" >&2; return 1; }
  Q3_WEIGHTS=$Q3_WEIGHTS_SWAP Q3_SUFFIX=-swap Q3_NEXT_EPOCH=3 Q3_ASSIGN_TAG=swap Q3_INCUMBENT="$Q3_DIR/cand-identities.json"
  q3_trust_base_v3 3 || return 1
  q3_build_assignment swap 1 2 3 4 || return 1
  if err=$(q3_derive_candidate 2>&1); then
    echo "the full heavy-weight swap (distance 10/9, budget $budget) was accepted" >&2; return 1
  fi
  Q3_WEIGHTS=$Q3_WEIGHTS_1; unset Q3_SUFFIX Q3_NEXT_EPOCH Q3_ASSIGN_TAG Q3_INCUMBENT
  printf '%s\n' "$err" | grep -q 'weight distance exceeded' || { echo "the swap was refused, but not for its weight distance: $err" >&2; return 1; }
  h3_registry_is 1 2 || { echo "the registry moved while the swap was refused" >&2; return 1; }
  { echo "committed budget continuity_max_distance=$budget (normalized weight distance sum|w/W - v/V|)"
    echo "inside the budget (accepted): handoff 1 (1,1,1,1)->(6,1,1,1) 5/6; handoff 2 (6,1,1,1)->(4,3,1,1) 4/9; handoff 3 is the derived recovery to K=(6,1,1,1), the last acknowledged committee (no new committee: a primary over a pending primary is refused)"
    echo "outside the budget (refused): (6,1,1,1)->(1,6,1,1) 10/9"
    echo "refusal:"; printf '%s\n' "$err" | grep -v '^$'; } >"$out"
}

q3_second_handoff() { q3_services_report "before handoff 2" || return 1; q3_handoff_n 2 3 "$Q3_WEIGHTS_2" 0 "$Q3_DIR/cand-identities.json"; }

q3_second_activation() {
  q3_install_n 3 || return 1
  q3_activation_n 2 3 || return 1
  # activated, not acknowledged: the registry has not moved
  h3_registry_is 1 2 || { echo "the registry moved (shard epoch $(h3_slot "$h3_slot_shard"), root epoch $(h3_slot "$h3_slot_root")) before handoff 2 was acknowledged" >&2; return 1; }
  { echo "handoff 2 activated at root epoch 3, acknowledgement withheld"; echo "registry shard epoch $(h3_slot "$h3_slot_shard"), root epoch $(h3_slot "$h3_slot_root")"; } >"$Q3_DIR/supersession.txt"
}

q3_supersede() {
  Q3_RECOVERY=1 q3_handoff_n 3 4 "$Q3_WEIGHTS_3" 1 "$Q3_DIR/cand-identities.json" || return 1
  q3_install_n 4 || return 1
  q3_activation_n 3 4 || return 1
  M2_ADVANCE_NO_REPLICA_WAIT=0 h3_advance_authorities 4 3 1 2 3 4 || { echo "authority advance to root epoch 4 / shard epoch 3 failed" >&2; return 1; }
  local i
  for i in $(seq 1 180); do h3_registry_is 3 4 && break; sleep 1; done
  h3_registry_is 3 4 || { echo "registry did not reach shard epoch 3 / root epoch 4 (shard epoch $(h3_slot "$h3_slot_shard"), root epoch $(h3_slot "$h3_slot_root"))" >&2; return 1; }
  { echo "handoff 3 (the derived recovery to K, assembled with --recovery --supersede) activated at root epoch 4 and acknowledged"; echo "registry shard epoch $(h3_slot "$h3_slot_shard") (was 1; the superseded assignment, shard epoch 2, was never acknowledged), root epoch $(h3_slot "$h3_slot_root")"; } >>"$Q3_DIR/supersession.txt"
  h3_paid 4 || { echo "post-supersession paid transaction was not certified at root epoch 4" >&2; return 1; }
  h3_progress after-supersession 8
}

# The leader schedule of the activated epoch: with mirrored weights (6,1,1,1) the proposer-priority selector of a weighted epoch (#403, activated by #489)
# gives the heavy root about 6/9 of the rounds; the legacy selector gave a quarter each. The evidence file states what the root logs show, and the
# step fails when the heavy root's share is not weight-proportional.
q3_leader_schedule() {
  # epoch 2 only: from its activation round to the activation round of epoch 3 (the weights change there)
  local astar end; astar=$(jq -r .activationRound "$Q3_DIR/activation-record.json")
  end=$(jq -r '.activationRound // empty' "$Q3_DIR/activation-record-3.json" 2>/dev/null); end=${end:-999999999}
  python3 - "$Q3_DIR/leader-schedule.txt" "$astar" "$end" "$(q3_weight_of 1)" "$Q3_WEIGHTS" test-nodes/root1/debug.log test-nodes/root2/debug.log test-nodes/root3/debug.log test-nodes/root4/debug.log <<'PY'
import re, sys, collections
out, astar, end, w1, weights, *logs = sys.argv[1:]
astar = int(astar); end = int(end); weights = [int(x) for x in weights.split()]
ids = {}
for i, path in enumerate(logs, 1):
    for line in open(path, errors="replace"):
        m = re.search(r"node_id=(16\*\w+)", line)
        if m:
            ids[m.group(1)] = i
            break
counts, seen = collections.Counter(), set()
for line in open(logs[0], errors="replace"):
    m = re.search(r"next leader <peer.ID (16\*\w+)>.* round=(\d+)", line)
    if m and "minimum required duration" in line:
        r = int(m.group(2))
        if astar <= r < end and r not in seen:
            seen.add(r)
            counts[ids.get(m.group(1), m.group(1))] += 1
total = sum(counts.values())
lines = [f"leader of the {total} rounds of epoch 2, from A*={astar} to {end} (next leader after each round, root 1's log):"]
for i, w in enumerate(weights, 1):
    n = counts.get(i, 0)
    lines.append(f"  root {i}: weight {w}/{sum(weights)} = {100 * w // sum(weights)}%, led {n} rounds = {100 * n // max(total, 1)}%")
heavy = counts.get(1, 0) / max(total, 1)
verdict = "weight-proportional (proposer-priority, root-wrr-v1)" if heavy >= 0.5 else "uniform: the legacy selector (no leader policy is activated; the weights do not shape the schedule)"
lines.append(f"selector in effect: {verdict}")
open(out, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
# since #489 a weighted epoch uses the proposer-priority selector: the heavy root (weight 6 of 9) leads about two thirds of the rounds
if not (0.5 <= heavy <= 0.8):
    sys.exit("the heavy root led %d%% of the rounds: the schedule is not weight-proportional" % int(100 * heavy))
PY
}

# The proof envelope for the activation (Go side; there is no Rust proof verifier any more).
q3_proof_envelope() {
  q3_x build/ubft q3 proof-envelope --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --epoch 2 --out "$Q3_DIR/proof-envelope.cbor" || return 1
  [ -s "$Q3_DIR/proof-envelope.cbor" ]
}

# ---- two independently verifying pairs (delta section 1: each pair's own Go reconstructs the history from the pinned root genesis and derives the
# exact execution input; another pair reproduces it). Pair A is entity 1's BFT node + Ureth. Pair B is entity 4 after a FRESH restore: its home and its
# Ureth data directory are new, so its Go rebuilds the verified history from the pinned root genesis (restore runs with --q3-lane) and its Ureth
# re-executes from genesis under its own bindings. It shares no store, verification result or cache with pair A. ---------------------------------------
Q3_PAIR_A=1
Q3_PAIR_B=4

q3_pair_export() { # pair-tag entity block-number: the pair's own retained canonical bytes and EVM head for the same numbered block
  local pair=$1 i=$2 number=$3
  q3_x build/ubft q3 pair-export --eth-url "$(q3_eth_url "$i")" --block-number "$number" \
    --root-input-out "$Q3_DIR/pair-root-input-$pair.bin" --transitions-out "$Q3_DIR/pair-transitions-$pair.bin" --state-out "$Q3_DIR/pair-state-$pair.json"
}

# Pair B startup: wipe entity 4's home and execution client (identity and authority kept), restore it from entity 1's archive from the genesis trust
# base, and wait for it to catch up to pair A's execution head. The restore is the repo's own h3_restore_validator; nothing is copied from pair A except
# the archive the restore protocol itself reads and re-verifies.
q3_start_second_pair() {
  local a=$Q3_PAIR_A b=$Q3_PAIR_B head_a head_b i
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json
  # the activation of epoch 2 is not archived as a handoff-delivery bundle: the restore pin takes the body identity the lane activated
  export H4_RESTORE_BODY_IDS="2=$(tr -d '[:space:]' <"$Q3_DIR/v3-body-id.txt")"
  h3_restore_validator "$b" "$a" || return 1
  for i in $(seq 1 240); do
    head_a=$(rpc "$(q3_eth_url "$a")" eth_blockNumber '[]' | pyget "['result']")
    head_b=$(rpc "$(q3_eth_url "$b")" eth_blockNumber '[]' | pyget "['result']")
    [ -n "$head_b" ] && [ "$head_b" != None ] && [ "$((head_a))" -le "$((head_b + 2))" ] && return 0
    sleep 1
  done
  echo "pair B (entity $b) did not catch up to pair A: A at ${head_a:-?}, B at ${head_b:-?}" >&2
  return 1
}

q3_second_pair() {
  local head_a head_b number
  h3_progress second-pair-sync 8 || return 1
  head_a=$(rpc "$(q3_eth_url "$Q3_PAIR_A")" eth_blockNumber '[]' | pyget "['result']")
  head_b=$(rpc "$(q3_eth_url "$Q3_PAIR_B")" eth_blockNumber '[]' | pyget "['result']")
  number=$(( head_a < head_b ? head_a : head_b ))
  number=$((number - 2))                    # a block both pairs have settled
  [ "$number" -gt 0 ] || { echo "no settled block to compare (A $head_a, B $head_b)" >&2; return 1; }
  q3_pair_export a "$Q3_PAIR_A" "$number" || return 1
  q3_pair_export b "$Q3_PAIR_B" "$number" || return 1
  q3_pair_equal "$Q3_DIR" || return 1
  { echo "block=$number"; echo "root-input sha256: $(shasum -a 256 "$Q3_DIR/pair-root-input-a.bin" | cut -d' ' -f1)"
    echo "transitions sha256: $(shasum -a 256 "$Q3_DIR/pair-transitions-a.bin" | cut -d' ' -f1)"
    echo "head: $(jq -r .head "$Q3_DIR/pair-state-a.json") stateRoot: $(jq -r .stateRoot "$Q3_DIR/pair-state-a.json")"; } >"$Q3_DIR/pair-equality.txt"
}

# Refusal controls on the current release only: each rebuilds pair A's latest block ONCE with exactly one thing changed (positive control first: the
# unchanged rebuild is accepted) and requires ITS OWN typed sentinel from ureth#52. After every control the chain is unchanged and still progressing.
q3_pair_control() { # kind sentinel-name
  local kind=$1 sentinel=$2 out=$Q3_DIR/pair-control-$1.out
  if q3_x build/ubft q3 pair-control --kind "$kind" --engine-url "$(q3_engine_url 1)" --jwt-secret test-nodes/evm1/jwt.hex --eth-url "$(q3_eth_url 1)" >"$out" 2>&1; then
    echo "tampered submission ($kind) was accepted" >&2; return 1
  fi
  { echo "== control: $kind"; cat "$out"; } >>"$Q3_DIR/refusals-pair.log"
  eval "sentinel=\$Q3_SENTINEL_$sentinel"
  q3_assert_refusal "$out" "$sentinel" "pair control $kind" || return 1
  h3_progress "after-control-$kind" 8
}

q3_pair_controls() {
  q3_services_report "before the pair controls" || return 1
  : >"$Q3_DIR/refusals-pair.log"
  q3_x build/ubft q3 pair-control --kind accept --engine-url "$(q3_engine_url 1)" --jwt-secret test-nodes/evm1/jwt.hex --eth-url "$(q3_eth_url 1)" >"$Q3_DIR/pair-control-accept.out" 2>&1 \
    || { echo "positive control failed: the unchanged rebuild was refused: $(cat "$Q3_DIR/pair-control-accept.out")" >&2; return 1; }
  q3_pair_control wrong-parent PAIR_PARENT || return 1
  q3_pair_control wrong-job PAIR_JOB || return 1
  q3_pair_control substituted-input PAIR_ROOT_INPUT || return 1
  q3_pair_control missing-evidence PAIR_MISSING || return 1
  q3_pair_restart_control || return 1
}

# Restart pair A's execution client with the SAME Engine secret its node holds (h3_start_reth draws a new one, which would cut the node off).
q3_restart_reth_same_secret() { # entity
  local i=$1 old waited=0
  old=$(cat "test-nodes/reth$i/pid" 2>/dev/null)
  stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' INT
  # the old client must be GONE before a new one opens its database: it flushes on ctrl-c and holds the storage lock until it exits
  while [ -n "$old" ] && kill -0 "$old" 2>/dev/null; do
    waited=$((waited + 1))
    [ "$waited" -le 180 ] || { echo "execution client $old of entity $i still running 90 s after ctrl-c" >&2; return 1; }
    sleep 0.5
  done
  "$URETH_BIN" node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) --http.api eth,net,web3,admin,debug \
    --rpc.eth-proof-window 64 --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    --engine.persistence-threshold "$d2cPersistenceThreshold" --builder.gaslimit "${URETH_BUILDER_GASLIMIT:-30000000}" \
    $(urethPinUnicityFlags) >>"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
  for _ in $(seq 1 120); do rpc "$(q3_eth_url "$i")" eth_blockNumber '[]' | grep -q '"result"' && return 0; sleep 1; done
  return 1
}

# The restart control: pair A's node and Ureth both restart. Ureth's retained accounting is a cached projection that resolves nothing until its head
# is admitted, and the ONLY admission is the node's own startup one: the node re-derives the head's root input from the witnesses retained with it
# under its own verified history and presents the binding of that derivation (a node that cannot refuses to start, so the progress check below fails).
# The retained block must then come back byte-identical.
q3_pair_restart_control() {
  local a=$Q3_PAIR_A number rootBoot bootnodes
  number=$(awk -F= '$1=="block"{print $2}' "$Q3_DIR/pair-equality.txt")
  rootBoot=$(m2_root_addr 1) || return 1
  stop_one_evm_validator "$a" || return 1
  q3_restart_reth_same_secret "$a" || return 1
  bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$a" $(m2_online_validators)) || return 1
  start_one_evm_validator "$a" 4 "$partitionID" "$rootBoot" engine-api rpc "$bootnodes" || return 1
  h3_progress after-restart-control 8 || return 1
  q3_pair_export a1 "$a" "$number" || return 1
  [ "$(jq -r .head "$Q3_DIR/pair-state-a.json")" = "$(jq -r .head "$Q3_DIR/pair-state-a1.json")" ] || { echo "restarted pair A reports another block $number" >&2; return 1; }
  q3_cmp_bytes "$Q3_DIR/pair-root-input-a.bin" "$Q3_DIR/pair-root-input-a1.bin" || { echo "restarted pair A reproduced different root-input bytes" >&2; return 1; }
  q3_cmp_bytes "$Q3_DIR/pair-transitions-a.bin" "$Q3_DIR/pair-transitions-a1.bin" || { echo "restarted pair A reproduced different transition bytes" >&2; return 1; }
  { echo "== control: restart (node + Ureth)"; echo "block $number reproduced after restart; the node's startup admission succeeded or the node would not have started"; } >>"$Q3_DIR/refusals-pair.log"
  echo "pair A restarted (node and Ureth); block $number reproduced byte-identically" >"$Q3_DIR/pair-restart.txt"
}

q3_evidence_complete() { q3_evidence_check "$Q3_DIR"; }

Q3_STEPS="q3_baseline q3_candidate q3_handoff q3_install_epoch2 q3_activation q3_acknowledge q3_progress_scheme2 q3_evm_request_weights \
q3_aggregators_unchanged q3_real_tc q3_root_boundary q3_evm_boundary q3_heavy_crash q3_proof_envelope q3_start_second_pair q3_second_pair q3_pair_controls q3_continuity_refusal q3_second_handoff q3_second_activation q3_supersede q3_leader_schedule q3_evidence_complete"

q3_run_lane() {
  local s
  mkdir -p "$Q3_DIR"; : >"$Q3_DIR/commands.log"
  cp "${Q3_PINS_FILE:?}" "$Q3_DIR/pins.txt"
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json
  Q3_GENESIS_IDENTITIES=test-nodes/genesis-identities.json
  H3_REGISTRY=0xff00000000000000000000000000000000000002
  H3_ONLINE="1 2 3 4"; H3_ROOTS="1 2 3 4"
  M2_NEXT_NONCE=${M2_NEXT_NONCE:-4}; M2_CHAIN_ID=31337
  read -r h3_slot_shard h3_slot_root h3_slot_conf h3_slot_cursor < <(H3_SLOT_LAYOUT=$([ "${Q3_B1:-0}" = 1 ] && echo 3 || echo 2) go run ./scripts/h3slots)
  echo "=== Q3 #50 weight-activation lane: fresh-B1 unit PoA -> mirrored weights $Q3_WEIGHTS ==="
  for s in $Q3_STEPS; do q3_step "$s" "$s"; done
  echo "Q3 weight-activation lane: all steps PASSED"
  q3_teardown
}
[ "${Q3_LANE_DEFINE_ONLY:-0}" = 1 ] || q3_run_lane
