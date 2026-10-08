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

q3_pass() { echo "  PASS: $*"; }
q3_x() { printf '%s\n' "$*" >>"$Q3_DIR/commands.log"; "$@"; }          # every lane command is recorded, then run
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
  jq --argjson w "{$w}" 'map(.weight = $w[.rootNodeId])' "$Q3_GENESIS_IDENTITIES" >"$out"
}

# The coupled assignment (the same four entities, mirrored weights): h3_build_assignment with the mirrored stakes, the successor identity
# records every possession proof signs, and the recovery authorization whose K is the genesis committee the root recorded at genesis.
q3_build_assignment() { # tag ids...
  local tag=$1 id pops=; shift
  q3_validators_json "$Q3_DIR/$tag-validators.json" "$@" || return 1
  build/ubft root handoff evm-context --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$Q3_DIR/$tag-context.json" || return 1
  q3_successor_identities "$Q3_DIR/$tag-identities.json" "$@" || return 1
  q3_x build/ubft root handoff evm-authorization --context "$Q3_DIR/$tag-context.json" --incumbent "$Q3_GENESIS_IDENTITIES" \
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
    --pops "$pops" --bindings "$Q3_DIR/$tag-bindings.json" --out "$Q3_DIR/$tag-assignment.json" || return 1
}

# The candidate root trust base: same members and keys, the mirrored weights (--root-weights follows the --node-info order; the V3 protocol tuple is
# the root's own configured one, carried by the V3 body, not by the trust base).
q3_trust_base_v3() { # epoch
  local epoch=$1 i infos=() w=${Q3_WEIGHTS// /,}
  for i in $H3_ROOTS; do infos+=(--node-info "test-nodes/root$i/node-info.json"); done
  q3_x build/ubft trust-base generate --home test-nodes --network-id 3 --epoch "$epoch" --epoch-start "$((epoch * 100000))" \
    --previous-trust-base "test-nodes/trust-base-epoch$((epoch-1)).json" --root-weights "$w" \
    --output-file-name "trust-base-epoch${epoch}.json" "${infos[@]}" >/dev/null || return 1
  for i in $H3_ROOTS; do build/ubft trust-base sign --home "test-nodes/root$i" --trust-base "test-nodes/trust-base-epoch${epoch}.json" >/dev/null || return 1; done
}

# The operator's own pins for the readiness check: never read from the execution client under test. The registry code comes from the chain spec the
# clients were started with; the genesis block hash is the one entity 1's client reported at the start of the lane (recorded in pins.txt).
q3_execution_pins() {
  Q3_EXEC_GENESIS=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBlockByNumber '["0x0",false]' | pyget "['result']['hash']") || return 1
  Q3_EXEC_CODE_HASH=$(python3 - "$chainSpec" "$H3_REGISTRY" <<'PY'
import hashlib, json, sys
alloc = json.load(open(sys.argv[1]))["alloc"]
want = sys.argv[2].lower().removeprefix("0x")
for k, v in alloc.items():
    if k.lower().removeprefix("0x") == want:
        print(hashlib.sha256(bytes.fromhex(v["code"].removeprefix("0x"))).hexdigest()); break
else:
    sys.exit("registry not in the chain spec")
PY
  ) || return 1
  printf 'execution genesis hash: %s\nregistry code sha256: %s\n' "$Q3_EXEC_GENESIS" "$Q3_EXEC_CODE_HASH" >>"$Q3_DIR/pins.txt"
}

# ---- the root's verified Q3 endpoints (local operator API) --------------------------------------------------------------------------------------
q3_signers_of() { curl -fsS -X POST -H 'content-type: application/json' -d '{}' "$(h3_rpc_url "$1")/api/v1/q3/signers"; }   # {epoch,round,scheme,signers,signedTotal,threshold,quorum}
q3_rec() { jq -r "$1" "$Q3_DIR/activation-record.json"; }
q3_weight_of() { echo "$Q3_WEIGHTS" | awk -v n="$1" '{print $n}'; }

# ---- readiness: one receipt per entity, from its root key, after checking its BFT node, its shard service and its paired Ureth --------------------
q3_readiness() { # entity out: a receipt for the staged candidate, or the typed refusal on stderr
  local i=$1 out=$2
  q3_x build/ubft root handoff q3-readiness --candidate "$Q3_DIR/candidate.cbor" --key-conf "test-nodes/root$i/keys.json" \
    --root-rpc "$(h3_rpc_url "$i")" --shard-rpc "http://$(evm_validator_rpc_addr "$i")" --eth-url "http://127.0.0.1:$((rethEthBase + i - 1))" \
    --execution-genesis-hash "$Q3_EXEC_GENESIS" --execution-code-hash "$Q3_EXEC_CODE_HASH" --out "$out"
}
q3_engine_url() { echo "http://127.0.0.1:$((rethEngineBase + $1 - 1))"; }
q3_eth_url() { echo "http://127.0.0.1:$((rethEthBase + $1 - 1))"; }

q3_derive_candidate() { # the root's derivation of the V3 candidate for the current attempt
  rm -rf "$Q3_DIR/candidate.d"
  q3_x build/ubft root handoff q3-candidate --next-trust-base test-nodes/trust-base-epoch2.json \
    --next-evm-assignment "$Q3_DIR/cand-assignment.json" --root-rpc "$(h3_root_rpcs)" --out-dir "$Q3_DIR/candidate.d" || return 1
  cp "$Q3_DIR/candidate.d/candidate.cbor" "$Q3_DIR/candidate.cbor"
  cp "$Q3_DIR/candidate.d/config.json" "$Q3_DIR/candidate-config.json"
  cp "$Q3_DIR/candidate.d/v3-body-id.txt" "$Q3_DIR/v3-body-id.txt"
  cp "$Q3_DIR/candidate.d/root-weights.json" "$Q3_DIR/root-weights.json"
  cp "$Q3_DIR/candidate.d/evm-weights.json" "$Q3_DIR/evm-weights.json"
}

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
  [ "$(registry_layout)" = 2 ] || { echo "registry layout is not 2" >&2; return 1; }
  registry_layout >"$Q3_DIR/registry-layout.txt"
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

q3_receipts() { # exactly one receipt per successor entity, from its root key
  local i
  for i in 1 2 3 4; do q3_readiness "$i" "$Q3_DIR/receipt-$i.json" || return 1; done
  [ "$(ls "$Q3_DIR"/receipt-[1-4].json | wc -l | tr -d ' ')" = 4 ]
}

q3_attempt() { # a retry rebuilds the proofs of possession, the candidate and the receipts for the new attempt number
  q3_build_assignment cand 1 2 3 4 || return 1
  q3_derive_candidate || return 1
  q3_receipts || return 1
  q3_x build/ubft root handoff propose --next-trust-base test-nodes/trust-base-epoch2.json --next-evm-assignment "$Q3_DIR/cand-assignment.json" \
    --root-rpc "$(h3_root_rpcs)" --readiness-receipts "$Q3_DIR/receipt-1.json,$Q3_DIR/receipt-2.json,$Q3_DIR/receipt-3.json,$Q3_DIR/receipt-4.json"
}

q3_handoff() {
  # no pre-restart certificate may be at epoch 2: the roots only install epoch 2 at the restart below
  h3_retry_handoff 1 q3_attempt || return 1
  echo "activating handoff committed at root epoch 1"
}

q3_history_ids() { # out: the verified history identities retained by the first root
  q3_x build/ubft q3 history --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$1" && [ -s "$1" ]
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
  M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 2 1 1 2 3 4 || { echo "authority advance to root epoch 2 / shard epoch 1 failed" >&2; return 1; }
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
  local i=$1
  stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' INT
  "$URETH_BIN" node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) --http.api eth,net,web3,admin,debug \
    --rpc.eth-proof-window 64 --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    --engine.persistence-threshold "$d2cPersistenceThreshold" --builder.gaslimit 30000000 \
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
q3_aggregators_unchanged q3_real_tc q3_heavy_crash q3_proof_envelope q3_start_second_pair q3_second_pair q3_pair_controls q3_evidence_complete"

q3_run_lane() {
  local s
  mkdir -p "$Q3_DIR"; : >"$Q3_DIR/commands.log"
  cp "${Q3_PINS_FILE:?}" "$Q3_DIR/pins.txt"
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json
  Q3_GENESIS_IDENTITIES=test-nodes/genesis-identities.json
  H3_REGISTRY=0xff00000000000000000000000000000000000002
  H3_ONLINE="1 2 3 4"; H3_ROOTS="1 2 3 4"
  M2_NEXT_NONCE=${M2_NEXT_NONCE:-4}; M2_CHAIN_ID=31337
  read -r h3_slot_shard h3_slot_root h3_slot_conf h3_slot_cursor < <(go run ./scripts/h3slots)
  echo "=== Q3 #50 weight-activation lane: layout-2 unit PoA -> mirrored weights $Q3_WEIGHTS ==="
  for s in $Q3_STEPS; do q3_step "$s" "$s"; done
  echo "Q3 weight-activation lane: all steps PASSED"
  q3_teardown
}
[ "${Q3_LANE_DEFINE_ONLY:-0}" = 1 ] || q3_run_lane
