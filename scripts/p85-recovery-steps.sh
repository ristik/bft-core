# Sourced by reth-paired-devnet.sh (P85_LANE=1, Q3_B1=1, M2_PROFILE2=1, SIGNING=authority) after the first paid certified block, in place of
# m2-profile2-handoffs.sh. Design: briefs/p85-recovery-lane.md. Every step prints PASS or FAIL; a FAIL tears down what the lane started.
#
# The genesis is proof of stake (scripts/lib/p85-lib.sh): custody, election and evidence are in the EVM genesis with four bonded identities
# (K = entities 1..4, unit weights), the roots run with --pos-deployment/--pos-evm-rpc/--pos-genesis-identities and ureth with the records hook.
#
# Entities 1..4 are the genesis committee; entity 5 is the JOINER (root5, evm5, auth5, reth5). Root epochs: 1 genesis, 2 the primary J = K + joiner,
# 3 the derived recovery back to K. Shard (EVM) epochs: 0, 1 (J, never acknowledged), 2 (K again, the recovery).
#
#   baseline        PoS genesis is live: custody/election state, records hook
#   joiner nodes    root5 is a FOLLOWER (its key is not in the epoch-1 committee: it signs nothing), evm5 restores as a staging-only joiner
#   joiner onboard  the joiner registers, bonds and delegates through the live contracts (register / bond / admitDelegation; the EVM possession
#                   is its signing authority's SignDelegationPossession)
#   election        the hook-driven election reserves J = K + joiner
#   proofs          `proposal --reserved` -> H3 proofs -> candidate -> every member's authority signs the EVM possession proof -> submit -> finalize
#   controls        the plan without the EVM proofs, and with a proof the election did not store, is refused by the root
#   handoff         readiness receipts (the joiner's too), the V3 plan with the v4 Freeze companion, H commits; install; activation
#   J stalls        the joiner and one retained member go down (their EVM services; their roots stay for the root quorum): J (3 of 5) cannot certify
#   recovery        the derived recovery (exact K, no receipts, supersedes J) commits, the roots return to K's entities, K (3 of 4) resumes
#   resolved        custody/election: the result is Recovered, K is the last acknowledged assignment, the session closed
#   restarts        every root and one validator restart; certification continues
source scripts/lib/m2-handoff-lib.sh
H3_DIR=${P85_RUN_DIR:-test-nodes/p85/run}
Q3_DIR=$H3_DIR
mkdir -p "$H3_DIR"
source scripts/lib/h3-lib.sh
source scripts/lib/q3-lib.sh
source scripts/lib/q3-flow-lib.sh
source scripts/lib/p85-lib.sh

p85_pass() { echo "  PASS: $*"; }
p85_step_die() {
  local i
  echo "  FAIL: $*" >&2
  for i in 1 2 3 4 5; do [ -f "test-nodes/root$i/debug.log" ] && { echo "--- tail of root$i/debug.log" >&2; tail -n 6 "test-nodes/root$i/debug.log" | cut -c1-300 >&2; }; done
  q3_teardown
  exit 1
}
p85_step() { local name=$1; shift; echo "--- P85 step: $name"; "$@" || p85_step_die "$name"; p85_pass "$name"; }

# ---- chain reads (cast) -------------------------------------------------------------------------------------------------------------------------
P85_DEPLOY=$P85_DIR/pos-deployment.json
p85_eth() { echo "http://127.0.0.1:$rethEthBase"; }
p85_custody() { jq -r .custody "$P85_DEPLOY"; }
p85_election() { jq -r .election "$P85_DEPLOY"; }
p85_call() { "$P85_CAST" call --rpc-url "$(p85_eth)" "$@"; }
p85_open_result() { p85_call "$(p85_election)" "openResult()(bytes32)"; }
p85_result_state() { # result -> the ResultState enum value (1 Reserved, 3 Acknowledged, 4 Recovered)
  "$P85_CAST" call --rpc-url "$(p85_eth)" "$(p85_election)" "result(bytes32)" "$1" | python3 -c "import sys;print(int(sys.stdin.read().strip()[2:66],16))"
}
p85_last_acked() { p85_call "$(p85_custody)" "lastAckedAssignment()(bytes32)"; }
p85_live_count() { p85_call "$(p85_election)" "liveCount()(uint32)" | awk '{print $1}'; }
p85_evm_round() { h3_evm_row | jq -r '.roundNumber'; }

P85_ENTITY_IDS=""   # the peer ids the contracts' node-id words are resolved with (they hold only keccak256 of them)
p85_node_ids() {
  local i out=""
  for i in 1 2 3 4 5; do
    [ -d "test-nodes/root$i" ] && [ -d "test-nodes/evm$i" ] || continue
    out+="${out:+,}$(h3_root_id "$i"),$(evm_validator_id "$i")"
  done
  echo "$out"
}

p85_genesis_assignment() { grep -o '0x[0-9a-fA-F]\{64\}' "$P85_DIR/genesis-assignment.txt" | head -1 | tr 'A-F' 'a-f'; }
p85_sender_key() { echo "$P85_DIR/joiner/owner.key"; }   # funded in the genesis alloc; pays the relayer's transactions

# ---- steps ------------------------------------------------------------------------------------------------------------------------------------
p85_baseline() {
  p85_progress baseline 8 || return 1
  [ -s "${EVM_B1_PROFILE:-}" ] || { echo "no B1 profile: the lane runs on the fresh-B1 stack" >&2; return 1; }
  h3_registry_is 0 1 || return 1
  q3_execution_pins || return 1
  [ "$(p85_live_count)" = 4 ] || { echo "the election's live index holds $(p85_live_count) identities, not the four genesis entities" >&2; return 1; }
  [ "$(p85_open_result)" = "0x0000000000000000000000000000000000000000000000000000000000000000" ] || { echo "an election result is already open" >&2; return 1; }
  [ "$(p85_last_acked | tr 'A-F' 'a-f')" = "$(p85_genesis_assignment)" ] || { echo "custody's last acknowledged assignment is not the genesis assignment" >&2; return 1; }
  cp "$P85_DEPLOY" "$H3_DIR/pos-deployment.json"; cp "$EVM_B1_PROFILE" "$H3_DIR/b1-profile.json"
  p85_bounds_agree || return 1
}

# The continuity budget the roots judge an assignment by (committed in the installed EVM configuration) is the distance bound the election
# was priced under (the contracts' genesis parameter): both are the testnet profile's P85_DIST_NUM/P85_DIST_DEN.
p85_bounds_agree() {
  local conf election onchain
  conf=$(jq -r '.partitionParams.continuity_max_distance // "1/4"' "$fullShardConf")
  election=$(p85_call "$(p85_election)" 'params()(uint32,uint32,uint32,uint64,uint64,uint64,uint64,uint64)' | awk 'NR==5{a=$1} NR==6{b=$1} END{print a"/"b}')
  [ "$conf" = "$P85_DIST_NUM/$P85_DIST_DEN" ] && [ "$election" = "$conf" ] || {
    echo "the distance bounds disagree: shard configuration $conf, election $election, lane $P85_DIST_NUM/$P85_DIST_DEN" >&2; return 1; }
  echo "continuity bound D <= $conf: committed in the shard configuration and in the election's genesis parameters"
}

# The joiner's nodes. Its root key is NOT in the epoch-1 committee: a root the committee does not name is a follower and signs nothing (#515),
# and its shard node comes up by RESTORING from a retained validator's archive, staging-only until a verified install names it (#507).
p85_joiner_nodes() {
  local boot
  if [ ! -f test-nodes/root5/node-info.json ]; then
    build/ubft root-node init --home test-nodes/root5 -g >/dev/null || return 1
    generate_log_configuration "test-nodes/root5/"
  fi
  h3_spare_identity 5 || return 1
  # the next committee (five entities) is signed by the incumbents: the joiner's authority is enrolled for the scope it will operate in
  H3_ROOTS="1 2 3 4 5" Q3_WEIGHTS="1 1 1 1 1" q3_trust_base_v3 2 || return 1
  h3_spare_authority 5 1 2 trust-base-epoch2.json || return 1
  boot=$(m2_root_addr 1)
  m2_start_root 5 1 "$boot" || { echo "the joiner's root did not start as a follower" >&2; return 1; }
  H3_ONLINE="1 2 3 4 5"
  local i st=""
  for i in $(seq 1 60); do
    st=$(curl -fsS -X POST -H 'content-type: application/json' -d '{}' "$(h3_rpc_url 5)/api/v1/q3/status" 2>/dev/null) || st=""
    [ -n "$st" ] && [ "$(echo "$st" | jq -r .follower 2>/dev/null)" = true ] && break
    sleep 1
  done
  [ -n "$st" ] && [ "$(echo "$st" | jq -r .follower)" = true ] || { echo "the joiner's root does not report follower: ${st:-no answer}" >&2; return 1; }
  echo "$st" | jq -c . >"$H3_DIR/joiner-root-status.json"
  # A follower is not fed the committee's consensus messages (the committee broadcasts to its members): it catches up to an installed epoch through the
  # existing recovery path when the install epoch names it, so its round is recorded here, not asserted to move (dev2's H3 joiner path asserts
  # the follower status and the staging-only shard node, as above).
  echo "joiner root round $(curl -fsS "$(h3_rpc_url 5)/api/v1/roundInfo" 2>/dev/null | jq -r '.roundNumber // empty'), follower=true" | tee "$H3_DIR/joiner-root-round.txt"
}

# The joiner is far behind the chain (the election takes hundreds of rounds), so its shard node restores from a retained validator's archive, and the
# archive serves it only once the incumbents have staged the candidate that names it (#527): at its readiness turn, after entities 1..4. It is
# restored staging-only (no session before the Commit, #520) and gives its readiness from there.
p85_joiner_restore() { # entity
  [ "$1" = 5 ] || return 0
  H3_ONLINE="1 2 3 4 5" H3_STAGING_JOINER=1 H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json h3_restore_validator 5 1 || return 1
  # The restore fetches the whole certified history through the incumbents' archive streams, which are limited while they catch replicas up (it
  # retries up to 150 s per record and logs nothing until it finishes; in run 14 it took ~40 min for ~1400 records at ~40 records/min): the node serves its operator API only once restored, so wait for that
  # (not a fixed interval, which staged the candidate on a node that was still restoring), then watch it stays up.
  local i up=0
  for i in $(seq 1 2400); do
    kill -0 "$(cat test-nodes/evm5/pid)" 2>/dev/null || { echo "the restored joiner shard node (evm5) exited" >&2; tail -20 test-nodes/evm5/debug.log >&2; return 1; }
    grep -aq "execution journal restored" test-nodes/evm5/debug.log && { up=1; break; }
    sleep 1
  done
  [ "$up" = 1 ] || { echo "the joiner's archive restore did not finish in 2400 s" >&2; tail -20 test-nodes/evm5/debug.log >&2; return 1; }
  for i in $(seq 1 30); do kill -0 "$(cat test-nodes/evm5/pid)" 2>/dev/null || { echo "the restored joiner shard node (evm5) exited" >&2; tail -20 test-nodes/evm5/debug.log >&2; return 1; }; sleep 1; done
}

# Write the joiner identity file (the node keys are the nodes' own) and onboard it through the live contracts.
p85_joiner_file() {
  local d=$P85_DIR/joiner
  jq -n --arg owner "$(cat "$d/owner.key")" --arg root "$(jq -r .sigKey.privateKey test-nodes/root5/keys.json)" \
    --arg w "$(cat "$d/withdrawal.addr")" --arg p "$(cat "$d/payee.addr")" --arg rid "$(h3_root_id 5)" --arg eid "$(evm_validator_id 5)" \
    '{ownerKey: $owner, rootKey: $root, withdrawal: $w, payee: $p, rootNodeId: $rid, evmNodeId: $eid, expiry: 4000000000}' >"$d/joiner.json"
  chmod 600 "$d/joiner.json"
}

p85_join() { # step [extra args]
  local step=$1; shift
  build/ubft pos-relayer tx join "$step" --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --joiner "$P85_DIR/joiner/joiner.json" \
    --evm-authority-socket test-nodes/auth5/operator.sock --evm-authority-credential test-nodes/auth5/operator.cred "$@"
}

p85_joiner_onboard() {
  local id
  p85_joiner_file || return 1
  id=$(p85_join register 2>"$H3_DIR/join-register.log") || { cat "$H3_DIR/join-register.log" >&2; return 1; }
  echo "$id" >"$P85_DIR/joiner/custody-id"
  [ "$id" = 5 ] || { echo "the joiner got custody id $id, not 5" >&2; return 1; }
  p85_join bond --id "$id" --value-wei "$(python3 -c "print($P85_BOND_UNIT * ${P85_JOINER_UNITS:-1})")" || return 1
  p85_join admit --id "$id" || return 1
  [ "$(p85_live_count)" = 5 ] || { echo "the election's live index holds $(p85_live_count) identities after the onboarding, not 5" >&2; return 1; }
}

# the election's clock and anchors, for the lane output while it waits (and when it never reserves)
p85_election_clock() {
  local roots; roots=$(jq -r .registry "$P85_DEPLOY")
  echo "election clock: progress=$(p85_call "$roots" 'progress()(uint64)' 2>&1 | awk '{print $1}') ucTime=$(p85_call "$roots" 'ucTime()(uint64)' 2>&1 | awk '{print $1}')" \
    "recordCount=$(p85_call "$roots" 'recordCount()(uint64)' 2>&1 | awk '{print $1}') custodyCursor=$(p85_call "$(p85_custody)" 'recordCursor()(uint64)' 2>&1 | awk '{print $1}')" \
    "thresholds=$(p85_call "$(p85_election)" 'thresholds()(uint256,uint256)' 2>&1 | tr '\n' ' ')" \
    "anchors=$(p85_call "$(p85_election)" 'anchorProgress()(uint64)' 2>&1 | awk '{print $1}')/$(p85_call "$(p85_election)" 'anchorTime()(uint64)' 2>&1 | awk '{print $1}')" \
    "attempt=$(p85_call "$(p85_election)" 'attemptProgress()(uint64)' 2>&1 | awk '{print $1}')/$(p85_call "$(p85_election)" 'attemptTime()(uint64)' 2>&1 | awk '{print $1}')" \
    "liveCount=$(p85_live_count)"
}

p85_election_reserved() {
  local i r
  for i in $(seq 1 600); do
    r=$(p85_open_result); [ "$r" != "0x0000000000000000000000000000000000000000000000000000000000000000" ] && break
    [ $((i % 60)) -ne 1 ] || p85_election_clock
    sleep 1
  done
  [ "$r" != "0x0000000000000000000000000000000000000000000000000000000000000000" ] || p85_election_clock >&2
  [ "$r" != "0x0000000000000000000000000000000000000000000000000000000000000000" ] || { echo "the election never reserved a result (cadence $P85_CADENCE_ROUNDS rounds / $P85_CADENCE_SECONDS s)" >&2; return 1; }
  echo "$r" >"$H3_DIR/result-id.txt"
  [ "$(p85_result_state "$r")" = 1 ] || { echo "the open result is not Reserved" >&2; return 1; }
  p85_call "$(p85_election)" "frozenMembers(bytes32)((uint64,uint64,uint64,uint64,bytes32)[])" "$r" >"$H3_DIR/frozen-members.txt"
  [ "$(grep -o 'bytes32\|(' "$H3_DIR/frozen-members.txt" | wc -l)" -gt 0 ] || true
}

# One assignment (the plan's EVM part) for entities 1..5, built from the election's own records. mode: reserved (before the proofs are
# submitted) or published (with the stored proofs). The H3 possession proofs are signed by each member's signing authority.
p85_build_assignment() { # tag mode
  local tag=$1 mode=$2 id pops= d extra=()
  d="$Q3_DIR/$tag-proposal"
  local ids; ids=$(p85_node_ids)
  build/ubft root handoff evm-context --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$Q3_DIR/$tag-context.json" || return 1
  [ "$mode" = reserved ] && extra+=(--reserved)
  [ "$mode" = published ] && extra+=(--evm-pops "$P85_DIR/run/evm-pops-collected.json")
  q3_x build/ubft pos-relayer proposal "${extra[@]}" --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --context "$Q3_DIR/$tag-context.json" \
    --result-id "$(cat "$H3_DIR/result-id.txt")" --node-ids "$ids" --trust-base test-nodes/trust-base.json --out-dir "$d" || return 1
  for id in 1 2 3 4 5; do
    build/ubft root handoff evm-pop --context "$Q3_DIR/$tag-context.json" --validators "$d/validators.json" --identities "$d/identities.json" \
      --node-id "$(evm_validator_id "$id")" --authority-socket "test-nodes/auth$id/operator.sock" --authority-credential "test-nodes/auth$id/operator.cred" \
      >"$Q3_DIR/$tag-pop-$id.json" || return 1
    pops+="${pops:+,}$Q3_DIR/$tag-pop-$id.json"
  done
  local -a evm=(); [ "$mode" = published ] && evm=(--evm-pops "$d/evm-pops.json")
  build/ubft root handoff evm-assemble --context "$Q3_DIR/$tag-context.json" --validators "$d/validators.json" --identities "$d/identities.json" \
    --authorization "$d/authorization.json" --pops "$pops" --bindings "$d/bindings.json" ${evm[@]+"${evm[@]}"} --out "$Q3_DIR/$tag-assignment.json" || return 1
}

# The Q3 flow's assignment builder for the lane's primary and for the derived recovery.
q3_build_assignment() { # tag ids...
  local tag=$1
  if [ -n "${Q3_RECOVERY:-}" ]; then
    build/ubft root handoff evm-context --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$Q3_DIR/$tag-context.json" || return 1
    build/ubft root handoff evm-assemble --context "$Q3_DIR/$tag-context.json" --recovery --supersede --out "$Q3_DIR/$tag-assignment.json" || return 1
    return 0
  fi
  p85_build_assignment "$tag" published
}

p85_proofs() {
  local r tag=sign i collected=() attempt
  r=$(cat "$H3_DIR/result-id.txt")
  H3_ROOTS="1 2 3 4" p85_build_assignment "$tag" reserved || return 1
  build/ubft pos-relayer candidate --context "$Q3_DIR/$tag-context.json" --assignment "$Q3_DIR/$tag-assignment.json" \
    --next-trust-base test-nodes/trust-base-epoch2.json --out "$Q3_DIR/$tag-candidate.hex" || return 1
  attempt=$(cat "$Q3_DIR/$tag-proposal/attempt.txt")
  for i in 1 2 3 4 5; do
    build/ubft pos-relayer sign-pop --candidate "$Q3_DIR/$tag-candidate.hex" --pos-deployment "$P85_DEPLOY" --attempt "$attempt" \
      --authority-socket "test-nodes/auth$i/operator.sock" --authority-credential "test-nodes/auth$i/operator.cred" \
      --out "$Q3_DIR/evmpop-$i.json" || return 1
    collected+=(--pop "$Q3_DIR/evmpop-$i.json")
  done
  build/ubft pos-relayer assemble --candidate "$Q3_DIR/$tag-candidate.hex" --pos-deployment "$P85_DEPLOY" --attempt "$attempt" "${collected[@]}" \
    --out "$P85_DIR/run/evm-pops-collected.json" || return 1
  q3_x build/ubft pos-relayer tx submit-pops --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --sender-key "$(p85_sender_key)" \
    --result-id "$r" --evm-pops "$P85_DIR/run/evm-pops-collected.json" || return 1
  q3_x build/ubft pos-relayer tx finalize --eth-rpc "$(p85_eth)" --pos-deployment "$P85_DEPLOY" --sender-key "$(p85_sender_key)" --result-id "$r" || return 1
  p85_call "$(p85_election)" "publication(bytes32)" "$r" | python3 -c "import sys;w=sys.stdin.read().strip()[2:];print(int(w[64*10:64*11],16))" | grep -qx 1 || { echo "the result is not published" >&2; return 1; }
}

# The root refuses a primary plan without the EVM possession proofs and one with a proof the election did not store (the same Freeze admission
# a witness of another result would meet: the proofs are checked against the proven slots).
# p85_expect_refusal <assignment> <sentinel text> <out>: the root refuses the plan, for that reason (a bare failure proves nothing: the first run of these
# controls was "refused" for a malformed mutation and a lapsed Prepare, not for the proof)
p85_expect_refusal() { # assignment sentinel out receipts
  local out
  if out=$(build/ubft root handoff propose --next-trust-base test-nodes/trust-base-epoch2.json --next-evm-assignment "$1" --readiness-receipts "$4" \
      --root-rpc "$(h3_root_rpcs)" --max-attempts 1 --prepare-timeout 20s 2>&1); then echo "the plan was accepted: $out" >&2; return 1; fi
  echo "$out" >"$3"
  grep -Fq "$2" "$3" || { echo "refused, but not for \"$2\":" >&2; tail -n 4 "$3" >&2; return 1; }
}

# The controls run inside the handoff, once the readiness receipts exist (the root judges the proofs only in a plan that carries them: without
# receipts the plan is built by the non-V3 path, which carries no proofs at all, and both controls were "refused" for that, not for the proof).
p85_controls() { # tag receipts
  local tag=$1 receipts=$2 a="$Q3_DIR/$1-assignment.json" d="$Q3_DIR/ctl"
  mkdir -p "$d"
  # (a) no EVM proofs: refused for exactly that
  jq 'del(.evmPops)' "$a" >"$d/no-evm-pops.json"
  p85_expect_refusal "$d/no-evm-pops.json" "the primary candidate carries no EVM proof" "$H3_DIR/control-no-proofs.txt" "$receipts" || return 1
  # (b) a proof that is not the member's own: member 1 carries member 2's signature (a well-formed list, so the shape check passes and the proofs are judged)
  jq '.evmPops[0].Signature = .evmPops[1].Signature' "$a" >"$d/wrong-evm-pop.json"
  [ "$(jq -c '.evmPops[0].Signature' "$d/wrong-evm-pop.json")" = "$(jq -c '.evmPops[1].Signature' "$a")" ] || { echo "control (b): the mutation did not apply" >&2; return 1; }
  p85_expect_refusal "$d/wrong-evm-pop.json" "the primary candidate's EVM proof is refused" "$H3_DIR/control-wrong-proof.txt" "$receipts" || return 1
}

p85_handoff() {
  H3_ROOTS="1 2 3 4 5"; H3_ONLINE="1 2 3 4 5"
  Q3_BEFORE_READINESS=p85_joiner_restore Q3_BEFORE_PROPOSE=p85_controls Q3_ENTITIES="1 2 3 4 5" Q3_TOTAL_WEIGHT=5 Q3_ROOT_QUORUM=4 Q3_EVM_QUORUM=4 Q3_WEIGHTS_1="1 1 1 1 1" \
    q3_handoff_n 1 2 "1 1 1 1 1" 0 "$P85_DIR/genesis-identities.json" || return 1
}

p85_install_activation() {
  H3_ROOTS="1 2 3 4 5"
  q3_install_n 2 || return 1
  Q3_TOTAL_WEIGHT=5 Q3_ROOT_QUORUM=4 q3_activation_n 1 2 || return 1
  # activated, not acknowledged: the registry has not moved, and custody's last acknowledged assignment is still K's
  h3_registry_is 0 1 || h3_registry_is 0 2 || { echo "the registry moved before J was acknowledged" >&2; return 1; }
}

# The joiner and one retained member lose their EVM service (processes of the pair; the roots stay: the root quorum must remain to order the
# recovery). The retained members advance into J's scope and cannot certify without them.
p85_j_stalls() {
  local i before after
  for i in 4 5; do
    stop_one_evm_validator "$i" 2>/dev/null || true
    stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' 2>/dev/null || true
    stop_pidfile "test-nodes/auth$i/pid" 'ubft signing-authority run' 2>/dev/null || true
  done
  H3_ONLINE="1 2 3"
  M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 2 1 1 2 3 || { echo "authority advance of the retained members into J's scope failed" >&2; return 1; }
  before=$(p85_evm_round); sleep 45; after=$(p85_evm_round)
  [ "$after" -le "$((before + 1))" ] || { echo "J certified rounds ($before -> $after) with 3 of its 5 validators" >&2; return 1; }
  [ "$(p85_last_acked | tr 'A-F' 'a-f')" != "" ] && [ "$(p85_result_state "$(cat "$H3_DIR/result-id.txt")")" = 1 ] || { echo "the result is no longer reserved" >&2; return 1; }
  echo "EVM round $before -> $after in 45 s with 3 of 5 validators of J" >"$H3_DIR/j-stalls.txt"
}

p85_recovery() {
  # the roots return to K's entities: the follower rule makes root5 a follower again once the successor committee omits it
  H3_ROOTS="1 2 3 4 5"
  Q3_WEIGHTS="1 1 1 1" Q3_NEXT_EPOCH=3 H3_ROOTS="1 2 3 4" q3_trust_base_v3 3 || return 1
  Q3_RECOVERY=1 Q3_SUPERSEDE=1 Q3_NEXT_EPOCH=3 Q3_ASSIGN_TAG=rec Q3_SUFFIX=-2 p85_recovery_attempt_loop || return 1
}

# A recovery plan: the exact K, no receipts (the root decides by the verified candidate kind), a V3 plan (--q3).
p85_recovery_attempt() {
  q3_build_assignment rec || return 1
  Q3_NO_ASSIGNMENT= Q3_NEXT_EPOCH=3 Q3_ASSIGN_TAG=rec Q3_SUFFIX=-2 q3_derive_candidate || return 1
  q3_x build/ubft root handoff propose --q3 --next-trust-base test-nodes/trust-base-epoch3.json --next-evm-assignment "$Q3_DIR/rec-assignment.json" \
    --root-rpc "$(h3_root_rpcs)"
}
p85_recovery_attempt_loop() {
  h3_retry_handoff 2 p85_recovery_attempt || return 1
  cp "$Q3_DIR/candidate-config-2.json" "$Q3_DIR/recovery-config.json" 2>/dev/null || true
  H3_ROOTS="1 2 3 4 5"
  q3_install_n 3 || return 1
  H3_ROOTS="1 2 3 4"
  Q3_TOTAL_WEIGHT=4 Q3_ROOT_QUORUM=3 q3_activation_n 2 3 2>/dev/null || true
  M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 3 2 1 2 3 || { echo "authority advance into the recovery's scope failed" >&2; return 1; }
  local i
  for i in $(seq 1 180); do h3_registry_is 2 3 && break; sleep 1; done
  h3_registry_is 2 3 || { echo "registry did not reach shard epoch 2 / root epoch 3 (shard epoch $(h3_slot "$h3_slot_shard"), root epoch $(h3_slot "$h3_slot_root"))" >&2; return 1; }
  H3_ONLINE="1 2 3"
  h3_paid 3 || { echo "post-recovery paid transaction was not certified at root epoch 3" >&2; return 1; }
}

p85_resolved() {
  local r; r=$(cat "$H3_DIR/result-id.txt")
  local i
  for i in $(seq 1 60); do [ "$(p85_result_state "$r")" = 4 ] && break; sleep 1; done
  [ "$(p85_result_state "$r")" = 4 ] || { echo "the result is in state $(p85_result_state "$r"), not Recovered" >&2; return 1; }
  [ "$(p85_open_result)" = "0x0000000000000000000000000000000000000000000000000000000000000000" ] || { echo "a result is still open" >&2; return 1; }
  p85_last_acked >"$H3_DIR/last-acked-after-recovery.txt"
  [ "$(tr 'A-F' 'a-f' <"$H3_DIR/last-acked-after-recovery.txt")" = "$(p85_genesis_assignment)" ] || echo "note: last acknowledged assignment differs from the genesis assignment (the recovery re-installs K under a new assignment id)" >&2
}

p85_restarts() {
  H3_ROOTS="1 2 3 4 5"
  H3_ROOTS="1 2 3 4" h3_restart_roots 3 || return 1
  stop_one_evm_validator 1 2>/dev/null || true
  M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 3 2 1 || return 1
  h3_paid 3 || { echo "post-restart paid transaction was not certified" >&2; return 1; }
  p85_progress after-restarts 8
}

# The election's refusal of an over-bound candidate (P85_MODE=overbound): the joiner bonds P85_JOINER_UNITS (3) units, so the only change from the
# acceptance run is the joiner's weight: K (four unit weights) -> K plus a weight-3 joiner is D = 24/28, over the budget 1/2. The election, which
# runs in the block hook at the cadence, must record NoCandidate for it (WeightChurn): no result opens, the attempt is recorded.
p85_election_refused() {
  local i cursor reason
  for i in $(seq 1 900); do
    cursor=$(p85_call "$(p85_election)" 'attemptCursor()(uint64)' | awk '{print $1}')
    [ "${cursor:-0}" -ge 1 ] && break
    [ $((i % 60)) -ne 1 ] || p85_election_clock
    sleep 1
  done
  [ "${cursor:-0}" -ge 1 ] || { echo "the election never ran (cadence $P85_CADENCE_ROUNDS rounds / $P85_CADENCE_SECONDS s)" >&2; p85_election_clock >&2; return 1; }
  [ "$(p85_open_result)" = "0x0000000000000000000000000000000000000000000000000000000000000000" ] || { echo "the over-bound candidate was reserved" >&2; return 1; }
  p85_election_clock
  reason=$(p85_attempt_reason) || return 1
  [ "$reason" = 4 ] || { echo "the recorded refusal is reason $reason, not 4 (WeightChurn)" >&2; return 1; }
  echo "the election recorded NoCandidate (WeightChurn) for the over-bound candidate; no result is open"
}

# The Reason of the election's last attempt, read from the state a simulated attempt writes: an election attempt in the system hook emits no log,
# and the result is keyed by an origin only the hook knows, so the same attempt is replayed with a self call (electNow) at the current clock.
p85_attempt_reason() {
  local e r roots t p pred data
  e=$(p85_election); roots=$(jq -r .registry "$P85_DEPLOY")
  t=$(p85_call "$roots" 'ucTime()(uint64)' | awk '{print $1}'); p=$(p85_call "$roots" 'progress()(uint64)' | awk '{print $1}')
  pred=$(p85_call "$(p85_custody)" 'lastAckedAssignment()(bytes32)')
  data=$("$P85_CAST" calldata 'electNow(bytes32,uint64,uint64,bytes32)' 0x0000000000000000000000000000000000000000000000000000000000001234 "$p" "$t" "$pred")
  curl -fsS -X POST -H 'content-type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"debug_traceCall\",\"params\":[{\"from\":\"$e\",\"to\":\"$e\",\"data\":\"$data\"},\"latest\",{\"tracer\":\"prestateTracer\",\"tracerConfig\":{\"diffMode\":true}}]}" "$(p85_eth)" |
    python3 -c "
import json,sys
post=json.load(sys.stdin)['result']['post'][sys.argv[1].lower()]['storage']
for v in post.values():
    b=bytes.fromhex(v[2:].rjust(64,'0'))
    if b[31]==2 and b[30]!=0:   # ResultState.NoCandidate, then its Reason
        print(b[30]); break
else: raise SystemExit('no NoCandidate result in the simulated attempt')" "$e"
}

P85_STEPS="p85_baseline p85_joiner_nodes p85_joiner_onboard p85_election_reserved p85_proofs p85_handoff p85_install_activation p85_j_stalls p85_recovery p85_resolved p85_restarts"

p85_run_lane() {
  local s
  mkdir -p "$Q3_DIR" "$P85_DIR/run"; : >"$Q3_DIR/commands.log"
  : >"$Q3_DIR/pins.txt"
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json
  Q3_GENESIS_IDENTITIES=$P85_DIR/genesis-identities.json
  H3_REGISTRY=0xff00000000000000000000000000000000000002
  H3_ONLINE="1 2 3 4"; H3_ROOTS="1 2 3 4"
  Q3_WEIGHTS="1 1 1 1"; Q3_TOTAL_WEIGHT=4; Q3_ROOT_QUORUM=3; Q3_EVM_QUORUM=3
  M2_NEXT_NONCE=${M2_NEXT_NONCE:-4}; M2_CHAIN_ID=31337
  cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
  read -r h3_slot_shard h3_slot_root h3_slot_conf h3_slot_cursor < <(H3_SLOT_LAYOUT=3 go run ./scripts/h3slots)
  echo "=== P85 recovery lane: PoS genesis (K = 4 entities) -> primary J = K + joiner -> J stalls -> derived recovery to K ==="
  echo "NOTE: every validator signs through its own signing authority, including the P85 EVM possession proofs (SignElectionPoP) and the delegation possession (SignDelegationPossession)."
  [ "${P85_MODE:-}" != overbound ] || { P85_JOINER_UNITS=3; P85_STEPS="p85_baseline p85_joiner_nodes p85_joiner_onboard p85_election_refused"; }
  for s in $P85_STEPS; do p85_step "$s" "$s"; done
  echo "P85 recovery lane: all steps PASSED"
  q3_teardown
}
[ "${P85_LANE_DEFINE_ONLY:-0}" = 1 ] || p85_run_lane
