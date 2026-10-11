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
#   J stalls        the joiner and two retained members (5, 3, 4) lose their EVM services (their roots stay for the root quorum): J (2 of 5, EVM quorum 3) cannot certify
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
# the paid transactions and the authority restarts go to the validators that are up (m2_online_validators is otherwise a fixed list)
m2_online_validators() { echo "${H3_ONLINE:-1 2 3 4}"; }

p85_pass() { echo "  PASS: $*"; }
p85_step_die() {
  local i
  echo "  FAIL: $*" >&2
  for i in 1 2 3 4 5; do [ -f "test-nodes/root$i/debug.log" ] && { echo "--- tail of root$i/debug.log" >&2; tail -n 6 "test-nodes/root$i/debug.log" | cut -c1-300 >&2; }; done
  q3_teardown
  exit 1
}
p85_step() {
  local name=$1; shift; echo "--- P85 step: $name"
  "$@" || { p85_view "$name:failed" || true; p85_step_die "$name"; }
  p85_view "$name" || true   # the election/custody view at the end of every step, kept with the run (reth state is not)
  p85_pass "$name"
}

# ---- chain reads (cast) -------------------------------------------------------------------------------------------------------------------------
P85_DEPLOY=$P85_DIR/pos-deployment.json
p85_eth() { echo "http://127.0.0.1:$rethEthBase"; }
p85_custody() { jq -r .custody "$P85_DEPLOY"; }
p85_election() { jq -r .election "$P85_DEPLOY"; }
p85_call() { "$P85_CAST" call --rpc-url "$(p85_eth)" "$@"; }
# a call that fails or answers anything but a bytes32 is an error, never a value (run 21: an empty answer from a dead devnet read as "a result is open")
p85_open_result() {
  local out; out=$(p85_call "$(p85_election)" "openResult()(bytes32)") || return 1
  [[ "$out" =~ ^0x[0-9a-fA-F]{64}$ ]] || return 1
  echo "$out"
}
p85_result_state() { # result -> the ResultState enum value (1 Reserved, 3 Acknowledged, 4 Recovered)
  "$P85_CAST" call --rpc-url "$(p85_eth)" "$(p85_election)" "result(bytes32)" "$1" | python3 -c "import sys;print(int(sys.stdin.read().strip()[2:66],16))"
}
p85_last_acked() { p85_call "$(p85_custody)" "lastAckedAssignment()(bytes32)"; }
p85_live_count() { p85_call "$(p85_election)" "liveCount()(uint32)" | awk '{print $1}'; }
# The paid transaction of a step takes the funded account's next nonce from the chain: the lane seeds three (0-2) and no other step sends one, so a
# fixed start of 4 (the M2/H3 lanes' value, after a paid block) leaves a gap that is never mined (run 28: "not certified" while the shard built blocks).
p85_chain_nonce() {
  local addr; addr=$(go run ./scripts/evmtx -address) || return 1
  "$P85_CAST" nonce --rpc-url "http://127.0.0.1:$((rethEthBase + $(echo "${H3_ONLINE:-1}" | awk '{print $1}') - 1))" "$addr" || return 1
}
p85_paid() { M2_NEXT_NONCE=$(p85_chain_nonce) || return 1; h3_paid "$1"; }
p85_eth_block() { "$P85_CAST" block-number --rpc-url "$(p85_eth)"; }
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
  rm -f "$H3_DIR/joiner-restored"
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
  # a refused attempt is retried and rebuilds the receipts: the joiner that restored (and still runs) is not restored again, which costs ~30 min
  # (run 15 looped on it)
  if [ -e "$H3_DIR/joiner-restored" ] && kill -0 "$(cat test-nodes/evm5/pid 2>/dev/null)" 2>/dev/null; then return 0; fi
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
  touch "$H3_DIR/joiner-restored"
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

# every root and EVM validator this run started is still alive: a lane step that waits (the election's cadence, the joiner's restore) must fail at once,
# naming the process, when the devnet was stopped under it, not spend its whole timeout on a dead chain (run 18: killed by someone else 2 min in)
p85_devnet_alive() {
  local f i pid dead=0
  for f in test-nodes/root1/pid test-nodes/root2/pid test-nodes/root3/pid test-nodes/root4/pid test-nodes/evm1/pid test-nodes/evm2/pid test-nodes/evm3/pid test-nodes/evm4/pid; do
    [ -f "$f" ] || continue
    pid=$(cat "$f" 2>/dev/null)
    kill -0 "$pid" 2>/dev/null || { echo "the devnet was stopped under the lane: $f (pid $pid) is gone; last log line: $(grep -a . "$(dirname "$f")/debug.log" | tail -1 | cut -c1-200)" >&2; dead=1; }
  done
  return $dead
}

p85_election_reserved() {
  local i r
  for i in $(seq 1 600); do
    p85_devnet_alive || return 1
    r=$(p85_open_result) || r=0x0000000000000000000000000000000000000000000000000000000000000000
    [ "$r" != "0x0000000000000000000000000000000000000000000000000000000000000000" ] && break
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
  Q3_BEFORE_READINESS=p85_joiner_restore Q3_BEFORE_PROPOSE=p85_controls Q3_ENTITIES="1 2 3 4 5" Q3_TOTAL_WEIGHT=5 Q3_ROOT_QUORUM=4 Q3_EVM_QUORUM=3 Q3_WEIGHTS_1="1 1 1 1 1" \
    q3_handoff_n 1 2 "1 1 1 1 1" 0 "$P85_DIR/genesis-identities.json" || return 1
}

p85_install_activation() {
  H3_ROOTS="1 2 3 4 5"
  q3_install_n 2 || return 1
  Q3_COMMIT_SCHEME=1 Q3_TOTAL_WEIGHT=4 Q3_ROOT_QUORUM=3 q3_activation_n 1 2 || return 1   # epoch 2's Commit is the genesis K's (legacy scheme 1, W=4, quorum 3)
  # activated, not acknowledged: the registry has not moved, and custody's last acknowledged assignment is still K's
  h3_registry_is 0 1 || h3_registry_is 0 2 || { echo "the registry moved before J was acknowledged" >&2; return 1; }
}

# J = K + joiner has five unit-weight validators and the EVM request quorum is a majority, floor(5/2)+1 = 3 (the 4 of the root quorum is another
# number). The joiner (5) and two retained members (3, 4) lose their EVM service, so J has 2 of 5 and cannot certify; the roots stay (the root
# quorum must remain to order the recovery). Entity 3 loses only its shard node: its reth and signing authority stay up, so the recovery
# step brings it back into K's scope (K = {1,2,3} of 4 = its quorum 3). Entities 4 and 5 lose everything (an authority's key lives in memory).
p85_j_stalls() {
  local i before after pdr
  for i in 4 5; do
    stop_one_evm_validator "$i" 2>/dev/null || true
    stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' 2>/dev/null || true
    stop_pidfile "test-nodes/auth$i/pid" 'ubft signing-authority run' 2>/dev/null || true
  done
  stop_one_evm_validator 3 2>/dev/null || true
  H3_ONLINE="1 2"
  M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 2 1 1 2 || { echo "authority advance of the retained members into J's scope failed" >&2; return 1; }
  # entity 3's authority is advanced into J's scope too, but its node stays down
  pdr=$(h3_pdr_file 1) || return 1
  build/ubft signing-authority advance-epoch --operator-socket "test-nodes/auth3/operator.sock" --operator-credential "test-nodes/auth3/operator.cred" \
    --trust-base test-nodes/trust-base-epoch2.json --shard-conf "$pdr" || { echo "authority 3 advance into J's scope failed" >&2; return 1; }
  before=$(p85_eth_block); sleep 45; after=$(p85_eth_block)
  [ "$after" -le "$((before + 1))" ] || { echo "J certified blocks ($before -> $after) with 2 of its 5 validators (majority quorum 3)" >&2; return 1; }
  [ "$(p85_last_acked | tr 'A-F' 'a-f')" = "$(p85_genesis_assignment | tr 'A-F' 'a-f')" ] || { echo "custody moved off the genesis assignment: J was acknowledged" >&2; return 1; }
  [ "$(p85_result_state "$(cat "$H3_DIR/result-id.txt")")" = 1 ] || { echo "the result is no longer reserved" >&2; return 1; }
  echo "EVM round $before -> $after in 45 s with 2 of 5 validators of J" >"$H3_DIR/j-stalls.txt"
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
  Q3_TOTAL_WEIGHT=5 Q3_ROOT_QUORUM=4 q3_activation_n 2 3 || return 1   # epoch 3's Commit is J's (W=5, quorum 4)
  M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 3 2 1 2 3 || { echo "authority advance into the recovery's scope failed" >&2; return 1; }
  local i
  for i in $(seq 1 180); do h3_registry_is 2 3 && break; sleep 1; done
  h3_registry_is 2 3 || { echo "registry did not reach shard epoch 2 / root epoch 3 (shard epoch $(h3_slot "$h3_slot_shard"), root epoch $(h3_slot "$h3_slot_root"))" >&2; return 1; }
  H3_ONLINE="1 2 3"
  p85_paid 3 || { echo "post-recovery paid transaction was not certified at root epoch 3" >&2; return 1; }
}

# One JSON line per call into $H3_DIR/views.jsonl: the election and custody state a later offline reading needs (the execution clients' databases are not
# kept). Best-effort: a dead devnet leaves a line with the error, never a failed step.
p85_view() { # label
  local open=null res=null sess=null r thr
  r=$(cat "$H3_DIR/result-id.txt" 2>/dev/null)
  python3 - "$1" "$(date -u +%FT%TZ)" "$(p85_open_result 2>&1 | tail -n1)" "$(p85_call "$(p85_election)" 'attemptCursor()(uint64)' 2>&1 | awk '{print $1}')" \
    "$(p85_last_acked 2>&1 | tail -n1)" "$(p85_cursor 2>&1 | tail -n1)" "$(p85_log_count 2>&1 | tail -n1)" "$(p85_log_target 2>&1 | tail -n1)" \
    "$(p85_call "$(p85_election)" 'thresholds()(uint256,uint256)' 2>&1 | tr '\n' ' ')" \
    "$(p85_call "$(p85_registry)" 'progress()(uint64)' 2>&1 | awk '{print $1}')" "$(p85_call "$(p85_registry)" 'ucTime()(uint64)' 2>&1 | awk '{print $1}')" \
    "$([ -n "$r" ] && p85_call "$(p85_election)" 'result(bytes32)' "$r" 2>/dev/null | p85_dec result 2>&1)" \
    "$([ -n "$r" ] && p85_call "$(p85_custody)" 'session(bytes32)' "$r" 2>/dev/null | p85_dec session 2>&1)" \
    "$(o=$(p85_open_result 2>/dev/null); if [ -n "$o" ] && [ "$o" != 0x0000000000000000000000000000000000000000000000000000000000000000 ]; then p85_call "$(p85_election)" 'result(bytes32)' "$o" 2>/dev/null | p85_dec result 2>&1; fi)" \
    >>"$H3_DIR/views.jsonl" <<'PY'
import json, sys
keys = ["label", "time", "openResult", "attemptCursor", "lastAcked", "custodyCursor", "recordCount", "recordTarget", "thresholds", "registryProgress",
        "registryUcTime", "resultView", "sessionView", "openResultView"]
row = dict(zip(keys, sys.argv[1:]))
for k in ("resultView", "sessionView", "openResultView"):
    try:
        row[k] = json.loads(row[k]) if row.get(k) else None
    except ValueError:
        pass
print(json.dumps(row, sort_keys=True))
PY
}

# ---- read-only chain state (the decoders are scripts/p85/chain_decode.py; no state is written) -----------------------------------------------
p85_registry() { jq -r .registry "$P85_DEPLOY"; }
p85_dec() { python3 -I scripts/p85/chain_decode.py "$@"; }
p85_assignment() { p85_call "$(p85_custody)" 'assignments(bytes32)' "$1" | p85_dec assignment; }   # one JSON line
p85_log_count() { p85_call "$(p85_registry)" 'recordCount()(uint64)' | awk '{print $1}'; }
p85_log_target() { p85_call "$(p85_registry)" 'recordTargetCount()(uint64)' | awk '{print $1}'; }
p85_cursor() { p85_call "$(p85_custody)" 'recordCursor()(uint64)' | awk '{print $1}'; }
p85_session_state() { p85_call "$(p85_custody)" 'session(bytes32)' "$1" | p85_dec word; }
p85_log_dump() { # every registry record, one line each: "index kind progress ucTime word0 word1" (kinds: 1 SessionClosed, 2 Ack, 3 RecoveryAck, 4 Closure)
  local n i; n=$(p85_log_count) || return 1
  for i in $(seq 0 $((n - 1))); do p85_call "$(p85_registry)" 'recordAt(uint64)' "$i" | p85_dec record || return 1; done
}
# The three assignments of the scenario from the log itself: G the genesis one, K the recovery assignment (word 1 of the RecoveryAck), J the
# one the other closure names. Sets P85_G, P85_J, P85_K and prints nothing.
p85_scenario_ids() { # log-dump-file
  local f=$1 g; g=$(p85_genesis_assignment)
  P85_G=$g
  P85_K=$(awk '$2==3{print $6; exit}' "$f" | tr 'A-F' 'a-f')
  P85_J=$(awk -v g="$g" '$2==4 && tolower($5)!=g {print $5; exit}' "$f" | tr 'A-F' 'a-f')
  [ -n "$P85_K" ] && [ "$P85_K" != "-" ] && [ -n "$P85_J" ] || { echo "the log has no RecoveryAck and a closure of an assignment other than the genesis one" >&2; return 1; }
}
# one JSON object of everything a restart must not change: the three assignments, the cursor, the log count and target, the last acknowledged
p85_snapshot() { # log-dump-file
  local f=$1
  python3 - "$(p85_assignment "$P85_G")" "$(p85_assignment "$P85_J")" "$(p85_assignment "$P85_K")" "$(p85_cursor)" "$(p85_log_count)" "$(p85_log_target)" "$(p85_last_acked)" <<'PY'
import json, sys
g, j, k, cursor, count, target, acked = sys.argv[1:8]
print(json.dumps({"G": json.loads(g), "J": json.loads(j), "K": json.loads(k), "cursor": int(cursor), "count": int(count), "target": int(target),
                  "lastAcked": acked.strip().lower()}, sort_keys=True))
PY
}
p85_stuck_report() { # what a stuck cursor looks like (run 25: the records hook reverted and the cursor never moved)
  local c n; c=$(p85_cursor 2>/dev/null); n=$(p85_log_count 2>/dev/null)
  echo "recordCursor=$c recordCount=$n recordTargetCount=$(p85_log_target 2>/dev/null); record at the cursor: $(p85_call "$(p85_registry)" 'recordAt(uint64)' "${c:-0}" 2>/dev/null | p85_dec record 2>/dev/null)" >&2
  grep -a "applyRootRecords" test-nodes/reth1/reth.log 2>/dev/null | tail -n 1 | cut -c1-300 >&2
}

p85_resolved() {
  local r i log; r=$(cat "$H3_DIR/result-id.txt"); log="$H3_DIR/registry-log.txt"
  for i in $(seq 1 180); do [ "$(p85_result_state "$r")" = 4 ] && break; sleep 1; done
  [ "$(p85_result_state "$r")" = 4 ] || { echo "the result is in state $(p85_result_state "$r"), not Recovered" >&2; p85_stuck_report; return 1; }
  # The resolved result is no longer the open one. The election's boundary is gated while a result is unresolved and its thresholds are measured
  # from the last attempt (recovery moves no anchor), so a LATER election may open right after the resolution: that is accepted only when it is
  # positively one (Reserved, a strictly later attempt than the resolved result's, started from K, at a progress and UC time not before the
  # RecoveryAck's anchors). Anything else is a finding.
  local open; open=$(p85_open_result) || return 1
  [ "$open" != "$r" ] || { echo "the resolved result $r is still the open one" >&2; return 1; }
  echo "$open" >"$H3_DIR/open-result-after-resolution.txt"
  if [ "$open" = 0x0000000000000000000000000000000000000000000000000000000000000000 ]; then
    echo "open result after the resolution: none"
  else
    p85_log_dump >"$H3_DIR/registry-log.txt" || return 1
    p85_scenario_ids "$H3_DIR/registry-log.txt" || return 1
    local ack_anchor; ack_anchor=$(awk -v r="$r" '$2==3 && tolower($5)==tolower(r){print $3, $4}' "$H3_DIR/registry-log.txt")
    local old new; old=$(p85_call "$(p85_election)" 'result(bytes32)' "$r" | p85_dec result) || return 1
    new=$(p85_call "$(p85_election)" 'result(bytes32)' "$open" | p85_dec result) || return 1
    echo "$new" >"$H3_DIR/open-result-after-resolution.json"
    python3 - "$old" "$new" "$ack_anchor" "$P85_K" "$(p85_call "$(p85_election)" 'attemptCursor()(uint64)' | awk '{print $1}')" <<'PY' || return 1
import json, sys
old, new = json.loads(sys.argv[1]), json.loads(sys.argv[2])
ack_p, ack_t = (int(x) for x in sys.argv[3].split())
k, cursor = sys.argv[4].lower(), int(sys.argv[5])
checks = [
    (new["state"] == 1, "the open result is not Reserved: state %d" % new["state"]),
    (new["attempt"] > old["attempt"], "attempt %d is not after the resolved result's %d" % (new["attempt"], old["attempt"])),
    (new["attempt"] == cursor, "attempt %d is not the election's attempt cursor %d" % (new["attempt"], cursor)),
    (new["predecessor"].lower() == k, "it does not start from K (%s), but from %s" % (k, new["predecessor"])),
    (new["progress"] >= ack_p and new["ucTime"] >= ack_t, "it was opened at (%d,%d), before the RecoveryAck's anchors (%d,%d)" % (new["progress"], new["ucTime"], ack_p, ack_t)),
    (new["assignmentID"] != old["assignmentID"], "it names the resolved result's assignment"),
]
bad = [m for ok, m in checks if not ok]
if bad:
    sys.exit("the open result after the resolution is not a later election: " + "; ".join(bad))
print("open result after the resolution: a later election, attempt %d (resolved %d), opened at (%d,%d) from K, RecoveryAck at (%d,%d)" %
      (new["attempt"], old["attempt"], new["progress"], new["ucTime"], ack_p, ack_t))
PY
  fi
  p85_last_acked >"$H3_DIR/last-acked-after-recovery.txt"
  # the root order the pending path exists for: both closures strictly before the RecoveryAck of this result
  p85_log_dump >"$log" || return 1
  p85_scenario_ids "$log" || return 1
  python3 - "$log" "$P85_G" "$P85_J" "$P85_K" "$r" <<'PY' || return 1
import sys
rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
g, j, k, result = (x.lower() for x in sys.argv[2:6])
def idx(kind, w0=None):
    for r in rows:
        if int(r[1]) == kind and (w0 is None or r[4].lower() == w0):
            return int(r[0])
    sys.exit("no record of kind %d%s in the log" % (kind, "" if w0 is None else " for " + w0))
cg, cj, ack = idx(4, g), idx(4, j), idx(3, result)
if not (cg < ack and cj < ack):
    sys.exit("the closures (G@%d, J@%d) are not both before the RecoveryAck@%d" % (cg, cj, ack))
print("log order: Closure(G)@%d Closure(J)@%d RecoveryAck@%d" % (cg, cj, ack))
PY
  local ack_row; ack_row=$(awk -v r="$r" '$2==3 && tolower($5)==tolower(r)' "$log")
  [ -n "$ack_row" ] || { echo "no RecoveryAck of $r in the log" >&2; return 1; }
  # K is what custody last acknowledged, and neither the genesis assignment nor J
  [ "$(tr 'A-F' 'a-f' <"$H3_DIR/last-acked-after-recovery.txt")" = "$P85_K" ] || { echo "last acknowledged $(cat "$H3_DIR/last-acked-after-recovery.txt") is not the RecoveryAck's assignment $P85_K" >&2; return 1; }
  [ "$P85_K" != "$P85_G" ] && [ "$P85_K" != "$P85_J" ] || { echo "K equals G or J" >&2; return 1; }
  # J was materialized by the recovery and closed with the CLOSURE's own anchors, never the RecoveryAck's; G closed at its own; K is open
  python3 - "$log" "$(p85_assignment "$P85_G")" "$(p85_assignment "$P85_J")" "$(p85_assignment "$P85_K")" "$P85_G" "$P85_J" <<'PY' || return 1
import json, sys
rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
g, j, k = (json.loads(x) for x in sys.argv[2:5])
gid, jid = sys.argv[5].lower(), sys.argv[6].lower()
def closure(a):
    return next(r for r in rows if int(r[1]) == 4 and r[4].lower() == a)
cg, cj = closure(gid), closure(jid)
ack = next(r for r in rows if int(r[1]) == 3)
checks = [
    (j["state"] == 2 and j["offsetSet"] == 1 and j["hKnown"] == 1, "J is not Active with offsets and H: %r" % j),
    (j["closed"] == 1, "J is not closed"),
    ((j["pClose"], j["tClose"]) == (int(cj[2]), int(cj[3])), "J closed at (%d,%d), not at its closure's anchors (%s,%s)" % (j["pClose"], j["tClose"], cj[2], cj[3])),
    ((j["pClose"], j["tClose"]) != (int(ack[2]), int(ack[3])) or (cj[2], cj[3]) == (ack[2], ack[3]), "J carries the RecoveryAck's anchors"),
    (g["closed"] == 1 and (g["pClose"], g["tClose"]) == (int(cg[2]), int(cg[3])), "G is not closed at its closure's anchors: %r" % g),
    (k["state"] == 2 and k["closed"] == 0 and k["offsetSet"] == 1, "K is not Active and open: %r" % k),
]
bad = [m for ok, m in checks if not ok]
if bad:
    sys.exit("; ".join(bad))
print("J closed at (%d,%d) = its closure; G at (%d,%d); K open" % (j["pClose"], j["tClose"], g["pClose"], g["tClose"]))
PY
  # reconciliation is complete: the cursor, the log and its target agree and the session is Recovered
  local c n t; c=$(p85_cursor); n=$(p85_log_count); t=$(p85_log_target)
  [ "$c" = "$n" ] && [ "$n" = "$t" ] || { echo "reconciliation incomplete: cursor=$c count=$n target=$t" >&2; return 1; }
  [ "$(p85_session_state "$r")" = 4 ] || { echo "custody's session of $r is not Recovered" >&2; return 1; }
  p85_snapshot "$log" >"$H3_DIR/state-after-resolution.json"
}

# Stops a validator's shard node and starts it again in the SAME scope. Its authority keeps its enrolled scope (root epoch 3, shard epoch 2 since
# p85_recovery): an advance-epoch into that same scope is refused (signing-context-mismatch, run 30), so only the session is replaced.
p85_restart_validator() { # id
  local i=$1 rootBoot bootnodes
  rootBoot=$(m2_root_addr "$(h3_first_root)") || return 1
  stop_one_evm_validator "$i" || return 1
  build/ubft signing-authority replace-session --operator-socket "test-nodes/auth$i/operator.sock" --operator-credential "test-nodes/auth$i/operator.cred" \
    --out "test-nodes/auth$i/client.cred" || return 1
  bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$i" $H3_ONLINE) || return 1
  start_one_evm_validator "$i" "$validators" "$partitionID" "$rootBoot" engine-api rpc "$bootnodes" || return 1
  echo "validator $i restarted in its scope"
}

# This step restarts after the resolution. It does NOT cover a restart at the pending boundary (the few blocks between J's closure and the
# RecoveryAck cannot be hit by a timed restart); that is the contract split test's job.
p85_restarts() {
  local log="$H3_DIR/registry-log.txt" before after
  H3_ROOTS="1 2 3 4 5"
  p85_log_dump >"$log" || return 1
  p85_scenario_ids "$log" || return 1
  before=$(p85_snapshot "$log") || return 1
  H3_ROOTS="1 2 3 4" h3_restart_roots 3 || return 1
  p85_restart_validator 1 || return 1
  p85_paid 3 || { echo "post-restart paid transaction was not certified" >&2; return 1; }
  p85_progress after-restarts 8
  # nothing the restart could reset: no assignment, anchor, cursor or log entry changed (records ordered since may only have been appended)
  p85_log_dump >"$log" || return 1
  after=$(p85_snapshot "$log") || return 1
  python3 - "$before" "$after" <<'PY' || return 1
import json, sys
b, a = (json.loads(x) for x in sys.argv[1:3])
for key in ("G", "J", "K", "lastAcked"):
    if b[key] != a[key]:
        sys.exit("%s changed across the restart: %r -> %r" % (key, b[key], a[key]))
for key in ("cursor", "count", "target"):
    if a[key] < b[key]:
        sys.exit("%s went backwards across the restart: %d -> %d" % (key, b[key], a[key]))
if not (a["cursor"] == a["count"] == a["target"]):
    sys.exit("reconciliation incomplete after the restart: %r" % {k: a[k] for k in ("cursor", "count", "target")})
print("state identical across the restart: G, J (pClose %d tClose %d), K, lastAcked; cursor %d -> %d" % (b["J"]["pClose"], b["J"]["tClose"], b["cursor"], a["cursor"]))
PY
  printf '%s\n%s\n' "$before" "$after" >"$H3_DIR/state-across-restart.json"
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
# Sourcing this file only defines the steps. The lane runs when the runner (scripts/p85-lane.sh, under the devnet lock) asks for it, and only while
# the lock is that runner's: a shell that sources the file to read or test the functions must not start, restart or tear down any node.
p85_lane_may_run() {
  [ "${P85_LANE_LOCKED:-0}" = 1 ] && [ "${P85_LANE_DEFINE_ONLY:-0}" != 1 ] || return 1
  [ "$(cat "${DEVNET_LOCK_DIR:-$PWD/../.devnet-lock}/owner" 2>/dev/null)" = "p85-recovery" ]
}
if p85_lane_may_run; then p85_run_lane; fi
