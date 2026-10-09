# Sourced by reth-paired-devnet.sh (H3_ASSIGNMENT_LANE=1, F8_MIXED_LANE=1, M2_PROFILE2=1, SIGNING=authority) after the
# first paid certified block, in place of m2-profile2-handoffs.sh. Every step prints PASS or FAIL; a FAIL exits nonzero.
# SIGNING=authority is the only mode: every validator signs through its own signing authority (as in production), a joiner's authority
# signs its proof of possession on the operator channel (`evm-pop --authority-socket`) and is enrolled against the activated
# configuration, retained validators' authorities advance (`advance-epoch`) at each activation, and a restored validator restores
# through its surviving authority (a local-key restore is refused by design).
# Design: briefs/h3-evm-assignment-design.md section 8 as amended: validator-set changes are always coupled (root entity and its
# delegated EVM validator). Every epoch change goes through the Q3 flow (candidate, readiness receipts of every successor member, plan, install
# restart); a joiner (evm5, evm6 and their roots) is started and gives its readiness BEFORE the Commit (briefs/joiner-readiness-review.md).
# Root epochs: 1 genesis, 2 configuration-only advance, 3 coupled s=1 (4->5), 4 coupled s=2 (3->6, J={1,2,5,6}), 5 the derived recovery to K = the s=1 set
# {1,2,3,5} (root 6->3), which supersedes s=2. EVM validators: evm1-4 genesis; evm5, evm6 spare identities that appear only in successor sets.
source scripts/lib/m2-handoff-lib.sh
source scripts/lib/h3-lib.sh
source scripts/lib/q3-lib.sh
source scripts/lib/q3-flow-lib.sh
source scripts/lib/h3-q3-lib.sh
H3_DIR=test-nodes/h3
mkdir -p "$H3_DIR"
cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
read -r h3_slot_shard h3_slot_root h3_slot_conf h3_slot_cursor < <(H3_SLOT_LAYOUT=$([ "${Q3_B1:-0}" = 1 ] && echo 3 || echo 2) go run ./scripts/h3slots)
H3_REGISTRY=0xff00000000000000000000000000000000000002
H3_ONLINE="1 2 3 4"
H3_ROOTS="1 2 3 4"
# the paired-devnet seeding leaves the funded sender at nonce 4 (run6c: "nonce too low: next nonce 4, tx nonce 3")
M2_NEXT_NONCE=${M2_NEXT_NONCE:-4}
M2_CHAIN_ID=31337

h3_pass() { echo "  PASS: $*"; }
# A failed step stops the lane at once: every process this lane started (including the joiners' and restored nodes, which the devnet's
# own cleanup does not know) is stopped, so the output pipe closes, the lane exits non-zero and any watcher fires.
h3_teardown() {
  local p i
  for i in 5 6 7; do
    # a pid file's value is signalled only if that process is this checkout's and matches the command (stop_pidfile; a reused pid is not)
    stop_pidfile "test-nodes/evm$i/pid" 'ubft shard-node (run|restore)' INT
    stop_pidfile "test-nodes/auth$i/pid" 'ubft signing-authority run' INT
    stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' INT
    stop_pidfile "test-nodes/h3/restore-$i/pid" 'ubft shard-node restore' INT
  done
  for p in $(owned_pids 'ubft root-node run|ubft shard-node (run|restore)|ubft signing-authority run|reth.* node|aggregator'); do
    kill -INT "$p" 2>/dev/null
  done
  return 0
}
h3_die() {
  echo "  FAIL: $*" >&2
  for i in 1 2 3 4 5 6; do [ -f "test-nodes/evm$i/debug.log" ] && { echo "--- tail of evm$i/debug.log" >&2; tail -n 6 "test-nodes/evm$i/debug.log" | cut -c1-300 >&2; }; done
  h3_teardown
  exit 1
}
h3_step() { local name=$1; shift; echo "--- H3 step: $name"; "$@" || h3_die "$name"; h3_pass "$name"; }



h3_evm_certifies_after() { # a certified EVM IR round above $1 within $2 seconds
  local base=$1 limit=${2:-90} i now
  for i in $(seq 1 "$limit"); do
    now=$(h3_evm_row | jq -r '.roundNumber')
    [ "$now" -gt "$base" ] && return 0
    sleep 1
  done
  return 1
}








# Coupled committee changes: every handoff that changes the EVM assignment also replaces one root entity. H3_BIND_ROOTS lists
# the successor root indices in the same order as the successor EVM validator indices passed to h3_build_assignment: root i is
# the entity whose delegated EVM validator is evm j at the same position.
H3_BIND_ROOTS=""

# h3_build_assignment <tag> <successor ids...>: context, one proof per successor key, assemble. No EVM parent is named anywhere:
# the root binds it when it orders the Prepare, after the proofs.
# Writes $H3_DIR/<tag>-assignment.json; leaves the propose exit status in $?.


# A committed H for the old epoch since the start of the retry loop, read from every root. Dropped plans are NOT a verdict on the
# current attempt: a root keeps older endorsed plans cached and logs "dropped" whenever it leads a round in which one is stale, so
# only "committed" ends the wait; an attempt that neither commits nor aborts within the window is simply retried.
H3_LOOP_MARK=$H3_DIR/loop-mark





h3_head_after_all() { # wait until every id in $@ logs a new certificate admitted at root epoch $1
  local epoch=$1 id i; shift
  for id in "$@"; do
    for i in $(seq 1 120); do
      grep -Eq "msg=\"certificate admitted\" .*rootEpoch=$epoch([[:space:]]|$)" "test-nodes/evm$id/debug.log" && continue 2
      sleep 1
    done
    echo "validator $id never admitted a certificate at root epoch $epoch" >&2; return 1
  done
}

# ----------------------------------------------------------------------------------------------------------------
echo "=== H3 acceptance lane: fresh-B1 genesis (registry layout 3) + three aggregator shards ==="
echo "NOTE: every validator signs through its own signing authority (SIGNING=authority): the rotation is authority-backed."
h3_step "baseline: EVM certifies and all three aggregator shards progress" h3_progress baseline 8
h3_step "genesis registry is the fresh-B1 registry, shard epoch 0, root epoch 1" h3_registry_is 0 1

# 1. Baseline: a configuration-only epoch advance (same committee, no EVM change): root epoch 2, shard epoch stays 0.
h3_config_only() {
  h3_q3_init || return 1
  h3_q3_config_handoff 2 || return 1
  h3_restart_roots 2 || { echo "root restart into epoch 2 failed" >&2; return 1; }
  echo "roots restarted into epoch 2" >&2
  # the F8 lane keeps certifying empty EVM blocks, so the "latest head" the replica wait targets moves faster than the peers acknowledge it
  M2_ADVANCE_NO_REPLICA_WAIT=1 m2_advance_authorities 2 trust-base-epoch2.json || { echo "authority advance to root epoch 2 failed" >&2; return 1; }
  h3_paid 2 || { echo "paid transaction at root epoch 2 was not certified" >&2; return 1; }
  # the registry's root epoch is written by an EVM block after the new root epoch is installed: poll like the later steps do
  local i
  for i in $(seq 1 120); do h3_registry_is 0 2 && return 0; sleep 1; done
  echo "registry did not reach shard epoch 0 / root epoch 2" >&2
  return 1
}
h3_step "baseline: configuration-only epoch advance (same committee): shard epoch stays 0, root epoch 2, paid tx certified" h3_config_only
h3_step "aggregators and EVM progress after the configuration-only advance" h3_progress config-only 8 "${H3_POST_RESTART_WINDOW:-}"
h3_has_coupling_param() { jq -e '.partitionParams.validator_coupling == "true"' "$fullShardConf" >/dev/null; }
h3_step "the genesis EVM configuration requires coupled validator-set changes (validator_coupling=true)" h3_has_coupling_param

# 2. An EVM proposal with a bad PoP is refused before freeze.
h3_spare_identity 5; h3_spare_identity 6
# The joiner evm5 and its root 5 start now, before any Commit: its root follows the committee and signs nothing, its shard node is staging-only, and
# its paired execution client is pinned. Its readiness receipt is one of the four the s=1 plan needs.
h3_join_s1() {
  build/ubft root-node init --home test-nodes/root5 -g >/dev/null 2>&1 || true
  generate_log_configuration "test-nodes/root5/"
  h3_q3_trust_base 3 "1 2 3 5" || return 1
  h3_q3_start_joiner 5 1 3 trust-base-epoch3.json
}
h3_step "joiner evm5 and root 5 start before the Commit: root follower, shard node staging-only, execution client paired" h3_join_s1
h3_bad_pop() {
  local start
  Q3_NEXT_EPOCH=3 Q3_ASSIGN_TAG=bad Q3_SUFFIX=-bad Q3_ENTITIES="1 2 3 5" Q3_INCUMBENT=$H3_INCUMBENT
  q3_build_assignment bad 1 2 3 5 || return 1
  python3 - "$H3_DIR/bad-assignment.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
sig=bytearray(bytes.fromhex(d['pops'][-1]['signature'].removeprefix('0x')))
sig[10]^=1                                  # the proof no longer verifies under this attempt's context
d['pops'][-1]['signature']='0x'+sig.hex()
json.dump(d,open(p,'w'))
PY
  start=$(wc -l <"test-nodes/root$(h3_first_root)/debug.log")
  # the candidate and every successor member's readiness are as for a good proposal; the root refuses the PLAN on the proofs of possession
  if Q3_ASSIGNMENT_BUILT=1 q3_attempt >"$H3_DIR/bad-propose.out" 2>&1; then echo "root accepted a proposal with a corrupted PoP" >&2; unset Q3_NEXT_EPOCH Q3_ASSIGN_TAG Q3_SUFFIX Q3_ENTITIES Q3_INCUMBENT; return 1; fi
  unset Q3_NEXT_EPOCH Q3_ASSIGN_TAG Q3_SUFFIX Q3_ENTITIES Q3_INCUMBENT
  cat "$H3_DIR/bad-propose.out"
  grep -Eq "invalid proof of possession|possession proofs differ" "$H3_DIR/bad-propose.out" || { echo "the refusal does not name the proofs of possession" >&2; return 1; }
  # refused at plan time, before any intent, Prepare or endorsement: nothing was ordered and the epoch did not move
  ! tail -n +"$((start+1))" "test-nodes/root$(h3_first_root)/debug.log" | grep -Eqi 'handoff (prepare|freeze|endorse)' || return 1
  [ "$(h3_root_info | jq -r '.epochNumber')" = 2 ]
}
h3_step "EVM proposal with a bad proof of possession is refused before any Prepare" h3_bad_pop

# 3. Coupled rotation s=1 during an in-flight old proposal: root 4 -> 5 together with evm4 -> evm5. The retained evm3 is stopped
#    and evm5 is not yet running, so the successor quorum cannot acknowledge until the root quorum restart is over.
h3_evm_s1() {
  local i tx
  # keep an old-epoch proposal in flight: submit a paid tx to every validator, then propose before it certifies
  for i in 1 2 3 4; do
    tx=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase+i-1))" -chain-id 31337 -nonce "$M2_NEXT_NONCE" 2>&1) || { echo "in-flight tx to validator $i failed (nonce $M2_NEXT_NONCE): $tx" >&2; return 1; }
  done
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
  h3_q3_handoff s1 3 "1 2 3 5" || return 1   # the Q3 flow: candidate, the four successor members' readiness (evm5's among them), plan, Commit
  stop_one_evm_validator 3 || return 1       # hold the acknowledgement: only evm1 and evm2 remain of {1,2,3,5}
  stop_one_evm_validator 4 || return 1       # evm4 is retired; its old process is stopped here
  stop_one_evm_validator 5 || return 1       # the staging-only joiner has given its readiness; its EVM state comes from the post-install restore
  echo "H committed at old epoch 2; successor quorum is held below threshold"
}
h3_step "coupled rotation s=1 (root 4->5, evm4->evm5) committed with an old proposal in flight; ack held" h3_evm_s1

h3_root_quorum_restart() {
  local row0 row1
  row0=$(h3_evm_row | jq -c '{round: .roundNumber, tr: .trRound}')
  h3_q3_activate_coupled 3 4 5 || return 1    # the root quorum restarts into the install epoch (follower root 5 first), the replaced root 4 stops
  H3_EVM_STALLED=1 h3_progress "after root quorum restart (ack still held)" 10 "${H3_POST_RESTART_WINDOW:-}" || return 1
  h3_registry_is 0 2 || return 1             # the successor set has not acknowledged: registry is still at the old shard epoch
  row1=$(h3_evm_row | jq -c '{round: .roundNumber, tr: .trRound}')
  echo "EVM row before restart $row0, after $row1"
}
h3_step "root quorum restarted at epoch 3; roots and aggregators progress while the ack is held" h3_root_quorum_restart

# Hard rejection assertion for a node id the installed assignment does not contain. The root's own refusal is
# `node "<id>" is not in the trustbase of the shard` (ShardInfo.Verify, logged by the root as "processing
# *certification.BlockCertificationRequest"). It must (1) appear in a root log since the mark, and (2) the id must never
# appear among the requestNodeIDs of a request set the root accepted ("reached consensus"), i.e. nothing it sent certified.
h3_assert_rejected() { # node id, what, [seconds to wait: a node that must first RESTORE needs minutes to reach the roots]
  local id=$1 what=$2 window=${3:-90} alt_log=${4:-} i refusals=0 accepted alt_used=0
  for i in $(seq 1 "$window"); do
    # The root refuses a retired or never-active key in one of two places, both of them the active-set check: at the handshake
    # ("node ID is not in active validator set ... <id>", the node then never gets a certificate and sends no request) or, for a
    # request that does arrive, at the request ("node <id> is not in the trustbase of the shard"). slog text escapes the quotes around the id
    # inside err="...", so the pattern allows an optional backslash before each quote.
    refusals=$(h3_since_mark | grep -E "processing \*(certification.BlockCertificationRequest|handshake.Handshake)" |
      grep -cE "node \\\\?\"$id\\\\?\" is not in the trustbase of the shard|node ID is not in active validator set .*$id" || true)
    [ "$refusals" -ge 1 ] && break
    # A retired key is refused one layer earlier too: the validators' archive replicas serve only the ACTIVE assignment's validators, so a
    # node that must first restore from them is refused there ("archive peer is not allowed") and never reaches a root at all.
    if [ -n "$alt_log" ] && grep -aq "archive peer is not allowed" "$alt_log" 2>/dev/null; then
      echo "$what: refused by the archive replicas (archive peer is not allowed): $id is not in the active assignment, so it cannot even restore"
      echo "NOTE: the ROOT-level refusal of this late acknowledgement was NOT exercised end to end in this run: the node was stopped earlier, at the archive, and never reached a root."
      echo "NOTE: root-side refusal of a superseded or retired set is covered by unit tests: TestSupersessionReplacesAnUnacknowledgedAssignmentOnTheSameParent (rootchain/consensus/storage/handoff_supersession_test.go: the superseded s=2 keys are 'not in the trustbase of the shard'), TestAcknowledgementEndsThePendingStateAndRetiredKeysStayRefused and TestRetiredKeyRequestIsNotCertifiedInTheActivationBlockOrTheNext (handoff_assignment_activation_test.go, handoff_changes_test.go), and Test_onBlockCertificationRequest case 1 (rootchain/node_test.go: the root rejects a request from a node outside the shard's trust base). The handshake-time refusal (rootchain/node.go 'node ID is not in active validator set') has NO unit test; the lane's retired-key (evm4) step exercises it end to end for the s=0 key only." >&2
      refusals=1
      alt_used=1
      break
    fi
    sleep 1
  done
  [ "$refusals" -ge 1 ] || { echo "$what: no root logged an active-set refusal for $id (handshake or request), and no archive replica refused it" >&2; return 1; }
  accepted=$(h3_since_mark | grep -F "reached consensus" | grep -F "requestNodeIDs" | grep -cF "$id" || true)
  [ "$accepted" -eq 0 ] || { echo "$what: root accepted $accepted request set(s) containing $id" >&2; return 1; }
  if [ "$alt_used" = 1 ]; then
    echo "$what: refused at the ARCHIVE (not at a root); 0 accepted request sets contain $id"
  else
    echo "$what: $refusals exact root refusal(s) for $id; 0 accepted request sets contain it"
  fi
}

h3_retired_key_rejected() {
  local id4
  id4=$(evm_validator_id 4)
  h3_mark
  # evm4's old process was stopped; start it again with the genesis home: its requests must be refused by the root.
  start_one_evm_validator 4 "$validators" "$partitionID" "$(m2_root_addr "$(h3_first_root)")" engine-api rpc \
    "$(evm_bootnodes_for_peers "$(m2_root_addr "$(h3_first_root)")" 4 1 2)" || return 1
  h3_assert_rejected "$id4" "retired key evm4" || return 1
  [ "$(h3_slot "$h3_slot_shard")" = 0 ]      # and it did not acknowledge anything
}
h3_step "retired-key (evm4) requests are rejected by the root" h3_retired_key_rejected
stop_one_evm_validator 4 2>/dev/null || true

# 4. Acknowledge with s=1: restart retained evm3 and restore evm5; certify the ack and a paid mint.
h3_ack_s1() {
  H3_ONLINE="1 2 3 5"
  # After s=1 evm4 is retired: a node refuses to start naming it as an archive replica (#365), so the restarts below name the s=1 set.
  # Each validator names the next two in pool order, and the product refuses a replica pair change that keeps no acknowledging replica:
  # the default pool gave 1->2,3  2->3,4  3->4,1; this pool gives 1->2,3  2->3,5  3->5,1, each retaining one (evm5 joins: 5->1,2).
  export EVM_ARCHIVE_REPLICA_POOL="1 2 3 5"
  # evm3 was held down through the Commit: it restarts before it has installed s=1, so it may only name members of the installed s=0 and s=1
  # sets (1 and 2), which retains one of its former pair (4,1)
  export EVM_ARCHIVE_REPLICAS_3="1 2"
  # The retained validators' authorities (1 and 2 running, 3 held down) advance to the activated scope (root epoch 3, shard epoch 1)
  # and their nodes restart with the new sessions; the joiner's authority is enrolled against the activated configuration.
  h3_advance_authorities 3 1 1 2 3 || { echo "authority advance to root epoch 3 / shard epoch 1 failed" >&2; return 1; }
  h3_enroll_authority 5 1 || { echo "enrolling the evm5 authority failed" >&2; return 1; }
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json   # anchored at the genesis trust base: the restore catches up forward through the verified handoffs
  h3_restore_validator 5 1 || return 1
  local i
  for i in $(seq 1 180); do h3_registry_is 1 3 && break; sleep 1; done
  h3_registry_is 1 3 || { echo "registry did not reach shard epoch 1 / root epoch 3" >&2; return 1; }
  # s=1 is the last acknowledged assignment: its committee is the incumbent K of every later handoff
  H3_INCUMBENT="$H3_DIR/s1-identities.json"
  h3_paid 3
}
h3_step "s=1 acknowledgement certified; paid transaction certified at root epoch 3" h3_ack_s1


h3_step "paid mint (lock) certified under the s=1 set" h3_mint 3
h3_step "F7 inclusion proof verifies offline with the epoch-3 trust base and the s=1 PDR" h3_verify_mint 3 1

# 5. H4 restore at s=1: a retained validator loses BFT and EL state and restores under the s=1 configuration.
h3_restore_s1() {
  local i
  H3_ONLINE="2 3 5"
  h3_restore_validator 1 2 || return 1
  H3_ONLINE="1 2 3 5"
  # the restored node re-executes the whole EL chain from its peers before it certifies: allow for a long lane (about 3 blocks/s)
  for i in $(seq 1 600); do
    grep -Eq 'handoff activated.*rootEpoch=3' "test-nodes/evm1/debug.log" &&
      grep -q 'submitting block certification request' "test-nodes/evm1/debug.log" &&
      grep -Eq 'msg="certificate admitted" .*rootEpoch=3([[:space:]]|$)' "test-nodes/evm1/debug.log" && return 0
    kill -0 "$(cat "test-nodes/evm1/pid")" 2>/dev/null || { tail -40 "test-nodes/evm1/debug.log" >&2; return 1; }
    sleep 1
  done
  tail -40 "test-nodes/evm1/debug.log" >&2
  return 1
}
h3_step "H4 restore at s=1: validator 1 restores, verifies epoch 3 and resumes signing" h3_restore_s1

# 6. s=2 = J = {1,2,5,6}: root 3 -> 6 with evm3 -> evm6 (the joiner), evm5 carried over from s=1. The joiner starts and gives its readiness BEFORE the Commit like
#    every successor member; AFTER the Commit enough of J's carried-over EVM weight is stopped to leave J below its quorum (Q=3 of 4): the joiner evm6 AND the
#    carried-over evm5, so evm1 and evm2 alone remain. Stopping only the joiner would leave {1,2,5} = Q and J would acknowledge (the continuity rule keeps most
#    of J carried over from K, so a joiner alone can never block it). K's own quorum {1,2,3} stays up: the recovery needs it.
h3_join_s2() {
  build/ubft root-node init --home test-nodes/root6 -g >/dev/null 2>&1 || true
  generate_log_configuration "test-nodes/root6/"
  h3_q3_trust_base 4 "1 2 5 6" || return 1
  # s=2 set {1,2,5,6}: 1->2,5  2->5,6  5->6,1 (each retains one replica of the s=1 pairs)
  EVM_ARCHIVE_REPLICA_POOL="1 2 5 6" h3_q3_start_joiner 6 2 4 trust-base-epoch4.json
}
h3_step "joiner evm6 and root 6 start before the s=2 Commit" h3_join_s2
h3_evm_s2() {
  h3_q3_handoff s2 4 "1 2 5 6" || return 1   # candidate, the four successor members' readiness (evm6's among them), plan, Commit
  stop_one_evm_validator 6 || return 1       # the joiner fails after the Commit ...
  stop_one_evm_validator 5 || return 1       # ... and so does a carried-over member: J keeps evm1 and evm2, below its quorum of 3
  export EVM_ARCHIVE_REPLICA_POOL="1 2 5 6"
  h3_q3_activate_coupled 4 3 6 || return 1
}
h3_step "coupled s=2 (root 3->6, J={1,2,5,6}) committed with all readiness; evm5 and evm6 fail after the Commit" h3_evm_s2
h3_s2_stalls() {
  local base
  base=$(h3_evm_row | jq -r '.roundNumber')
  sleep 25
  [ "$(h3_evm_row | jq -r '.roundNumber')" = "$base" ] || { echo "EVM certified past H without an s=2 quorum" >&2; return 1; }
  h3_registry_is 1 3 || return 1
  H3_EVM_STALLED=1 h3_progress "s=2 stalled EVM" 8 "${H3_POST_RESTART_WINDOW:-}"
}
h3_step "EVM waits (no certification) while root and aggregators progress" h3_s2_stalls

# 7. Supersede s=2 on the same parent. A supersession is the derived recovery of the pending primary: exactly K, the committee of the last acknowledged
#    assignment (s=1, evm {1,2,3,5}), and its root committee is K's coupled image, so root 6 gives way to root 3 again. It needs no readiness (K is the
#    committee the chain already acknowledged). The retired s=2 set's late acknowledgement is then refused.
h3_supersede_s3() {
  h3_q3_handoff s3 5 "1 2 3 5" recovery || return 1   # root 6 -> 3, committee {1,2,3,5}: the coupled image of K
  export EVM_ARCHIVE_REPLICA_POOL="1 2 3 5"   # back to the s=1 pairs: 1->2,3  2->3,5  3->5,1  5->1,2
  h3_q3_activate_coupled 5 6 3 || return 1
  # the folded acknowledgement needs the retained and returning validators' authorities at the activated scope (root epoch 5, shard epoch 3)
  H3_ONLINE="1 2 3"
  h3_advance_authorities 5 3 1 2 3 5 || { echo "authority advance to root epoch 5 / shard epoch 3 failed" >&2; return 1; }
  local i
  for i in $(seq 1 180); do h3_registry_is 3 5 && return 0; sleep 1; done
  echo "registry did not reach shard epoch 3 / root epoch 5" >&2
  return 1
}
h3_step "the derived recovery to K (root 6->3) supersedes s=2 on the same parent; folded acknowledgement certified" h3_supersede_s3
h3_late_s2_ack_refused() {
  local id6
  id6=$(evm_validator_id 6)
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json   # anchored at the genesis trust base: the restore catches up forward through the verified handoffs
  H3_ONLINE="1 2 3"
  h3_mark
  h3_enroll_authority 6 2 || { echo "enrolling the evm6 authority against the s=2 configuration failed" >&2; return 1; }
  h3_restore_validator 6 1 || true            # the s=2 key tries to acknowledge late
  h3_assert_rejected "$id6" "late s=2 acknowledgement from evm6" 480 test-nodes/evm6/debug.log || return 1
  h3_registry_is 3 5                          # the registry shows s=3's folded acknowledgement, not s=2's
}
h3_step "s=2's late acknowledgement does not succeed (refused at the root when the node reaches one, otherwise at the archive: the output says which)" h3_late_s2_ack_refused
h3_final() {
  stop_one_evm_validator 6 2>/dev/null || true
  H3_ONLINE="1 2 3"
  h3_paid 5 && h3_mint 5 && h3_verify_mint 5 3
}
h3_step "certify and verify a paid mint under s=3 (epoch-5 trust base, s=3 PDR)" h3_final
h3_step "aggregators progressed through the whole lane" h3_progress final 8
echo "H3 acceptance lane: all steps PASSED"
# A green lane stops what it started too: the joiners' and restored nodes are not known to the devnet's own cleanup, and a process left running
# keeps the lane's output pipe (and the devnet lock) open long after the last step.
h3_teardown
