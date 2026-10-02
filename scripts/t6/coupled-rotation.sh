#!/usr/bin/env bash
# T6 rehearsal: one real, key-replacing coupled rotation (shard epoch 0 -> 1) after the placeholder rehearsal's own checks, reusing the H3
# lane's authority helpers (scripts/lib/h3-lib.sh). Sourced by reth-paired-devnet.sh in the T6 lane when T6_COUPLED_ROTATION=1.
#
# The rotation retires one validator (evm4, with its root entity) and adds a joiner (evm5, with its root entity): authority-backed proofs of
# possession (the joiner's authority signs on the operator channel), the root handoff with the operators' endorsements, the root quorum restart,
# the retained validators' authorities advancing to the activated scope, the joiner's authority enrolled and the joiner restored through it,
# the successor set's acknowledgement (the registry reaches shard epoch 1), and a paid mint under the new set verified offline.

source scripts/lib/m2-handoff-lib.sh
source scripts/lib/h3-lib.sh

# The rotation starts processes the devnet's own cleanup does not know (the joiner's node, authority, execution client and root): stop them.
t6_rotation_teardown() {
  local p
  for p in test-nodes/evm5/pid test-nodes/auth5/pid test-nodes/reth5/pid test-nodes/root5/pid; do
    [ -f "$p" ] && kill -INT "$(cat "$p")" 2>/dev/null
  done
  for p in $(owned_pids 'ubft root-node run|ubft shard-node (run|restore)|ubft signing-authority run|reth.* node'); do
    kill -INT "$p" 2>/dev/null
  done
  return 0
}

t6_rotation_attempt() {
  H3_BIND_ROOTS="1 2 3 5" H3_SUPERSEDE=0 h3_build_assignment s1 1 2 3 5 || return 1
  h3_propose s1 "$T6_ROTATION_NEXT_EPOCH"
}

t6_coupled_rotation_s1() {
  local cur next i
  # the lane's own state at this point: four roots and four validators, validator 1 running through the H4 restore command
  H3_DIR=test-nodes/h3; mkdir -p "$H3_DIR"
  H3_ROOTS="1 2 3 4"; H3_ONLINE="1 2 3 4"
  H3_ARCHIVES=${EVM_ARCHIVE_ROOT:?}
  H3_REGISTRY=0xff00000000000000000000000000000000000002
  H3_LOOP_MARK=$H3_DIR/loop-mark
  M2_CHAIN_ID=${POST_M2A_CHAIN_ID:-1337}
  H3_RESTORE_RESTART="1"          # the retained validator that is running through `restore` comes back by restoring, not by a plain start
  read -r h3_slot_shard h3_slot_root h3_slot_conf h3_slot_cursor < <(go run ./scripts/h3slots) || return 1
  cur=$(h3_root_info | jq -r '.epochNumber') || return 1
  next=$((cur + 1)); T6_ROTATION_NEXT_EPOCH=$next
  echo "T6 coupled rotation: root epoch $cur -> $next, shard epoch 0 -> 1; evm4 (root 4) retires, evm5 (root 5) joins"

  h3_spare_identity 5 || return 1
  h3_prepare_coupled "$next" 4 5 || return 1
  h3_spare_authority 5 1 "$next" "trust-base-epoch${next}.json" || return 1
  h3_start_reth 5 || return 1
  h3_retry_handoff "$cur" t6_rotation_attempt || return 1
  echo "T6 coupled rotation: H committed at root epoch $cur"

  # the validator running through the H4 restore command and the retired validator stop here; the roots restart on the install epoch
  stop_pidfile test-nodes/h4-replaced/pid 'ubft shard-node restore' || true
  stop_one_evm_validator 4 || return 1
  h3_activate_coupled "$next" 4 5 || return 1

  H3_ONLINE="1 2 3 5"
  h3_advance_authorities "$next" 1 1 2 3 || { echo "authority advance to root epoch $next / shard epoch 1 failed" >&2; return 1; }
  h3_enroll_authority 5 1 || { echo "enrolling the evm5 authority failed" >&2; return 1; }
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json   # anchored at the genesis trust base: the restore catches up forward through the verified handoffs
  h3_restore_validator 5 2 || return 1
  for i in $(seq 1 180); do h3_registry_is 1 "$next" && break; sleep 1; done
  h3_registry_is 1 "$next" || { echo "registry did not reach shard epoch 1 / root epoch $next" >&2; return 1; }
  echo "T6 coupled rotation: the successor set acknowledged (registry: shard epoch 1, root epoch $next)"

  h3_mint "$next" || return 1
  h3_verify_mint "$next" 1 || return 1
  echo "T6 coupled rotation: paid mint under the s=1 set verified offline with the epoch-$next trust base and the s=1 PDR"
}
