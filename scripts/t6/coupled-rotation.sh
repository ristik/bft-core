#!/usr/bin/env bash
# T6 rehearsal: one real, key-replacing coupled rotation (shard epoch 0 -> 1) after the placeholder rehearsal's own checks, on the fresh-B1 layout through
# the Q3 flow, reusing the H3 lane's helpers (scripts/lib/h3-lib.sh, h3-q3-lib.sh, q3-flow-lib.sh). Sourced by reth-paired-devnet.sh in the T6 lane when
# T6_COUPLED_ROTATION=1.
#
# The rotation retires one validator (evm4, with its root entity) and adds a joiner (evm5, with its root entity). The joiner's root starts as a follower
# and its shard node staging-only BEFORE the Commit; the four successor members give readiness receipts (candidate staged on each entity's own root and
# shard), authority-backed proofs of possession (the joiner's authority signs on the operator channel), the root handoff with the operators'
# endorsements, the root quorum restart into the install epoch, the retained validators' authorities advancing to the activated scope, the joiner's authority
# enrolled and the joiner restored through it, the successor set's acknowledgement (the registry reaches shard epoch 1), and a paid mint under the new set
# verified offline. A failure of any step FAILS the step (return 1); nothing here aborts the sourcing shell except the documented test hook.

source scripts/lib/m2-handoff-lib.sh
source scripts/lib/h3-lib.sh
source scripts/lib/q3-lib.sh
source scripts/lib/q3-flow-lib.sh
source scripts/lib/h3-q3-lib.sh

# The rotation starts processes the devnet's own cleanup does not know (the joiner's node, authority, execution client and root): stop them.
t6_rotation_teardown() {
  local p
  # a pid file's value is signalled only if that process is this checkout's and matches the command (stop_pidfile; a reused pid is not)
  stop_pidfile test-nodes/evm5/pid 'ubft shard-node (run|restore)' INT
  stop_pidfile test-nodes/auth5/pid 'ubft signing-authority run' INT
  stop_pidfile test-nodes/auth6/pid 'ubft signing-authority run' INT
  stop_pidfile test-nodes/reth5/pid 'reth.* node' INT
  stop_pidfile test-nodes/root5/pid 'ubft root-node run' INT
  for p in $(owned_pids 'ubft root-node run|ubft shard-node (run|restore)|ubft signing-authority run|reth.* node'); do
    kill -INT "$p" 2>/dev/null
  done
  return 0
}

# Every Q3 activation of the lane so far: the restore pin names the V3 body identity of the tip's root epoch (a Q3 activation is not archived as a bundle).
t6_body_ids() {
  local f n ids=
  for f in test-nodes/q3/v3-body-id-m2e*.txt; do
    [ -f "$f" ] || continue
    n=${f##*m2e}; n=${n%.txt}
    ids+="${ids:+,}$n=$(tr -d '[:space:]' <"$f")"
  done
  echo "$ids"
}

# A candidate outside the committed churn budget is refused at the candidate, naming the weight distance, and nothing moves: the epoch is unchanged.
# Two of four members replaced by new identities (entities 5 and 6 for 3 and 4): 4 -> 4 with unit weights is D = 1 > 1/2. The turnover gate (3*2 >= 4) and
# the overlap gate refuse it as well, but the exact reason asserted is the distance, and the refusal comes from the continuity rule and from nothing earlier
# (a shape, binding or proof failure would not name it). The candidate is the first call of the flow: no readiness, plan or Commit follows.
t6_over_bound_refused() { # next-epoch
  local next=$1 out=$H3_DIR/over-bound.out epoch rc
  build/ubft root-node init --home test-nodes/root6 -g >/dev/null 2>&1 || true
  generate_log_configuration "test-nodes/root6/"
  h3_q3_trust_base "$next" "1 2 5 6" || return 1
  h3_spare_identity 6 || return 1
  h3_spare_authority 6 1 "$next" "trust-base-epoch${next}.json" || return 1
  Q3_NEXT_EPOCH=$next Q3_ASSIGN_TAG=over Q3_SUFFIX=-over Q3_ENTITIES="1 2 5 6" Q3_INCUMBENT=$H3_INCUMBENT
  if ! q3_attempt >"$out" 2>&1; then rc=0; else rc=1; fi
  unset Q3_NEXT_EPOCH Q3_ASSIGN_TAG Q3_SUFFIX Q3_ENTITIES Q3_INCUMBENT
  [ "$rc" = 0 ] || { echo "T6: the over-budget candidate (two of four members replaced) was not refused" >&2; cat "$out" >&2; return 1; }
  # D = sum |w*V-v*W| / (V*W): two removed and two added, each |4-0| = 4, so 16 over V*W = 16
  grep -qF 'continuity: weight distance exceeded: sum |w*V-v*W|=16 over V*W' "$out" || {
    echo "T6: the over-budget refusal is not the weight distance 16 over V*W" >&2; cat "$out" >&2; return 1; }
  epoch=$(h3_root_info | jq -r '.epochNumber')
  [ "$epoch" = "$((next - 1))" ] || { echo "T6: the root epoch moved to $epoch on a refused candidate" >&2; return 1; }
  echo "T6 coupled rotation: a candidate replacing two of four members (D=1 > 1/2) was refused: weight distance exceeded"
}

t6_coupled_rotation_s1() {
  local cur next ids
  # the lane's own state at this point: four roots and four validators, validator 1 running through the H4 restore command
  H3_DIR=test-nodes/h3; mkdir -p "$H3_DIR"
  H3_ROOTS="1 2 3 4"; H3_ONLINE="1 2 3 4"
  H3_ARCHIVES=${EVM_ARCHIVE_ROOT:-}
  [ -n "$H3_ARCHIVES" ] || { echo "T6 coupled rotation: EVM_ARCHIVE_ROOT is not set" >&2; return 1; }
  H3_REGISTRY=0xff00000000000000000000000000000000000002
  H3_LOOP_MARK=$H3_DIR/loop-mark
  M2_CHAIN_ID=${POST_M2A_CHAIN_ID:-1337}
  # set before anything that can restore (h3_advance_authorities restores the H3_RESTORE_RESTART validators): anchored at the genesis trust
  # base, the restore catches up forward through the verified handoffs
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json
  H3_RESTORE_RESTART="1"          # the retained validator that is running through `restore` comes back by restoring, not by a plain start
  read -r h3_slot_shard h3_slot_root h3_slot_conf h3_slot_cursor < <(H3_SLOT_LAYOUT=3 go run ./scripts/h3slots) || return 1
  cur=$(h3_root_info | jq -r '.epochNumber') || return 1
  [ -n "$cur" ] && [ "$cur" != null ] || { echo "T6 coupled rotation: the root epoch is unreadable" >&2; return 1; }
  next=$((cur + 1)); T6_ROTATION_NEXT_EPOCH=$next
  echo "T6 coupled rotation: root epoch $cur -> $next, shard epoch 0 -> 1; evm4 (root 4) retires, evm5 (root 5) joins"
  ids=$(t6_body_ids)
  [ -z "$ids" ] || export H4_RESTORE_BODY_IDS="${H4_RESTORE_BODY_IDS:+$H4_RESTORE_BODY_IDS,}$ids"

  # The H4 restore of validator 1 wiped its home and ran from test-nodes/h4-replaced, keeping the identity there: put it back, so the node id
  # can be read and the validator can be restored into its own home again.
  if [ ! -f test-nodes/evm1/keys.json ] && [ -f test-nodes/h4-replaced/keys.json ]; then
    mkdir -p test-nodes/evm1
    cp test-nodes/h4-replaced/keys.json test-nodes/evm1/keys.json
    [ -f test-nodes/evm1/logger-config.yaml ] || cp test-nodes/evm2/logger-config.yaml test-nodes/evm1/logger-config.yaml 2>/dev/null || true
    [ -f test-nodes/evm1/jwt.hex ] || cp test-nodes/h4-replaced/jwt.hex test-nodes/evm1/jwt.hex 2>/dev/null || true
  fi
  h3_q3_init || return 1

  # the joiner starts BEFORE the Commit: its root a follower of the committee, its shard node staging-only, its execution client paired and pinned
  build/ubft root-node init --home test-nodes/root5 -g >/dev/null 2>&1 || true
  generate_log_configuration "test-nodes/root5/"
  h3_q3_trust_base "$next" "1 2 3 5" || return 1
  # evm5 is a LATER joiner (two Q3 activations already precede it): a fresh node holds the genesis tip only and would refuse a candidate that is not its
  # successor, so its shard node starts as a restore from evm2's archive at its readiness turn (as the H3 lane's s=2 joiner does)
  EVM_ARCHIVE_REPLICA_POOL="1 2 3 5" H3_ONLINE="1 2 3" h3_q3_start_joiner 5 1 "$next" "trust-base-epoch${next}.json" 2 || return 1
  # Test hook (documented, off by default): T6_TEST_FAIL_AFTER_AUTH5=return fails this step, =abort aborts the shell (as an unbound variable
  # does under set -u), right after the joiner's authority and execution client started: the run must still stop them and exit.
  case "${T6_TEST_FAIL_AFTER_AUTH5:-}" in return) return 1 ;; abort) exit 1 ;; esac

  # The testnet profile's churn budget is D <= 1/2 (owner decision 19, briefs/p85-churn-bound-note.md), committed in the genesis configuration: the rotation
  # below replaces one of four (D = 1/2, within it), and a candidate that replaces two of four (D = 1) is refused with the distance named.
  # T6_TEST_SKIP_OVER_BOUND=1 (development iterations only, never evidence): omit the refused candidate, to tell its effects from the rotation's
  [ -n "${T6_TEST_SKIP_OVER_BOUND:-}" ] || t6_over_bound_refused "$next" || return 1

  # the verified history the root holds before the rotation (the stage refusal names the shard node's own tip to compare with)
  q3_history_ids "$Q3_DIR/history-before-s1.txt" && sed "s/^/root history: /" "$Q3_DIR/history-before-s1.txt"
  t6_joiner_restore() { [ "$1" != 5 ] || EVM_ARCHIVE_REPLICA_POOL="1 2 3 5" H3_ONLINE="1 2 3" h3_q3_joiner_shard_restore 5 2; }
  Q3_BEFORE_READINESS=t6_joiner_restore h3_q3_handoff s1 "$next" "1 2 3 5" || return 1   # the Q3 flow: candidate, the four successor members' readiness, plan, Commit
  echo "T6 coupled rotation: H committed at root epoch $cur"

  # the validator running through the H4 restore command, the retired validator and the staging-only joiner stop here; the roots restart on the install epoch
  stop_pidfile test-nodes/h4-replaced/pid 'ubft shard-node restore' || true
  stop_one_evm_validator 4 || return 1
  stop_one_evm_validator 5 || return 1
  h3_q3_activate_coupled "$next" 4 5 || return 1

  H3_ONLINE="1 2 3 5"
  # the retired evm4 is no longer a valid archive replica: the restarted retained validators name members of the successor set; each keeps one
  # acknowledging replica of its former pair (1->2,3  2->3,5  3->5,1, and 5->1,2)
  export EVM_ARCHIVE_REPLICA_POOL="1 2 3 5"
  h3_advance_authorities "$next" 1 1 2 3 || { echo "authority advance to root epoch $next / shard epoch 1 failed" >&2; return 1; }
  h3_enroll_authority 5 1 || { echo "enrolling the evm5 authority failed" >&2; return 1; }
  h3_restore_validator 5 2 || return 1
  for _ in $(seq 1 180); do h3_registry_is 1 "$next" && break; sleep 1; done
  h3_registry_is 1 "$next" || { echo "registry did not reach shard epoch 1 / root epoch $next" >&2; return 1; }
  echo "T6 coupled rotation: the successor set acknowledged (registry: shard epoch 1, root epoch $next)"

  h3_mint "$next" || return 1
  h3_verify_mint "$next" 1 || return 1
  echo "T6 coupled rotation: paid mint under the s=1 set verified offline with the epoch-$next trust base and the s=1 PDR"
}
