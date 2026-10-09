# The H3 lane's Q3-flow handoffs (the fresh-B1 layout has one handoff flow): the successor trust base, the candidate every successor member declares
# readiness for, the readiness receipts, the plan, and the activation by install restart. Sourced by scripts/h3-assignment-steps.sh after
# scripts/lib/q3-flow-lib.sh and scripts/lib/h3-lib.sh. Definitions only.
#
# Entities: root i and its delegated EVM validator i share the index i (the lane's spare identities are 5, 6, 7). Unit weights throughout (the PoA
# committee); a handoff names its successor entities in Q3_ENTITIES.
#
# A JOINER (a successor member the committee does not name yet) is started BEFORE the Commit, as the joiner design requires: its root follows the
# committee and signs nothing (a root the trust base does not name is a follower), its shard node is staging-only (its signer refuses every request),
# and its execution client is paired and pinned. It stages the candidate and gives its readiness receipt; after the Commit the lane restarts the
# roots into the install epoch, and the joiner's EVM state comes from the existing post-install restore.

h3_q3_init() {
  Q3_DIR=$H3_DIR
  mkdir -p "$Q3_DIR"; : >>"$Q3_DIR/commands.log"; : >>"$Q3_DIR/pins.txt"
  q3_execution_pins || return 1
  Q3_WEIGHTS="1 1 1 1"
  H3_INCUMBENT=${H3_INCUMBENT:-test-nodes/genesis-identities.json}
}

# The H3 flavour of the assignment the flow's q3_attempt names (the Q3 lane has its own: the same four entities with mirrored weights): the successor
# identity records, the recovery authorization over the incumbent K, one proof of possession per successor key, assembled; or, with Q3_RECOVERY=1,
# the derived recovery of the pending primary (exactly K: no validators, bindings, proofs, identities or authorization).
q3_build_assignment() { # tag ids...
  local tag=$1; shift
  if [ -n "${Q3_RECOVERY:-}" ]; then h3_build_recovery "$tag"; return; fi
  H3_NEXT_EPOCH=${Q3_NEXT_EPOCH:?} H3_INCUMBENT=${Q3_INCUMBENT:-$H3_INCUMBENT} H3_BIND_ROOTS="$*" h3_build_assignment "$tag" "$@"
}

# The successor root trust base of a coupled change: the successor roots with unit weights, signed by the roots that stay and by the new root (the replaced
# root does not sign), the V3 candidate's input.
h3_q3_trust_base() { # epoch successor-roots
  local epoch=$1 roots=$2 saved=$H3_ROOTS rc
  H3_ROOTS=$roots q3_trust_base_v3 "$epoch"; rc=$?
  H3_ROOTS=$saved
  return $rc
}

# One handoff through the Q3 flow, to $epoch with the successor entities $ents: trust base, then attempts (candidate, receipts, plan) until the Commit.
h3_q3_handoff() { # tag epoch "successor entities" [recovery]
  local tag=$1 epoch=$2 ents=$3 recovery=${4:-} rc
  h3_q3_trust_base "$epoch" "$ents" || return 1
  Q3_NEXT_EPOCH=$epoch Q3_ASSIGN_TAG=$tag Q3_SUFFIX=-$tag Q3_ENTITIES=$ents Q3_INCUMBENT=$H3_INCUMBENT
  if [ -n "$recovery" ]; then Q3_RECOVERY=1; Q3_SUPERSEDE=1; else unset Q3_RECOVERY Q3_SUPERSEDE; fi
  h3_retry_handoff $((epoch - 1)) q3_attempt; rc=$?
  unset Q3_NEXT_EPOCH Q3_ASSIGN_TAG Q3_SUFFIX Q3_ENTITIES Q3_INCUMBENT Q3_RECOVERY Q3_SUPERSEDE
  return $rc
}

# The same-members configuration-only handoff: no EVM assignment, the committee and its unit weights unchanged.
h3_q3_config_handoff() { # epoch
  local epoch=$1 rc
  Q3_NO_ASSIGNMENT=1 h3_q3_handoff "config$epoch" "$epoch" "$H3_ROOTS"; rc=$?
  return $rc
}

# A joiner's stack before its Commit: its execution client (paired and pinned), its signing authority (pending at the successor scope), its root as
# a follower of the committee, and its shard node, staging-only. Idempotent.
h3_q3_start_joiner() { # entity shardEpoch rootEpoch trustFile
  local i=$1 shardEpoch=$2 rootEpoch=$3 trust=$4 bootnodes
  if [ ! -f "test-nodes/root$i/node-info.json" ]; then
    build/ubft root-node init --home "test-nodes/root$i" -g >/dev/null || return 1
    generate_log_configuration "test-nodes/root$i/"
  fi
  h3_spare_identity "$i" || return 1
  [ -f "test-nodes/reth$i/pid" ] && kill -0 "$(cat "test-nodes/reth$i/pid")" 2>/dev/null || h3_start_reth "$i" || return 1
  h3_spare_authority "$i" "$shardEpoch" "$rootEpoch" "$trust" || return 1
  # no session yet: the authority issues none before the Commit enrolls it, and a staging-only node signs nothing (the restore after the Commit takes one)
  # the follower root: no install epoch (it is not a member of any installed epoch yet), the committee's roots as bootnodes
  m2_start_root "$i" "" "$(m2_root_addr "$(h3_first_root)")" || return 1
  bootnodes=$(evm_bootnodes_for_peers "$(m2_root_addr "$(h3_first_root)")" "$i" $H3_ONLINE) || return 1
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))" "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
  start_one_evm_validator "$i" "$validators" "$partitionID" "$(m2_root_addr "$(h3_first_root)")" engine-api rpc "$bootnodes" || return 1
  h3_q3_wait_joiner "$i"
}

# The joiner's own status reports it as a follower / staging-only: the root says follower, the shard node answers its status endpoint.
h3_q3_wait_joiner() { # entity
  local i=$1 n
  for n in $(seq 1 60); do
    if curl -fsS -m 5 -X POST -H 'content-type: application/json' -d '{}' "$(h3_rpc_url "$i")/api/v1/q3/status" 2>/dev/null | jq -e '.follower == true' >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "joiner root $i never reported itself a follower (q3/status)" >&2
  curl -sS -m 5 -X POST -H 'content-type: application/json' -d '{}' "$(h3_rpc_url "$i")/api/v1/q3/status" >&2 || true
  return 1
}

# After the Commit: the new root (already running as a follower) restarts into the install epoch first, the retained roots follow, the replaced one stops.
h3_q3_activate_coupled() { # epoch replaced new
  local epoch=$1 replace=$2 new=$3 i oldBoot
  oldBoot=$(m2_root_addr "$replace")
  # the new root is a running follower (a joiner) or a stopped member that returns (the recovery's root): either way it restarts into the install epoch
  [ ! -f "test-nodes/root$new/pid" ] || stop_pidfile "test-nodes/root$new/pid" 'ubft root-node' || true
  for _ in $(seq 1 50); do lsof -nP -iTCP:"$(m2_rpc_port "$new")" -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 0.2; done
  m2_archive_root_state "$new" "$epoch" || return 1
  m2_start_root "$new" "$epoch" "$oldBoot" || return 1
  for i in $H3_ROOTS; do
    [ "$i" = "$replace" ] && continue
    stop_pidfile "test-nodes/root$i/pid" 'ubft root-node' || return 1
    for _ in $(seq 1 50); do lsof -nP -iTCP:"$(m2_rpc_port "$i")" -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 0.2; done
    m2_archive_root_state "$i" "$epoch" || return 1
    m2_start_root "$i" "$epoch" "$oldBoot" || return 1
  done
  stop_pidfile "test-nodes/root$replace/pid" 'ubft root-node' || return 1
  H3_ROOTS=$(for i in $H3_ROOTS; do [ "$i" = "$replace" ] && echo "$new" || echo "$i"; done | tr '\n' ' ' | sed 's/ $//')
  m2_wait_root_epoch "$(h3_first_root)" "$epoch"
}
