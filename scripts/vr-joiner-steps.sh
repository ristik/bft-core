#!/usr/bin/env bash
# The VR lane's spare validator (VT-09, bft-core#1149): a fifth identity that applies, is admitted by the Foundation multisig and elected, and
# validates in epoch 2. Sourced by scripts/vr-boundary-steps.sh under VR_JOINER=1, in the lane's shell (its variables and helper functions).
#
#   vrj_start_nodes     the joiner's root (a follower of the committee, VR mode, its member steps its own), its shard node (staging only
#                       before the Commit) and its execution client, paired and peered with the running ones
#   vrj_apply           `ubft validator apply`: VR.register the root and EVM keys with a payee, then PoaElection.submitApplication
#   vrj_admit           `ubft governance`: three of the five Foundation signers approve ModuleAction(Admit, id); the multisig queues it; once both
#                       governance delays have passed (DELAY_ROUNDS and DELAY_SECONDS, 3600 s of certified time) the change is executed
#   vrj_validates       the joiner's root is a member of epoch 2 and its shard node validates under it

vrj_id=5
vrj_log() { vrb_log "$@"; }

vrj_source_libs() {
  declare -F m2_start_root >/dev/null || source scripts/lib/m2-handoff-lib.sh || return 1
  declare -F h3_start_reth >/dev/null || source scripts/lib/h3-lib.sh || return 1
  declare -F reth_trust >/dev/null || source scripts/lib/reth-peers.sh || return 1
  H3_ROOTS="1 2 3 4"; H3_ONLINE="1 2 3 4"; H3_DIR=test-nodes/h3; mkdir -p "$H3_DIR"
}

vrj_start_nodes() {
  local i=$vrj_id boot bootnodes
  vrj_source_libs || { vrj_log "FAIL: the joiner's libraries"; return 1; }
  build/ubft root-node init --home "test-nodes/root$i" -g >/dev/null 2>&1 || true
  generate_log_configuration "test-nodes/root$i/"
  h3_spare_identity "$i" || { vrj_log "FAIL: the joiner's shard node identity"; return 1; }
  h3_start_reth "$i" || { vrj_log "FAIL: the joiner's execution client"; return 1; }
  boot=$(m2_root_addr 1)
  { m2_start_root "$i" 1 "$boot"; } >/dev/null 2>&1 || true   # its readiness check needs lsof: the RPC is the check
  vrb_wait 90 "the joiner's root answers on its RPC" curl -sf "http://127.0.0.1:$(m2_rpc_port "$i")/api/v1/roundInfo" || return 1
  bootnodes=$(evm_bootnodes_for_peers "$boot" "$i" 1 2 3 4) || return 1
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))" "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
  EVM_ARCHIVE_REPLICA_POOL="1 2 3 4 5" start_one_evm_validator "$i" "${validators:-4}" "$partitionID" "$boot" engine-api rpc "$bootnodes" || return 1
  sleep 5
  kill -0 "$(cat "test-nodes/evm$i/pid")" 2>/dev/null || { vrj_log "FAIL: the joiner's shard node exited"; tail -30 "test-nodes/evm$i/debug.log" >&2; return 1; }
  vrj_log "PASS: the joiner's root$i, evm$i and reth$i are up"
}
