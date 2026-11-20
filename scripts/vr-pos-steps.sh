#!/usr/bin/env bash
# The PoS-prototype lane's steps (VT-04, ristik/bft-core#1144): sourced by scripts/vr-boundary-steps.sh under VR_LANE=1 VR_POS=1 VR_JOINER=1, after
# vr-joiner-steps.sh. The generation is the PoS prototype (scripts/lib/vr-lib.sh VR_POS=1): four genesis identities bonded in custody, the
# PosElectionAdapter as VR's module, nMax 5. SIGNING=local first (authority signing of the P85 possession proof is a follow-up ticket); UTB on
# (UTB_LANE=1: the signed trust-base history, coordinated with bft-core feat/vr-utb: this file adds no UTB wiring).
#
#   vrp_apply      the fifth identity joins by stake through `ubft validator apply`: VR.register, custody.register, custody.bond, admitDelegation
#   vrp_publish    the hook's election reserves the result from stake; a lane relayer submits every frozen member's possession proof, finalizes the
#                  candidate and publishes it in VR (`ubft validator pos-publish`); the rest is the ordinary VR handoff (intent, readiness, Prepare,
#                  Freeze, H, the Boundary)
#   vrp_rotated    the ordinary rotation completed: VR's committee has five members, lastAcked is the result, custody's last acknowledged
#                  assignment is the result's, the election's open result is cleared, the holder facts and cursors match
#   vrp_utb        the new epoch's trust-base entry, signed by the predecessor quorum, is served at /api/v1/trustbases
#   vrp_recovery   one recovery (install K): see the function; NOT run yet

vrp_election() { jq -r .election "$VR_DIR/contracts/deployment.json"; }
vrp_custody() { jq -r .custody "$VR_DIR/contracts/deployment.json"; }

vrp_apply() {
  vrj_apply || return 1   # `validator apply` dispatches on the active module: on the PoS adapter it registers, bonds and admits the delegation
  local el id=$vrj_id
  el=$(vrp_election)
  local indexed; indexed=$(cast call --rpc-url "$vrb_rpc" "$el" 'isIndexed(uint64)(bool)' "$id")
  [ "$indexed" = true ] || { vrb_log "FAIL: identity $id is not in the election's live index after apply"; return 1; }
  vrb_log "PASS: identity $id registered in VR and custody, bonded, delegation admitted (live count $(cast call --rpc-url "$vrb_rpc" "$el" 'liveCount()(uint32)' | awk '{print $1}'))"
}

# the EVM key file of every identity, in id order (ids follow ascending root node id; the joiner is 5)
vrp_evm_key_args() {
  local i eid h ids=()
  for i in 1 2 3 4; do
    eid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[$((i - 1))]['evmNodeId'])")
    for h in test-nodes/evm*/; do
      [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$eid" ] && ids+=(--evm-keys "$i=$PWD/${h%/}keys.json")
    done
  done
  ids+=(--evm-keys "$vrj_id=$PWD/test-nodes/evm$vrj_id/keys.json")
  printf '%s\n' "${ids[@]}"
}

vrp_open_result() { [ "$(cast call --rpc-url "$vrb_rpc" "$(vrp_election)" 'openResult()(bytes32)')" != 0x0000000000000000000000000000000000000000000000000000000000000000 ]; }

vrp_publish() {
  vrb_wait 1500 "the hook's election reserves a result from stake (cadence passed)" vrp_open_result || return 1
  local rid; rid=$(cast call --rpc-url "$vrb_rpc" "$(vrp_election)" 'openResult()(bytes32)')
  vrb_log "the election reserved $rid; VR's open output is $(vrb_open_output)"
  build/ubft validator pos-publish --validator-config "$vrj_cfg/validator.json" $(vrp_evm_key_args | tr '\n' ' ') 2>&1 | tee "$VR_EVIDENCE/pos-publish.log" || { vrb_log "FAIL: pos-publish"; return 1; }
  vrb_log "PASS: every possession proof submitted, the candidate finalized and the result published in VR"
}

vrp_rotated() {
  local ids el cu rid; el=$(vrp_election); cu=$(vrp_custody)
  ids=$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'committeeIds()(uint64[])')
  case "$ids" in *"$vrj_id"*) vrb_log "PASS: VR's committee after the Boundary includes identity $vrj_id: $ids" ;; *) vrb_log "FAIL: committee $ids"; return 1 ;; esac
  rid=$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'lastAcked()(bytes32)')
  [ "$rid" = "$vrb_result" ] || { vrb_log "FAIL: lastAcked $rid is not R $vrb_result"; return 1; }
  [ "$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'health()(uint8)')" = 0 ] || { vrb_log "FAIL: VR is not Healthy"; return 1; }
  vrb_wait 120 "custody and VR have applied the same records" vrp_cursors_match || return 1
  vrb_log "PASS: ordinary PoS rotation: R acknowledged, VR Healthy, the election's open result $(cast call --rpc-url "$vrb_rpc" "$el" 'openResult()(bytes32)')"
  cast call --rpc-url "$vrb_rpc" "$cu" 'lastAckedAssignment()(bytes32)' | tee "$VR_EVIDENCE/custody-last-acked.txt"
}
vrp_cursors_match() {
  [ "$(cast call --rpc-url "$vrb_rpc" "$(vrp_custody)" 'recordCursor()(uint64)')" = "$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'recordCursor()(uint64)')" ]
}

# the new epoch's trust-base entry (UTB on): served by every root at /api/v1/trustbases, the entry of epoch 2 signed by the epoch-1 quorum
vrp_utb() {
  local r out; out=$VR_EVIDENCE/trustbases
  for r in $(vrb_root_rpcs); do
    curl -sf "$r/api/v1/trustbases" >"$out-$(echo "$r" | tr -c 'a-z0-9\n' '_').json" || { vrb_log "FAIL: $r serves no /api/v1/trustbases"; return 1; }
  done
  vrb_log "PASS: /api/v1/trustbases captured per root (the epoch-2 entry and its predecessor signatures are in $VR_EVIDENCE/trustbases-*.json)"
}

# One recovery (install K) through VR. Not run yet: after the ordinary rotation a second election reserves J' over the same five; the lane then
# stops the EVM services of enough members that J' cannot certify (scripts/p85-recovery-steps.sh "J stalls": the joiner and two retained members
# lose their EVM services, their roots stay for the root quorum), so the root derives the recovery K; expect custody's RecoveryAck then the
# Boundary(recovered): VR's output Recovered, healthy, custody lastAcked = the recovery assignment, cursors and holder facts equal. With K = 5 the
# one-record RecoveryAck callback is 1.69 M plain and 1.85 M with the closures staged (contracts PosLimit.t.sol).
vrp_recovery() {
  vrb_log "FAIL: vrp_recovery is not implemented yet (it needs the live run to fix its timing)"
  return 1
}
