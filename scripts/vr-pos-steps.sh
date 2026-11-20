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
#   vrp_recovery   one recovery (install K) with the saved-closure path (VR_POS_RECOVERY=1): see the function; written before its first live run

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
      [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$eid" ] && ids+=(--evm-keys "$i=$PWD/${h%/}/keys.json")
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

# ---- the recovery (install K) through VR -------------------------------------------------------------------------------------------------
# After the ordinary rotation (K = the five of epoch 2) a second election reserves J' over the same five. J' is handed off by the nodes themselves;
# once its H has committed the lane stops the EVM services of three of the five (J' has 2 of 5, EVM quorum 3: it cannot certify), so the shard never
# acknowledges J'. The roots then derive the recovery (exactly K, no receipts, supersedes J') with the harness commands of the P85 recovery lane
# (`root handoff evm-assemble --recovery --supersede`, `root handoff propose --q3`), and VR applies RecoveryAck(J') and the Boundary (recovered)
# that keeps K. Because the roots close the incumbent K when J' installs and stage J''s own closure when the recovery supersedes it, the
# RecoveryAck record carries the saved-closure path (the contracts' PosLimit saved-closure fixture, K = 5: 1.85 M callback).
# Expected end state: VR output Recovered, VR Healthy, VR's lastAcked = J' (the pair's result), custody's last acknowledged assignment = the recovery
# assignment, the election's result Recovered, custody and VR cursors equal, every holder fact equal to custody's own state. Written before its
# first live run: its timing and the harness helpers it borrows (q3-flow-lib) are what the run fixes.

vrp_source_q3() {
  declare -F q3_trust_base_v3 >/dev/null || source scripts/lib/q3-lib.sh || return 1
  declare -F q3_attempt >/dev/null || source scripts/lib/q3-flow-lib.sh || return 1
  Q3_DIR=${Q3_DIR:-$H3_DIR}; mkdir -p "$Q3_DIR"
  # the recovery's assignment is the derived one: no proofs, no authorities
  q3_build_assignment() {
    build/ubft root handoff evm-context --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$Q3_DIR/$1-context.json" || return 1
    build/ubft root handoff evm-assemble --context "$Q3_DIR/$1-context.json" --recovery --supersede --out "$Q3_DIR/$1-assignment.json"
  }
}

vrp_result_state() { cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'output(bytes32)' "$1" 2>/dev/null | python3 -c "import sys;h=sys.stdin.read().strip()[2:];w=[h[i:i+64] for i in range(0,len(h),64)];print(int(w[2],16))"; }
vrp_new_open_result() { local r; r=$(cast call --rpc-url "$vrb_rpc" "$(vrp_election)" 'openResult()(bytes32)'); [ "$r" != 0x0000000000000000000000000000000000000000000000000000000000000000 ] && [ "$r" != "$vrb_result" ]; }
vrp_root_epoch_is() { curl -sf -X POST -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$(m2_rpc_port 1)/api/v1/q3/status" | python3 -c "import json,sys;sys.exit(0 if json.load(sys.stdin).get('activeEpoch')==$1 else 1)"; }
vrp_eth_block() { cast block-number --rpc-url "$vrb_rpc"; }

# the holder facts (design 3.9.2) read from custody's storage at the frozen slots equal custody's own getters, for every identity at generation 1
vrp_facts_ok() {
  local cu; cu=$(vrp_custody)
  python3 - "$vrb_rpc" "$cu" <<'PY' || return 1
import subprocess, sys
rpc, cu = sys.argv[1:3]
def cast(*a): return subprocess.check_output(["cast", *a, "--rpc-url", rpc]).decode().strip()
def kk(h): return "0x" + subprocess.check_output(["cast", "keccak", h]).decode().strip()[2:]
def word(x): return "0x" + int(x).to_bytes(32, "big").hex()
B = int("0xb2905100cfe7c1af5dee2b1b6726fdfd755820e0f51ef675ed653be4f1102d00", 16)
n = int(cast("call", cu, "nextStakingID()(uint64)").split()[0])
for i in range(1, n + 1):
    q = kk(word(i) + word(B + 1)[2:])
    s = kk(word(1) + q[2:])
    w0 = int(cast("storage", cu, s), 16)
    w1 = cast("storage", cu, hex(int(s, 16) + 1))
    live = int(cast("call", cu, "liveExposures(uint64,uint64)(uint32)", str(i), "1").split()[0])
    anchor = int(cast("call", cu, "maxLiabilityAnchor(uint64,uint64)(uint64)", str(i), "1").split()[0])
    chain = cast("call", cu, "exposureChain(uint64,uint64)(bytes32)", str(i), "1")
    assert (w0 >> 136) == 0, f"id {i}: reserved bits"
    assert ((w0 >> 8) & 0xffffffff) == live, f"id {i}: liveExposures {(w0 >> 8) & 0xffffffff} != {live}"
    assert ((w0 >> 72) & 0xffffffffffffffff) == anchor, f"id {i}: anchor"
    assert w1.lower() == chain.lower(), f"id {i}: refDigest"
cursor = int(cast("storage", cu, hex(B)), 16)
assert cursor == int(cast("call", cu, "recordCursor()(uint64)").split()[0]), "facts cursor"
print("holder facts equal custody's state for", n, "identities")
PY
}

vrp_recovery() {
  vrp_source_q3 || { vrb_log "FAIL: the q3 helpers"; return 1; }
  local first=$vrb_result i rid2 rec
  # 1. the second election over the same five, published and handed off by the nodes themselves
  vrb_wait 1500 "the second election reserves J' from stake" vrp_new_open_result || return 1
  rid2=$(cast call --rpc-url "$vrb_rpc" "$(vrp_election)" 'openResult()(bytes32)')
  vrb_result=$rid2
  vrp_publish || return 1
  vrb_wait 900 "the roots installed J' (root epoch 3)" vrp_root_epoch_is 3 || return 1
  vrb_log "J' = $rid2 is installed at the roots; its VR output state $(vrp_result_state "$rid2") (2 = Published)"
  # 2. J' stalls: three of the five lose their EVM services, so its EVM quorum (3 of 5) cannot form
  local before after
  for i in 3 4 5; do stop_one_evm_validator "$i" 2>/dev/null || true; done
  before=$(vrp_eth_block); sleep 45; after=$(vrp_eth_block)
  [ "$after" -le "$((before + 1))" ] || { vrb_log "FAIL: J' certified blocks ($before -> $after) with 2 of 5 validators"; return 1; }
  [ "$(vrp_result_state "$rid2")" = 2 ] || { vrb_log "FAIL: J' is no longer Published in VR"; return 1; }
  vrb_log "PASS: J' stalls (EVM block $before -> $after in 45 s with 2 of its 5 validators)"
  # 3. the recovery: the roots return to K's committee (epoch 4), exact K, no receipts, supersedes J'
  H3_ROOTS="1 2 3 4 5"
  Q3_WEIGHTS="1 1 1 1 1" Q3_NEXT_EPOCH=4 q3_trust_base_v3 4 || { vrb_log "FAIL: the recovery's trust base"; return 1; }
  Q3_RECOVERY=1 Q3_SUPERSEDE=1 Q3_NEXT_EPOCH=4 Q3_ASSIGN_TAG=rec Q3_SUFFIX=-2 h3_retry_handoff 3 q3_attempt || { vrb_log "FAIL: the recovery handoff"; return 1; }
  Q3_EXPECT_SWITCHED="1 2 3 4 5" q3_install_n 4 || { vrb_log "FAIL: the roots did not install the recovery"; return 1; }
  vrb_log "PASS: the roots installed the recovery K (root epoch 4)"
  # 4. the three stopped validators return into K's scope; VR imports RecoveryAck(J') and the Boundary (recovered)
  for i in 3 4 5; do start_one_evm_validator "$i" "${validators:-4}" "$partitionID" "$(m2_root_addr 1)" engine-api rpc "$(evm_bootnodes_for_peers "$(m2_root_addr 1)" "$i" 1 2 3 4)" >/dev/null 2>&1 || true; done
  vrb_wait 900 "VR's output of J' is Recovered (state 6)" bash -c "[ \"\$(cast call --rpc-url $vrb_rpc $vrb_vr 'output(bytes32)' $rid2 | python3 -c \"import sys;h=sys.stdin.read().strip()[2:];print(int(h[128:192],16))\")\" = 6 ]" || return 1
  [ "$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'health()(uint8)')" = 0 ] || { vrb_log "FAIL: VR is not Healthy after the recovery"; return 1; }
  [ "$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'lastAcked()(bytes32)')" = "$rid2" ] || { vrb_log "FAIL: lastAcked is not J's pair result"; return 1; }
  vrb_wait 300 "custody and VR have applied the same records" vrp_cursors_match || return 1
  rec=$(cast call --rpc-url "$vrb_rpc" "$(vrp_custody)" 'lastAckedAssignment()(bytes32)')
  vrb_log "custody's last acknowledged assignment is the recovery assignment $rec"
  vrp_facts_ok || { vrb_log "FAIL: the holder facts differ from custody's state"; return 1; }
  vrb_log "PASS: the recovery (install K) completed through VR: Recovered, Healthy, cursors and holder facts match"
}
