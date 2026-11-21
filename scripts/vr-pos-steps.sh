#!/usr/bin/env bash
# The PoS-prototype lane's steps (VT-04, ristik/bft-core#1144): sourced by scripts/vr-boundary-steps.sh under VR_LANE=1 VR_POS=1 VR_JOINER=1, after
# vr-joiner-steps.sh. The generation is the PoS prototype (scripts/lib/vr-lib.sh VR_POS=1): four genesis identities bonded in custody, the
# PosElectionAdapter as VR's module, nMax 5. SIGNING=local or SIGNING=authority (#1216: the EVM key is the signing authority's; the delegation and
# assignment possession proofs are its typed operations under the P85 pin of `signing-authority pos-policy`; VR_ARCHIVE=1 restores the joiner's shard node
# from an incumbent's archive, which refuses a local key); UTB on
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

# the adapter's deployed code hash and the profile values the lane ran under (#1216 evidence): VR's active module account, its runtime code hash, the
# election's and the custody's, and the b1 profile's ElectGas, envelope (system, record and companion gas) and MaxGas
vrp_record_profile() {
  local mod out=$VR_EVIDENCE/pos-profile.json
  mod=$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'activeModule()(address)' 2>/dev/null || jq -r .module "$VR_DIR/contracts/deployment.json")
  python3 - "$out" "$VR_DIR/contracts/deployment.json" test-nodes/b1-profile.json "$mod" "$(cast codehash --rpc-url "$vrb_rpc" "$mod" 2>/dev/null || cast keccak "$(cast code --rpc-url "$vrb_rpc" "$mod")")" <<'PY'
import json, sys
out, dep, prof, mod, h = sys.argv[1:6]
d, p = json.load(open(dep)), json.load(open(prof))
json.dump({"adapter": mod, "adapterCodeHash": h.strip(), "election": d["election"], "custody": d["custody"],
           "profile": {k: p[k] for k in ("electGas", "systemGas", "forcedGas", "maxGas", "ordinaryCapacity", "restGas", "companionBytes",
                                         "otherCompanionBytes", "hookRecordGas", "hRecords", "deltaEv", "deltaHold") if k in p}}, open(out, "w"), indent=1)
print(open(out).read())
PY
}

vrp_apply() {
  vrp_record_profile || vrb_log "note: the adapter's code hash and the profile values could not be recorded"
  vrj_apply || return 1   # `validator apply` dispatches on the active module: on the PoS adapter it registers, bonds and admits the delegation
  local el id=$vrj_id
  el=$(vrp_election)
  # the joiner's authority is pinned to the id VR and custody confirmed at registration (the apply's receipts; saved in its validator config), never a guess
  local cid; cid=$(jq -r '.id // empty' "$vrj_cfg/validator.json")
  [ -n "$cid" ] && [ "$cid" = "$vrj_id" ] || { vrb_log "FAIL: the joiner's confirmed identity ($cid) is not the id its lane expects ($vrj_id)"; return 1; }
  M2_CHAIN_ID="${M2_CHAIN_ID:-$postM2aChainID}" vr_pos_pin_authority "$vrj_id" "$cid" || { vrb_log "FAIL: the joiner's P85 pin"; return 1; }
  local indexed; indexed=$(cast call --rpc-url "$vrb_rpc" "$el" 'isIndexed(uint64)(bool)' "$id")
  [ "$indexed" = true ] || { vrb_log "FAIL: identity $id is not in the election's live index after apply"; return 1; }
  vrb_log "PASS: identity $id registered in VR and custody, bonded, delegation admitted (live count $(cast call --rpc-url "$vrb_rpc" "$el" 'liveCount()(uint32)' | awk '{print $1}'))"
}

# the EVM key holder of every identity, in id order (ids follow ascending root node id; the joiner is 5). SIGNING=authority: each identity's EVM key is
# its signing authority's, reached on the operator channel (--evm-authority id=socket,credential,nodeInfo); the proofs are its typed operation.
vrp_evm_key_args() {
  local i eid h ids=() a
  if [ "${SIGNING:-local}" = authority ]; then
    for i in 1 2 3 4; do
      eid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[$((i - 1))]['evmNodeId'])")
      for a in test-nodes/auth*/; do
        [ "$(python3 -c "import json;print(json.load(open('${a}node-info.json'))['nodeId'])")" = "$eid" ] &&
          ids+=(--evm-authority "$i=$PWD/${a}operator.sock,$PWD/${a}operator.cred,$PWD/${a}node-info.json")
      done
    done
    [ "${VR_JOINER:-0}" != 1 ] || ids+=(--evm-authority "$vrj_id=$PWD/test-nodes/auth$vrj_id/operator.sock,$PWD/test-nodes/auth$vrj_id/operator.cred,$PWD/test-nodes/auth$vrj_id/node-info.json")
    printf '%s\n' "${ids[@]}"
    return 0
  fi
  for i in 1 2 3 4; do
    eid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[$((i - 1))]['evmNodeId'])")
    for h in test-nodes/evm*/; do
      [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$eid" ] && ids+=(--evm-keys "$i=$PWD/${h%/}/keys.json")
    done
  done
  [ "${VR_JOINER:-0}" != 1 ] || ids+=(--evm-keys "$vrj_id=$PWD/test-nodes/evm$vrj_id/keys.json")
  printf '%s\n' "${ids[@]}"
}

vrp_open_result() { [ "$(cast call --rpc-url "$vrb_rpc" "$(vrp_election)" 'openResult()(bytes32)')" != 0x0000000000000000000000000000000000000000000000000000000000000000 ]; }

# a validator config for the relayer when no joiner created one: the dev-funded operator, the first root's and shard node's keys
vrp_relay_evm_holder() {
  if [ "${SIGNING:-local}" = authority ]; then
    printf '"evmAuthority":{"socket":"%s","credential":"%s","nodeInfo":"%s"}' "$PWD/test-nodes/auth1/operator.sock" "$PWD/test-nodes/auth1/operator.cred" "$PWD/test-nodes/auth1/node-info.json"
  else
    printf '"evmKeys":"%s"' "$PWD/test-nodes/evm1/keys.json"
  fi
}
vrp_relay_cfg() {
  [ -n "${vrj_cfg:-}" ] && [ -f "$vrj_cfg/validator.json" ] && return 0
  local d keys; d=$(mktemp -d); vrj_cfg=$d; keys=$VR_DIR/dev-keys/keys.json
  python3 -c "import json;print(json.load(open('$keys'))['signers'][0]['privateKey'])" >"$d/operator.key"; chmod 600 "$d/operator.key"
  openssl rand -hex 32 >"$d/ureth.key"
  cat >"$d/validator.json" <<JSON
{"format":"unicity.validator.config.v1","rpc":"$vrb_rpc","registry":"$vrb_vr","rootKeys":"$PWD/test-nodes/root1/keys.json",
 $(vrp_relay_evm_holder),"urethKey":"$d/ureth.key","jwt":"$d/none","operatorKey":"$d/operator.key",
 "payee":"$(python3 -c "import json;print(json.load(open('$keys'))['signers'][0]['address'])")"}
JSON
}

vrp_publish() {
  vrp_relay_cfg || return 1
  vrb_wait 1500 "the hook's election reserves a result from stake (cadence passed)" vrp_open_result || return 1
  local rid; rid=$(cast call --rpc-url "$vrb_rpc" "$(vrp_election)" 'openResult()(bytes32)')
  vrb_log "the election reserved $rid; VR's open output is $(vrb_open_output)"
  local -a holders=(); local line
  while IFS= read -r line; do [ -z "$line" ] || holders+=("$line"); done < <(vrp_evm_key_args)
  build/ubft validator pos-publish --validator-config "$vrj_cfg/validator.json" ${holders[@]+"${holders[@]}"} 2>&1 | tee "$VR_EVIDENCE/pos-publish.log" || { vrb_log "FAIL: pos-publish"; return 1; }
  vrb_log "PASS: every possession proof submitted, the candidate finalized and the result published in VR"
}

vrp_rotated() {
  local ids el cu rid; el=$(vrp_election); cu=$(vrp_custody)
  ids=$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'committeeIds()(uint64[])')
  if [ "${VR_JOINER:-0}" = 1 ]; then
    case "$ids" in *"$vrj_id"*) vrb_log "PASS: VR's committee after the Boundary includes identity $vrj_id: $ids" ;; *) vrb_log "FAIL: committee $ids"; return 1 ;; esac
  else
    vrb_log "VR's committee after the Boundary: $ids"
  fi
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

# the signed trust-base history (UTB on, no aggregator): every root's own entry store exports from the pinned genesis and verifies epochs 1..N, and
# the entry of epoch 2 is signed by epoch 1's quorum (the verifier's own line). With VR_AGG=1 the aggregator's /api/v1/trustbases is the UTB agent's
# check (vr-utb-steps.sh vru_after); a root's own REST serves the V1 runtime projection only, never the signed history.
vrp_utb() { # <last epoch expected>
  local last=${1:-2} out=$VR_EVIDENCE/utb n f bad=0 i
  declare -F vru_ev >/dev/null || source scripts/vr-utb-steps.sh || { vrb_log "FAIL: scripts/vr-utb-steps.sh"; return 1; }
  mkdir -p "$out"
  # every expected root by id (the incumbents 1..validators, and the joiner's root when there is one), each with its own store
  for i in $(seq 1 "${validators:-4}") $([ "${VR_JOINER:-0}" = 1 ] && echo "${vrj_id:-5}"); do
    f=test-nodes/root$i/root-utb-entries.db
    [ -f "$f" ] || { vrb_log "FAIL: root$i has no entry store at $f"; bad=$((bad + 1)); continue; }
    n=root$i; cp "$f" "$out/$n.db"
    if build/ubft trust-base utb-export --utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id "$(utb_pin)" --utb-entries-db "$out/$n.db" --out "$out/$n.cbor" >"$out/$n.export.log" 2>&1 \
      && vru_ev verify --bundle "$out/$n.cbor" --pin "$(utb_pin)" >"$out/$n.verify.txt" 2>&1 && grep -q "^ok: epochs 1\.\.$last," "$out/$n.verify.txt"; then
      grep '^epoch 2 ' "$out/$n.verify.txt" >"$out/$n.epoch2.line" || true
    else
      vrb_log "FAIL: $n's entry store holds no verified epochs 1..$last ($(tail -n 1 "$out/$n.verify.txt" 2>/dev/null))"; bad=$((bad + 1))
    fi
    rm -f "$out/$n.db"
  done
  [ "$bad" = 0 ] || return 1
  vrb_log "PASS: every expected root's own entry store verifies epochs 1..$last from the pinned genesis; $(cat "$out"/root1.epoch2.line 2>/dev/null)"
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
  declare -F vrj_source_libs >/dev/null || source scripts/vr-joiner-steps.sh || return 1
  vrj_source_libs || return 1   # m2, h3 and reth-peers libraries; H3_DIR
  declare -F q3_trust_base_v3 >/dev/null || source scripts/lib/q3-lib.sh || return 1
  declare -F q3_attempt >/dev/null || source scripts/lib/q3-flow-lib.sh || return 1
  Q3_DIR=${Q3_DIR:-$H3_DIR}; mkdir -p "$Q3_DIR"
  # the recovery's assignment is the derived one: no proofs, no authorities
  q3_build_assignment() {
    build/ubft root handoff evm-context --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$Q3_DIR/$1-context.json" || return 1
    build/ubft root handoff evm-assemble --context "$Q3_DIR/$1-context.json" --recovery --supersede --out "$Q3_DIR/$1-assignment.json"
  }
}

vrp_result_state() { cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'output(bytes32)' "$1" 2>/dev/null | python3 -c "import sys;h=sys.stdin.read().strip()[2:];w=[h[i:i+64] for i in range(0,len(h),64)];print(int(w[1],16))"; }
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

# why no election was reserved: the cadence thresholds against the clock, the last attempt and its recorded reason, VR's health and cursors
vrp_election_diag() {
  local el seal=0xff00000000000000000000000000000000000002 last; el=$(vrp_election)
  {
    echo "election thresholds (progress, ucTime): $(cast call --rpc-url "$vrb_rpc" "$el" 'thresholds()(uint256,uint256)' | tr '\n' ' ')"
    echo "clock (progress, ucTime): $(cast call --rpc-url "$vrb_rpc" "$seal" 'progress()(uint64)') $(cast call --rpc-url "$vrb_rpc" "$seal" 'ucTime()(uint64)')"
    last=$(cast call --rpc-url "$vrb_rpc" "$el" 'lastAttemptResult()(bytes32)'); echo "last attempt result $last"
    echo "result (state, reason, attempt, ...): $(cast call --rpc-url "$vrb_rpc" "$el" 'result(bytes32)((uint8,uint8,uint64,uint64,uint64,uint32,bytes32,bytes32,bytes32,bytes32))' "$last" | tr '\n' ' ')"
    echo "VR health $(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'health()(uint8)'), open output $(vrb_open_output), VR cursor $(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'recordCursor()(uint64)'), custody cursor $(cast call --rpc-url "$vrb_rpc" "$(vrp_custody)" 'recordCursor()(uint64)')"
  } 2>&1 | tee "$VR_EVIDENCE/second-election-diagnostics.txt"
}

# q3_install_n for K: the restart helper's readiness check needs lsof (not on the dev server), so a root it restarted is judged by its own q3/status
vrp_root_active() { curl -sf -X POST -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$(m2_rpc_port "$1")/api/v1/q3/status" | python3 -c "import json,sys;sys.exit(0 if json.load(sys.stdin).get('activeEpoch')==$2 else 1)"; }
vrp_install_k() { # <epoch> <roots expected to switch in process>
  local epoch=$1 r
  if ! Q3_EXPECT_SWITCHED="$2" q3_install_roots "$epoch"; then
    for r in $H3_ROOTS; do vrb_wait 180 "root $r runs epoch $epoch" vrp_root_active "$r" "$epoch" || return 1; done
  fi
  for r in $(seq 1 120); do [ "$(q3_signers_of "$(h3_first_root)" 2>/dev/null | jq -r .epoch 2>/dev/null)" = "$epoch" ] && break; sleep 1; done
  q3_signers_of "$(h3_first_root)" | jq -c . >"$Q3_DIR/first-epoch${epoch}-certificate.json"
  [ "$(jq -r .epoch "$Q3_DIR/first-epoch${epoch}-certificate.json")" = "$epoch" ] || return 1
  q3_history_ids "$Q3_DIR/history-ids-epoch${epoch}.txt"
}

# what VR, custody and the roots say when the recovery's acknowledgement does not arrive
vrp_recovery_diag() {
  local d=$VR_EVIDENCE/recovery-diag.txt r=$1 i
  {
    echo "output(R): $(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'output(bytes32)' "$r" 2>&1 | head -c 600)"
    echo "health $(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'health()(uint8)' 2>&1) lastAcked $(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'lastAcked()(bytes32)' 2>&1) openOutput $(vrb_open_output 2>&1)"
    echo "VR cursor $(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'recordCursor()(uint64)' 2>&1) custody cursor $(cast call --rpc-url "$vrb_rpc" "$(vrp_custody)" 'recordCursor()(uint64)' 2>&1)"
    echo "custody lastAckedAssignment $(cast call --rpc-url "$vrb_rpc" "$(vrp_custody)" 'lastAckedAssignment()(bytes32)' 2>&1) eth block $(vrp_eth_block 2>&1)"
    for i in 1 2 3 4 5; do echo "root$i q3status: $(curl -s -m 3 -X POST -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$(m2_rpc_port "$i")/api/v1/q3/status" | head -c 300)"; done
    for i in 1 2 3 4; do echo "evm$i: $(grep -c 'certification request signed' test-nodes/evm$i/debug.log) signed; $(grep 'level=ERROR' test-nodes/evm$i/debug.log | tail -1 | cut -c1-300)"; done
    grep -h 'ack\|Ack' test-nodes/root1/debug.log | grep -vi 'backoff\|callback\|track\|replica' | tail -10 | cut -c1-300
  } >"$d" 2>&1
  vrb_log "recovery diagnostics written to $d"
}

vrp_recovery_attempt() { q3_x build/ubft root handoff propose --vr-recovery --root-rpc "$(q3_propose_rpcs)"; }

# what the roots' logs show of the recovery (#1221): the leader's Prepare/Freeze/H of the exact recovery, the committed outcome at root epoch 3, and the in-process switch 3 -> 4
vrp_recovery_evidence() { # <old root epoch> <handoff = the handoff committed | switch = the in-process switch to old+1>
  local old=$1 phase=$2 inproc=${3:-$H3_ROOTS} d=$VR_EVIDENCE/recovery-logs r f ok=0 want=${M2_RUN_LOG_DIR:-test-nodes}
  mkdir -p "$d"
  for r in $H3_ROOTS; do
    f=test-nodes/root$r/debug.log; [ -f "$f" ] || f=$want/root$r/debug.log
    grep -a 'VR recovery:\|root handoff outcome\|switched epoch in process' "$f" >"$d/root$r.$phase.txt" 2>/dev/null || true
  done
  if [ "$phase" = handoff ]; then
    grep -aqh 'VR recovery: the leader orders the Prepare' "$d"/root*.handoff.txt || { vrb_log "FAIL: no root logged the recovery Prepare"; return 1; }
    grep -aqh 'VR recovery: the leader follows the exact recovery.*phase=prepared' "$d"/root*.handoff.txt || { vrb_log "FAIL: no root logged the recovery Freeze"; return 1; }
    grep -aqh "root handoff outcome.*phase=committed.*rootEpoch=$old" "$d"/root*.handoff.txt || { vrb_log "FAIL: no committed outcome at root epoch $old"; return 1; }
    vrb_log "PASS: the leader ordered Prepare, Freeze (v3, exact recovery) and H at root epoch $old (logs in $d)"
  else
    ok=0; for r in $inproc; do grep -aq "switched epoch in process.*epoch=$((old + 1)).*from=$old\|switched epoch in process.*from=$old.*epoch=$((old + 1))" "$d/root$r.switch.txt" && ok=$((ok + 1)); done
    [ "$ok" = "$(echo $inproc | wc -w | tr -d ' ')" ] || { vrb_log "FAIL: $ok of the roots switched $old -> $((old + 1)) in process"; return 1; }
    vrb_log "PASS: every one of K's $ok roots switched $old -> $((old + 1)) in process"
  fi
}

vrp_k_shard_serving() {
  local i=$1 node status
  node=$(evm_validator_id "$i") || return 1
  status=$(curl -fsS -m 2 "http://$(evm_validator_rpc_addr "$i")/api/v1/health") || return 1
  jq -e --arg node "$node" --argjson partition "$partitionID" '
    .executorOk == true and .voting == true and .binding.member == true and
    .binding.nodeId == $node and .binding.partitionId == $partition and
    .binding.shardEpoch == 3 and .binding.history[-1].epoch == 4
  ' <<<"$status" >/dev/null || return 1
  printf '%s\n' "$status" >"$VR_EVIDENCE/evm$i-k-health.json"
}

vrp_recovery() {
  vrp_source_q3 || { vrb_log "FAIL: the q3 helpers"; return 1; }
  local first=$vrb_result i rid2 rec
  # 1. a committee change makes the second election: unchanged stake elects nothing new (pos7). The joiner (identity $vrj_id) requests retirement
  # (`validator exit`); the next election reserves J' = the other four, published and handed off by the roots
  [ "${VR_JOINER:-0}" = 1 ] || { vrb_log "FAIL: the PoS recovery needs the joiner (VR_JOINER=1): a retirement is its committee change"; return 1; }
  build/ubft validator exit --validator-config "$vrj_cfg/validator.json" 2>&1 | tee "$VR_EVIDENCE/exit.log" || { vrb_log "FAIL: validator exit"; return 1; }
  vrb_wait 1500 "the election reserves J' (the four) after the retirement" vrp_new_open_result || { vrp_election_diag; return 1; }
  rid2=$(cast call --rpc-url "$vrb_rpc" "$(vrp_election)" 'openResult()(bytes32)')
  vrb_result=$rid2
  vrp_publish || return 1
  vrb_wait 900 "the roots installed J' (root epoch 3)" vrp_root_epoch_is 3 || return 1
  vrb_log "J' = $rid2 is installed at the roots; its VR output state $(vrp_result_state "$rid2") (2 = Published)"
  # 2. J' stalls: two of its four lose their EVM services, so its EVM quorum (3 of 4) cannot form
  local before after n stop
  n=$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'committeeIds()(uint64[])' | tr -cd ',' | wc -c); n=$((n + 1))   # K, the five
  local nj=$((n - 1)); stop=$((nj - nj / 2))
  vrb_log "K has $n members, J' has $nj: the EVM services of the last $stop of J' (identities $(seq -s ' ' $((nj - stop + 1)) "$nj")) stop (J' keeps $((nj - stop)), the EVM quorum is $((nj / 2 + 1)))"
  for i in $(seq $((nj - stop + 1)) "$nj"); do stop_one_evm_validator "$i" 2>/dev/null || true; done
  before=$(vrp_eth_block); sleep 45; after=$(vrp_eth_block)
  [ "$after" -le "$((before + 1))" ] || { vrb_log "FAIL: J' certified blocks ($before -> $after) without its EVM quorum"; return 1; }
  [ "$(vrp_result_state "$rid2")" = 2 ] || { vrb_log "FAIL: J' is no longer Published in VR"; return 1; }
  vrb_log "PASS: J' stalls (EVM block $before -> $after in 45 s with $((nj - stop)) of its $nj validators)"
  # 3. the recovery (#1221): the VR leader proposes the exact recovery to K (epoch 4) after J' committed and failed to acknowledge. The operator only
  # requests it (`root handoff propose --vr-recovery`: nothing named, the root derives K from the retained authorization); the leader orders the Prepare,
  # J''s four roots endorse it, the Freeze is a v3 companion (KindRecovery, exact K, no receipts) and then H. The endorsements are scoped to J''s roots
  # (the retired joiner's root is not in epoch 3) and the install barrier to K's five roots.
  H3_ROOTS="$(seq -s ' ' 1 "$nj")"
  h3_retry_handoff 3 vrp_recovery_attempt || { vrb_log "FAIL: the recovery handoff"; return 1; }
  vrp_recovery_evidence 3 handoff || return 1
  H3_ROOTS="$(seq -s ' ' 1 "$n")"
  # K's roots that were in J' switch in process; the retired joiner's root, a follower of epoch 3, installs by the harness's restart path when its in-process
  # switch fails (a P85 record-log prefix it cannot fetch: filed in briefs/owner-questions.md)
  local inproc; inproc="$(seq -s ' ' 1 "$nj")"
  vrp_install_k 4 "$inproc" || { vrb_log "FAIL: the roots did not install the recovery"; return 1; }
  vrp_recovery_evidence 3 switch "$inproc" || return 1
  vrb_log "PASS: the roots installed the recovery K (root epoch 4): J''s $nj roots switched in process, restarted: ${Q3_RESTARTED:-none}"
  # each authority signs for one scope: K's five move into the recovery's (root epoch 4, shard epoch 3) before the shard can acknowledge it
  if [ "${SIGNING:-local}" = authority ]; then
    build/ubft q3 trust-base --root-rpc "http://127.0.0.1:$(m2_rpc_port 1)" --epoch 4 --out test-nodes/trust-base-epoch4.json || { vrb_log "FAIL: the trust base of epoch 4"; return 1; }
    H3_ONLINE="$(seq -s ' ' 1 "$nj")" M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 4 3 $(seq -s ' ' 1 "$nj") || { vrb_log "FAIL: the authority advance of J''s four"; return 1; }
    # the joiner (identity 5) is a running member of K already (J named it): its authority advances and its shard node restarts under the new session
    local op5=(--operator-socket "test-nodes/auth5/operator.sock" --operator-credential "test-nodes/auth5/operator.cred")
    stop_one_evm_validator 5 2>/dev/null || true
    source helper.sh
    authority_advance_scope 5 4 test-nodes/trust-base-epoch4.json "$(h3_pdr_file 3)" || { vrb_log "FAIL: identity 5's authority advance"; return 1; }
    build/ubft signing-authority replace-session "${op5[@]}" --out test-nodes/auth5/client.cred || { vrb_log "FAIL: identity 5's session"; return 1; }
    start_one_evm_validator 5 "${validators:-4}" "$partitionID" "$(m2_root_addr 1)" engine-api rpc "$(evm_bootnodes_for_peers "$(m2_root_addr 1)" 5 1 2 3 4 5)" >/dev/null 2>&1 || { vrb_log "FAIL: identity 5's shard node did not start"; return 1; }
    vrb_log "PASS: K's authorities advanced into root epoch 4 / shard epoch 3"
  fi
  # 4. the three stopped validators return into K's scope; VR imports RecoveryAck(J') and the Boundary (recovered)
  for i in $(seq $((nj - stop + 1)) "$nj"); do kill -0 "$(cat "test-nodes/evm$i/pid" 2>/dev/null)" 2>/dev/null || start_one_evm_validator "$i" "${validators:-4}" "$partitionID" "$(m2_root_addr 1)" engine-api rpc "$(evm_bootnodes_for_peers "$(m2_root_addr 1)" "$i" 1 2 3 4 5)" >/dev/null 2>&1 || true; done
  vrb_wait 900 "VR's output of J' is Recovered (state 6)" bash -c "[ \"\$(cast call --rpc-url $vrb_rpc $vrb_vr 'output(bytes32)' $rid2 | python3 -c \"import sys;h=sys.stdin.read().strip()[2:];print(int(h[64:128],16))\")\" = 6 ]" || { vrp_recovery_diag "$rid2"; return 1; }
  [ "$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'health()(uint8)')" = 0 ] || { vrb_log "FAIL: VR is not Healthy after the recovery"; return 1; }
  [ "$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'lastAcked()(bytes32)')" = "$rid2" ] || { vrb_log "FAIL: lastAcked is not J's pair result"; return 1; }
  vrb_wait 300 "custody and VR have applied the same records" vrp_cursors_match || return 1
  rec=$(cast call --rpc-url "$vrb_rpc" "$(vrp_custody)" 'lastAckedAssignment()(bytes32)')
  vrb_log "custody's last acknowledged assignment is the recovery assignment $rec"
  vrp_facts_ok || { vrb_log "FAIL: the holder facts differ from custody's state"; return 1; }
  for i in $(seq 1 "$n"); do
    vrb_wait 180 "K's shard node $i serves as a voting member (root epoch 4, shard epoch 3)" vrp_k_shard_serving "$i" || {
      tail -n 30 "test-nodes/evm$i/debug.log" >&2
      return 1
    }
  done
  vrb_log "PASS: the recovery (install K) completed through VR: Recovered, Healthy, cursors and holder facts match"
  if [ "${UTB_LANE:-0}" = 1 ]; then vrp_utb 4 || return 1; fi
}
