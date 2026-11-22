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

vrj_id=$((${validators:-4} + 1))
vrj_incumbents=$(seq -s " " 1 "${validators:-4}")
vrj_members="$vrj_incumbents $vrj_id"
vrj_log() { vrb_log "$@"; }

vrj_source_libs() {
  declare -F m2_start_root >/dev/null || source scripts/lib/m2-handoff-lib.sh || return 1
  declare -F h3_start_reth >/dev/null || source scripts/lib/h3-lib.sh || return 1
  declare -F reth_trust >/dev/null || source scripts/lib/reth-peers.sh || return 1
  H3_ROOTS="$vrj_incumbents"; H3_ONLINE="$vrj_incumbents"; H3_DIR=test-nodes/h3; mkdir -p "$H3_DIR"
}

vrj_start_nodes() {
  local i=$vrj_id boot bootnodes
  vrj_source_libs || { vrj_log "FAIL: the joiner's libraries"; return 1; }
  build/ubft root-node init --home "test-nodes/root$i" -g >/dev/null 2>&1 || true
  generate_log_configuration "test-nodes/root$i/"
  h3_spare_identity "$i" || { vrj_log "FAIL: the joiner's shard node identity"; return 1; }
  h3_start_reth "$i" || { vrj_log "FAIL: the joiner's execution client"; return 1; }
  if [ "${SIGNING:-local}" = authority ]; then   # its EVM key is its authority's, pending at shard epoch 1 until J's configuration names it
    h3_spare_authority "$i" 1 1 trust-base.json || { vrj_log "FAIL: the joiner's signing authority"; return 1; }
  fi
  if declare -F vrs_import >/dev/null; then vrs_import || { vrj_log "FAIL: the seed import"; return 1; }; fi   # VT-11: the joiner starts from the fetched seed
  boot=$(m2_root_addr 1)
  { m2_start_root "$i" 1 "$boot"; } >/dev/null 2>&1 || true   # its readiness check needs lsof: the RPC is the check
  vrb_wait 90 "the joiner's root answers on its RPC" curl -sf "http://127.0.0.1:$(m2_rpc_port "$i")/api/v1/roundInfo" || return 1
  bootnodes=$(evm_bootnodes_for_peers "$boot" "$i" $vrj_incumbents) || return 1
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))" "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
  if [ "${VR_ARCHIVE:-0}" = 1 ]; then
    vrj_log "the joiner's shard node is restored from an incumbent's archive once the incumbents stage the successor (vrj_restore_evm5)"
    vrj_log "PASS: the joiner's root$i and reth$i are up"
    return 0
  fi
  EVM_ARCHIVE_REPLICA_POOL="$vrj_members" start_one_evm_validator "$i" "${validators:-4}" "$partitionID" "$boot" engine-api rpc "$bootnodes" || return 1
  sleep 5
  kill -0 "$(cat "test-nodes/evm$i/pid")" 2>/dev/null || { vrj_log "FAIL: the joiner's shard node exited"; tail -30 "test-nodes/evm$i/debug.log" >&2; return 1; }
  vrj_log "PASS: the joiner's root$i, evm$i and reth$i are up"
}

vrj_cfg=
vrj_owner_key() { python3 -c "import json;print(json.load(open('$VR_DIR/dev-keys/keys.json'))['signers'][0]['privateKey'])"; }

vrj_apply() {
  local d keys
  d=$(mktemp -d); vrj_cfg=$d; keys=$VR_DIR/dev-keys/keys.json
  vrj_owner_key >"$d/operator.key"; chmod 600 "$d/operator.key"
  openssl rand -hex 32 >"$d/ureth.key"
  local evmAuth="\"evmKeys\":\"$PWD/test-nodes/evm$vrj_id/keys.json\","
  [ "${SIGNING:-local}" != authority ] || evmAuth="\"evmAuthority\":{\"socket\":\"$PWD/test-nodes/auth$vrj_id/operator.sock\",\"credential\":\"$PWD/test-nodes/auth$vrj_id/operator.cred\",\"nodeInfo\":\"$PWD/test-nodes/auth$vrj_id/node-info.json\"},"
  cat >"$d/validator.json" <<JSON
{"format":"unicity.validator.config.v1","rpc":"$vrb_rpc","registry":"$vrb_vr","rootKeys":"$PWD/test-nodes/root$vrj_id/keys.json",
 $evmAuth"urethKey":"$d/ureth.key","jwt":"$d/none","operatorKey":"$d/operator.key",
 "payee":"$(python3 -c "import json;print(json.load(open('$keys'))['signers'][0]['address'])")"}
JSON
  build/ubft validator apply --validator-config "$d/validator.json" 2>&1 | tee "$VR_EVIDENCE/joiner-apply.log" || { vrj_log "FAIL: validator apply"; return 1; }
  if [ "${VR_POS:-0}" = 1 ]; then   # the PoS module has no PoA status: vrp_apply checks the election's live index
    vrj_log "identity $vrj_id: validator apply completed (PoS: registered, bonded, delegation admitted; checked by vrp_apply)"
    return 0
  fi
  local st; st=$(cast call --rpc-url "$vrb_rpc" 0xff00000000000000000000000000000000000007 'status(uint64)(uint8,uint64)' "$vrj_id" 2>&1) \
    || { vrj_log "FAIL: the PoA status of identity $vrj_id could not be read ($st)"; return 1; }
  st=$(echo "$st" | head -1)
  [ "$st" = 1 ] || { vrj_log "FAIL: identity $vrj_id is in PoA state $st, not Applied (1)"; return 1; }
  vrj_log "PASS: identity $vrj_id applied (PoA state $st; 1 = Applied)"
}

vrj_signer_key() { # <n 0..4> <file>
  python3 -c "import json;print(json.load(open('$VR_DIR/dev-keys/keys.json'))['signers'][$1]['privateKey'])" >"$2"; chmod 600 "$2"
}

# vrj_gov_dir: the Foundation's pipeline for one proposal, files under $VR_EVIDENCE/governance (signer keys are dev keys: never evidence)
vrj_admit() {
  local g=$VR_EVIDENCE/governance k change i
  mkdir -p "$g"; local kd; kd=$(mktemp -d)
  build/ubft governance propose admit --rpc "$vrb_rpc" --id "$vrj_id" --out "$g/proposal.json" --note "VT-09 live run: admit the joiner" 2>&1 | tee "$g/propose.log" || { vrj_log "FAIL: propose admit"; return 1; }
  local ap=()
  for k in 0 1 2; do
    vrj_signer_key "$k" "$kd/signer$k.key"
    build/ubft governance sign --rpc "$vrb_rpc" --proposal "$g/proposal.json" --signer-key "$kd/signer$k.key" --out "$g/approval$k.json" >>"$g/sign.log" 2>&1 || { vrj_log "FAIL: sign $k"; return 1; }
    ap+=(--approval "$g/approval$k.json")
  done
  build/ubft governance aggregate --rpc "$vrb_rpc" --proposal "$g/proposal.json" "${ap[@]}" --out "$g/bundle.json" 2>&1 | tee "$g/aggregate.log" || { vrj_log "FAIL: aggregate"; return 1; }
  build/ubft governance execute --rpc "$vrb_rpc" --bundle "$g/bundle.json" --sender-key "$vrj_cfg/operator.key" 2>&1 | tee "$g/execute-bundle.log" || { vrj_log "FAIL: queue the change"; return 1; }
  change=$(python3 -c "import json;print(json.load(open('$g/proposal.json'))['predictedChangeId'])")
  build/ubft governance list --rpc "$vrb_rpc" --change "$change" 2>&1 | tee "$g/list-queued.log"
  vrj_log "the Admit is queued as change $change; both governance delays (DELAY_ROUNDS 2000 and DELAY_SECONDS 3600) must pass"
  local waited=0
  while ! build/ubft governance execute --rpc "$vrb_rpc" --change "$change" --sender-key "$vrj_cfg/operator.key" >"$g/execute-change.log" 2>&1; do
    sleep 60; waited=$((waited + 60))
    [ "$waited" -lt 9000 ] || { vrj_log "FAIL: the Admit's delays did not pass within 150 minutes"; tail -5 "$g/execute-change.log"; return 1; }
    for i in 1; do [ $((waited % 600)) = 0 ] && vrj_log "waiting for the governance delays ($((waited / 60)) min): $(tail -1 "$g/execute-change.log" | cut -c1-160)"; done
  done
  cat "$g/execute-change.log"
  vrj_log "PASS: the Foundation admitted identity $vrj_id (change $change executed after ${waited}s)"
}

vrj_validates() {
  local i=$vrj_id
  vrb_wait 600 "the joiner's root is a member of epoch 2 (not a follower)" vrj_root_member || return 1
  vrb_wait 300 "the joiner's shard node activated root epoch 2" grep -Fq 'msg="handoff activated" rootEpoch=2' "test-nodes/evm$i/debug.log" || return 1
  local ids; ids=$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'committeeIds()(uint64[])')
  vrj_log "VR's committee after the Boundary: $ids"
  case "$ids" in *"$i"*) vrj_log "PASS: identity $i is in VR's committee" ;; *) vrj_log "FAIL: identity $i is not in VR's committee"; return 1 ;; esac
}
vrj_root_member() {
  curl -sf -X POST -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$(m2_rpc_port "$vrj_id")/api/v1/q3/status" | python3 -c "
import json,sys
d=json.load(sys.stdin)
sys.exit(0 if d.get('activeEpoch')==2 and not d.get('follower') else 1)"
}

# VR_JOINER_FOLLOW=1 (development, fast loop): tries the joiner's following of the committed chain without the Foundation's governance delays. The
# incumbents are restarted with the development staging hook naming the joiner's root and EVM node as extra staged members; the lane then runs
# the payee election of the plain lane, and every root, the joiner's included, must derive the same intent from its own committed state.
vrj_dev_follow() {
  local rid eid n
  rid=$(build/ubft node-id --home "test-nodes/root$vrj_id" | tail -n1); eid=$(build/ubft node-id --home "test-nodes/evm$vrj_id" | tail -n1)
  export UBFT_VR_DEV_STAGE_EXTRA_ROOTS=$rid UBFT_VR_DEV_STAGE_EXTRA_EVM=$eid
  for n in $vrj_incumbents; do vrb_restart_root "$n" "with the development staging hook" || return 1; sleep 3; done
  vrj_log "PASS: the incumbents run with the joiner staged (development hook)"
  if [ "${VR_ARCHIVE:-0}" = 1 ]; then vrj_restore_evm5 || return 1; fi
  vrb_wait 900 "the joiner's execution client caught up with the chain (it is driven by its shard node, which syncs from the incumbents)" vrj_reth_synced || return 1
}

vrj_eth_number() { curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "http://127.0.0.1:$1" | python3 -c "import json,sys;print(int(json.load(sys.stdin)['result'],16))"; }
vrj_reth_synced() {
  local a b
  a=$(vrj_eth_number $((rethEthBase + vrj_id - 1))) || return 1
  b=$(vrj_eth_number "$rethEthBase") || return 1
  vrb_log "joiner reth $a, reth1 $b"
  [ "$a" -gt 0 ] && [ $((b - a)) -le 3 ]
}

# The joiner's shard node is restored from an incumbent's archive (as the P85 lane's joiner is, H3), staging-only: it serves only once the
# incumbents have staged the successor (the roots' tell their shard nodes, which then serve the joiner's EVM node).
vrj_restore_evm5() {
  local i=$vrj_id
  vrj_source_libs || return 1
  declare -F lane_go_run >/dev/null || source scripts/lib/portable.sh
  [ -z "${vrs_fetched:-}" ] || export H3_RESTORE_SEED_DIR=$vrs_fetched   # VT-11: restore from the verified seed's pin
  export H3_ARCHIVES=$EVM_ARCHIVE_ROOT H3_RESTORE_NO_SESSION=1 H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json H3_ONLINE="$vrj_incumbents"
  export EVM_ARCHIVE_REPLICA_POOL="$vrj_members"
  vrb_wait 300 "the incumbents' shard nodes hold the staged successor" vrj_incumbents_staged || return 1
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))" "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
  h3_restore_validator "$i" 1 || { vrj_log "FAIL: restoring the joiner's shard node"; return 1; }
  vrb_wait 600 "the restored joiner's shard node answers" curl -fsS -m 5 -X POST -H 'content-type: application/json' -d '{}' "http://$(evm_validator_rpc_addr "$i")/api/v1/q3/status" || return 1
  vrj_log "PASS: the joiner's shard node is restored from evm1's archive and serves its status"
}
vrj_incumbents_staged() { grep -q 'paired shard node holds the staged successor" node_id=[^ ]* evmNodes=[1-9]' test-nodes/root1/debug.log; }

# SIGNING=authority: after the roots switched to J (root epoch 2, shard epoch 1) the authorities move into its scope. The trust base of epoch 2 and the
# shard configuration of epoch 1 come from the root that holds them; the incumbents advance (their nodes restart under a new session), the joiner's
# authority (pending since it started, at shard epoch 1 and root epoch 1) completes its enrollment against that configuration, advances and takes a session.
vrj_advance_authorities() {
  local root1 pdr i
  vrj_source_libs || return 1
  root1="http://127.0.0.1:$(m2_rpc_port 1)"
  for i in $(seq 1 "${validators:-4}"); do
    vrb_wait 300 "evm$i activated root epoch 2" grep -Fq 'msg="handoff activated" rootEpoch=2' "test-nodes/evm$i/debug.log" || return 1
  done
  build/ubft q3 trust-base --root-rpc "$root1" --epoch 2 --out test-nodes/trust-base-epoch2.json || { vrj_log "FAIL: the trust base of epoch 2"; return 1; }
  cp "test-nodes/trust-base-epoch2.json" "$VR_EVIDENCE/trust-base-epoch2.json"
  pdr=$(h3_pdr_file 1) || { vrj_log "FAIL: the shard configuration of epoch 1"; return 1; }
  cp "$pdr" "$VR_EVIDENCE/shard-conf-epoch1.json"
  if [ "${VR_JOINER:-0}" = 1 ]; then
    local op=(--operator-socket "test-nodes/auth$vrj_id/operator.sock" --operator-credential "test-nodes/auth$vrj_id/operator.cred")
    build/ubft signing-authority complete-enrollment "${op[@]}" --shard-conf "$pdr" || { vrj_log "FAIL: the joiner's enrollment"; return 1; }
    source helper.sh
    authority_advance_scope "$vrj_id" 2 test-nodes/trust-base-epoch2.json "$pdr" || { vrj_log "FAIL: the joiner's advance"; return 1; }
    build/ubft signing-authority replace-session "${op[@]}" --out "test-nodes/auth$vrj_id/client.cred" || { vrj_log "FAIL: the joiner's session"; return 1; }
    vrj_log "PASS: the joiner's authority is enrolled against shard epoch 1, advanced to root epoch 2 and has a session"
  fi
  H3_ONLINE="$(seq -s ' ' 1 "${validators:-4}")" M2_ADVANCE_NO_REPLICA_WAIT=1 h3_advance_authorities 2 1 $(seq -s ' ' 1 "${validators:-4}") || { vrj_log "FAIL: the incumbents' authority advance"; return 1; }
  vrj_log "PASS: the incumbents' authorities advanced into root epoch 2 / shard epoch 1 and their shard nodes restarted under new sessions"
}
