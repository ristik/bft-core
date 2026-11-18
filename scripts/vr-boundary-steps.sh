#!/usr/bin/env bash
# The first real VR boundary (VT-14 item 5, VT-05b): sourced by reth-paired-devnet.sh under VR_LANE=1 with VR_STEPS set to this file, after
# VR reads back the genesis committee. An owner stages a new payee for identity 4 (VR.proposeBinding through `ubft validator rotate`), the
# PoA module's election is due and publishes R, every root observes R's source and derives the intent, the successors' PoPs and readiness
# reach every root through the staged protocol (made by the members themselves, VT-09: no harness drive), the committed view's
# assembler root assembles, a leader orders the Prepare, the Freeze v5 and H, the roots switch to J, the EVM shard acknowledges, and VR
# applies the Boundary that installs J. Evidence goes to $VR_EVIDENCE (default ~/evidence/vt14/boundary).

VR_EVIDENCE=${VR_EVIDENCE:-$HOME/evidence/vt09}
mkdir -p "$VR_EVIDENCE"
vrb_log() { echo "vr-boundary: $*" | tee -a "$VR_EVIDENCE/steps.log"; }
vrb_rpc=http://127.0.0.1:$rethEthBase
vrb_vr=0xff00000000000000000000000000000000000003

vrb_root_rpcs() {
  local p
  for p in $(pgrep -f 'ubft root-node run --home test-nodes/root'); do   # this devnet's roots only (never another project's)
    tr '\0' ' ' </proc/"$p"/cmdline 2>/dev/null | grep -o -- '--rpc-server-address [^ ]*' | awk '{print "http://"$2}'
  done | sort -u
}

vrb_wait() { # <seconds> <description> <command...>
  local secs=$1 what=$2 i; shift 2
  for i in $(seq 1 "$secs"); do
    if "$@" >/dev/null 2>&1; then vrb_log "PASS: $what (after ${i}s)"; return 0; fi
    sleep 1
  done
  vrb_log "FAIL: $what within ${secs}s"
  return 1
}

vrb_open_output() { cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'openOutput()(bytes32)'; }
vrb_published() { # VR's open output is Published (state 2)
  local r; r=$(vrb_open_output) || return 1
  [ "$r" != 0x0000000000000000000000000000000000000000000000000000000000000000 ] || return 1
  local raw; raw=$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'output(bytes32)' "$r") || return 1
  python3 -c "import sys;h=sys.argv[1][2:];w=[h[i:i+64] for i in range(0,len(h),64)];sys.exit(0 if int(w[1],16)==2 else 1)" "$raw"
}
vrb_intent() { curl -sf -H 'Content-Type: application/json' "$1/api/v1/vr/intent"; }
vrb_all_intents() { local r; for r in $(vrb_root_rpcs); do vrb_intent "$r" >/dev/null || return 1; done; }
vrb_members_logged() { # every successor's root node (the four of this lane) logged the line
  local i; for i in $(seq 1 "${validators:-4}"); do grep -q -- "$1" "test-nodes/root$i/debug.log" 2>/dev/null || return 1; done
}
vrb_logs_have() { grep -l -- "$1" test-nodes/root*/debug.log >/dev/null 2>&1; }
vrb_acked() { [ "$(cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'lastAcked()(bytes32)')" = "$vrb_result" ]; }
vrb_root_epoch2() { local r n=0; for r in $(vrb_root_rpcs); do curl -sf -X POST -H 'Content-Type: application/json' -d '{}' "$r/api/v1/q3/status" | grep -q '"activeEpoch": *2' && n=$((n+1)); done; [ "$n" -ge 3 ]; }

# VR_RESTART_MEMBER=1: one member (identity 1's root) is stopped once every member has signed and the assembly is held, and restarted mid-protocol,
# before the Prepare: it resumes from its persisted state, signs nothing again, and the handoff still completes.
vrb_restart_member() {
  local node=1 before after boot
  declare -F m2_start_root >/dev/null || source scripts/lib/m2-handoff-lib.sh || { vrb_log "FAIL: the root restart library"; return 1; }
  before=$(grep -c 'VR handoff member: readiness' "test-nodes/root$node/debug.log")
  vrb_log "restarting root$node mid-protocol"
  boot=$(m2_root_addr 2)
  stop_pidfile "test-nodes/root$node/pid" 'ubft root-node' || { vrb_log "FAIL: stopping root$node"; return 1; }
  cp "test-nodes/root$node/vr-member.json" "$VR_EVIDENCE/root$node-vr-member-before-restart.json" 2>/dev/null || true
  m2_start_root "$node" 1 "$boot" || { vrb_log "FAIL: restarting root$node"; return 1; }
  sleep 10
  after=$(grep -c 'VR handoff member: readiness' "test-nodes/root$node/debug.log")
  [ "$before" = "$after" ] || { vrb_log "FAIL: root$node signed a view again after its restart"; return 1; }
  cp "test-nodes/root$node/vr-member.json" "$VR_EVIDENCE/root$node-vr-member-after-restart.json" 2>/dev/null || true
  vrb_log "PASS: root$node restarted mid-protocol and signed nothing again"
}

vrb_main() {
  local i keys owner payee cfg
  vrb_log "roots: $(vrb_root_rpcs | tr '\n' ' ')"
  # 1. an owner stages a new payee for identity 4: the election is due (a staged binding)
  keys=$VR_DIR/dev-keys/keys.json
  owner=$(python3 -c "import json;print(json.load(open('$keys'))['owners'][3]['privateKey'])")
  payee=0x$(openssl rand -hex 20)
  # identity 4's own homes: the identities follow ascending root node id, not the devnet's numbering
  local rid eid rhome= ehome= h
  rid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[3]['rootNodeId'])")
  eid=$(python3 -c "import json;print(json.load(open('$VR_DIR/genesis-identities.json'))[3]['evmNodeId'])")
  for h in test-nodes/root*/; do [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$rid" ] && rhome=${h%/}; done
  for h in test-nodes/evm*/; do [ "$(build/ubft node-id --home "$h" 2>/dev/null | tail -n1)" = "$eid" ] && ehome=${h%/}; done
  [ -n "$rhome" ] && [ -n "$ehome" ] || { vrb_log "FAIL: identity 4's homes not found"; return 1; }
  vrb_log "identity 4 is $rhome / $ehome"
  cfg=$(mktemp -d)
  printf '%s\n' "$owner" >"$cfg/operator.key"; chmod 600 "$cfg/operator.key"
  openssl rand -hex 32 >"$cfg/ureth.key"
  cat >"$cfg/validator.json" <<EOF
{"format":"unicity.validator.config.v1","rpc":"$vrb_rpc","registry":"$vrb_vr","rootKeys":"$PWD/$rhome/keys.json",
 "evmKeys":"$PWD/$ehome/keys.json","urethKey":"$cfg/ureth.key","jwt":"$cfg/none","operatorKey":"$cfg/operator.key",
 "payee":"$(python3 -c "import json;print(json.load(open('$keys'))['owners'][3]['address'])")","id":4}
EOF
  build/ubft validator rotate --validator-config "$cfg/validator.json" --new-payee "$payee" 2>&1 | tee "$VR_EVIDENCE/rotate.log" || { vrb_log "FAIL: rotate"; return 1; }
  vrb_log "PASS: identity 4 staged a new payee $payee"
  # 2. the PoA election publishes R
  vrb_wait 900 "VR's open output is Published" vrb_published || return 1
  vrb_result=$(vrb_open_output)
  cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'output(bytes32)' "$vrb_result" >"$VR_EVIDENCE/output.hex"
  vrb_log "R = $vrb_result"
  # 3. every root observed the source and derives the intent
  vrb_wait 300 "every root derives the intent over its committed state" vrb_all_intents || return 1
  for i in $(vrb_root_rpcs); do vrb_intent "$i" | python3 -c "import json,sys;d=json.load(sys.stdin);print(sys.argv[1], d['digest'], d['view'], d['assembler'])" "$i"; done | tee "$VR_EVIDENCE/intents.txt"
  [ "$(awk '{print $2}' "$VR_EVIDENCE/intents.txt" | sort -u | wc -l)" = 1 ] || { vrb_log "FAIL: the roots derive different intents"; return 1; }
  vrb_log "PASS: every root derives the same intent"
  cp "$VR_DIR"/../root1/vr-sources.json "$VR_EVIDENCE/root1-vr-sources.json" 2>/dev/null || true
  # 4. the members do their steps themselves (VT-09): no harness message is sent. Every successor's root node logs its own proof and readiness.
  vrb_wait 300 "every successor member signed its possession proof itself" vrb_members_logged 'VR handoff member: possession proof' || return 1
  vrb_wait 300 "every successor member signed its readiness itself" vrb_members_logged 'VR handoff member: readiness' || return 1
  vrb_wait 300 "the committed view's assembler root assembled" vrb_logs_have 'VR handoff: assembled' || return 1
  vrb_wait 300 "a complete verified certificate is held" vrb_logs_have 'a complete verified certificate is held' || return 1
  grep -h 'VR handoff member' test-nodes/root*/debug.log >"$VR_EVIDENCE/member-steps.log" 2>/dev/null || true
  [ "${VR_RESTART_MEMBER:-0}" = 1 ] && { vrb_restart_member || return 1; }
  # 5. Prepare, Freeze v5, H, the epoch switch, the shard's acknowledgement and the Boundary
  vrb_wait 300 "a leader ordered the Prepare" vrb_logs_have 'VR handoff: ordering the prepare' || return 1
  vrb_wait 300 "a leader ordered the Freeze v5" vrb_logs_have 'VR handoff: ordering the freeze' || return 1
  vrb_wait 300 "a leader ordered H" vrb_logs_have 'VR handoff: ordering the commit' || return 1
  vrb_wait 600 "the roots switched to J (epoch 2)" vrb_root_epoch2 || return 1
  vrb_wait 900 "the EVM shard acknowledged and VR applied the Boundary (lastAcked = R)" vrb_acked || return 1
  cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'committee()' >"$VR_EVIDENCE/committee-after.hex"
  cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'identity(uint64)' 4 >"$VR_EVIDENCE/identity4-after.hex"
  vrb_log "PASS: the Boundary installed J"
  for i in $(seq 1 "${validators:-4}"); do
    grep -E 'VR handoff|VR output published|root handoff outcome|switched|epoch' "test-nodes/root$i/debug.log" | tail -n 400 >"$VR_EVIDENCE/root$i-vr.log"
  done
  return 0
}

if vrb_main; then
  vrb_log "VR BOUNDARY DONE"
else
  failures=$((failures + 1))
  for i in $(seq 1 "${validators:-4}"); do tail -n 3000 "test-nodes/root$i/debug.log" >"$VR_EVIDENCE/root$i-tail.log" 2>/dev/null; done
  for i in $(seq 1 "${validators:-4}"); do tail -n 1000 "test-nodes/evm$i/debug.log" >"$VR_EVIDENCE/evm$i-tail.log" 2>/dev/null; done
fi
