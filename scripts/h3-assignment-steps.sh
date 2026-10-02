# Sourced by reth-paired-devnet.sh (H3_ASSIGNMENT_LANE=1, F8_MIXED_LANE=1, M2_PROFILE2=1, SIGNING=authority) after the
# first paid certified block, in place of m2-profile2-handoffs.sh. Every step prints PASS or FAIL; a FAIL exits nonzero.
# SIGNING=authority is the only mode: every validator signs through its own signing authority (as in production), a joiner's authority
# signs its proof of possession on the operator channel (`evm-pop --authority-socket`) and is enrolled against the activated
# configuration, retained validators' authorities advance (`advance-epoch`) at each activation, and a restored validator restores
# through its surviving authority (a local-key restore is refused by design).
# Design: briefs/h3-evm-assignment-design.md section 8 as amended: validator-set changes are always coupled (root entity and its
# delegated EVM validator). Root epochs: 1 genesis, 2 configuration-only advance, 3 coupled s=1, 4 coupled s=2, 5 coupled s=3. EVM validators: evm1-4 genesis; evm5-7 spare identities that appear only in successor sets.
source scripts/lib/m2-handoff-lib.sh
H3_DIR=test-nodes/h3
mkdir -p "$H3_DIR"
cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
read -r h3_slot_shard h3_slot_root h3_slot_conf h3_slot_cursor < <(go run ./scripts/h3slots)
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
    for p in "test-nodes/evm$i/pid" "test-nodes/auth$i/pid" "test-nodes/reth$i/pid" "test-nodes/h3/restore-$i/pid"; do
      [ -f "$p" ] && kill -INT "$(cat "$p")" 2>/dev/null
    done
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

h3_paid() { M2_PAID_REGISTRY_CHECK=0 m2_send_paid "$1" "$M2_NEXT_NONCE"; }
h3_mark() { local r; for r in $H3_ROOTS; do wc -l <"test-nodes/root$r/debug.log" >"$H3_DIR/mark-$r"; done; }
h3_since_mark() { local r; for r in $H3_ROOTS; do tail -n +"$(( $(cat "$H3_DIR/mark-$r") + 1 ))" "test-nodes/root$r/debug.log"; done; }
h3_rpc_url() { echo "http://127.0.0.1:$(m2_rpc_port "$1")"; }
h3_first_root() { echo "$H3_ROOTS" | awk '{print $1}'; }
h3_root_rpcs() { local r out=; for r in $H3_ROOTS; do out+="${out:+,}$(h3_rpc_url "$r")"; done; echo "$out"; }
h3_slot() { python3 -c "print(int('$(rpc "http://127.0.0.1:$rethEthBase" eth_getStorageAt "[\"$H3_REGISTRY\",\"$1\",\"latest\"]" | pyget "['result']")',16))"; }
h3_registry_is() { [ "$(h3_slot "$h3_slot_shard")" = "$1" ] && [ "$(h3_slot "$h3_slot_root")" = "$2" ]; }
h3_root_info() { curl -fsS "$(h3_rpc_url "$(h3_first_root)")/api/v1/roundInfo"; }
h3_evm_row() { h3_root_info | jq -c '.partitionShards[] | select(.partitionId==8)'; }

# Both the EVM shard and the three aggregator shards must advance: certified IR round for each, root round, aggregator height.
# Polls until every shard has advanced (an aggregator shard's authorized TR round moves with its T2 timeout, up to 7.5 s, so a fixed
# short window is not a fair measure): up to ${2:-10}+25 s, then it reports which shard did not.
h3_progress() {
  local label=$1 waited=0 limit=$(( ${2:-10} + 25 )) rc=1
  f8_trace >"$H3_DIR/progress-before.jsonl" || return 1
  sleep "${2:-10}"
  while :; do
    f8_trace >"$H3_DIR/progress-after.jsonl" || return 1
    h3_progress_check "$label" && return 0
    waited=$((waited + 3)); [ "$waited" -lt "$limit" ] || return 1
    sleep 3
  done
}
h3_progress_check() {
  local label=$1
  python3 - "$H3_DIR/progress-before.jsonl" "$H3_DIR/progress-after.jsonl" "$label" <<'PY'
import json,sys
b={}; a={}
for path,d in ((sys.argv[1],b),(sys.argv[2],a)):
    for line in open(path):
        if line.strip():
            r=json.loads(line); d[r['shard']]=r
# An idle aggregator shard produces no block, so its certified IR round only moves under load (F8's own probe
# drives that once). What must hold continuously is the root's authorized TR round for each shard (the shard is
# covered and certified), the root round, and the EVM certifying; aggregator /health is checked by f8_trace itself.
for shard in ('a-left','a-right','b-left'):
    if int(a[shard]['authorizedTRRound'])<=int(b[shard]['authorizedTRRound']):
        raise SystemExit(f"{sys.argv[3]}: aggregator {shard}: root made no TR progress for it")
    if int(a[shard]['certifiedIRRound'])<int(b[shard]['certifiedIRRound']) or int(a[shard]['aggregatorBlockHeight'])<int(b[shard]['aggregatorBlockHeight']):
        raise SystemExit(f"{sys.argv[3]}: aggregator {shard} went backwards")
# While a successor assignment's acknowledgement is held (or its set is unavailable) the EVM must NOT certify: the lane then asserts
# the roots and aggregators only (H3_EVM_STALLED=1), and the stall itself is asserted by its own step.
import os
if os.environ.get('H3_EVM_STALLED')!='1' and int(a['evm']['certifiedIRRound'])<=int(b['evm']['certifiedIRRound']):
    raise SystemExit(f"{sys.argv[3]}: EVM certified no new round")
if int(a['a-left']['rootRound'])<=int(b['a-left']['rootRound']):
    raise SystemExit(f"{sys.argv[3]}: root round did not advance")
print(f"{sys.argv[3]}: root round {b['a-left']['rootRound']}->{a['a-left']['rootRound']}; aggregators " +
      ", ".join(f"{s} IR {b[s]['certifiedIRRound']}->{a[s]['certifiedIRRound']} height {b[s]['aggregatorBlockHeight']}->{a[s]['aggregatorBlockHeight']}" for s in ('a-left','a-right','b-left')))
PY
}

h3_evm_certifies_after() { # a certified EVM IR round above $1 within $2 seconds
  local base=$1 limit=${2:-90} i now
  for i in $(seq 1 "$limit"); do
    now=$(h3_evm_row | jq -r '.roundNumber')
    [ "$now" -gt "$base" ] && return 0
    sleep 1
  done
  return 1
}

h3_validators_json() { # ids -> sorted JSON array of successor node infos
  local out=$1 id files=; shift
  for id in "$@"; do files+=" test-nodes/auth$id/node-info.json"; done
  # shellcheck disable=SC2086
  jq -s 'map({nodeId, sigKey, stake: 1}) | sort_by(.nodeId)' $files >"$out"
}

h3_spare_identity() {
  local i=$1
  [ -f "test-nodes/evm$i/node-info.json" ] || build/ubft shard-node init --home "test-nodes/evm$i" -g >/dev/null || return 1
  mkdir -p "test-nodes/reth$i"
}

# A joining validator's signing authority, started pending at the successor scope it will operate in (shard epoch, root epoch, that
# root epoch's trust base). Its key is what the successor assignment names; it is enrolled against the activated configuration later
# (h3_enroll_authority). Idempotent.
h3_spare_authority() { # id shardEpoch rootEpoch trustFile
  local i=$1
  if [ -f "test-nodes/auth$i/pid" ] && kill -0 "$(cat "test-nodes/auth$i/pid")" 2>/dev/null; then return 0; fi
  source helper.sh
  init_evm_authorities "$i" "$partitionID" "$i" "$2" "$3" "test-nodes/$4" || return 1
}

# The activated configuration of the EVM shard at a shard epoch, from the derived index of the first root (after the handoff activated).
h3_pdr_file() { # shard epoch -> path
  local out="$H3_DIR/pdr-$1.json"
  go run ./scripts/h3-pdr --orchestration "test-nodes/root$(h3_first_root)/orchestration.db" --epoch "$1" >"$out" || return 1
  echo "$out"
}

# Enroll a joiner's pending authority against the activated configuration and issue its session.
h3_enroll_authority() { # id shard epoch
  local pdr
  pdr=$(h3_pdr_file "$2") || return 1
  source helper.sh
  enroll_evm_authorities "$1" "$partitionID" "$1" "$pdr" || return 1
}

# Advance the retained validators' authorities to the activated scope (root epoch, shard epoch) and restart their nodes with the new
# sessions: the M2 lane's advance-epoch pattern, for the given validators only.
h3_advance_authorities() { # root epoch, shard epoch, ids...
  local rootEpoch=$1 shardEpoch=$2 pdr; shift 2
  pdr=$(h3_pdr_file "$shardEpoch") || return 1
  M2_ADVANCE_TOLERATE_STOPPED=1 M2_ADVANCE_NO_REPLICA_WAIT=1 m2_advance_authorities "$rootEpoch" "trust-base-epoch${rootEpoch}.json" "$pdr" "$*"
}

# Same root keys at the next epoch (a configuration-only boundary advances the root epoch with unchanged members).
h3_same_members_trust_base() {
  local epoch=$1 i infos=()
  for i in $H3_ROOTS; do infos+=(--node-info "test-nodes/root$i/node-info.json"); done
  build/ubft trust-base generate --home test-nodes --network-id 3 --epoch "$epoch" --epoch-start "$((epoch * 100000))" \
    --previous-trust-base "test-nodes/trust-base-epoch$((epoch-1)).json" \
    --output-file-name "trust-base-epoch${epoch}.json" "${infos[@]}" >/dev/null || return 1
  for i in $H3_ROOTS; do build/ubft trust-base sign --home "test-nodes/root$i" --trust-base "test-nodes/trust-base-epoch${epoch}.json" >/dev/null || return 1; done
}

# Coupled committee changes: every handoff that changes the EVM assignment also replaces one root entity. H3_BIND_ROOTS lists
# the successor root indices in the same order as the successor EVM validator indices passed to h3_build_assignment: root i is
# the entity whose delegated EVM validator is evm j at the same position.
H3_BIND_ROOTS=""
h3_root_id() { build/ubft node-id --home "test-nodes/root$1" | tail -n1; }
h3_bindings_json() { # out evm-ids...  (uses H3_BIND_ROOTS)
  local out=$1 k=0 root; shift
  local roots=($H3_BIND_ROOTS) items=()
  for id in "$@"; do
    items+=("{\"rootNodeId\":\"$(h3_root_id "${roots[$k]}")\",\"evmNodeId\":\"$(evm_validator_id "$id")\"}")
    k=$((k+1))
  done
  printf '[%s]\n' "$(IFS=,; echo "${items[*]}")" >"$out"
}
# A new root entity and the next trust base with it replacing one current member (signed by the old committee).
h3_prepare_coupled() { # epoch replaced new
  local epoch=$1 replace=$2 new=$3
  if [ ! -f "test-nodes/root$new/node-info.json" ]; then
    build/ubft root-node init --home "test-nodes/root$new" -g >/dev/null || return 1
    generate_log_configuration "test-nodes/root$new/"
  fi
  m2_next_trust_base "$epoch" "$replace" "$new" "$H3_ROOTS" "trust-base-epoch${epoch}.json" || return 1
}
# After H: the new root starts first (it proves H committed), the retained roots restart on the install epoch, the replaced one stops.
h3_activate_coupled() { # epoch replaced new
  local epoch=$1 replace=$2 new=$3 i oldBoot
  oldBoot=$(m2_root_addr "$replace")
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

# h3_build_assignment <tag> <successor ids...>: context, one proof per successor key, assemble. No EVM parent is named anywhere:
# the root binds it when it orders the Prepare, after the proofs.
# Writes $H3_DIR/<tag>-assignment.json; leaves the propose exit status in $?.
H3_SUPERSEDE=0
h3_build_assignment() {
  local tag=$1 id; shift
  h3_validators_json "$H3_DIR/$tag-validators.json" "$@" || return 1
  build/ubft root handoff evm-context --root-rpc "$(h3_rpc_url "$(h3_first_root)")" --out "$H3_DIR/$tag-context.json" || return 1
  local pops=
  for id in "$@"; do
    build/ubft root handoff evm-pop --context "$H3_DIR/$tag-context.json" --validators "$H3_DIR/$tag-validators.json" \
      --node-id "$(evm_validator_id "$id")" --authority-socket "test-nodes/auth$id/operator.sock" \
      --authority-credential "test-nodes/auth$id/operator.cred" >"$H3_DIR/$tag-pop-$id.json" || return 1
    pops+="${pops:+,}$H3_DIR/$tag-pop-$id.json"
  done
  local sup=(); [ "$H3_SUPERSEDE" = 1 ] && sup=(--supersede)
  h3_bindings_json "$H3_DIR/$tag-bindings.json" "$@" || return 1
  build/ubft root handoff evm-assemble --context "$H3_DIR/$tag-context.json" --validators "$H3_DIR/$tag-validators.json" \
    --pops "$pops" --bindings "$H3_DIR/$tag-bindings.json" --out "$H3_DIR/$tag-assignment.json" ${sup[@]+"${sup[@]}"} || return 1
}

h3_propose() { # tag epoch: plans, waits for the Prepare, endorses the Prepare-bound state
  local tag=$1 epoch=$2
  build/ubft root handoff propose --next-trust-base "test-nodes/trust-base-epoch${epoch}.json" \
    --next-evm-assignment "$H3_DIR/$tag-assignment.json" --root-rpc "$(h3_root_rpcs)"
}

# A committed H for the old epoch since the start of the retry loop, read from every root. Dropped plans are NOT a verdict on the
# current attempt: a root keeps older endorsed plans cached and logs "dropped" whenever it leads a round in which one is stale, so
# only "committed" ends the wait; an attempt that neither commits nor aborts within the window is simply retried.
H3_LOOP_MARK=$H3_DIR/loop-mark
h3_loop_mark() { local r; for r in $H3_ROOTS; do wc -l <"test-nodes/root$r/debug.log" >"$H3_LOOP_MARK-$r"; done; }
h3_committed_since_loop() { # old epoch
  local r
  for r in $H3_ROOTS; do
    tail -n +"$(( $(cat "$H3_LOOP_MARK-$r") + 1 ))" "test-nodes/root$r/debug.log"
  done | grep -E "msg=\"root handoff outcome\" .*phase=committed .*rootEpoch=$1([[:space:]]|$)" | grep -q .
}
# A lapsed Prepare (no Freeze in time) is reported by the roots as `phase=lapsed`; the attempt is dead, so the caller re-plans at once
# instead of waiting out the window.
h3_lapsed_since_loop() { # old epoch
  local r
  for r in $H3_ROOTS; do
    tail -n +"$(( $(cat "$H3_LOOP_MARK-$r") + 1 ))" "test-nodes/root$r/debug.log"
  done | grep -E "msg=\"root handoff outcome\" .*phase=lapsed .*rootEpoch=$1([[:space:]]|$)" | grep -q .
}
h3_wait_committed() { # old epoch: up to 90 s for a commit of this or an earlier attempt; a lapse ends the wait early
  local i
  for i in $(seq 1 90); do
    h3_committed_since_loop "$1" && return 0
    h3_lapsed_since_loop "$1" && { echo "attempt lapsed: re-planning" >&2; h3_loop_mark; return 1; }
    sleep 1
  done
  return 1
}

# An attempt that is refused (a Prepare that lapsed, an aborted attempt) is rebuilt for the next attempt number: the proofs of
# possession bind the attempt. The root binds the frozen parent at the Prepare, so nothing here samples or names a parent.
h3_retry_handoff() { # old epoch, attempt function (builds the assignment and proposes)
  local old=$1 fn=$2 i
  h3_loop_mark
  for i in $(seq 1 60); do
    h3_committed_since_loop "$old" && return 0
    h3_mark
    if "$fn"; then h3_wait_committed "$old" && return 0; fi
    sleep 1
  done
  echo "handoff at old epoch $old did not commit in 60 attempts" >&2
  return 1
}

# Restart every root of the quorum with the install epoch; each fetches and verifies the bundle, derives and installs the configuration.
h3_restart_roots() {
  local epoch=$1 i prev boot
  for i in $H3_ROOTS; do
    prev=$(echo "$H3_ROOTS" | tr ' ' '\n' | grep -vx "$i" | head -1)
    boot=$(m2_root_addr "$prev")
    stop_pidfile "test-nodes/root$i/pid" 'ubft root-node' || return 1
    for _ in $(seq 1 50); do lsof -nP -iTCP:"$(m2_rpc_port "$i")" -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 0.2; done
    m2_archive_root_state "$i" "$epoch" || return 1
    m2_start_root "$i" "$epoch" "$boot" || return 1
  done
  m2_wait_root_epoch "$(h3_first_root)" "$epoch"
}

h3_start_reth() { # spare execution client i, peered with the running ones
  local i=$1 j enode
  openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
  mkdir -p "test-nodes/reth$i"
  "$URETH_BIN" node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) --http.api eth,net,web3,admin,debug \
    --rpc.eth-proof-window 64 --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable \
    --engine.persistence-threshold "$d2cPersistenceThreshold" --builder.gaslimit 30000000 \
    $(urethPinUnicityFlags) >"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
  for _ in $(seq 1 120); do
    rpc "http://127.0.0.1:$((rethEthBase+i-1))" eth_blockNumber '[]' | grep -q '"result"' && break
    sleep 1
  done
  for j in $H3_ONLINE; do
    [ "$j" = "$i" ] && continue
    enode=$(rpc "http://127.0.0.1:$((rethEthBase+j-1))" admin_nodeInfo '[]' | pyget "['result']['enode']") || continue
    rpc "http://127.0.0.1:$((rethEthBase+i-1))" admin_addPeer "[\"$enode\"]" >/dev/null
  done
}

# Restore validator i (fresh home and execution client, identity kept) from a surviving replica's archive, through its surviving authority.
h3_restore_validator() {
  local i=$1 replica=$2; shift 2
  local evidence="$H3_DIR/restore-$i" bodyID rootBoot bootnodes peers=() p
  rm -rf "$evidence"; mkdir -p "$evidence"
  cp "test-nodes/evm$i/keys.json" "test-nodes/evm$i/node-info.json" "$evidence/" || return 1
  # the authority (not the node) holds the signing key: a fresh session for the restored node, the old client being gone
  build/ubft signing-authority replace-session --operator-socket "test-nodes/auth$i/operator.sock" \
    --operator-credential "test-nodes/auth$i/operator.cred" --out "test-nodes/auth$i/client.cred" || return 1
  cp "test-nodes/evm$i/jwt.hex" "$evidence/jwt.hex" 2>/dev/null || openssl rand -hex 32 >"$evidence/jwt.hex"
  stop_one_evm_validator "$i" 2>/dev/null || true
  stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' 2>/dev/null || true
  rm -rf "test-nodes/reth$i/dd"
  cp "$evidence/jwt.hex" "test-nodes/evm$i/jwt.hex"
  h3_start_reth "$i" || return 1
  cp "test-nodes/evm$i/jwt.hex" "$evidence/jwt.hex"   # h3_start_reth drew a new secret for the new execution client
  go run ./scripts/h4-restore-pin "test-nodes/h3-archives/evm$replica" "$H3_RESTORE_TRUST_BASE" "$evidence/tip" >"$evidence/pin.txt" || return 1
  bodyID=$(tr ' ' '\n' <"$evidence/pin.txt" | sed -n 's/^bodyID=//p')
  rootBoot=$(m2_root_addr "$(h3_first_root)")
  bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$i" $H3_ONLINE) || return 1
  # exactly two replicas: each is two array elements (the flag and the node id)
  for p in $H3_ONLINE; do [ "$p" = "$i" ] || [ "${#peers[@]}" -ge 4 ] || peers+=(--archive-replica "$(evm_validator_id "$p")"); done
  build/ubft shard-node restore --home "$evidence" --executor engine-api \
    --address "/ip4/127.0.0.1/tcp/$((evmValidatorPortStart + i - 1))" --bootnodes "$bootnodes" \
    --trust-base "$H3_RESTORE_TRUST_BASE" --full-shard-conf "$EVM_FULL_SHARD_CONF" --registry-layout 2 \
    --genesis "$EVM_GENESIS_FILE" --engine-url "http://127.0.0.1:$((rethEngineBase+i-1))" \
    --eth-url "http://127.0.0.1:$((rethEthBase+i-1))" --jwt-secret "$evidence/jwt.hex" \
    --engine-fee-collector "$EVM_ENGINE_FEE_COLLECTOR" --execution-journal "$evidence/journal.db" \
    --archive-store "$evidence/archive" --archive-prune --trust-history-profile-2 --journal-candidates "${EVM_JOURNAL_CANDIDATES:-32}" \
    --signing-authority-socket "test-nodes/auth$i/client.sock" --signing-authority-credential "test-nodes/auth$i/client.cred" \
    "${peers[@]}" --tip-uc "$evidence/tip.uc.cbor" --tip-tr "$evidence/tip.tr.cbor" --trust-body-id "$bodyID" \
    --log-format text --log-level info >>"$evidence/restore.log" 2>&1 &
  echo $! >"$evidence/pid"
  cp "$evidence/pid" "test-nodes/evm$i/pid"
  ln -sf "restore-$i/restore.log" "test-nodes/evm$i/debug.log" 2>/dev/null || true
}

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
echo "=== H3 acceptance lane: M3-shaped genesis (layout 2) + three aggregator shards ==="
echo "NOTE: every validator signs through its own signing authority (SIGNING=authority): the rotation is authority-backed."
h3_step "baseline: EVM certifies and all three aggregator shards progress" h3_progress baseline 8
h3_step "genesis registry is layout 2, shard epoch 0, root epoch 1" h3_registry_is 0 1

# 1. Baseline: a configuration-only epoch advance (same committee, no EVM change): root epoch 2, shard epoch stays 0.
h3_config_attempt() { build/ubft root handoff propose --next-trust-base test-nodes/trust-base-epoch2.json --root-rpc "$(h3_root_rpcs)"; }
h3_config_only() {
  h3_same_members_trust_base 2 || return 1
  h3_retry_handoff 1 h3_config_attempt || return 1
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
h3_step "aggregators and EVM progress after the configuration-only advance" h3_progress config-only 8
h3_has_coupling_param() { jq -e '.partitionParams.validator_coupling == "true"' "$fullShardConf" >/dev/null; }
h3_step "the genesis EVM configuration requires coupled validator-set changes (validator_coupling=true)" h3_has_coupling_param

# 2. An EVM proposal with a bad PoP is refused before freeze.
build/ubft shard-node init --home test-nodes/evm5 -g >/dev/null 2>&1 || true
h3_spare_identity 5; h3_spare_identity 6; h3_spare_identity 7
h3_bad_pop() {
  local start outcomeBefore
  h3_prepare_coupled 3 4 5 || return 1
  h3_spare_authority 5 1 3 trust-base-epoch3.json || return 1
  H3_BIND_ROOTS="1 2 3 5" h3_build_assignment bad 1 2 3 5 || return 1
  python3 - "$H3_DIR/bad-assignment.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
sig=bytearray(bytes.fromhex(d['pops'][-1]['signature'].removeprefix('0x')))
sig[10]^=1                                  # the proof no longer verifies under this attempt's context
d['pops'][-1]['signature']='0x'+sig.hex()
json.dump(d,open(p,'w'))
PY
  start=$(wc -l <"test-nodes/root$(h3_first_root)/debug.log")
  if h3_propose bad 3 >"$H3_DIR/bad-propose.out" 2>&1; then echo "root accepted a proposal with a corrupted PoP" >&2; return 1; fi
  cat "$H3_DIR/bad-propose.out"
  # refused at plan time, before any intent, Prepare or endorsement: nothing was ordered and the epoch did not move
  ! tail -n +"$((start+1))" "test-nodes/root$(h3_first_root)/debug.log" | grep -Eqi 'handoff (prepare|freeze|endorse)' || return 1
  [ "$(h3_root_info | jq -r '.epochNumber')" = 2 ]
}
h3_step "EVM proposal with a bad proof of possession is refused before any Prepare" h3_bad_pop

# 3. Coupled rotation s=1 during an in-flight old proposal: root 4 -> 5 together with evm4 -> evm5. The retained evm3 is stopped
#    and evm5 is not yet running, so the successor quorum cannot acknowledge until the root quorum restart is over.
h3_s1_attempt() {
  H3_AGG_CHANGE=${H3_AGG_CHANGE:-0} H3_BIND_ROOTS="1 2 3 5" h3_build_assignment s1 1 2 3 5 || return 1
  h3_propose s1 3
}
h3_evm_s1() {
  local i tx
  h3_start_reth 5 || return 1
  h3_prepare_coupled 3 4 5 || return 1
  # keep an old-epoch proposal in flight: submit a paid tx to every validator, then propose before it certifies
  for i in 1 2 3 4; do
    tx=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase+i-1))" -chain-id 31337 -nonce "$M2_NEXT_NONCE" 2>&1) || { echo "in-flight tx to validator $i failed (nonce $M2_NEXT_NONCE): $tx" >&2; return 1; }
  done
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
  h3_retry_handoff 2 h3_s1_attempt || return 1
  stop_one_evm_validator 3 || return 1       # hold the acknowledgement: only evm1 and evm2 remain of {1,2,3,5}
  stop_one_evm_validator 4 || return 1       # evm4 is retired; its old process is stopped here
  echo "H committed at old epoch 2; successor quorum is held below threshold"
}
h3_step "coupled rotation s=1 (root 4->5, evm4->evm5) committed with an old proposal in flight; ack held" h3_evm_s1

h3_root_quorum_restart() {
  local row0 row1
  row0=$(h3_evm_row | jq -c '{round: .roundNumber, tr: .trRound}')
  h3_activate_coupled 3 4 5 || return 1       # the root quorum restarts (new root 5 first), the replaced root 4 stops
  H3_EVM_STALLED=1 h3_progress "after root quorum restart (ack still held)" 10 || return 1
  h3_registry_is 0 2 || return 1             # the successor set has not acknowledged: registry is still at the old shard epoch
  row1=$(h3_evm_row | jq -c '{round: .roundNumber, tr: .trRound}')
  echo "EVM row before restart $row0, after $row1"
}
h3_step "root quorum restarted at epoch 3; roots and aggregators progress while the ack is held" h3_root_quorum_restart

# Hard rejection assertion for a node id the installed assignment does not contain. The root's own refusal is
# `node "<id>" is not in the trustbase of the shard` (ShardInfo.Verify, logged by the root as "processing
# *certification.BlockCertificationRequest"). It must (1) appear in a root log since the mark, and (2) the id must never
# appear among the requestNodeIDs of a request set the root accepted ("reached consensus"), i.e. nothing it sent certified.
h3_assert_rejected() { # node id, what
  local id=$1 what=$2 i refusals=0 accepted
  for i in $(seq 1 90); do
    # The root refuses a retired or never-active key in one of two places, both of them the active-set check: at the handshake
    # ("node ID is not in active validator set ... <id>", the node then never gets a certificate and sends no request) or, for a
    # request that does arrive, at the request ("node <id> is not in the trustbase of the shard").
    refusals=$(h3_since_mark | grep -E "processing \*(certification.BlockCertificationRequest|handshake.Handshake)" |
      grep -cE "node \"$id\" is not in the trustbase of the shard|node ID is not in active validator set .*$id" || true)
    [ "$refusals" -ge 1 ] && break
    sleep 1
  done
  [ "$refusals" -ge 1 ] || { echo "$what: no root logged an active-set refusal for $id (handshake or request)" >&2; return 1; }
  accepted=$(h3_since_mark | grep -F "reached consensus" | grep -F "requestNodeIDs" | grep -cF "$id" || true)
  [ "$accepted" -eq 0 ] || { echo "$what: root accepted $accepted request set(s) containing $id" >&2; return 1; }
  echo "$what: $refusals exact root refusal(s) for $id; 0 accepted request sets contain it"
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
  # The retained validators' authorities (1 and 2 running, 3 held down) advance to the activated scope (root epoch 3, shard epoch 1)
  # and their nodes restart with the new sessions; the joiner's authority is enrolled against the activated configuration.
  h3_advance_authorities 3 1 1 2 3 || { echo "authority advance to root epoch 3 / shard epoch 1 failed" >&2; return 1; }
  h3_enroll_authority 5 1 || { echo "enrolling the evm5 authority failed" >&2; return 1; }
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json   # anchored at the genesis trust base: the restore catches up forward through the verified handoffs
  h3_restore_validator 5 1 || return 1
  local i
  for i in $(seq 1 180); do h3_registry_is 1 3 && break; sleep 1; done
  h3_registry_is 1 3 || { echo "registry did not reach shard epoch 1 / root epoch 3" >&2; return 1; }
  h3_paid 3
}
h3_step "s=1 acknowledgement certified; paid transaction certified at root epoch 3" h3_ack_s1

# Send one transaction to every online validator and wait for a certified receipt at the given root epoch.
h3_send_certified() { # epoch args...
  local epoch=$1 id sent expected= first i receipt status block; shift
  for id in $H3_ONLINE; do
    sent=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase+id-1))" -chain-id 31337 -nonce "$M2_NEXT_NONCE" "$@" 2>&1) || { echo "$sent" >&2; return 1; }
    [ -z "$expected" ] || [ "$expected" = "$sent" ] || return 1
    expected=$sent
  done
  first=${H3_ONLINE%% *}
  for i in $(seq 1 180); do
    receipt=$(rpc "http://127.0.0.1:$((rethEthBase+first-1))" eth_getTransactionReceipt "[\"$expected\"]")
    status=$(echo "$receipt" | pyget "['result']['status']"); block=$(echo "$receipt" | pyget "['result']['blockHash']")
    if [ "$status" = 0x1 ] && [ -n "$block" ] && [ "$block" != None ] &&
       grep -Eq "msg=\"certificate admitted\" block=${block#0x} .*rootEpoch=$epoch([[:space:]]|$)" "test-nodes/evm$first/debug.log"; then
      H3_RECEIPT=$receipt; M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1)); return 0
    fi
    sleep 1
  done
  return 1
}

# F7: deploy the lock contract and lock 42 wei; extract the inclusion bundle (absence proofs are not required); verify offline with the trust base of the UC's root epoch.
h3_mint() { # root epoch of the certificate
  local epoch=$1 initcode contract topic block txIndex logIndex first=${H3_ONLINE%% *}
  initcode=$(go run ./scripts/evmtx -lock-initcode) || return 1
  h3_send_certified "$epoch" -create -data "$initcode" -gas-limit 200000 -value 0 || return 1
  contract=$(go run ./scripts/evmtx -create-address -nonce "$((M2_NEXT_NONCE - 1))") || return 1
  topic=$(go run ./scripts/evmtx -event-topic 'Locked(uint256)') || return 1
  h3_send_certified "$epoch" -to "$contract" -value 42 -gas-limit 100000 || return 1
  block=$(echo "$H3_RECEIPT" | pyget "['result']['blockHash']")
  txIndex=$(python3 -c "print(int('$(echo "$H3_RECEIPT" | pyget "['result']['transactionIndex']")',16))")
  logIndex=$(python3 -c "print(int('$(echo "$H3_RECEIPT" | pyget "['result']['logs'][0]['logIndex']")',16))")
  H3_MINT="$block $txIndex $logIndex $contract $topic"
  echo "locked 42 wei: block=$block tx=$txIndex log=$logIndex contract=$contract"
}
h3_verify_mint() { # root epoch (trust base) shard epoch (PDR)
  local trustEpoch=$1 shardEpoch=$2 block txIndex logIndex contract topic first=${H3_ONLINE%% *} tmp=$H3_DIR/f7-$1-$2
  read -r block txIndex logIndex contract topic <<<"$H3_MINT"
  mkdir -p "$tmp"
  go build -o "$tmp/extract" ./scripts/f7-mintproof-extract || return 1
  go build -o "$tmp/verify" ./scripts/f7-mintproof-verify || return 1
  go build -o "$tmp/pdr" ./scripts/h3-pdr || return 1
  "$tmp/pdr" --orchestration "test-nodes/root$(h3_first_root)/orchestration.db" --epoch "$shardEpoch" >"$tmp/config-pdr.json" || return 1
  for _ in $(seq 1 60); do [ -d "test-nodes/h3-archives/evm$first" ] && break; sleep 1; done
  "$tmp/extract" extract --archive "test-nodes/h3-archives/evm$first" --block-hash "$block" --tx-index "$txIndex" --log-index "$logIndex" \
    --emitter "$contract" --topic "$topic" --config-pdr "$tmp/config-pdr.json" --out "$tmp/locked.cbor" || return 1
  # offline: no network, only the bundle, the genesis pin and the trust base for the certificate's root epoch
  local offline='(version 1) (allow default) (deny network*)'
  env -i PATH="$PATH" sandbox-exec -p "$offline" "$tmp/verify" --bundle "$tmp/locked.cbor" --trust-base "test-nodes/trust-base-epoch$trustEpoch.json" \
    --genesis-conf "$fullShardConf" --lock-contract "$contract" --mode locked >"$tmp/verify-locked.json" || return 1
  cat "$tmp/verify-locked.json"
}
h3_step "paid mint (lock) certified under the s=1 set" h3_mint 3
h3_step "F7 inclusion proof verifies offline with the epoch-3 trust base and the s=1 PDR" h3_verify_mint 3 1

# 5. H4 restore at s=1: a retained validator loses BFT and EL state and restores under the s=1 configuration.
h3_restore_s1() {
  local i
  H3_ONLINE="2 3 5"
  h3_restore_validator 1 2 || return 1
  H3_ONLINE="1 2 3 5"
  for i in $(seq 1 180); do
    grep -Eq 'handoff activated.*rootEpoch=3' "$H3_DIR/restore-1/restore.log" &&
      grep -q 'submitting block certification request' "$H3_DIR/restore-1/restore.log" &&
      grep -Eq 'msg="certificate admitted" .*rootEpoch=3([[:space:]]|$)' "$H3_DIR/restore-1/restore.log" && return 0
    kill -0 "$(cat "$H3_DIR/restore-1/pid")" 2>/dev/null || { tail -40 "$H3_DIR/restore-1/restore.log" >&2; return 1; }
    sleep 1
  done
  tail -40 "$H3_DIR/restore-1/restore.log" >&2
  return 1
}
h3_step "H4 restore at s=1: validator 1 restores, verifies epoch 3 and resumes signing" h3_restore_s1

# 6. s=2 with a PoP-valid set whose successors are unavailable after H (evm6, evm7 never start).
h3_s2_attempt() {
  H3_BIND_ROOTS="1 2 5 6" H3_SUPERSEDE=0 h3_build_assignment s2 1 2 6 7 || return 1
  h3_propose s2 4
}
h3_evm_s2() {
  h3_prepare_coupled 4 3 6 || return 1       # root 3 -> 6, committee {1,2,5,6}
  h3_spare_authority 6 2 4 trust-base-epoch4.json || return 1
  h3_spare_authority 7 2 4 trust-base-epoch4.json || return 1
  h3_retry_handoff 3 h3_s2_attempt || return 1
  h3_activate_coupled 4 3 6 || return 1
}
h3_step "coupled s=2 (root 3->6; PoP-valid; evm6/evm7 unavailable) committed at H" h3_evm_s2
h3_s2_stalls() {
  local base
  base=$(h3_evm_row | jq -r '.roundNumber')
  sleep 25
  [ "$(h3_evm_row | jq -r '.roundNumber')" = "$base" ] || { echo "EVM certified past H without an s=2 quorum" >&2; return 1; }
  h3_registry_is 1 3 || return 1
  H3_EVM_STALLED=1 h3_progress "s=2 stalled EVM" 8
}
h3_step "EVM waits (no certification) while root and aggregators progress" h3_s2_stalls

# 7. Supersede s=2 with s=3 at the same parent; the retired s=2 set's late ack is refused.
h3_supersede_s3() {
  h3_prepare_coupled 5 2 7 || return 1       # root 2 -> 7, committee {1,5,6,7}
  H3_BIND_ROOTS="1 5 6 7" H3_SUPERSEDE=1 h3_build_assignment s3 1 2 3 5 || return 1
  h3_loop_mark
  h3_propose s3 5 || return 1
  h3_wait_committed 4 || return 1
  h3_activate_coupled 5 2 7 || return 1
  # the folded acknowledgement needs the retained and returning validators' authorities at the activated scope (root epoch 5, shard epoch 3)
  H3_ONLINE="1 2 3 5"
  h3_advance_authorities 5 3 1 2 3 5 || { echo "authority advance to root epoch 5 / shard epoch 3 failed" >&2; return 1; }
  local i
  for i in $(seq 1 180); do h3_registry_is 3 5 && return 0; sleep 1; done
  echo "registry did not reach shard epoch 3 / root epoch 5" >&2
  return 1
}
h3_step "coupled s=3 (root 2->7) supersedes s=2 on the same parent; folded acknowledgement certified" h3_supersede_s3
h3_late_s2_ack_refused() {
  local id6
  id6=$(evm_validator_id 6)
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json   # anchored at the genesis trust base: the restore catches up forward through the verified handoffs
  H3_ONLINE="1 2 3 5"
  h3_mark
  h3_enroll_authority 6 2 || { echo "enrolling the evm6 authority against the s=2 configuration failed" >&2; return 1; }
  h3_restore_validator 6 1 || true            # the s=2 key tries to acknowledge late
  h3_assert_rejected "$id6" "late s=2 acknowledgement from evm6" || return 1
  h3_registry_is 3 5                          # the registry shows s=3's folded acknowledgement, not s=2's
}
h3_step "s=2's late acknowledgement is rejected" h3_late_s2_ack_refused
h3_final() {
  stop_one_evm_validator 6 2>/dev/null || true
  H3_ONLINE="1 2 3 5"
  h3_paid 5 && h3_mint 5 && h3_verify_mint 5 3
}
h3_step "certify and verify a paid mint under s=3 (epoch-5 trust base, s=3 PDR)" h3_final
h3_step "aggregators progressed through the whole lane" h3_progress final 8
echo "H3 acceptance lane: all steps PASSED"
