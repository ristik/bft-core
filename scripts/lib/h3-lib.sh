# Sourced by scripts/h3-assignment-steps.sh (the H3 acceptance lane) and by the T6 rehearsal's coupled-rotation step: the H3 lane helpers.
# Definitions and defaults only: sourcing starts nothing. They need the paired-devnet context (rpc, pyget, evm_validator_id, m2_* helpers) and the
# variables the caller sets (H3_DIR, H3_ROOTS, H3_ONLINE, H3_REGISTRY, h3_slot_*, M2_NEXT_NONCE, M2_CHAIN_ID; optionally H3_ARCHIVES, H3_RESTORE_RESTART).
H3_SUPERSEDE=${H3_SUPERSEDE:-0}
H3_ARCHIVES=${H3_ARCHIVES:-test-nodes/h3-archives}
H3_LOOP_MARK=${H3_LOOP_MARK:-${H3_DIR:-test-nodes/h3}/loop-mark}

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
  local retained=() joiners=() i
  for i in "$@"; do if [ "$i" -ge 5 ] || [[ " ${H3_RESTORE_RESTART:-} " == *" $i "* ]]; then joiners+=("$i"); else retained+=("$i"); fi; done
  if [ "${#retained[@]}" -gt 0 ]; then
    M2_ADVANCE_TOLERATE_STOPPED=1 M2_ADVANCE_NO_REPLICA_WAIT=1 m2_advance_authorities "$rootEpoch" "trust-base-epoch${rootEpoch}.json" "$pdr" "${retained[*]}" || return 1
  fi
  # A joiner's genesis configuration does not name it, so a plain start of its node is refused: it comes back by RESTORING (its signing key
  # is bound from the verified handoff history), under its advanced authority.
  for i in ${joiners[@]+"${joiners[@]}"}; do
    stop_one_evm_validator "$i" 2>/dev/null || true
    build/ubft signing-authority advance-epoch --operator-socket "test-nodes/auth$i/operator.sock" \
      --operator-credential "test-nodes/auth$i/operator.cred" --trust-base "test-nodes/trust-base-epoch${rootEpoch}.json" --shard-conf "$pdr" || return 1
    h3_restore_validator "$i" 2 || return 1
    echo "joiner $i advanced to root epoch $rootEpoch and restored"
  done
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
    --engine.persistence-threshold "$d2cPersistenceThreshold" --builder.gaslimit "${URETH_BUILDER_GASLIMIT:-30000000}" \
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
  # No default: an empty trust base would restore against the wrong anchor. The caller sets it before any path that can restore
  # (h3_advance_authorities restores the H3_RESTORE_RESTART validators too).
  [ -n "${H3_RESTORE_TRUST_BASE:-}" ] || { echo "h3_restore_validator $i: H3_RESTORE_TRUST_BASE is not set" >&2; return 1; }
  # The restored node lives in the validator's own home, with the paths a plain start uses (journal, archive store, debug.log), so the
  # lane's later authority-advance restarts (start_one_evm_validator) find it where they expect it. Its stale state is cleared first.
  local evidence="test-nodes/evm$i" bodyID rootBoot bootnodes peers=() p
  # a lane that keeps its execution journals elsewhere (the post-M2a lanes) names the root; the H3 lane keeps it in the home
  local journal="$evidence/execution-journal.db"
  [ -z "${EVM_EXECUTION_JOURNAL_ROOT:-}" ] || journal="$EVM_EXECUTION_JOURNAL_ROOT/evm$i.db"
  stop_one_evm_validator "$i" 2>/dev/null || true
  stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' 2>/dev/null || true
  # Clearing state under a live node can corrupt it (and the evidence): every process that owns this validator's node home or its
  # execution client's data directory must be GONE first, or the lane fails. Found by pattern, not only by pid file (a pid file names the
  # last process started, not one that is still shutting down).
  local waited=0 alive
  while :; do
    alive=$(pgrep -f -- "--home test-nodes/evm$i( |$)|test-nodes/reth$i/dd" 2>/dev/null | tr '\n' ' ')
    [ -z "$alive" ] && break
    waited=$((waited + 1))
    if [ "$waited" -ge 120 ]; then echo "validator $i: process(es) $alive still running after 60s: refusing to clear its state" >&2; return 1; fi
    sleep 0.5
  done
  find "$evidence" -mindepth 1 ! -name keys.json ! -name node-info.json ! -name jwt.hex ! -name logger-config.yaml -exec rm -rf {} + 2>/dev/null
  rm -rf "$H3_ARCHIVES/evm$i" "$journal" "$journal"-*
  mkdir -p "$evidence"
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
  go run ./scripts/h4-restore-pin "$H3_ARCHIVES/evm$replica" "$H3_RESTORE_TRUST_BASE" "$evidence/tip" >"$evidence/pin.txt" || return 1
  bodyID=$(tr ' ' '\n' <"$evidence/pin.txt" | sed -n 's/^bodyID=//p')
  rootBoot=$(m2_root_addr "$(h3_first_root)")
  bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$i" $H3_ONLINE) || return 1
  # exactly two replicas: each is two array elements (the flag and the node id)
  for p in $H3_ONLINE; do [ "$p" = "$i" ] || [ "${#peers[@]}" -ge 4 ] || peers+=(--archive-replica "$(evm_validator_id "$p")"); done
  local -a layoutArgs=(--registry-layout "$(registry_layout)")
  [ -z "${EVM_B1_PROFILE:-}" ] || layoutArgs=(--b1-profile "$EVM_B1_PROFILE")   # a fresh-B1 deployment: the profile selects registry layout 3
  build/ubft shard-node restore --home "$evidence" --executor engine-api \
    --address "/ip4/127.0.0.1/tcp/$((evmValidatorPortStart + i - 1))" --bootnodes "$bootnodes" \
    --trust-base "$H3_RESTORE_TRUST_BASE" --full-shard-conf "$EVM_FULL_SHARD_CONF" "${layoutArgs[@]}" \
    --genesis "$EVM_GENESIS_FILE" --engine-url "http://127.0.0.1:$((rethEngineBase+i-1))" \
    --eth-url "http://127.0.0.1:$((rethEthBase+i-1))" --jwt-secret "$evidence/jwt.hex" \
    --engine-fee-collector "$EVM_ENGINE_FEE_COLLECTOR" --execution-journal "$journal" \
    --archive-store "$H3_ARCHIVES/evm$i" --archive-prune --trust-history-profile-2 --journal-candidates "${EVM_JOURNAL_CANDIDATES:-32}" \
    --signing-authority-socket "test-nodes/auth$i/client.sock" --signing-authority-credential "test-nodes/auth$i/client.cred" \
    "${peers[@]}" --tip-uc "$evidence/tip.uc.cbor" --tip-tr "$evidence/tip.tr.cbor" --trust-body-id "$bodyID" \
    $([ "${Q3_B1:-0}" != 1 ] || echo --q3-lane --rpc-server-address "$(evm_validator_rpc_addr "$i")") \
    --log-format text --log-level info >>"$evidence/debug.log" 2>&1 &
  echo $! >"$evidence/pid"
}

# Send one transaction to every online validator and wait for a certified receipt at the given root epoch.
h3_send_certified() { # epoch args...
  local epoch=$1 id sent expected= first i receipt status block; shift
  for id in $H3_ONLINE; do
    sent=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase+id-1))" -chain-id "${M2_CHAIN_ID:-31337}" -nonce "$M2_NEXT_NONCE" "$@" 2>&1) || { echo "$sent" >&2; return 1; }
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
  for _ in $(seq 1 60); do [ -d "$H3_ARCHIVES/evm$first" ] && break; sleep 1; done
  "$tmp/extract" extract --archive "$H3_ARCHIVES/evm$first" --block-hash "$block" --tx-index "$txIndex" --log-index "$logIndex" \
    --emitter "$contract" --topic "$topic" --config-pdr "$tmp/config-pdr.json" --out "$tmp/locked.cbor" || return 1
  # offline: no network, only the bundle, the genesis pin and the trust base for the certificate's root epoch
  local offline='(version 1) (allow default) (deny network*)'
  env -i PATH="$PATH" sandbox-exec -p "$offline" "$tmp/verify" --bundle "$tmp/locked.cbor" --trust-base "test-nodes/trust-base-epoch$trustEpoch.json" \
    --genesis-conf "$fullShardConf" --lock-contract "$contract" --mode locked >"$tmp/verify-locked.json" || return 1
  cat "$tmp/verify-locked.json"
}

# ---- progress across the root, the EVM shard and the three aggregator shards (shared by the H3 and Q3 lanes; needs f8_trace) ----
# Both the EVM shard and the three aggregator shards must advance: certified IR round for each, root round, aggregator height.
# Polls until every shard has advanced (an aggregator shard's authorized TR round moves with its T2 timeout, up to 7.5 s, so a fixed
# short window is not a fair measure): up to ${2:-10}+25 s, then it reports which shard did not.
# Per-shard progress of the root's authorized TR round between the two traces: the shards that advanced.
h3_progress_shards() {
  python3 - "$H3_DIR/progress-before.jsonl" "$H3_DIR/progress-after.jsonl" <<'PY'
import json,sys
b={}; a={}
for path,d in ((sys.argv[1],b),(sys.argv[2],a)):
    for line in open(path):
        if line.strip():
            r=json.loads(line); d[r['shard']]=r
print(" ".join(s for s in ('a-left','a-right','b-left') if int(a[s]['authorizedTRRound'])>int(b[s]['authorizedTRRound'])))
PY
}

# h3_progress <label> [seconds before the first look] [window seconds]. The window defaults to the pause plus 25 s; the steps right after a
# ROOT restart pass a longer one (about 3 minutes): an aggregator shard whose subscription the restart dropped is covered again only after
# its own inactivity re-handshake, which takes tens of seconds to minutes. H3_POST_RESTART_WINDOW (seconds) widens those steps (unset: the
# default window, which is what the lane asserts once the root recovers promptly). That lag is MEASURED, not hidden: the time to the first TR progress
# of each shard is written to the lane output.
h3_progress() {
  local label=$1 waited=0 pause=${2:-10} limit start now shard seen
  limit=${3:-$(( pause + 25 ))}
  local first_a=- first_r=- first_b=-
  f8_trace >"$H3_DIR/progress-before.jsonl" || return 1
  start=$(date +%s)
  sleep "$pause"
  while :; do
    f8_trace >"$H3_DIR/progress-after.jsonl" || return 1
    now=$(( $(date +%s) - start ))
    seen=$(h3_progress_shards 2>/dev/null)
    case " $seen " in *" a-left "*) [ "$first_a" = - ] && first_a=$now;; esac
    case " $seen " in *" a-right "*) [ "$first_r" = - ] && first_r=$now;; esac
    case " $seen " in *" b-left "*) [ "$first_b" = - ] && first_b=$now;; esac
    if h3_progress_check "$label"; then
      echo "progress lag [$label]: time to first TR progress a-left=${first_a}s a-right=${first_r}s b-left=${first_b}s (window ${limit}s)"
      return 0
    fi
    waited=$((waited + 3))
    if [ "$waited" -ge "$limit" ]; then
      echo "progress lag [$label]: time to first TR progress a-left=${first_a}s a-right=${first_r}s b-left=${first_b}s (window ${limit}s; '-' = none)" >&2
      return 1
    fi
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
