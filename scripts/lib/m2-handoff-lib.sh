#!/usr/bin/env bash
# Functions of the M2 profile-2 handoff lane, shared with the H3 assignment lane.
# Definitions only: sourcing starts nothing. Needs reth-paired-devnet.sh context (rpc, pyget, validators, ...).

m2_rpc_port() { echo $((25866 + $1 - 1)); }
m2_p2p_port() { echo $((rootPortStart + $1 - 1)); }
m2_root_addr() { boot_node "test-nodes/root$1" "$(m2_p2p_port "$1")"; }
m2_online_validators() {
  if [ "${M2A_VALIDATOR1_WIPED:-0}" = 1 ] && [ "${M2A_VALIDATOR1_RESTORED:-0}" != 1 ]; then
    echo "2 3 4"
  else
    echo "1 2 3 4"
  fi
}

m2_wait_root_epoch() {
  local node=$1 epoch=$2 i seen
  for i in $(seq 1 120); do
    seen=$(curl -fsS "http://127.0.0.1:$(m2_rpc_port "$node")/api/v1/roundInfo" 2>/dev/null |
      python3 -c 'import json,sys; print(json.load(sys.stdin).get("epochNumber",""))' 2>/dev/null) || seen=
    [ "$seen" = "$epoch" ] && return 0
    sleep 1
  done
  return 1
}

m2_start_root() {
  local node=$1 epoch=$2 boot=$3 port pid i conf
  local -a shardConfArgs=(--shard-conf "$fullShardConf")
  port=$(m2_rpc_port "$node")
  if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
    for conf in test-nodes/shard-conf-f8-a-left.json test-nodes/shard-conf-f8-a-right.json test-nodes/shard-conf-f8-b-left.json; do
      shardConfArgs+=(--shard-conf "$conf")
    done
  fi
  mkdir -p "test-nodes/root$node"
  for i in $(seq 1 90); do
    build/ubft root-node run --home "test-nodes/root$node" \
      --address "/ip4/127.0.0.1/tcp/$(m2_p2p_port "$node")" \
      --bootnodes "$boot" --trust-base test-nodes/trust-base.json \
      "${shardConfArgs[@]}" --profile-2 --install-handoff-epoch "$epoch" \
      --rpc-server-address "127.0.0.1:$port" --log-format text --log-level debug \
      >>"test-nodes/root$node/debug.log" 2>&1 &
    pid=$!
    echo "$pid" >"test-nodes/root$node/pid"
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
      local ready
      for ready in $(seq 1 30); do
        lsof -nP -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -qx "$pid" && return 0
        local state
        state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')
        [ -n "$state" ] && [[ "$state" != Z* ]] || break
        sleep 1
      done
      state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')
      if [ -n "$state" ] && [[ "$state" != Z* ]]; then return 1; fi
    fi
    wait "$pid" 2>/dev/null || true
    sleep 1
  done
  return 1
}

m2_next_trust_base() {
  local epoch=$1 replace=$2 new=$3 previous=$4 out=$5 i infos=()
  for i in $previous; do
    if [ "$i" != "$replace" ]; then infos+=(--node-info "test-nodes/root$i/node-info.json"); fi
  done
  infos+=(--node-info "test-nodes/root$new/node-info.json")
  build/ubft trust-base generate --home test-nodes --network-id 3 --epoch "$epoch" \
    --epoch-start "$((epoch * 100000))" --previous-trust-base "test-nodes/trust-base-epoch$((epoch-1)).json" \
    --output-file-name "$out" "${infos[@]}" >/dev/null
  for i in $previous; do
    if [ "$i" != "$replace" ]; then
      build/ubft trust-base sign --home "test-nodes/root$i" --trust-base "test-nodes/$out" >/dev/null
    fi
  done
  build/ubft trust-base sign --home "test-nodes/root$new" --trust-base "test-nodes/$out" >/dev/null
}

m2_archive_root_state() {
  local node=$1 epoch=$2 file
  local archive="test-nodes/root${node}/pre-epoch-${epoch}-state"
  mkdir -p "$archive"
  for file in rootchain.db trustbase.db root-trust-history.db orchestration.db; do
    if [ -e "test-nodes/root${node}/$file" ]; then
      mv "test-nodes/root${node}/$file" "$archive/$file" || return 1
    fi
  done
}

m2_send_paid() {
  local epoch=$1 nonce=${M2_NEXT_NONCE:-$2} expected='' sent='' i receipt block hash status log j rpcPort logValidator
  for i in $(m2_online_validators); do
    sent=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase+i-1))" \
      -chain-id "${M2_CHAIN_ID:-31337}" -nonce "$nonce" 2>&1) || { echo "m2_send_paid: evmtx failed on validator $i (nonce $nonce): $sent" >&2; return 1; }
    [[ "$sent" = 0x* ]] || { echo "m2_send_paid: validator $i returned no transaction hash (nonce $nonce): $sent" >&2; return 1; }
    [ -z "$expected" ] || [ "$expected" = "$sent" ] || { echo "m2_send_paid: validators disagree on the transaction hash: $expected vs $sent" >&2; return 1; }
    expected=$sent
  done
  for j in $(seq 1 180); do
    rpcPort=$((rethEthBase + $(m2_online_validators | awk '{print $1}') - 1))
    receipt=$(rpc "http://127.0.0.1:$rpcPort" eth_getTransactionReceipt "[\"$expected\"]")
    status=$(echo "$receipt" | pyget "['result']['status']")
    hash=$(echo "$receipt" | pyget "['result']['blockHash']")
    if [ "$status" = 0x1 ] && [ -n "$hash" ] && [ "$hash" != None ]; then
      block=${hash#0x}
      logValidator=$(m2_online_validators | awk '{print $1}')
      log="test-nodes/evm$logValidator/debug.log"
      if grep -Eq "msg=\"certificate admitted\" block=$block .*rootEpoch=$epoch([[:space:]]|$)" "$log"; then
        if [ "${M2_PAID_REGISTRY_CHECK:-1}" = 0 ]; then
          # a lane with its own registry layout (H3, layout 2) checks the registry itself
          echo "paid epoch $epoch nonce $nonce hash=$expected"
          if [ -n "${M2_NEXT_NONCE:-}" ]; then M2_NEXT_NONCE=$((nonce + 1)); fi
          return 0
        fi
        local registry=0xff00000000000000000000000000000000000002 assignment cursor
        assignment=$(rpc "http://127.0.0.1:$rpcPort" eth_getStorageAt "[\"$registry\",\"$m2_epoch_slot\",\"latest\"]" | pyget "['result']")
        cursor=$(rpc "http://127.0.0.1:$rpcPort" eth_getStorageAt "[\"$registry\",\"$m2_cursor_slot\",\"latest\"]" | pyget "['result']")
        local registryOk=false shardEpoch=
        if [ "$(registry_layout)" = 2 ]; then
          # Layout 2 separates the root epoch (m2_epoch_slot) from the shard assignment epoch, which a coupled
          # configuration-only advance leaves unchanged.
          shardEpoch=$(rpc "http://127.0.0.1:$rpcPort" eth_getStorageAt "[\"$registry\",\"$m2_shard_epoch_slot\",\"latest\"]" | pyget "['result']")
          if [ "$(python3 -c "print(int('$assignment',16))" 2>/dev/null)" = "$epoch" ] &&
             [ "$(python3 -c "print(int('$shardEpoch',16))" 2>/dev/null)" = "${M2_EXPECT_SHARD_EPOCH:-0}" ]; then registryOk=true; fi
        elif [ "$(python3 -c "print(int('$assignment',16))" 2>/dev/null)" = "$epoch" ] &&
             [ "$(python3 -c "print(int('$cursor',16))" 2>/dev/null)" = "$((epoch-1))" ]; then
          registryOk=true
        fi
        if $registryOk; then
          echo "paid epoch $epoch nonce $nonce hash=$expected registryRootEpoch=$epoch transitionCursor=$((epoch-1)) layout=$(registry_layout)"
          if [ -n "${M2_NEXT_NONCE:-}" ]; then M2_NEXT_NONCE=$((nonce + 1)); fi
          return 0
        fi
      fi
    fi
    sleep 2
  done
  return 1
}

m2_measure_pause() {
  local old=$1 new=$2
  local logValidator
  logValidator=$(m2_online_validators | awk '{print $1}')
  python3 - "test-nodes/evm$logValidator/debug.log" "$old" "$new" <<'PY' | tee -a test-nodes/m2-pauses.log
from datetime import datetime
from pathlib import Path
import re,sys
path,old,new=sys.argv[1],sys.argv[2],sys.argv[3]
last=None; first=None
for line in Path(path).read_text(errors='replace').splitlines():
    if 'msg="certificate admitted"' not in line: continue
    epoch=re.search(r'rootEpoch=(\d+)',line)
    stamp=re.search(r'time=(\S+)',line)
    if not epoch or not stamp: continue
    time=datetime.strptime(stamp.group(1),'%Y-%m-%dT%H:%M:%S.%f%z')
    if epoch.group(1)==old: last=time
    if epoch.group(1)==new and first is None: first=time
if last is None or first is None or first < last:
    print(f'handoff {old}->{new} certification pause=unmeasured: missing ordered epoch certificates in {path}')
    raise SystemExit(0)
print(f'handoff {old}->{new} certification pause={(first-last).total_seconds():.3f}s')
PY
}

# The authority survives each shard restart. Advance one key at a time and wait for
# a durable replica acknowledgement before moving to the next configured peer.
m2_wait_archive_replica_catchup() {
  local target=$1 startLine=$2 targetId latestHash source i targetLog peerAck nodeAck
  targetId=$(evm_validator_id "$target") || return 1
  targetLog="test-nodes/evm$target/debug.log"
  latestHash=$(python3 - $(m2_online_validators) <<'PY'
from pathlib import Path
import re,sys
best=(-1,'')
for node in sys.argv[1:]:
    path=Path(f'test-nodes/evm{node}/debug.log')
    if not path.exists(): continue
    for line in path.read_text(errors='replace').splitlines():
        if 'msg="certificate admitted"' not in line: continue
        block=re.search(r'\bblock=([0-9a-f]{64})\b',line)
        round_=re.search(r'\brootRound=(\d+)',line)
        if block and round_ and int(round_.group(1)) > best[0]:
            best=(int(round_.group(1)),block.group(1))
print(best[1])
PY
  )
  [ -n "$latestHash" ] || { echo "cannot find a certified archive head before restarting validator $target" >&2; return 1; }
  echo "waiting for archive replica $target ($targetId) to acknowledge certified head $latestHash"
  for i in $(seq 1 120); do
    peerAck=false
    nodeAck=false
    for source in $(m2_online_validators); do
      [ "$source" = "$target" ] && continue
      if grep -Fq "msg=\"archive replica ack catch-up\" replica=$targetId block=$latestHash" "test-nodes/evm$source/debug.log" 2>/dev/null; then
        peerAck=true
        break
      fi
    done
    if tail -n +"$((startLine+1))" "$targetLog" 2>/dev/null | grep -F 'msg="archive replica ack catch-up"' >/dev/null; then
      nodeAck=true
    fi
    if $peerAck && $nodeAck; then
      echo "archive replica $target caught up through $latestHash and resumed replication"
      return 0
    fi
    if [ $((i % 15)) -eq 0 ]; then
      echo "still waiting for archive replica $target after ${i}s (peer_ack=$peerAck node_ack=$nodeAck)"
    fi
    sleep 1
  done
  echo "archive replica $target did not resume with a current peer acknowledgment within 120s" >&2
  return 1
}

# Advance the authorities (default 1..4) to the successor scope: root trust `trustFile` and shard configuration `$3` (default the genesis
# full configuration: a root-only advance). `$4` lists the validators to advance. M2_ADVANCE_TOLERATE_STOPPED=1 lets a validator whose node
# is already stopped be advanced and restarted (the H3 lane holds validators down on purpose); M2_ADVANCE_NO_REPLICA_WAIT=1 skips the
# archive-replica catch-up wait after each restart (replicas that are down on purpose cannot acknowledge).
m2_advance_authorities() {
  local epoch=$1 trustFile=$2 conf=${3:-$fullShardConf} ids=${4:-1 2 3 4} i offline rootBoot onlineValidators bootnodes startLine
  [ "${SIGNING:-local}" = authority ] || return 0
  rootBoot=$(m2_root_addr 1) || return 1
  onlineValidators=$(m2_online_validators)
  for i in $ids; do
    offline=false
    if [ "$i" = 1 ] && [ "${M2A_VALIDATOR1_WIPED:-0}" = 1 ] && [ "${M2A_VALIDATOR1_RESTORED:-0}" != 1 ]; then
      offline=true
    else
      # Observers (the T6 finality monitor) treat a planned restart as an expected outage, not a failure.
      mkdir -p test-nodes/post-m2a-evidence/restarting && : >"test-nodes/post-m2a-evidence/restarting/$i"
      stop_one_evm_validator "$i" || [ "${M2_ADVANCE_TOLERATE_STOPPED:-0}" = 1 ] || return 1
    fi
    build/ubft signing-authority advance-epoch \
      --operator-socket "test-nodes/auth$i/operator.sock" \
      --operator-credential "test-nodes/auth$i/operator.cred" \
      --trust-base "test-nodes/$trustFile" --shard-conf "$conf" || return 1
    build/ubft signing-authority replace-session \
      --operator-socket "test-nodes/auth$i/operator.sock" \
      --operator-credential "test-nodes/auth$i/operator.cred" \
      --out "test-nodes/auth$i/client.cred" || return 1
    if ! $offline; then
      bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$i" $onlineValidators) || return 1
      startLine=$(wc -l < "test-nodes/evm$i/debug.log")
      start_one_evm_validator "$i" "$validators" "$partitionID" "$rootBoot" engine-api rpc "$bootnodes" || return 1
      [ "${M2_ADVANCE_NO_REPLICA_WAIT:-0}" = 1 ] || m2_wait_archive_replica_catchup "$i" "$startLine" || return 1
    fi
    rm -f "test-nodes/post-m2a-evidence/restarting/$i"
    echo "authority $i advanced to root epoch $epoch"
  done
}

# Use the latest common canonical EVM head only after each validator has logged
# its positive-height certificate admission. A log line from one root node is
# not a freshness or quorum check, and its subscription may have zero receivers.
m2_latest_certified_parent() {
  local i url head block hash blockNumber expectedHead= expectedHash= hashLower
  for i in $(m2_online_validators); do
    url="http://127.0.0.1:$((rethEthBase+i-1))"
    head=$(rpc "$url" eth_blockNumber '[]' | pyget "['result']") || return 1
    [[ "$head" = 0x* ]] || return 1
    block=$(rpc "$url" eth_getBlockByNumber "[\"$head\",false]") || return 1
    hash=$(printf '%s' "$block" | pyget "['result']['hash']") || return 1
    blockNumber=$(printf '%s' "$block" | pyget "['result']['number']") || return 1
    [ -n "$hash" ] && [ "$hash" != None ] && [ "$blockNumber" = "$head" ] || return 1
    hashLower=$(printf '%s' "$hash" | tr '[:upper:]' '[:lower:]')
    grep -Eq "msg=\"certificate admitted\" block=${hashLower#0x} .*height=[1-9][0-9]* round=[0-9]+ rootRound=[0-9]+" \
      "test-nodes/evm$i/debug.log" || return 1
    if [ -z "$expectedHead" ]; then
      expectedHead=$head
      expectedHash=$hashLower
    elif [ "$head" != "$expectedHead" ] || [ "$hashLower" != "$expectedHash" ]; then
      return 1
    fi
  done
  printf '%s\n' "$expectedHash"
}

m2_handoff() {
  local epoch=$1 replace=$2 new=$3 previous=$4 oldBoot=$5 oldRpcs=$6
  local nextFile="trust-base-epoch${epoch}.json"
  build/ubft root-node init --home "test-nodes/root$new" -g >/dev/null || return 1
  generate_log_configuration "test-nodes/root$new/"
  m2_next_trust_base "$epoch" "$replace" "$new" "$previous" "$nextFile" || return 1
  if [ "${F8_MIXED_LANE:-0}" = 1 ] && [ "${H3_ASSIGNMENT_LANE:-0}" != 1 ]; then
    local logStart outcome waitStep activated committed=false oldEpoch=$((epoch-1))
    for attempt in $(seq 1 30); do
      logStart=$(wc -l < test-nodes/root1/debug.log)
      if ! build/ubft root handoff propose --next-trust-base "test-nodes/$nextFile" --root-rpc "$oldRpcs"; then
        sleep 1
        continue
      fi
      for waitStep in $(seq 1 90); do
        outcome=$(tail -n +"$((logStart+1))" test-nodes/root1/debug.log |
          grep -E "msg=\\\"root handoff outcome\\\" .*rootEpoch=$oldEpoch([[:space:]]|$)" | tail -1 || true)
        [[ "$outcome" = *phase=committed* ]] && { committed=true; break; }
        [[ "$outcome" = *phase=aborted* || "$outcome" = *phase=lapsed* ]] && break
        sleep 1
      done
      $committed && break
      [[ "$outcome" = *phase=aborted* || "$outcome" = *phase=lapsed* ]] && echo "F8 handoff attempt $attempt aborted or lapsed; retrying with the next attempt"
    done
    $committed || { echo "F8 root handoff did not commit after retries" >&2; return 1; }
    for i in $(seq 1 "$validators"); do
      activated=false
      for waitStep in $(seq 1 90); do
        if grep -Eq "msg=\\\"handoff activated\\\" rootEpoch=$epoch([[:space:]]|$)" "test-nodes/evm$i/debug.log"; then
          activated=true; break
        fi
        sleep 1
      done
      $activated || { echo "EVM validator $i did not activate root epoch $epoch" >&2; return 1; }
    done
    echo "F8 root handoff epoch $epoch committed and activated while aggregators remained live"
    return 0
  fi
  # Root validators enforce the ordered freeze and bind the frozen parent at the Prepare: the operator names no parent and only
  # retries (next attempt) if a Prepare lapsed or an attempt was aborted.
  local waitStep oldEpoch=$((epoch-1)) outcome logStart
  local committed=false
  for i in $(seq 1 30); do
    logStart=$(wc -l < test-nodes/root1/debug.log)
    if ! build/ubft root handoff propose --next-trust-base "test-nodes/$nextFile" --root-rpc "$oldRpcs"; then
      sleep 1
      continue
    fi
    for waitStep in $(seq 1 60); do
      outcome=$(tail -n +"$((logStart+1))" test-nodes/root1/debug.log |
        grep -E "msg=\"root handoff outcome\" .*rootEpoch=$oldEpoch([[:space:]]|$)" | tail -1 || true)
      if [[ "$outcome" = *phase=committed* ]]; then committed=true; break; fi
      if [[ "$outcome" = *phase=aborted* || "$outcome" = *phase=lapsed* ]]; then
        echo "root handoff aborted or its Prepare lapsed; retrying with the next attempt"
        break
      fi
      sleep 1
    done
    $committed && break
    [ -n "$outcome" ] || return 1
  done
  $committed || return 1
  # The replacement first proves that the old committee really committed H.
  m2_start_root "$new" "$epoch" "$oldBoot" || return 1
  for i in $previous; do
    [ "$i" = "$replace" ] && continue
    stop_pidfile "test-nodes/root$i/pid" 'ubft root-node' || return 1
    for waitPort in $(seq 1 50); do
      lsof -nP -iTCP:"$(m2_rpc_port "$i")" -sTCP:LISTEN >/dev/null 2>&1 || break
      sleep 0.2
    done
    m2_archive_root_state "$i" "$epoch" || return 1
    m2_start_root "$i" "$epoch" "$oldBoot" || return 1
  done
  stop_pidfile "test-nodes/root$replace/pid" 'ubft root-node' || return 1
  m2_wait_root_epoch 1 "$epoch" || return 1
  for i in $(m2_online_validators); do
    local activated=false waitStep
    for waitStep in $(seq 1 90); do
      if grep -Eq "msg=\"handoff activated\" rootEpoch=$epoch([[:space:]]|$)" "test-nodes/evm$i/debug.log"; then
        activated=true; break
      fi
      sleep 1
    done
    $activated || return 1
  done
  m2_advance_authorities "$epoch" "$nextFile" || return 1
  if [ "$epoch" = 2 ]; then
    m2_send_paid "$epoch" "${M2_NEXT_NONCE:-$((epoch+1))}" || return 1
  fi
  m2_wait_certified_idle "$epoch" || return 1
  m2_measure_pause "$((epoch-1))" "$epoch"
}

# --- Coupled configuration-only epoch advance (#328) -----------------------------------------------------
# The same root committee with the same keys moves to the next root epoch; the EVM assignment (shard epoch) is
# unchanged. No successor key signs a proof of possession, so it works with SIGNING=authority: the signing
# authority still advances its epoch, validators restart under it, and restore/archive behaviour is exercised
# above the authority high-water mark. A key-replacing coupled rotation needs successor PoPs (SIGNING=local) and
# is covered by the H3 acceptance lane, not here.
m2_same_members_trust_base() {
  local epoch=$1 roots=$2 out=$3 i infos=()
  for i in $roots; do infos+=(--node-info "test-nodes/root$i/node-info.json"); done
  build/ubft trust-base generate --home test-nodes --network-id 3 --epoch "$epoch" \
    --epoch-start "$((epoch * 100000))" --previous-trust-base "test-nodes/trust-base-epoch$((epoch-1)).json" \
    --output-file-name "$out" "${infos[@]}" >/dev/null || return 1
  for i in $roots; do
    build/ubft trust-base sign --home "test-nodes/root$i" --trust-base "test-nodes/$out" >/dev/null || return 1
  done
}

m2_config_only_handoff() { # epoch roots oldRpcs
  local epoch=$1 roots=$2 oldRpcs=$3 oldEpoch=$(($1-1)) nextFile="trust-base-epoch$1.json"
  local i logStart outcome waitStep committed=false first boot prev activated
  first=$(echo "$roots" | awk '{print $1}')
  m2_same_members_trust_base "$epoch" "$roots" "$nextFile" || return 1
  for i in $(seq 1 30); do
    logStart=$(wc -l < "test-nodes/root$first/debug.log")
    if ! build/ubft root handoff propose --next-trust-base "test-nodes/$nextFile" --root-rpc "$oldRpcs"; then
      sleep 1; continue
    fi
    outcome=
    for waitStep in $(seq 1 90); do
      outcome=$(tail -n +"$((logStart+1))" "test-nodes/root$first/debug.log" |
        grep -E "msg=\"root handoff outcome\" .*rootEpoch=$oldEpoch([[:space:]]|$)" | tail -1 || true)
      [[ "$outcome" = *phase=committed* ]] && { committed=true; break; }
      # An aborted attempt, or one whose Prepare lapsed (#336: no Freeze in time), is dead: re-plan now instead of sitting out the wait.
      if [[ "$outcome" = *phase=aborted* || "$outcome" = *phase=lapsed* ]]; then
        echo "config-only handoff attempt ended ${outcome##*phase=}; retrying with the next attempt"
        break
      fi
      sleep 1
    done
    $committed && break
  done
  $committed || { echo "config-only handoff to epoch $epoch did not commit" >&2; return 1; }
  # Every root restarts on the install epoch; each fetches and verifies the committed bundle.
  for i in $roots; do
    prev=$(echo "$roots" | tr ' ' '\n' | grep -vx "$i" | head -1)
    boot=$(m2_root_addr "$prev")
    stop_pidfile "test-nodes/root$i/pid" 'ubft root-node' || return 1
    for waitStep in $(seq 1 50); do
      lsof -nP -iTCP:"$(m2_rpc_port "$i")" -sTCP:LISTEN >/dev/null 2>&1 || break
      sleep 0.2
    done
    m2_archive_root_state "$i" "$epoch" || return 1
    m2_start_root "$i" "$epoch" "$boot" || return 1
  done
  m2_wait_root_epoch "$first" "$epoch" || return 1
  for i in $(m2_online_validators); do
    activated=false
    for waitStep in $(seq 1 90); do
      if grep -Eq "msg=\"handoff activated\" rootEpoch=$epoch([[:space:]]|$)" "test-nodes/evm$i/debug.log"; then activated=true; break; fi
      sleep 1
    done
    $activated || { echo "EVM validator $i did not activate root epoch $epoch" >&2; return 1; }
  done
  m2_advance_authorities "$epoch" "$nextFile" || return 1
  m2_send_paid "$epoch" "${M2_NEXT_NONCE:-$((epoch+1))}" || return 1
  m2_measure_pause "$oldEpoch" "$epoch"
}

# M2_HANDOFF_MODE: config-only (default on registry layout 2) or rotate (key-replacing, layout 1 only: layout 2
# enforces coupled validator-set changes, which this root-only rotation is not).

# The #261 comparison needs both paid and idle certified blocks on each side of
# the handoff. Do not infer idleness from an empty mempool or a short interval:
# require a zero-transaction EL block that the active BFT node admitted in this
# root epoch.
m2_wait_certified_idle() {
  local epoch=$1 source port head block hash count log
  source=$(m2_online_validators | awk '{print $1}')
  port=$((rethEthBase + source - 1))
  log="test-nodes/evm$source/debug.log"
  for attempt in $(seq 1 90); do
    head=$(rpc "http://127.0.0.1:$port" eth_blockNumber '[]' | pyget "['result']") || head=
    if [ -n "$head" ] && [ "$head" != None ]; then
      block=$(rpc "http://127.0.0.1:$port" eth_getBlockByNumber "[\"$head\",true]") || block=
      hash=$(printf '%s' "$block" | pyget "['result']['hash']" || true)
      count=$(printf '%s' "$block" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["result"]["transactions"]))' 2>/dev/null) || count=-1
      if [ "$count" = 0 ] && [ -n "$hash" ] && [ "$hash" != None ] &&
        grep -Eq "msg=\"certificate admitted\" block=${hash#0x} .*rootEpoch=$epoch([[:space:]]|$)" "$log"; then
        echo "certified idle root-epoch=$epoch block=$hash height=$((head)) source-validator=$source"
        return 0
      fi
    fi
    if [ $((attempt % 15)) -eq 0 ]; then
      echo "waiting for a zero-transaction certificate in root epoch $epoch ($attempt/90)"
    fi
    sleep 1
  done
  echo "no certified zero-transaction block appeared in root epoch $epoch" >&2
  return 1
}
