#!/usr/bin/env bash
# Sourced by reth-paired-devnet.sh after the first paid certified block.
# Uses the same four real shard validators and their running ureth instances.

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
  if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
    for conf in test-nodes/shard-conf-f8-a-left.json test-nodes/shard-conf-f8-a-right.json test-nodes/shard-conf-f8-b-left.json; do
      shardConfArgs+=(--shard-conf "$conf")
    done
  fi
  port=$(m2_rpc_port "$node")
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
  local epoch=$1 nonce=${M2_NEXT_NONCE:-$2} expected='' sent='' i receipt block hash status log j rpcPort
  for i in $(m2_online_validators); do
    sent=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase+i-1))" \
      -chain-id "${M2_CHAIN_ID:-31337}" -nonce "$nonce" 2>&1) || return 1
    [[ "$sent" = 0x* ]] || return 1
    [ -z "$expected" ] || [ "$expected" = "$sent" ] || return 1
    expected=$sent
  done
  for j in $(seq 1 180); do
    rpcPort=$((rethEthBase + $(m2_online_validators | awk '{print $1}') - 1))
    receipt=$(rpc "http://127.0.0.1:$rpcPort" eth_getTransactionReceipt "[\"$expected\"]")
    status=$(echo "$receipt" | pyget "['result']['status']")
    hash=$(echo "$receipt" | pyget "['result']['blockHash']")
    if [ "$status" = 0x1 ] && [ -n "$hash" ] && [ "$hash" != None ]; then
      block=${hash#0x}
      local logValidator
      logValidator=$(m2_online_validators | awk '{print $1}')
      log="test-nodes/evm$logValidator/debug.log"
      if grep -Eq "msg=\"certificate admitted\" block=$block .*rootEpoch=$epoch([[:space:]]|$)" "$log"; then
        local registry=0xff00000000000000000000000000000000000002 assignment cursor
        assignment=$(rpc "http://127.0.0.1:$rpcPort" eth_getStorageAt "[\"$registry\",\"$m2_epoch_slot\",\"latest\"]" | pyget "['result']")
        cursor=$(rpc "http://127.0.0.1:$rpcPort" eth_getStorageAt "[\"$registry\",\"$m2_cursor_slot\",\"latest\"]" | pyget "['result']")
        if [ "$(python3 -c "print(int('$assignment',16))" 2>/dev/null)" = "$epoch" ] &&
           [ "$(python3 -c "print(int('$cursor',16))" 2>/dev/null)" = "$((epoch-1))" ]; then
          echo "paid epoch $epoch nonce $nonce hash=$expected registryRootEpoch=$epoch transitionCursor=$((epoch-1))"
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

# Use the latest common canonical EVM head only after each validator has logged
# its positive-height certificate admission. A log line from one root node is
# not a freshness or quorum check, and its subscription may have zero receivers.
m2_latest_certified_parent() {
  local i url head block hash blockNumber expectedHead= expectedHash= hashLower
  for i in $(seq 1 "$validators"); do
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

# The operator moves each surviving key to the activated root trust before its
# shard client resumes. Validator 1's authority also survives the disk wipe;
# its client remains stopped until the restore probe after Handoff 2.
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

m2_advance_authorities() {
  local epoch=$1 trustFile=$2 i offline rootBoot onlineValidators bootnodes startLine
  [ "${SIGNING:-local}" = authority ] || return 0
  rootBoot=$(m2_root_addr 1) || return 1
  onlineValidators=$(m2_online_validators)
  for i in 1 2 3 4; do
    offline=false
    if [ "$i" = 1 ] && [ "${M2A_VALIDATOR1_WIPED:-0}" = 1 ] && [ "${M2A_VALIDATOR1_RESTORED:-0}" != 1 ]; then
      offline=true
    else
      stop_one_evm_validator "$i" || return 1
    fi
    build/ubft signing-authority advance-epoch \
      --operator-socket "test-nodes/auth$i/operator.sock" \
      --operator-credential "test-nodes/auth$i/operator.cred" \
      --trust-base "test-nodes/$trustFile" --shard-conf "$fullShardConf" || return 1
    build/ubft signing-authority replace-session \
      --operator-socket "test-nodes/auth$i/operator.sock" \
      --operator-credential "test-nodes/auth$i/operator.cred" \
      --out "test-nodes/auth$i/client.cred" || return 1
    if ! $offline; then
      bootnodes=$(evm_bootnodes_for_peers "$rootBoot" "$i" $onlineValidators) || return 1
      startLine=$(wc -l < "test-nodes/evm$i/debug.log")
      start_one_evm_validator "$i" "$validators" "$partitionID" "$rootBoot" engine-api rpc "$bootnodes" || return 1
      # Keep one previously available replica alive while the restarted node
      # catches up. Do not advance/restart the next validator until a peer has
      # durably acknowledged the current certified archive head on this node.
      m2_wait_archive_replica_catchup "$i" "$startLine" || return 1
    fi
    echo "authority $i advanced to root epoch $epoch"
  done
}

m2_handoff() {
  local epoch=$1 replace=$2 new=$3 previous=$4 oldBoot=$5 oldRpcs=$6
  local nextFile="trust-base-epoch${epoch}.json"
  build/ubft root-node init --home "test-nodes/root$new" -g >/dev/null || return 1
  generate_log_configuration "test-nodes/root$new/"
  m2_next_trust_base "$epoch" "$replace" "$new" "$previous" "$nextFile" || return 1
  if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
    local parent logStart outcome waitStep activated committed=false oldEpoch=$((epoch-1))
    for attempt in $(seq 1 30); do
      parent=$(m2_latest_certified_parent) || {
        echo "F8 handoff attempt $attempt: waiting for a common certified EVM parent"
        sleep 1
        continue
      }
      logStart=$(wc -l < test-nodes/root1/debug.log)
      if ! build/ubft root handoff propose --next-trust-base "test-nodes/$nextFile" \
        --frozen-parent "$parent" --root-rpc "$oldRpcs"; then
        sleep 1
        continue
      fi
      for waitStep in $(seq 1 90); do
        outcome=$(tail -n +"$((logStart+1))" test-nodes/root1/debug.log |
          grep -E "msg=\\\"root handoff outcome\\\" .*rootEpoch=$oldEpoch([[:space:]]|$)" | tail -1 || true)
        [[ "$outcome" = *phase=committed* ]] && { committed=true; break; }
        [[ "$outcome" = *phase=aborted* ]] && break
        sleep 1
      done
      $committed && break
      [[ "$outcome" = *phase=aborted* ]] && echo "F8 handoff attempt $attempt aborted; retrying with the current certified parent"
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
  # Root validators enforce the ordered freeze. The operator only selects a
  # currently certified EVM tip and retries if an endorser has advanced.
  local parent waitStep oldEpoch=$((epoch-1)) outcome logStart
  local committed=false
  for i in $(seq 1 30); do
    parent=$(m2_latest_certified_parent) || {
      echo "handoff attempt $i: waiting for a common certified EVM parent"
      sleep 1
      continue
    }
    logStart=$(wc -l < test-nodes/root1/debug.log)
    if ! build/ubft root handoff propose --next-trust-base "test-nodes/$nextFile" \
      --frozen-parent "$parent" --root-rpc "$oldRpcs"; then
      sleep 1
      continue
    fi
    for waitStep in $(seq 1 60); do
      outcome=$(tail -n +"$((logStart+1))" test-nodes/root1/debug.log |
        grep -E "msg=\"root handoff outcome\" .*rootEpoch=$oldEpoch([[:space:]]|$)" | tail -1 || true)
      if [[ "$outcome" = *phase=committed* ]]; then committed=true; break; fi
      if [[ "$outcome" = *phase=aborted* ]]; then
        echo "root handoff aborted; selecting a fresh certified parent and attempt"
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
    m2_send_paid "$epoch" "$m2_next_nonce" || return 1
    m2_next_nonce=$((m2_next_nonce + 1))
  fi
  m2_measure_pause "$((epoch-1))" "$epoch"
}

cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
read -r m2_epoch_slot m2_cursor_slot < <(go run ./scripts/m2slots)
for initialHash in $(printf '%b' "$txHashes"); do
  initialReady=false
  for i in $(seq 1 90); do
    initialReceipt=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionReceipt "[\"$initialHash\"]")
    initialBlock=$(echo "$initialReceipt" | pyget "['result']['blockHash']")
    if [ "$(echo "$initialReceipt" | pyget "['result']['status']")" = 0x1 ] &&
       [ -n "$initialBlock" ] && [ "$initialBlock" != None ] &&
       grep -Eq "msg=\"certificate admitted\" block=${initialBlock#0x} .*rootEpoch=1([[:space:]]|$)" test-nodes/evm1/debug.log; then
      initialReady=true; break
    fi
    sleep 2
  done
  $initialReady || return 1
done
m2_next_nonce=3
m2a_head=$(rpc "http://127.0.0.1:$((rethEthBase+1))" eth_blockNumber '[]' | pyget "['result']")
while [ -n "$m2a_head" ] && [ "$((m2a_head))" -lt 5 ]; do
  m2_send_paid 1 "$m2_next_nonce" || return 1
  m2_next_nonce=$((m2_next_nonce + 1))
  m2a_head=$(rpc "http://127.0.0.1:$((rethEthBase+1))" eth_blockNumber '[]' | pyget "['result']")
done
if [ "${M2A_FINAL_RESTORE:-0}" = 1 ]; then
  bash scripts/h4-restore-probe.sh stop || return 1
  export M2A_VALIDATOR1_WIPED=1
fi
m2_handoff 2 4 5 '1 2 3 4' "$(m2_root_addr 4)" \
  'http://127.0.0.1:25866,http://127.0.0.1:25867,http://127.0.0.1:25868,http://127.0.0.1:25869' || return 1
if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
  echo "F8 mixed lane completed one root handoff while all aggregator shards remained active"
  return 0
fi
m2_handoff 3 3 6 '1 2 3 5' "$(m2_root_addr 3)" \
  'http://127.0.0.1:25866,http://127.0.0.1:25867,http://127.0.0.1:25868,http://127.0.0.1:25870' || return 1
if [ "${M2A_FINAL_RESTORE:-0}" = 1 ]; then
  bash scripts/h4-restore-probe.sh restore || return 1
  ln -sf ../h4-replaced/restore.log test-nodes/evm1/debug.log
  restoreLog=test-nodes/h4-replaced/restore.log
  restored=false
  for waitStep in $(seq 1 180); do
    if grep -Eq 'handoff activated.*rootEpoch=2' "$restoreLog" &&
       grep -Eq 'handoff activated.*rootEpoch=3' "$restoreLog" &&
       grep -q 'submitting block certification request' "$restoreLog" &&
       grep -Eq 'msg="certificate admitted" .*rootEpoch=3([[:space:]]|$)' "$restoreLog"; then
      restored=true; break
    fi
    if ! kill -0 "$(cat test-nodes/h4-replaced/pid)" 2>/dev/null; then
      echo 'restored validator exited before catch-up' >&2; tail -60 "$restoreLog" >&2; return 1
    fi
    sleep 1
  done
  $restored || { echo 'restore did not verify both handoff epochs and resume signing' >&2; tail -60 "$restoreLog" >&2; return 1; }
  build/ubft signing-authority status --operator-socket test-nodes/auth1/operator.sock \
    --operator-credential test-nodes/auth1/operator.cred >test-nodes/h4-replaced/authority-after.json || return 1
  before=$(python3 -c 'import json;print(json.load(open("test-nodes/h4-replaced/authority-before.json"))["reservedRound"])')
  after=$(python3 -c 'import json;print(json.load(open("test-nodes/h4-replaced/authority-after.json"))["reservedRound"])')
  [ "$after" -gt "$before" ] || { echo "restored signer did not advance authority high-water: $before -> $after" >&2; return 1; }
  export M2A_VALIDATOR1_RESTORED=1
  m2_send_paid 3 "$m2_next_nonce" || return 1
  echo "RESTORE PASS: epochs 2 and 3 activated; authority high-water $before -> $after"
fi
