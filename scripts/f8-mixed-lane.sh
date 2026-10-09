#!/usr/bin/env bash
# Mixed F8 fixture hooks; sourced only by the paired devnet with F8_MIXED_LANE=1.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/f8-rugregator-pin.sh"
F8_PIN=$F8_RUGREGATOR_PIN
F8_BIN=${RUGREGATOR_BIN:-}
F8_SRC=${RUGREGATOR_SOURCE:-}
F8_ROOT_RPC_BASE=${F8_ROOT_RPC_BASE:-25866}
F8_LOG_DIR=${F8_LOG_DIR:-test-nodes/f8-mixed}
# A is deliberately split into two non-default ranges; B is a single full-range
# (unsharded) partition, whose canonical end-marker encoding is 0x80.
F8_IDS=(0x40 0xc0 0x80)
F8_PARTITIONS=(9 9 10)
F8_NAMES=(a-left a-right b-left)
F8_HTTP_PORTS=(28601 28602 28603)
F8_PIDS=()
# Rugregator's canonical absent-deadline SDK request fixture. Its witness is
# valid, and every fresh shard DB can independently certify the same StateID.
F8_LOAD_REQUEST=d9987684015820ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81ad998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820c034e096d7bdf71ba759558663b5cafb7279ecb7e284443e5e6cbce0461aceeef6584154ca6b19a7dbcae7a6adc38af5c8672f81943ecaf51345436684299b4b7ac81a57db2653f32048981e37913db4749ca08d998d1fac4a52ab5579988bc2c50de90000

f8_require_pin() {
  [ -x "$F8_BIN" ] || { echo "F8 requires executable RUGREGATOR_BIN" >&2; return 1; }
  [ -n "$F8_SRC" ] || { echo "F8 requires RUGREGATOR_SOURCE" >&2; return 1; }
  local rev
  rev=$(git -C "$F8_SRC" rev-parse HEAD)
  [ "$rev" = "$F8_PIN" ] || { echo "rugregator pin mismatch: $rev != $F8_PIN" >&2; return 1; }
  # The aggregator partitions run proof_type=aggregator_rsmt_v1, so the aggregator must attach the envelope: the pinned binary reads
  # AGGREGATOR_CONSISTENCY_PROOF_MODE (default off, a null proof). A binary that does not know that setting would send no proof and the root would
  # reject every state-changing block after the first (the first is verified against no previous state root and skipped).
  "$F8_BIN" --help 2>&1 | grep -q 'AGGREGATOR_CONSISTENCY_PROOF_MODE' || { echo "RUGREGATOR_BIN does not read AGGREGATOR_CONSISTENCY_PROOF_MODE" >&2; return 1; }
  echo "rugregator commit=$rev binary_sha256=$(shasum -a 256 "$F8_BIN" | awk '{print $1}')"
}

f8_prepare() {
  f8_require_pin
  mkdir -p "$F8_LOG_DIR"
  rm -f "$F8_LOG_DIR/trace.jsonl"
  local i name part shard home confHome
  for i in 0 1 2; do
    name=${F8_NAMES[$i]}; part=${F8_PARTITIONS[$i]}; shard=${F8_IDS[$i]}
    home="test-nodes/f8-$name"; confHome="test-nodes/f8-conf-$name"
    mkdir -p "$home" "$confHome"
    rm -rf "$home/db"
    rm -f "$F8_LOG_DIR/$name.log"
    build/ubft shard-node init --home "$home" -g >/dev/null
    build/ubft shard-conf generate --home "$confHome" --network-id 3 \
      --partition-id "$part" --partition-type-id "$part" --shard-id "$shard" \
      --epoch 0 --epoch-start 1 --t2-timeout "$((2500 + i*2500))" \
      --partition-params proof_type=aggregator_rsmt_v1 --node-info "$home/node-info.json"
    cp "$confHome/shard-conf-${part}_0.json" "$F8_LOG_DIR/shard-conf-${name}.json"
    cp "$F8_LOG_DIR/shard-conf-${name}.json" "test-nodes/shard-conf-f8-${name}.json"
    jq -e '.partitionParams.proof_type == "aggregator_rsmt_v1"' \
      "$F8_LOG_DIR/shard-conf-${name}.json" >/dev/null
    echo "prepared partition=$part shard=$shard name=$name t2_ms=$((2500 + i*2500)) config_sha256=$(shasum -a 256 "$F8_LOG_DIR/shard-conf-${name}.json" | awk '{print $1}')"
  done
  echo "topology: EVM 8/0x80; aggregator A=9/{0x40,0xc0}; B=10/0x80 (single full-range shard)"
}

f8_start_one() {
	local i=$1 name part port home nodeID boot auth sig
	name=${F8_NAMES[$i]}; part=${F8_PARTITIONS[$i]}; port=${F8_HTTP_PORTS[$i]}
	home="test-nodes/f8-$name"
  nodeID=$(build/ubft node-id --home "$home" | tail -n 1)
  boot=$(boot_node test-nodes/root1 "$rootPortStart")
  auth=$(jq -r '.authKey.privateKey | sub("^0x"; "")' "$home/keys.json")
  sig=$(jq -r '.sigKey.privateKey | sub("^0x"; "")' "$home/keys.json")
  mkdir -p "$home/db"
  env AGGREGATOR_LISTEN="127.0.0.1:$port" AGGREGATOR_BFT_MODE=live \
    AGGREGATOR_PARTITION_ID="$part" AGGREGATOR_SHARD_ID="${F8_IDS[$i]}" \
    AGGREGATOR_BFT_PEER_ID="${boot##*/p2p/}" AGGREGATOR_BFT_ADDR="${boot%/p2p/*}" \
    AGGREGATOR_P2P_ADDR=/ip4/127.0.0.1/tcp/0 AGGREGATOR_AUTH_KEY="$auth" \
    AGGREGATOR_SIG_KEY="$sig" AGGREGATOR_DB_PATH="$home/db" \
    AGGREGATOR_SMT_BACKEND=disk AGGREGATOR_ROUND_DURATION_MS=1000 \
    AGGREGATOR_FAKE_STATE_TRANSITIONS=false AGGREGATOR_UC_TIMEOUT_MS=30000 \
    AGGREGATOR_BATCH_LIMIT=100000 AGGREGATOR_CONSISTENCY_PROOF_MODE=rsmt RUST_LOG=debug \
    "$F8_BIN" >>"$F8_LOG_DIR/${name}.log" 2>&1 &
  F8_PIDS[$i]=$!
  echo "${F8_PIDS[$i]}" >"$home/pid"
  echo "started $name node=$nodeID partition=$part shard=${F8_IDS[$i]} http=$port"
}

f8_start() {
  : >"$F8_LOG_DIR/trace.jsonl"
  for name in "${F8_NAMES[@]}"; do : >"$F8_LOG_DIR/${name}.log"; done
  for i in 0 1 2; do f8_start_one "$i"; done
  for i in 0 1 2; do
    local port=${F8_HTTP_PORTS[$i]} ready=false
    for _ in $(seq 1 60); do
      if curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1; then ready=true; break; fi
      kill -0 "${F8_PIDS[$i]}" 2>/dev/null || break
      sleep 1
    done
    $ready || { echo "aggregator ${F8_NAMES[$i]} failed health startup" >&2; return 1; }
  done
}

f8_trace() {
  local rpc="http://127.0.0.1:$F8_ROOT_RPC_BASE/api/v1/roundInfo" evmURL="http://127.0.0.1:$rethEthBase"
  local info evm i name part shard aggPort
  info=$(curl -fsS "$rpc") || return 1
  evm=$(rpc "$evmURL" eth_blockNumber '[]' | pyget "['result']")
  for i in 0 1 2; do
    name=${F8_NAMES[$i]}; part=${F8_PARTITIONS[$i]}; shard=${F8_IDS[$i]}; aggPort=${F8_HTTP_PORTS[$i]}
    F8_INFO="$info" F8_EVM="$evm" F8_PART="$part" F8_SHARD="$shard" \
      F8_AGG_PORT="$aggPort" F8_NAME="$name" python3 - <<'PY'
import json, os
state=json.loads(os.environ['F8_INFO'])
part=int(os.environ['F8_PART']); shard=os.environ['F8_SHARD']
row=next((x for x in state['partitionShards'] if x['partitionId']==part and x['shardId'].lower()==shard.lower()), None)
health=json.loads(__import__('urllib.request').request.urlopen('http://127.0.0.1:'+os.environ['F8_AGG_PORT']+'/health', timeout=2).read())
if row is None: raise SystemExit(f"missing certified shard {part}/{shard}")
print(json.dumps({'shard':os.environ['F8_NAME'],'partition':part,'shardId':shard,
 'rootRound':state['roundNumber'],'certifiedIRRound':row['roundNumber'],
 'stateRoot':row['stateRoot'],
 'authorizedTRRound':row['trRound'],'authorizedTRLeader':row['trLeader'],
 'evmBlockHeight':int(os.environ['F8_EVM'],16),'aggregatorBlockHeight':int(health['blockNumber'])},sort_keys=True))
PY
  done | tee -a "$F8_LOG_DIR/trace.jsonl"
  F8_INFO="$info" F8_EVM="$evm" python3 - <<'PY' | tee -a "$F8_LOG_DIR/trace.jsonl"
import json,os
state=json.loads(os.environ['F8_INFO'])
row=next((x for x in state['partitionShards'] if x['partitionId']==8 and x['shardId'].lower()=='0x80'),None)
if row is None: raise SystemExit('missing EVM shard in certified root state')
print(json.dumps({'shard':'evm','partition':8,'shardId':'0x80','rootRound':state['roundNumber'],
 'certifiedIRRound':row['roundNumber'],'authorizedTRRound':row['trRound'],
 'authorizedTRLeader':row['trLeader'],'evmBlockHeight':int(os.environ['F8_EVM'],16)},sort_keys=True))
PY
}

f8_inflight_evm_probe() {
  local evmURL="http://127.0.0.1:$rethEthBase" nonce tx sent i before after receipt blockHash certRound
  local from
  from=$(go run ./scripts/evmtx -address) || return 1
  nonce=$(rpc "$evmURL" eth_getTransactionCount "[\"$from\",\"pending\"]" | pyget "['result']")
  [ -n "$nonce" ] && [ "$nonce" != None ] || { echo "could not query funded EVM account nonce" >&2; return 1; }
  nonce=$((nonce))
  before=$(curl -fsS "http://127.0.0.1:$F8_ROOT_RPC_BASE/api/v1/roundInfo" | jq -r '.roundNumber')
  tx=""
  for i in $(seq 1 "$validators"); do
    sent=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase+i-1))" -chain-id 31337 -nonce "$nonce") || return 1
    [ -z "$tx" ] || [ "$tx" = "$sent" ] || { echo "EVM validators submitted different transaction hashes" >&2; return 1; }
    tx=$sent
  done
  for _ in $(seq 1 180); do
    receipt=$(rpc "$evmURL" eth_getTransactionReceipt "[\"$tx\"]")
    after=$(curl -fsS "http://127.0.0.1:$F8_ROOT_RPC_BASE/api/v1/roundInfo" | jq -r '.roundNumber')
    blockHash=$(echo "$receipt" | pyget "['result']['blockHash']")
    certRound=$(python3 - "test-nodes/evm1/debug.log" "${blockHash#0x}" <<'PY'
import re,sys
pattern=sys.argv[2].lower()
for line in open(sys.argv[1],errors='replace'):
    if 'msg="certificate admitted"' not in line: continue
    block=re.search(r'\bblock=([0-9a-fA-F]{64})\b',line)
    root=re.search(r'\brootRound=(\d+)',line)
    if block and root and block.group(1).lower()==pattern:
        print(root.group(1)); break
PY
)
    f8_trace >/dev/null
    if [ "$(echo "$receipt" | pyget "['result']['status']")" = 0x1 ] && [ -n "$certRound" ] && [ "$((certRound-before))" -ge 3 ]; then
      echo "in-flight EVM tx=$tx certified at root round $certRound after root rounds advanced from $before; EVM TR leader=$(curl -fsS "http://127.0.0.1:$F8_ROOT_RPC_BASE/api/v1/roundInfo" | jq -r '.partitionShards[] | select(.partitionId==8) | .trLeader')"
      return 0
    fi
    sleep 1
  done
  echo "EVM proposal did not certify while root rounds advanced" >&2
  return 1
}

f8_slow_stop_resume_evm() {
  local i pid port response progress=false allSubmitted
  local -a submitted=(false false false)
  f8_trace >/dev/null
  python3 - "$F8_LOG_DIR/trace.jsonl" "$F8_LOG_DIR/evm-stop-before.json" <<'PY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
latest={r['shard']:r for r in rows if r['shard'] in ('a-left','a-right','b-left')}
if len(latest)!=3: raise SystemExit('missing baseline trace for all aggregator shards')
json.dump(latest,open(sys.argv[2],'w'),sort_keys=True)
PY
  # Pause every EVM validator, then place a real SDK certification request on
  # each aggregator so each partition must commit a new RSMT state root.
  for i in $(seq 1 "$validators"); do pid=$(cat "test-nodes/evm$i/pid"); kill -STOP "$pid"; done
  for i in $(seq 1 "$validators"); do
    pid=$(cat "test-nodes/evm$i/pid")
    [[ "$(ps -o stat= -p "$pid" | tr -d ' ')" == *T* ]] || { echo "EVM validator $i did not stop" >&2; return 1; }
  done
  sleep 4
  f8_trace >/dev/null
  # These aggregators can start before the first root UC pins their reference
  # time. Retry SERVICE_NOT_READY on every shard until all three accept real
  # requests; any other response is a lane failure.
  for _ in $(seq 1 90); do
    allSubmitted=true
    for i in 0 1 2; do
      [ "${submitted[$i]}" = true ] && continue
      port=${F8_HTTP_PORTS[$i]}
      response=$(curl -fsS -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"certification_request\",\"params\":\"$F8_LOAD_REQUEST\"}" \
        "http://127.0.0.1:$port/") || return 1
      if echo "$response" | jq -e '.result.status == "SUCCESS"' >/dev/null; then
        submitted[$i]=true
        echo "submitted real certification request to ${F8_NAMES[$i]} while EVM was stopped"
      elif echo "$response" | jq -e '.error.message == "SERVICE_NOT_READY"' >/dev/null; then
        allSubmitted=false
      else
        echo "${F8_NAMES[$i]} rejected the mixed-lane certification request: $response" >&2
        return 1
      fi
    done
    [ "$allSubmitted" = true ] && break
    sleep 1
  done
  for i in 0 1 2; do
    [ "${submitted[$i]}" = true ] || { echo "${F8_NAMES[$i]} did not become ready to accept a certification request" >&2; return 1; }
  done
  for _ in $(seq 1 90); do
    f8_trace >/dev/null
    if python3 - "$F8_LOG_DIR/trace.jsonl" "$F8_LOG_DIR/evm-stop-before.json" "$F8_LOG_DIR/evm-stop-after.json" <<'PY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
before=json.load(open(sys.argv[2]))
latest={r['shard']:r for r in rows if r['shard'] in before}
if len(latest)==3 and all(
    int(latest[name]['certifiedIRRound']) > int(before[name]['certifiedIRRound'])
    and int(latest[name]['aggregatorBlockHeight']) > int(before[name]['aggregatorBlockHeight'])
    and latest[name]['stateRoot'] != before[name]['stateRoot']
    for name in before):
    json.dump(latest,open(sys.argv[3],'w'),sort_keys=True)
    raise SystemExit(0)
raise SystemExit(1)
PY
    then progress=true; break; fi
    sleep 1
  done
  $progress || { echo "aggregator certified roots did not advance during the EVM stop" >&2; return 1; }
  cat "$F8_LOG_DIR/evm-stop-after.json"
  for i in $(seq 1 "$validators"); do pid=$(cat "test-nodes/evm$i/pid"); kill -CONT "$pid"; done
  sleep 8
  f8_trace
  python3 - "$F8_LOG_DIR/trace.jsonl" <<'PY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
for shard in ('a-left','a-right','b-left'):
    samples=[r for r in rows if r['shard']==shard]
    if len(samples)<3: raise SystemExit(f'{shard}: missing slow/stop/resume trace samples')
    if int(samples[-1]['authorizedTRRound']) <= int(samples[0]['authorizedTRRound']):
        raise SystemExit(f'{shard}: authorized TR did not advance while EVM was paused')
    if int(samples[-1]['rootRound']) <= int(samples[0]['rootRound']):
        raise SystemExit(f'{shard}: root round did not advance')
before=json.load(open(sys.argv[1].replace('trace.jsonl','evm-stop-before.json')))
after=json.load(open(sys.argv[1].replace('trace.jsonl','evm-stop-after.json')))
for shard in before:
    if int(after[shard]['certifiedIRRound']) <= int(before[shard]['certifiedIRRound']):
        raise SystemExit(f'{shard}: certified IR round did not advance during EVM stop')
    if int(after[shard]['aggregatorBlockHeight']) <= int(before[shard]['aggregatorBlockHeight']):
        raise SystemExit(f'{shard}: aggregator block height did not advance during EVM stop')
    if after[shard]['stateRoot'] == before[shard]['stateRoot']:
        raise SystemExit(f'{shard}: certified state root did not advance during EVM stop')
print('all three aggregator shards certified new state roots and rounds while EVM was stopped; TR and root rounds advanced across pause/resume')
PY
}

f8_reconnect_probe() {
  # A-right uses the non-default 0xc0 shard ID, so this exercises the configurable
  # shard identity on both initial connect and reconnect.
  local i=1 startLine
  startLine=$(wc -l <"$F8_LOG_DIR/${F8_NAMES[$i]}.log")
  kill "${F8_PIDS[$i]}"
  wait "${F8_PIDS[$i]}" 2>/dev/null || true
  f8_start_one "$i"
  for _ in $(seq 1 60); do
    if tail -n +"$((startLine+1))" "$F8_LOG_DIR/${F8_NAMES[$i]}.log" | grep -q 'Dialer: Received confirmation for protocol: /ab/handshake/0.0.1'; then break; fi
    sleep 1
  done
  tail -n +"$((startLine+1))" "$F8_LOG_DIR/${F8_NAMES[$i]}.log" | grep -q 'Dialer: Received confirmation for protocol: /ab/handshake/0.0.1' || { echo "non-default shard reconnect did not negotiate its BFT handshake protocol" >&2; return 1; }
  f8_trace
}

f8_stop() {
  local i evmPid
  # The EVM probe may have failed while validators were SIGSTOP'd. Resume them
  # before the parent lane's ownership-scoped teardown signals its node PIDs.
  for i in $(seq 1 "$validators"); do
    evmPid=$(cat "test-nodes/evm$i/pid" 2>/dev/null || true)
    [ -n "$evmPid" ] && kill -CONT "$evmPid" 2>/dev/null || true
  done
  for i in 0 1 2; do
    [ -n "${F8_PIDS[$i]:-}" ] && kill "${F8_PIDS[$i]}" 2>/dev/null || true
  done
  for i in 0 1 2; do
    [ -n "${F8_PIDS[$i]:-}" ] && wait "${F8_PIDS[$i]}" 2>/dev/null || true
  done
}
