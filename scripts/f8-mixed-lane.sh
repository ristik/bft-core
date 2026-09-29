#!/usr/bin/env bash
# Mixed F8 fixture hooks; sourced only by the paired devnet with F8_MIXED_LANE=1.
set -euo pipefail

F8_PIN=662e37a56e6da67fcb67aa4ebc32be5076bc301c
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

f8_require_pin() {
  [ -x "$F8_BIN" ] || { echo "F8 requires executable RUGREGATOR_BIN" >&2; return 1; }
  [ -n "$F8_SRC" ] || { echo "F8 requires RUGREGATOR_SOURCE" >&2; return 1; }
  local rev
  rev=$(git -C "$F8_SRC" rev-parse HEAD)
  [ "$rev" = "$F8_PIN" ] || { echo "rugregator pin mismatch: $rev != $F8_PIN" >&2; return 1; }
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
    AGGREGATOR_BATCH_LIMIT=100000 AGGREGATOR_CONSISTENCY_PROOFS=true RUST_LOG=debug \
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
  local i pid
  # Exercise both a delayed EVM participant and a fully stopped EVM partition while
  # the three aggregator processes continue to receive root certificates.
  for i in $(seq 1 "$validators"); do pid=$(cat "test-nodes/evm$i/pid"); kill -STOP "$pid"; done
  sleep 4
  f8_trace
  sleep 8
  f8_trace
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
print('all three shard TRs and root rounds advanced across EVM pause/resume')
PY
}

f8_reconnect_probe() {
  # A-right uses the non-default 0xc0 shard ID, so this exercises the configurable
  # shard identity on both initial connect and reconnect.
  local i=1 startLine
  startLine=$(wc -l <"$F8_LOG_DIR/b-left.log")
  kill "${F8_PIDS[$i]}"
  wait "${F8_PIDS[$i]}" 2>/dev/null || true
  f8_start_one "$i"
  for _ in $(seq 1 60); do
    if tail -n +"$((startLine+1))" "$F8_LOG_DIR/b-left.log" | grep -q 'Received handshake response'; then break; fi
    sleep 1
  done
  tail -n +"$((startLine+1))" "$F8_LOG_DIR/b-left.log" | grep -q 'Received handshake response' || { echo "non-default shard reconnect did not complete its BFT handshake" >&2; return 1; }
  f8_trace
}

f8_stop() {
  local i
  for i in 0 1 2; do
    [ -n "${F8_PIDS[$i]:-}" ] && kill "${F8_PIDS[$i]}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
