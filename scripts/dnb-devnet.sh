#!/usr/bin/env bash
# DN-B (#73) paired devnet with B1 and B2 enabled in the single genesis profile.
#
#   briefs/devnet-lock.sh dnb scripts/dnb-devnet.sh up       # build genesis, start 4 roots, 4 ureth pairs, 4 shard validators
#   scripts/dnb-devnet.sh status | down
#
# One profile file (ubft engine-api b1-profile) is the source of: the registry genesis (layout 3), the ureth --unicity.* bindings and the
# shard nodes' Update admission (--b1-profile). B2 at 0x0104 is registered by the ureth Unicity EVM factory and needs no switch.
# Needs URETH_BIN (a unicity-reth built from a merged ureth that has B1 PR4b and B2 registration), a built build/ubft, go, python3, curl, openssl.
# Run from the repository root. State: test-nodes/ (kept after `down` for inspection).
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source helper.sh

validators=4 rootValidators=4 partitionID=8 aggPartition=9 chainID=${DNB_CHAIN_ID:-31337}
# DNB_AGG_SHARDS=2 runs the aggregator partition as the depth-1 topology of the B3 profile: two aggregator-go shards, 0x40 and 0xc0 (the
# top bit of a state ID picks the shard), each its own BFT shard of the one root chain. 1 (default) is the single full-range shard 0x80.
aggShards=${DNB_AGG_SHARDS:-1}
case "$aggShards" in 1) aggShardIDs=(0x80) ;; 2) aggShardIDs=(0x40 0xc0) ;; *) echo "DNB_AGG_SHARDS must be 1 or 2" >&2; exit 2 ;; esac
# agg_dir K (1-based) is test-nodes/agg for one shard (the layout of the single-shard lane) and test-nodes/agg1, agg2 for two.
agg_dir() { if [ "$aggShards" = 1 ]; then echo test-nodes/agg; else echo "test-nodes/agg$1"; fi; }
agg_conf() { if [ "$aggShards" = 1 ]; then echo "test-nodes/shard-conf-${aggPartition}_0.json"; else echo "test-nodes/shard-conf-${aggPartition}_0-s$1.json"; fi; }
agg_port() { echo $((${AGG_PORT:-3001} + $1 - 1)); }
rethEngineBase=18551 rethEthBase=18545 rethP2PBase=30401 rootRpcPort=25866
: "${URETH_BIN:?set URETH_BIN to the pinned unicity-reth}"
fee=${DNB_FEE_COLLECTOR:-0x000000000000000000000000000000000000dead}
# Restarted validators vote again only with an independent signing record (#105): SIGNING=authority keeps one per validator in a separate process that is not restarted.
export M2_PROFILE2=1 SIGNING=${DNB_SIGNING:-authority}

info() { echo "dnb: $*"; }
rpc() { curl -sS --max-time 10 -X POST "$1" -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"; }

down() {
  for p in test-nodes/auth*/pid; do [ -f "$p" ] && stop_pidfile "$p" 'ubft signing-authority' || true; done
  for p in test-nodes/reth*/pid; do [ -f "$p" ] && stop_pidfile "$p" 'unicity-reth|reth.* node' || true; done
  for k in $(seq 1 "$aggShards"); do [ -f "$(agg_dir "$k")/pid" ] && stop_pidfile "$(agg_dir "$k")/pid" 'aggregator' || true; done
  stop_evm_validators 2>/dev/null || true
  stop_root_nodes 2>/dev/null || true
}

up() {
  [ -x build/ubft ] || { echo "build/ubft missing (go build -o build/ubft ./cli/ubft)" >&2; exit 1; }
  rm -rf test-nodes; mkdir test-nodes
  info "identities and shard topology"
  init_root_nodes "$rootValidators" >/dev/null
  init_evm_validators "$validators" >/dev/null
  if [ "$SIGNING" = authority ]; then init_evm_authorities "$validators" "$partitionID" >/dev/null; fi
  generate_evm_shard_conf "$validators" "$partitionID" "$chainID" 5000 exec >/dev/null
  conf=test-nodes/shard-conf-${partitionID}_0.json

  info "B1 profile, funded genesis, identities"
  build/ubft engine-api b1-profile --shard-conf "$conf" --trust-base test-nodes/trust-base.json --w-cert "${DNB_W_CERT:-15}" --out test-nodes/b1-profile.json | tee test-nodes/b1-profile.out
  python3 - <<PY
import json, subprocess
p = json.load(open("test-nodes/b1-profile.json"))
g = {"config": {"chainId": $chainID, "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0, "byzantiumBlock": 0,
     "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0, "mergeNetsplitBlock": 0,
     "shanghaiTime": 0, "cancunTime": 0, "terminalTotalDifficulty": 0, "terminalTotalDifficultyPassed": True},
     "nonce": "0x0", "timestamp": "0x0", "extraData": "0x", "gasLimit": hex(p["maxGas"]), "difficulty": "0x0",
     "mixHash": "0x" + "00" * 32, "coinbase": "0x" + "00" * 20, "baseFeePerGas": "0x3b9aca00"}
g["alloc"] = json.loads(subprocess.check_output(["go", "run", "./scripts/evmtx", "-alloc"]))
json.dump(g, open("test-nodes/evm-genesis-funded.json", "w"), indent=2)
PY
  build/ubft engine-api genesis --shard-conf "$conf" --trust-base test-nodes/trust-base.json --b1-profile test-nodes/b1-profile.json \
    --alloc-source test-nodes/evm-genesis-funded.json --out test-nodes/evm-genesis-finalized.json \
    --full-shard-conf test-nodes/evm-full-shard-conf.json --identities-out test-nodes/genesis-identities.json | tee test-nodes/genesis.out
  # The root chain certifies the FULL shard configuration.
  cp test-nodes/evm-full-shard-conf.json "$conf"
  if [ "$SIGNING" = authority ]; then enroll_evm_authorities "$validators" "$partitionID" >/dev/null; info "signing authorities enrolled against the full shard configuration"; fi
  ureth_flags=$(sed -n 's/^ureth flags: *//p' test-nodes/b1-profile.out)

  # The root's aggregator_rsmt_v1 verifier demands an SMT consistency proof with every non-empty certification request; aggregator-go ae08165
  # produces none, so by default the aggregator partition runs on m-of-n signature verification only (DNB_AGG_PROOF_TYPE=aggregator_rsmt_v1 for rugregator).
  if [ "${DNB_AGG:-1}" = 1 ]; then
    for k in $(seq 1 "$aggShards"); do
      d=$(agg_dir "$k")
      info "aggregator shard configuration (partition $aggPartition, shard ${aggShardIDs[$((k - 1))]})"
      build/ubft shard-node init --home "$d" -g >/dev/null
      build/ubft shard-conf generate --home "$d.conf" --network-id 3 --partition-id "$aggPartition" --partition-type-id "$aggPartition" \
        --shard-id "${aggShardIDs[$((k - 1))]}" --epoch 0 --epoch-start 1 --t2-timeout 5000 ${DNB_AGG_PROOF_TYPE:+--partition-params proof_type=$DNB_AGG_PROOF_TYPE} \
        --node-info "$d/node-info.json" >/dev/null
      cp "$d.conf/shard-conf-${aggPartition}_0.json" "$(agg_conf "$k")"
    done
  fi

  info "start one ureth per validator"
  for i in $(seq 1 "$validators"); do
    mkdir -p "test-nodes/reth$i"
    openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
    # shellcheck disable=SC2086
    "$URETH_BIN" node --chain test-nodes/evm-genesis-finalized.json --datadir "test-nodes/reth$i/dd" \
      --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
      --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) --http.api eth,net,web3,admin,debug --rpc.eth-proof-window 64 \
      --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable --engine.persistence-threshold "${DNB_PERSIST:-0}" \
      --builder.gaslimit "$(python3 -c "import json;print(json.load(open('test-nodes/b1-profile.json'))['maxGas'])")" \
      --unicity.fee-collector "$fee" $ureth_flags \
      >"test-nodes/reth$i/reth.log" 2>&1 &
    echo $! >"test-nodes/reth$i/pid"
  done
  for i in $(seq 1 "$validators"); do
    for _ in $(seq 1 90); do rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_chainId '[]' 2>/dev/null | grep -q result && break; sleep 1; done
    rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_chainId '[]' | grep -q result || { tail -20 "test-nodes/reth$i/reth.log" >&2; echo "reth $i did not start" >&2; exit 1; }
  done
  for i in $(seq 1 "$validators"); do
    enode=$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_nodeInfo '[]' | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['enode'])")
    for j in $(seq 1 "$validators"); do [ "$i" = "$j" ] || rpc "http://127.0.0.1:$((rethEthBase + j - 1))" admin_addPeer "[\"$enode\"]" >/dev/null; done
  done
  info "reth clients up and peered"

  info "start roots and shard validators (fresh-B1 pair admission)"
  export EVM_ARCHIVE_ROOT=test-nodes/archives; mkdir -p "$EVM_ARCHIVE_ROOT"
  export EVM_GENESIS_FILE=test-nodes/evm-genesis-finalized.json EVM_FULL_SHARD_CONF=$conf EVM_B1_PROFILE=test-nodes/b1-profile.json EVM_ENGINE_FEE_COLLECTOR=$fee
  for i in $(seq 1 "$validators"); do
    export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))" "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
  done
  ./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1
  if [ "${DNB_AGG:-1}" = 1 ]; then for k in $(seq 1 "$aggShards"); do start_agg "$k"; done; fi
  info "up; roots rpc 127.0.0.1:25866, reth eth $rethEthBase.., engine $rethEngineBase.."
}

# Restarts: SIGTERM one process of the running devnet and start it again from its own state.
restart_agg() { # [K]: one aggregator shard, or all of them
  local ks=${1:-$(seq 1 "$aggShards")} k
  for k in $ks; do [ -f "$(agg_dir "$k")/pid" ] && stop_pidfile "$(agg_dir "$k")/pid" 'aggregator' || true; done
  sleep 2
  for k in $ks; do start_agg "$k"; done
}

start_reth() { # N: start (or restart) validator N's ureth on its datadir
  local i=$1 ureth_flags; ureth_flags=$(sed -n 's/^ureth flags: *//p' test-nodes/b1-profile.out)
  # shellcheck disable=SC2086
  "$URETH_BIN" node --chain test-nodes/evm-genesis-finalized.json --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
    --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) --http.api eth,net,web3,admin,debug --rpc.eth-proof-window 64 \
    --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable --engine.persistence-threshold "${DNB_PERSIST:-0}" \
    --builder.gaslimit "$(python3 -c "import json;print(json.load(open('test-nodes/b1-profile.json'))['maxGas'])")" \
    --unicity.fee-collector "$fee" $ureth_flags >>"test-nodes/reth$i/reth.log" 2>&1 &
  echo $! >"test-nodes/reth$i/pid"
}
wait_reth() { for _ in $(seq 1 90); do rpc "http://127.0.0.1:$((rethEthBase + $1 - 1))" eth_chainId '[]' 2>/dev/null | grep -q result && return; sleep 1; done; echo "reth $1 did not come back" >&2; return 1; }

restart_validator() { # N: the shard validator and its ureth
  local i=$1
  stop_one_evm_validator "$i" || true
  stop_pidfile "test-nodes/reth$i/pid" 'unicity-reth|reth.* node' || true
  sleep 3
  start_reth "$i"; wait_reth "$i"
  export EVM_ARCHIVE_ROOT=test-nodes/archives EVM_GENESIS_FILE=test-nodes/evm-genesis-finalized.json EVM_FULL_SHARD_CONF=test-nodes/shard-conf-${partitionID}_0.json EVM_B1_PROFILE=test-nodes/b1-profile.json EVM_ENGINE_FEE_COLLECTOR=$fee
  for j in $(seq 1 "$validators"); do export "EVM_ENGINE_URL_$j=http://127.0.0.1:$((rethEngineBase + j - 1))" "EVM_ETH_URL_$j=http://127.0.0.1:$((rethEthBase + j - 1))"; done
  local rootBoot; rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")
  start_one_evm_validator "$i" "$validators" "$partitionID" "$rootBoot" engine-api
  info "validator $i restarted"
}

# Stops every shard validator and ureth at once (roots and aggregator keep running), then starts them all from their own state.
restart_all_validators() {
  for i in $(seq 1 "$validators"); do stop_one_evm_validator "$i" || true; stop_pidfile "test-nodes/reth$i/pid" 'unicity-reth|reth.* node' || true; done
  sleep 5
  for i in $(seq 1 "$validators"); do start_reth "$i"; done
  for i in $(seq 1 "$validators"); do wait_reth "$i"; done
  export EVM_ARCHIVE_ROOT=test-nodes/archives EVM_GENESIS_FILE=test-nodes/evm-genesis-finalized.json EVM_FULL_SHARD_CONF=test-nodes/shard-conf-${partitionID}_0.json EVM_B1_PROFILE=test-nodes/b1-profile.json EVM_ENGINE_FEE_COLLECTOR=$fee
  for j in $(seq 1 "$validators"); do export "EVM_ENGINE_URL_$j=http://127.0.0.1:$((rethEngineBase + j - 1))" "EVM_ETH_URL_$j=http://127.0.0.1:$((rethEthBase + j - 1))"; done
  local rootBoot; rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")
  for i in $(seq 1 "$validators"); do start_one_evm_validator "$i" "$validators" "$partitionID" "$rootBoot" engine-api; done
  info "all validators restarted"
}

# aggregator-go (SDK3 leaf protocol) as a BFT shard of the live root chain. Needs AGG_BIN, and MongoDB with a replica set at AGG_MONGO.
start_agg() { # K (1-based): one aggregator-go shard
  local k=${1:-1} d port
  d=$(agg_dir "$k"); port=$(agg_port "$k")
  : "${AGG_BIN:?set AGG_BIN to the pinned aggregator-go binary}"
  : "${AGG_MONGO:=mongodb://127.0.0.1:27117/aggregator?replicaSet=rs0&directConnection=true}"
  local boot
  boot=$(boot_node test-nodes/root1 "$rootPortStart")
  mkdir -p "$d/logs"
  env PORT=$port HOST=127.0.0.1 ENABLE_DOCS=false ENABLE_CORS=true \
    MONGODB_URI="$AGG_MONGO" MONGODB_DATABASE="$(cat "$d/dbname" 2>/dev/null || { n=dnb_agg${k}_$(date +%s); echo $n | tee "$d/dbname"; })" DISABLE_HIGH_AVAILABILITY=true USE_REDIS_FOR_COMMITMENTS=false \
    SMT_BACKEND=memory SHARDING_MODE=standalone LOG_LEVEL=info LOG_FORMAT=text LOG_ENABLE_JSON=false LOG_FILE_PATH="$PWD/$d/logs/aggregator.log" \
    SIGNING_KEY_FILE="$PWD/$d/keys.json" BFT_ENABLED=true BFT_ADDRESS=/ip4/127.0.0.1/tcp/$((29100 + k)) BFT_RPC_ADDRESS=http://127.0.0.1:$rootRpcPort \
    BFT_SHARD_CONF_FILE="$PWD/$(agg_conf "$k")" BFT_TRUST_BASE_FILES="$PWD/test-nodes/trust-base.json" \
    BFT_BOOTSTRAP_ADDRESSES="$boot" \
    "$AGG_BIN" >"$d/stdout.log" 2>&1 &
  echo $! >"$d/pid"
  for _ in $(seq 1 60); do curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1 && { info "aggregator-go shard $k up on $port"; return; }; sleep 1; done
  tail -20 "$d/stdout.log" >&2; echo "aggregator shard $k did not become healthy" >&2; exit 1
}

# Fails fast when the root chain is not advancing (the stall that otherwise leaves a deploy waiting for a first block forever).
root_alive() {
  local a b
  a=$(curl -fsS http://127.0.0.1:$rootRpcPort/api/v1/roundInfo | python3 -c "import sys,json;print(json.load(sys.stdin)['roundNumber'])") || return 1
  sleep 8
  b=$(curl -fsS http://127.0.0.1:$rootRpcPort/api/v1/roundInfo | python3 -c "import sys,json;print(json.load(sys.stdin)['roundNumber'])") || return 1
  [ "$b" -gt "$a" ] || { echo "root chain stalled at round $b (see root*/debug.log: 'voter clock skew' / 'in recovery'); a loaded host (concurrent builds) is the known trigger" >&2; return 1; }
}

status() {
  for i in $(seq 1 "$validators"); do
    printf 'reth%s block=%s\n' "$i" "$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_blockNumber '[]' | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo down)"
  done
  curl -fsS http://127.0.0.1:$rootRpcPort/api/v1/roundInfo 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print('root round',d['roundNumber'])" || echo "root rpc down"
}

# Deploys the TokenVerifier and the BridgeVault (unicity-pos-contracts script/BridgeDeploy.s.sol, which refuses a vault whose rootGenesis,
# executionGenesis or b1ProfileHash differ from the genesis') on the running devnet. Needs CONTRACTS (a checkout with the script), forge, DNB_TOOL.
vault() {
  : "${CONTRACTS:?set CONTRACTS to a unicity-pos-contracts checkout with script/BridgeDeploy.s.sol}" "${DNB_TOOL:?set DNB_TOOL to the built dnb-tool}"
  local dep=$CONTRACTS/script/bridge-deploy key=${DNB_DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}
  "$DNB_TOOL" deployment --identities test-nodes/genesis-identities.json --agg-conf "$(for k in $(seq 1 "$aggShards"); do printf '%s,' "$(agg_conf "$k")"; done | sed 's/,$//')" --out test-nodes/bridge-deployment.json
  cp test-nodes/genesis-identities.json "$dep/genesis.json"; cp test-nodes/bridge-deployment.json "$dep/deployment.json"
  root_alive || return 1
  (cd "$CONTRACTS" && BRIDGE_GENESIS=script/bridge-deploy/genesis.json BRIDGE_DEPLOYMENT=script/bridge-deploy/deployment.json \
     timeout "${DNB_FORGE_TIMEOUT:-600}" forge script script/BridgeDeploy.s.sol --rpc-url "http://127.0.0.1:$rethEthBase" --private-key "$key" --broadcast --slow) | tee test-nodes/vault-deploy.log
  python3 - "$CONTRACTS" <<'PY'
import json, sys
run = json.load(open(sys.argv[1] + "/broadcast/BridgeDeploy.s.sol/31337/run-latest.json"))
addr = {t["contractName"]: t["contractAddress"] for t in run["transactions"] if t.get("contractName") in ("BridgeVault", "TokenVerifier")}
json.dump(addr, open("test-nodes/bridge-addresses.json", "w"), indent=2)
print(addr)
PY
  rm -f "$dep/genesis.json" "$dep/deployment.json"
}

# Writes the lane's derived inputs next to the devnet state (SDK trust document, EVM PDR, config for the driver).
config() {
  : "${DNB_TOOL:?set DNB_TOOL to the built dnb-tool}"
  "$DNB_TOOL" trust-doc --trust-base test-nodes/trust-base.json --out test-nodes/sdk-trust-base.json
  "$DNB_TOOL" pdr --full-shard-conf test-nodes/evm-full-shard-conf.json --out test-nodes/evm-pdr.cbor
  python3 - <<PY
import json
a = json.load(open("test-nodes/bridge-addresses.json"))
json.dump({"dir": "$PWD/test-nodes", "ethUrls": ["http://127.0.0.1:%d" % (18545 + i) for i in range($validators)], "aggUrl": "http://127.0.0.1:${AGG_PORT:-3001}", "aggUrls": ["http://127.0.0.1:%d" % (${AGG_PORT:-3001} + i) for i in range($aggShards)],
  "vault": a["BridgeVault"], "verifier": a["TokenVerifier"], "rootRpc": "http://127.0.0.1:$rootRpcPort", "chainId": $chainID, "evmPartition": $partitionID,
  "aggPartition": $aggPartition, "archive": "$PWD/test-nodes/archives/evm1"}, open("test-nodes/lane-config.json", "w"), indent=2)
PY
}

case "${1:-}" in restart-agg) restart_agg "${2:-}" ;; restart-all) restart_all_validators ;; restart-validator) restart_validator "${2:?validator number}" ;; all) up && vault && config ;; config) config ;; vault) vault ;; up) up ;; down) down ;; status) status ;; *) echo "usage: $0 up|down|status" >&2; exit 2 ;; esac
