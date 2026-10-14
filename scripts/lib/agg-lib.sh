# Aggregator-go shard(s) and the bridge contracts for a paired devnet, shared by scripts/dnb-devnet.sh (the DN-B lane) and scripts/reth-paired-devnet.sh
# (the any-age final lane, ANYAGE_LANE=1). Definitions only: sourcing this file starts nothing, reads nothing and takes no port.
#
# The caller defines (before calling a function): info, rpc, root_alive, boot_node (helper.sh), stop_pidfile (helper.sh), and the variables
# validators, partitionID, chainID, rethEthBase, rootRpcPort, rootPortStart (helper.sh). Optional: aggPartition (9), DNB_AGG_SHARDS (1).

aggPartition=${aggPartition:-9}
# DNB_AGG_SHARDS=2 runs the aggregator partition as the depth-1 topology of the B3 profile: two aggregator-go shards, 0x40 and 0xc0 (the
# top bit of a state ID picks the shard), each its own BFT shard of the one root chain. 1 (default) is the single full-range shard 0x80.
aggShards=${DNB_AGG_SHARDS:-1}
case "$aggShards" in 1) aggShardIDs=(0x80) ;; 2) aggShardIDs=(0x40 0xc0) ;; *) echo "DNB_AGG_SHARDS must be 1 or 2" >&2; aggShards=1; aggShardIDs=(0x80) ;; esac
# agg_dir K (1-based) is test-nodes/agg for one shard (the layout of the single-shard lane) and test-nodes/agg1, agg2 for two.
agg_dir() { if [ "$aggShards" = 1 ]; then echo test-nodes/agg; else echo "test-nodes/agg$1"; fi; }
agg_conf() { if [ "$aggShards" = 1 ]; then echo "test-nodes/shard-conf-${aggPartition}_0.json"; else echo "test-nodes/shard-conf-${aggPartition}_0-s$1.json"; fi; }
# aggregator-go (internal/config/config.go Validate): a shard conf with a non-empty shard ID REQUIRES SHARDING_MODE=bft-shard (with BFT_ENABLED,
# the shard's own conf/PDR and signing key, and SHARDING_CHILD_SHARD_ID unset); the empty shard 0x80 of a one-shard partition REQUIRES standalone.
agg_mode() { if [ "$aggShards" = 1 ]; then echo standalone; else echo bft-shard; fi; }
agg_port() { echo $((${AGG_PORT:-3001} + $1 - 1)); }

# The aggregator shard configurations, written under test-nodes/ BEFORE the roots start (the roots register every test-nodes/shard-conf-* file).
# The root's aggregator_rsmt_v1 verifier demands an SMT consistency proof with every non-empty certification request; aggregator-go ae08165
# produces none, so by default the aggregator partition runs on m-of-n signature verification only (DNB_AGG_PROOF_TYPE=aggregator_rsmt_v1 for rugregator).
agg_prepare_confs() {
  local k d
  for k in $(seq 1 "$aggShards"); do
    d=$(agg_dir "$k")
    info "aggregator shard configuration (partition $aggPartition, shard ${aggShardIDs[$((k - 1))]})"
    build/ubft shard-node init --home "$d" -g >/dev/null
    build/ubft shard-conf generate --home "$d.conf" --network-id 3 --partition-id "$aggPartition" --partition-type-id "$aggPartition" \
      --shard-id "${aggShardIDs[$((k - 1))]}" --epoch 0 --epoch-start 1 --t2-timeout 5000 ${DNB_AGG_PROOF_TYPE:+--partition-params proof_type=$DNB_AGG_PROOF_TYPE} \
      --node-info "$d/node-info.json" >/dev/null
    cp "$d.conf/shard-conf-${aggPartition}_0.json" "$(agg_conf "$k")"
  done
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
    SMT_BACKEND=memory SHARDING_MODE=$(agg_mode) LOG_LEVEL=info LOG_FORMAT=text LOG_ENABLE_JSON=false LOG_FILE_PATH="$PWD/$d/logs/aggregator.log" \
    SIGNING_KEY_FILE="$PWD/$d/keys.json" BFT_ENABLED=true BFT_ADDRESS=/ip4/127.0.0.1/tcp/$((29100 + k)) BFT_RPC_ADDRESS=http://127.0.0.1:$rootRpcPort \
    BFT_SHARD_CONF_FILE="$PWD/$(agg_conf "$k")" BFT_TRUST_BASE_FILES="$PWD/test-nodes/trust-base.json" \
    BFT_BOOTSTRAP_ADDRESSES="$boot" \
    "$AGG_BIN" >"$d/stdout.log" 2>&1 &
  echo $! >"$d/pid"
  for _ in $(seq 1 60); do curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1 && { info "aggregator-go shard $k up on $port"; return; }; sleep 1; done
  tail -20 "$d/stdout.log" >&2; echo "aggregator shard $k did not become healthy" >&2; return 1
}
start_aggs() { local k; for k in $(seq 1 "$aggShards"); do start_agg "$k" || return 1; done; }
# Stops this run's aggregators by their own pid files, never by a name pattern.
stop_aggs() { local k; for k in $(seq 1 "$aggShards"); do [ -f "$(agg_dir "$k")/pid" ] && stop_pidfile "$(agg_dir "$k")/pid" 'aggregator' || true; done; }
restart_agg() { # [K]: one aggregator shard, or all of them
  local ks=${1:-$(seq 1 "$aggShards")} k
  for k in $ks; do [ -f "$(agg_dir "$k")/pid" ] && stop_pidfile "$(agg_dir "$k")/pid" 'aggregator' || true; done
  sleep 2
  for k in $ks; do start_agg "$k"; done
}

# Deploys the TokenVerifier and the BridgeVault (unicity-pos-contracts script/BridgeDeploy.s.sol, which refuses a vault whose rootGenesis,
# executionGenesis or b1ProfileHash differ from the genesis') on the running devnet. Needs CONTRACTS (a checkout with the script), forge, DNB_TOOL;
# BRIDGE_IDENTITIES is the genesis identities file the finalized genesis wrote.
bridge_deploy_vault() {
  : "${CONTRACTS:?set CONTRACTS to a unicity-pos-contracts checkout with script/BridgeDeploy.s.sol}" "${DNB_TOOL:?set DNB_TOOL to the built dnb-tool}"
  local ids=${BRIDGE_IDENTITIES:-test-nodes/genesis-identities.json}
  local dep=$CONTRACTS/script/bridge-deploy key=${DNB_DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80} k
  "$DNB_TOOL" deployment --identities "$ids" --agg-conf "$(for k in $(seq 1 "$aggShards"); do printf '%s,' "$(agg_conf "$k")"; done | sed 's/,$//')" --out test-nodes/bridge-deployment.json
  cp "$ids" "$dep/genesis.json"; cp test-nodes/bridge-deployment.json "$dep/deployment.json"
  root_alive || return 1
  (cd "$CONTRACTS" && BRIDGE_GENESIS=script/bridge-deploy/genesis.json BRIDGE_DEPLOYMENT=script/bridge-deploy/deployment.json \
     timeout "${DNB_FORGE_TIMEOUT:-600}" forge script script/BridgeDeploy.s.sol --rpc-url "http://127.0.0.1:$rethEthBase" --private-key "$key" --broadcast --slow) | tee test-nodes/vault-deploy.log
  python3 - "$CONTRACTS" "$chainID" <<'PY'
import json, sys
run = json.load(open(sys.argv[1] + "/broadcast/BridgeDeploy.s.sol/%s/run-latest.json" % sys.argv[2]))
addr = {t["contractName"]: t["contractAddress"] for t in run["transactions"] if t.get("contractName") in ("BridgeVault", "TokenVerifier")}
json.dump(addr, open("test-nodes/bridge-addresses.json", "w"), indent=2)
print(addr)
PY
  rm -f "$dep/genesis.json" "$dep/deployment.json"
}

# Writes the lane's derived inputs next to the devnet state (SDK trust document, EVM PDR, config for the plug-in driver).
# BRIDGE_FULL_CONF is the full shard configuration the root certifies (the EVM genesis' evm-full-shard-conf*.json).
bridge_write_config() {
  : "${DNB_TOOL:?set DNB_TOOL to the built dnb-tool}"
  local full=${BRIDGE_FULL_CONF:-test-nodes/evm-full-shard-conf.json}
  "$DNB_TOOL" trust-doc --trust-base test-nodes/trust-base.json --out test-nodes/sdk-trust-base.json
  "$DNB_TOOL" pdr --full-shard-conf "$full" --out test-nodes/evm-pdr.cbor
  python3 - "$PWD" "$validators" "$rethEthBase" "$rootRpcPort" "$chainID" "$partitionID" "$aggPartition" "$aggShards" "${AGG_PORT:-3001}" "${BRIDGE_ARCHIVE:-test-nodes/archives}" <<'PY'
import json, sys
pwd, validators, eth_base, root_rpc, chain, evm_part, agg_part, shards, agg_port, archive = sys.argv[1:]
a = json.load(open("test-nodes/bridge-addresses.json"))
validators, eth_base, shards, agg_port = int(validators), int(eth_base), int(shards), int(agg_port)
json.dump({"dir": pwd + "/test-nodes", "ethUrls": ["http://127.0.0.1:%d" % (eth_base + i) for i in range(validators)],
  "aggUrl": "http://127.0.0.1:%d" % agg_port, "aggUrls": ["http://127.0.0.1:%d" % (agg_port + i) for i in range(shards)],
  "vault": a["BridgeVault"], "verifier": a["TokenVerifier"], "rootRpc": "http://127.0.0.1:" + root_rpc, "chainId": int(chain),
  "evmPartition": int(evm_part), "aggPartition": int(agg_part), "archive": pwd + "/" + archive + "/evm1"},
  open("test-nodes/lane-config.json", "w"), indent=2)
PY
}

# Fails fast when the root chain is not advancing (the stall that otherwise leaves a deploy waiting for a first block forever).
root_alive() {
  local a b
  a=$(curl -fsS http://127.0.0.1:$rootRpcPort/api/v1/roundInfo | python3 -c "import sys,json;print(json.load(sys.stdin)['roundNumber'])") || return 1
  sleep 8
  b=$(curl -fsS http://127.0.0.1:$rootRpcPort/api/v1/roundInfo | python3 -c "import sys,json;print(json.load(sys.stdin)['roundNumber'])") || return 1
  [ "$b" -gt "$a" ] || { echo "root chain stalled at round $b (see root*/debug.log: 'voter clock skew' / 'in recovery'); a loaded host (concurrent builds) is the known trigger" >&2; return 1; }
}
