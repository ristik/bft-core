#!/bin/bash

rootPortStart=26662

# generate logger configuration file
function generate_log_configuration() {
  # to iterate over all home directories
  for homedir in $1; do
    # generate log file itself
    cat <<EOT >> "$homedir/logger-config.yaml"
# File name to log to. If not set, logs to stdout.
outputPath:
# Controls if goroutine ID is added to log.
showGoroutineID: true
# The default log level for all loggers
# Possible levels: NONE; ERROR; WARNING; INFO; DEBUG; TRACE
defaultLevel: DEBUG
# Output format for log records (text: "parser friendly" plain text;)
format: text
# Sets time format to use for log record timestamp. Uses Go time
# format, ie "2006-01-02T15:04:05.0000Z0700" for more see
# https://pkg.go.dev/time#pkg-constants
# special value "none" can be used to disable logging timestamp;
timeFormat: "2006-01-02T15:04:05.0000Z0700"
# How to format peer ID values (ie node id):
# - none: do not log peer id at all;
# - short: log shortened id (middle part replaced with single *);
# otherwise full peer id is logged.
# This setting is not respected by ECS handler which always logs full ID.
peerIdFormat: short
EOT
  done
  return 0
}

# generate bootstrap parameter from key file and port
function boot_node() {
  local home=$1
  local rootPort=$2
  nodeId=$(build/ubft node-id --home $home | tail -n1)
  echo "/ip4/127.0.0.1/tcp/$rootPort/p2p/$nodeId"
}

# Initiallize root nodes
# $1 number of root nodes
function init_root_nodes() {
  home=test-nodes/root
  nodeInfoFiles=
  echo "initializing $1 nodes for root chain"
  for i in $(seq 1 "$1")
  do
    build/ubft root-node init --home "${home}$i" -g
    nodeInfoFiles+=" --node-info ${home}$i/node-info.json"
  done

  # Generate trust-base once to test-nodes. Genesis epoch must be 1 (trust_base.go
  # rejects 0: "genesis trust base epoch must be 1") — this was 0 and broke
  # setup-nodes.sh outright; fixed here rather than left for the EVM scripts to
  # work around, since every caller of init_root_nodes hit it.
  build/ubft trust-base generate --home test-nodes --epoch 1 --epoch-start 1 --network-id 3 $nodeInfoFiles

  # Sign trust-base by each node
  for i in $(seq 1 "$1")
  do
    build/ubft trust-base sign --home ${home}$i --trust-base test-nodes/trust-base.json
  done
}

function start_root_nodes() {
  # use root node 1 as bootstrap node
  local bootNode=""
  local p2pPort=$rootPortStart
  local rpcPort=25866

  bootNode=$(boot_node test-nodes/root1 "$rootPortStart")

  i=1
  for node in test-nodes/root*
  do
    if [[ $i -ne 1 ]]; then
      bootNodeParam="--bootnodes=$bootNode"
    fi

    build/ubft root-node run \
                    --home test-nodes/root$i \
                    --address "/ip4/127.0.0.1/tcp/$p2pPort" \
                    $bootNodeParam \
                    --trust-base test-nodes/trust-base.json \
                    --rpc-server-address "localhost:$rpcPort" \
                    --log-format text \
                    --log-level debug \
                    --metrics prometheus \
                    >> test-nodes/root$i/debug.log 2>&1 &
    nodePID=$!
    # wait until node starts listening on RPC port OR exits because of some error
    until lsof -i:$rpcPort >/dev/null || ! ps -p $nodePID >/dev/null
    do
      echo -n "."
      sleep 0.200
    done

    if ! ps -p $nodePID >/dev/null; then
      echo "failed"
      exit
    fi

    if ls test-nodes/shard-conf-* >/dev/null 2>&1; then
      # uplaod all shard confs
      for shardConf in test-nodes/shard-conf-*
      do
        curl -X PUT -H "Content-Type: application/json" -d @${shardConf} \
             http://localhost:${rpcPort}/api/v1/configurations
      done
    fi

    ((p2pPort=p2pPort+1))
    ((rpcPort=rpcPort+1))
    ((i=i+1))
  done

  echo
  echo "started $(($i-1)) root nodes"
}

# ============================================================================
# EVM shard helpers — see docs/engine-api-adapter-plan.md.
#
# These are additive: they don't touch the root-chain-only functions above,
# and setup-evm-nodes.sh/start-evm.sh/stop-evm.sh are the scripts that use
# them, parallel to setup-nodes.sh/start.sh/stop.sh rather than replacing
# them.
# ============================================================================

evmValidatorPortStart=28111
evmDisseminationPortStart=28211

# init_evm_validators - generate keys + node-info for N shard validators
# $1 number of validators
function init_evm_validators() {
  echo "initializing $1 EVM shard validator identities"
  for i in $(seq 1 "$1")
  do
    build/ubft shard-node init --home "test-nodes/evm$i" -g
  done
}

# generate_evm_shard_conf - generate the shard conf for the EVM partition,
# naming every validator init_evm_validators created.
# $1 number of validators
# $2 partition id
# $3 chain id (the EVM chainId — distinct from --network-id)
# $4 t2 timeout in milliseconds
# $5 proof_type (exec | light_client | sp1 — see the build plan §8)
function generate_evm_shard_conf() {
  local n=$1 partitionID=$2 chainID=$3 t2=$4 proofType=$5
  nodeInfoFiles=
  for i in $(seq 1 "$n")
  do
    nodeInfoFiles+=" --node-info test-nodes/evm$i/node-info.json"
  done

  build/ubft shard-conf generate --home test-nodes \
    --network-id 3 --partition-id "$partitionID" --partition-type-id "$partitionID" \
    --shard-id 0x80 --epoch-start 1 --t2-timeout "$t2" \
    --partition-params "proof_type=$proofType,chain_id=$chainID" \
    $nodeInfoFiles

  echo "generated test-nodes/shard-conf-${partitionID}_0.json"
}

# generate_evm_genesis - emit the reth chain spec derived from the shard
# conf generate_evm_shard_conf just wrote — see engine_api_genesis.go for
# why this must be derived, not hand-written separately.
# $1 partition id
function generate_evm_genesis() {
  local partitionID=$1
  build/ubft engine-api genesis --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --out test-nodes/evm-genesis.json
}

# evm_validator_id - node id of EVM validator $1 (must already be initialized)
function evm_validator_id() {
  build/ubft node-id --home "test-nodes/evm$1" | tail -n1
}

# evm_validator_addr - this validator's own dialable multiaddress, for
# other validators' bootnode lists
function evm_validator_addr() {
  local i=$1 port=$((evmValidatorPortStart + i - 1))
  echo "/ip4/127.0.0.1/tcp/$port/p2p/$(evm_validator_id "$i")"
}

# start_evm_validators - start N shard-node processes, each bootstrapped to
# the root chain AND directly to every sibling validator (a full mesh,
# guaranteeing dissemination connectivity without depending on DHT peer
# routing — see shardnode/net_dissemination.go's doc comment).
# $1 number of validators
# $2 partition id
# $3 root boot address (from init_root_nodes/boot_node)
# $4 executor: "fake" or "engine-api"
# For --executor engine-api, set EVM_ENGINE_URL_i / EVM_ETH_URL_i env vars
# per validator (i = 1..N) before calling, or every validator defaults to
# the same single reth instance on the standard ports — fine for a
# single-reth smoke test, wrong for a real multi-reth deployment.
function start_evm_validators() {
  local n=$1 partitionID=$2 rootBoot=$3 executor=$4

  # pass 1: every validator's own address, before any of them are running
  local addrs=()
  for i in $(seq 1 "$n"); do
    addrs+=("$(evm_validator_addr "$i")")
  done

  for i in $(seq 1 "$n"); do
    local port=$((evmValidatorPortStart + i - 1))
    local bootnodes="$rootBoot"
    for j in $(seq 1 "$n"); do
      if [ "$j" != "$i" ]; then
        bootnodes+=",${addrs[$((j-1))]}"
      fi
    done

    local executorArgs=()
    if [ "$executor" == "engine-api" ]; then
      local engineURLVar="EVM_ENGINE_URL_$i" ethURLVar="EVM_ETH_URL_$i"
      local engineURL="${!engineURLVar:-http://127.0.0.1:8551}"
      local ethURL="${!ethURLVar:-http://127.0.0.1:8545}"
      executorArgs=(--engine-url "$engineURL" --eth-url "$ethURL" --jwt-secret "test-nodes/evm$i/jwt.hex")
    fi

    build/ubft shard-node run --home "test-nodes/evm$i" --executor "$executor" \
      --address "/ip4/127.0.0.1/tcp/$port" --bootnodes "$bootnodes" \
      --trust-base test-nodes/trust-base.json \
      --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
      --log-format text --log-level info "${executorArgs[@]}" \
      >> "test-nodes/evm$i/debug.log" 2>&1 &
    echo $! > "test-nodes/evm$i/pid"
  done

  echo "started $n EVM shard validators (executor=$executor)"
}

# stop_evm_validators - kill every started validator by its recorded pid
function stop_evm_validators() {
  for pidfile in test-nodes/evm*/pid; do
    [ -f "$pidfile" ] || continue
    local pid
    pid=$(cat "$pidfile")
    if ps -p "$pid" >/dev/null 2>&1; then
      kill "$pid"
    fi
    rm -f "$pidfile"
  done
}
