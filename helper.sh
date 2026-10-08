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

# wait_for_root_chain_settle - pause after start_root_nodes and before
# starting any shard validators against it. Root-node startup's shard-conf
# registration (the curl PUT inside start_root_nodes) returns 200 as soon as
# it's durably written to that root node's own orchestration store, but the
# root chain's live consensus state (what a shard validator's handshake is
# actually checked against — rootchain/consensus_manager.go's ShardInfo)
# only picks up a newly-registered shard a few root rounds later. A
# validator that handshakes before that catches "unknown partition ...
# shard" and has to wait out its own 30s inactivity timeout to retry — 5s
# here is confirmed (empirically, see docs/troubleshooting.md) to comfortably
# clear that window, against root rounds that in practice complete in well
# under a second each once the chain is up.
function wait_for_root_chain_settle() {
  echo "letting the root chain settle before starting validators..."
  sleep 5
}

# collect_shard_conf_args - fill shardConfArgs with --shard-conf <file> for every test-nodes/shard-conf-* file. Without any such
# file the unmatched glob stays a literal pattern in a plain for loop, so skip entries that do not exist instead of handing the
# literal "test-nodes/shard-conf-*" to the root node.
function collect_shard_conf_args() {
  local conf
  shardConfArgs=()
  for conf in test-nodes/shard-conf-*; do
    [ -e "$conf" ] || continue
    shardConfArgs+=(--shard-conf "$conf")
  done
}

function start_root_nodes() {
  # use root node 1 as bootstrap node
  local bootNode=""
  local p2pPort=$rootPortStart
  local rpcPort=25866
  local rpcHost=localhost
  if [ "${M2_PROFILE2:-0}" = 1 ]; then rpcHost=127.0.0.1; fi

  bootNode=$(boot_node test-nodes/root1 "$rootPortStart")

  i=1
  for node in test-nodes/root*
  do
    if [[ $i -ne 1 ]]; then
      bootNodeParam="--bootnodes=$bootNode"
    fi

    local profileArgs=()
    if [ "${M2_PROFILE2:-0}" = 1 ]; then
      profileArgs=(--profile-2)
      # Under the handoff profile PUT /api/v1/configurations is refused (#329): the genesis shard
      # configurations are fixed at start, so hand every one of them over by flag.
      collect_shard_conf_args
      profileArgs+=(${shardConfArgs[@]+"${shardConfArgs[@]}"})
    fi
    build/ubft root-node run \
                    --home test-nodes/root$i \
                    --address "/ip4/127.0.0.1/tcp/$p2pPort" \
                    $bootNodeParam \
                    --trust-base test-nodes/trust-base.json \
                    --rpc-server-address "$rpcHost:$rpcPort" \
                    --log-format text \
                    --log-level debug \
                    --metrics prometheus \
                    ${profileArgs[@]+"${profileArgs[@]}"} \
                    >> test-nodes/root$i/debug.log 2>&1 &
    nodePID=$!
    echo "$nodePID" > "test-nodes/root$i/pid"
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

    if [ "${M2_PROFILE2:-0}" != 1 ] && ls test-nodes/shard-conf-* >/dev/null 2>&1; then
      # uplaod all shard confs
      for shardConf in test-nodes/shard-conf-*
      do
        curl --retry 5 --retry-all-errors --retry-delay 1 -f -X PUT -H "Content-Type: application/json" -d @${shardConf} \
             http://${rpcHost}:${rpcPort}/api/v1/configurations
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
evmRPCPortStart=28311

# evm_validator_rpc_addr - this validator's metrics/health address, for
# scripts/chaos-evm.sh's post-restart health checks.
function evm_validator_rpc_addr() {
  # Two statements, not one: bash expands EVERY word of a `local` before performing any of its
  # assignments, so `local i=$1 port=$((... i ...))` computes port from the CALLER's i, not from the
  # one being assigned. Found while wiring the anchor-evidence acceptance run — evm_validator_addr
  # below had the same shape, and every validator was therefore handed its OWN port as each
  # sibling's address, so the "full mesh" this file documents was never formed.
  local i=$1
  local port=$((evmRPCPortStart + i - 1))
  echo "127.0.0.1:$port"
}

# init_evm_validators - generate keys + node-info for N shard validators
# $1 number of validators
function init_evm_validators() {
  echo "initializing $1 EVM shard validator identities"
  for i in $(seq 1 "$1")
  do
    build/ubft shard-node init --home "test-nodes/evm$i" -g
  done
}

# Keep each authority outside its shard node's process and home. Its key exists only for this
# process lifetime, so the paired lane must leave it running while shard nodes are restarted.
#
# Optional $3..$6 start authorities first..n at another scope (default: 1..n at shard epoch 0, root epoch 1 under the genesis trust base):
# a joining validator's authority is started pending at the successor scope it will operate in.
function init_evm_authorities() {
  local n=$1 partitionID=$2 first=${3:-1} shardEpoch=${4:-0} rootEpoch=${5:-1} trustBase=${6:-test-nodes/trust-base.json} i home nodeID attempt
  for i in $(seq "$first" "$n"); do
    home="test-nodes/auth$i"
    mkdir -p "$home"
    chmod 700 "$home"
    nodeID=$(evm_validator_id "$i") || return 1
    build/ubft signing-authority credential --out "$home/operator.cred" || return 1
    build/ubft signing-authority run --home "$home" \
      --client-socket "$home/client.sock" --operator-socket "$home/operator.sock" \
      --operator-credential "$home/operator.cred" --authority-id "paired-evm-$i" \
      --node-id "$nodeID" --network-id 3 --partition-id "$partitionID" --shard-id 0x80 \
      --shard-epoch "$shardEpoch" --root-epoch "$rootEpoch" --trust-base "$trustBase" \
      --log-format text --log-level info >"$home/authority.log" 2>&1 &
    echo $! >"$home/pid"
    for attempt in $(seq 1 100); do
      [ -S "$home/operator.sock" ] && break
      if ! kill -0 "$(cat "$home/pid")" 2>/dev/null; then
        echo "authority $i exited during startup" >&2
        tail -20 "$home/authority.log" >&2
        return 1
      fi
      sleep 0.1
    done
    [ -S "$home/operator.sock" ] || { echo "authority $i did not open its socket" >&2; return 1; }
    # the socket file can exist a moment before the authority accepts: the process says so when it is serving
    for attempt in $(seq 1 100); do
      grep -q 'signing authority running' "$home/authority.log" 2>/dev/null && break
      sleep 0.1
    done
    build/ubft signing-authority node-info --operator-socket "$home/operator.sock" \
      --operator-credential "$home/operator.cred" --out "$home/node-info.json" || return 1
  done
}

# Optional $3/$4 enroll first..n against another configuration (default: validators 1..n against the genesis shard configuration).
function enroll_evm_authorities() {
  local n=$1 partitionID=$2 first=${3:-1} conf=${4:-} i home
  conf=${conf:-test-nodes/shard-conf-${partitionID}_0.json}
  for i in $(seq "$first" "$n"); do
    home="test-nodes/auth$i"
    build/ubft signing-authority complete-enrollment --operator-socket "$home/operator.sock" \
      --operator-credential "$home/operator.cred" \
      --shard-conf "$conf" || return 1
    build/ubft signing-authority replace-session --operator-socket "$home/operator.sock" \
      --operator-credential "$home/operator.cred" --out "$home/client.cred" || return 1
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
    if [ "${SIGNING:-local}" = authority ]; then
      nodeInfoFiles+=" --node-info test-nodes/auth$i/node-info.json"
    else
      nodeInfoFiles+=" --node-info test-nodes/evm$i/node-info.json"
    fi
  done

  build/ubft shard-conf generate --home test-nodes \
    --network-id 3 --partition-id "$partitionID" --partition-type-id "$partitionID" \
    --shard-id 0x80 --epoch-start 1 --t2-timeout "$t2" \
    --partition-params "proof_type=$proofType,chain_id=$chainID${EVM_PARTITION_PARAMS_EXTRA:+,$EVM_PARTITION_PARAMS_EXTRA}" \
    $nodeInfoFiles

  echo "generated test-nodes/shard-conf-${partitionID}_0.json"
}

# --- SealRegistry layout: resolved ONCE per run, persisted in the run directory -----------------------
# Layout 2 (registrygenesis/seal-registry-v2.json, code hash 0x7787f316...caf38, contracts ce3e40b4) is what
# ureth unicity/main pins since #47 and is the default (use the H3 Ureth 5f3bb7e4 or later; the layout-1 pins below are
# legacy, kept only so an old client is still classified as layout 1, and cannot run the current epoch-transition encoding). Ureth commits listed in REGISTRY_LAYOUT1_URETH_PINS predate
# it and need layout 1; REGISTRY_LAYOUT=1|2 overrides at resolution time only.
# registry_layout_init writes test-nodes/registry-layout (layout, artifact sha256, ureth commit) once, at run start
# (setup-evm-nodes.sh, reth-paired-devnet.sh and the f6b lanes via setup). Every script that seeds genesis or
# starts/restarts shard-node or reth reads it from there, in whatever shell it runs, and refuses to start when the
# file is missing, the artifact changed, or it was resolved for a different ureth commit than $URETH_PIN_COMMIT.
REGISTRY_LAYOUT_FILE=${REGISTRY_LAYOUT_FILE:-test-nodes/registry-layout}
REGISTRY_LAYOUT1_URETH_PINS="39d7e59d ae6e6be9 055a314f d2af1fb1"

function registry_layout_for_commit() { # $1 ureth commit (may be empty)
  local c=$1 p
  if [ -n "${REGISTRY_LAYOUT:-}" ]; then echo "$REGISTRY_LAYOUT"; return; fi
  for p in $REGISTRY_LAYOUT1_URETH_PINS; do
    case "$c" in "$p"*) echo 1; return ;; esac
  done
  echo 2
}

function registry_layout_init() { # $1 ureth commit (default: $URETH_PIN_COMMIT)
  local commit=${1:-${URETH_PIN_COMMIT:-}} layout
  layout=$(registry_layout_for_commit "$commit")
  case "$layout" in 1 | 2) ;; *) echo "registry layout: REGISTRY_LAYOUT must be 1 or 2, got '$layout'" >&2; return 1 ;; esac
  mkdir -p "$(dirname "$REGISTRY_LAYOUT_FILE")"
  printf 'layout=%s\nartifactSha256=%s\nurethCommit=%s\n' "$layout" \
    "$(shasum -a 256 "registrygenesis/seal-registry-v$layout.json" | cut -d' ' -f1)" "$commit" >"$REGISTRY_LAYOUT_FILE"
  echo "registry layout=$layout (resolved once for ureth '${commit:-unspecified}'; $REGISTRY_LAYOUT_FILE)"
}

function registry_layout_field() { sed -n "s/^$1=//p" "$REGISTRY_LAYOUT_FILE" 2>/dev/null | head -1; }

# registry_layout_require - refuse (non-zero) unless the persisted layout exists, matches the artifact on disk and
# the ureth pin in use. Call it before seeding genesis or starting/restarting shard-node or reth.
function registry_layout_require() {
  local layout sha stored commit
  layout=$(registry_layout_field layout)
  if [ "$layout" != 1 ] && [ "$layout" != 2 ]; then
    echo "registry layout: $REGISTRY_LAYOUT_FILE is missing or invalid; resolve it once with registry_layout_init (setup-evm-nodes.sh does) before seeding or starting nodes" >&2
    return 1
  fi
  sha=$(shasum -a 256 "registrygenesis/seal-registry-v$layout.json" | cut -d' ' -f1)
  if [ "$sha" != "$(registry_layout_field artifactSha256)" ]; then
    echo "registry layout: registrygenesis/seal-registry-v$layout.json changed since this run resolved layout $layout" >&2
    return 1
  fi
  stored=$(registry_layout_field urethCommit)
  commit=${URETH_PIN_COMMIT:-}
  if [ -n "$commit" ] && [ -n "$stored" ] && [ "$commit" != "$stored" ]; then
    echo "registry layout: resolved for ureth $stored but this launch uses $commit" >&2
    return 1
  fi
  if [ -n "$commit" ] && [ "$(registry_layout_for_commit "$commit")" != "$layout" ]; then
    echo "registry layout: layout $layout does not match ureth $commit (REGISTRY_LAYOUT overrides: ${REGISTRY_LAYOUT:-none})" >&2
    return 1
  fi
}

function registry_layout() { registry_layout_field layout; }
function registry_artifact() { echo "registrygenesis/seal-registry-v$(registry_layout).json"; }

# generate_evm_genesis - emit the reth chain spec derived from the shard
# conf generate_evm_shard_conf just wrote — see engine_api_genesis.go for
# why this must be derived, not hand-written separately.
# $1 partition id
function generate_evm_genesis() {
  local partitionID=$1
  registry_layout_require || return 1
  build/ubft engine-api genesis --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --out test-nodes/evm-genesis.json --registry-layout "$(registry_layout)"
}

# evm_validator_id - node id of EVM validator $1 (must already be initialized)
function evm_validator_id() {
  build/ubft node-id --home "test-nodes/evm$1" | tail -n1
}

# evm_validator_addr - this validator's own dialable multiaddress, for
# other validators' bootnode lists
function evm_validator_addr() {
  # See evm_validator_rpc_addr for why this is two statements rather than one.
  local i=$1
  local port=$((evmValidatorPortStart + i - 1))
  echo "/ip4/127.0.0.1/tcp/$port/p2p/$(evm_validator_id "$i")"
}

# require_peer_id_address - fail before launching a node if a boot address has no peer ID.
function require_peer_id_address() {
  local address=$1 source=$2 peer
  case "$address" in
    */p2p/*) peer=${address##*/p2p/} ;;
    *) echo "$source is missing its /p2p/<peer-id> suffix: '$address'" >&2; return 1 ;;
  esac
  if [ -z "$peer" ] || [[ "$peer" == */* ]] || [[ "$peer" == *[[:space:]]* ]]; then
    echo "$source has an empty or malformed peer ID: '$address'" >&2
    return 1
  fi
  printf '%s\n' "$peer"
}

# evm_bootnodes_for_peers - root address plus the listed online validators except $2.
function evm_bootnodes_for_peers() {
  local rootBoot=$1 exclude=$2
  shift 2
  local bootnodes=$rootBoot i peerID address addressPeer
  require_peer_id_address "$rootBoot" "root boot node" >/dev/null || return 1
  for i in "$@"; do
    [ "$i" = "$exclude" ] && continue
    peerID=$(evm_validator_id "$i") || peerID=
    if [ -z "$peerID" ]; then
      echo "online validator $i has no peer ID; refusing to build an incomplete boot-node list" >&2
      return 1
    fi
    address=$(evm_validator_addr "$i") || return 1
    addressPeer=$(require_peer_id_address "$address" "online validator $i boot node") || return 1
    if [ "$addressPeer" != "$peerID" ]; then
      echo "online validator $i boot-node peer ID $addressPeer does not match node ID $peerID" >&2
      return 1
    fi
    bootnodes+=",$address"
  done
  printf '%s\n' "$bootnodes"
}

# start_evm_validators - start N shard-node processes, each bootstrapped to
# the root chain AND directly to every sibling validator (a full mesh,
# guaranteeing dissemination connectivity without depending on DHT peer
# routing — see shardnode/net_dissemination.go's doc comment).
# $1 number of validators
# $2 partition id
# $3 root boot address (from init_root_nodes/boot_node)
# $4 executor: "fake" or "engine-api"
# $5 "rpc" (optional) - expose each validator's /api/v1/metrics and
#    /api/v1/health on 127.0.0.1:evmRPCPortStart+i-1 (see evm_validator_rpc_addr).
#    Omit for a plain smoke test; scripts/chaos-evm.sh passes it.
# For --executor engine-api, set EVM_ENGINE_URL_i / EVM_ETH_URL_i env vars
# per validator (i = 1..N) before calling, or every validator defaults to
# the same single reth instance on the standard ports — fine for a
# single-reth smoke test, wrong for a real multi-reth deployment.
function start_evm_validators() {
  local n=$1 partitionID=$2 rootBoot=$3 executor=$4 exposeRPC=$5

  for i in $(seq 1 "$n"); do
    start_one_evm_validator "$i" "$n" "$partitionID" "$rootBoot" "$executor" "$exposeRPC"
  done

  echo "started $n EVM shard validators (executor=$executor)"
}

# start_one_evm_validator - (re)start a single validator $1 of $2, bootstrapped
# to the root chain and (full-mesh) every sibling — the same computation
# start_evm_validators does per-node, factored out so scripts/chaos-evm.sh can
# restart exactly one validator (kill-and-recover scenarios) without
# duplicating the bootnode/executor-args logic. Safe to call on an already-
# initialized validator any number of times — e.g. after stop_one_evm_validator.
# $1 this validator's index (1..$2)
# $2 total number of validators (for the full-mesh bootnode list)
# $3 partition id
# $4 root boot address
# $5 executor: "fake" or "engine-api"
# $6 "rpc" (optional) - see start_evm_validators
# $7 optional prevalidated comma-separated boot nodes for offline-peer lanes
function start_one_evm_validator() {
  local i=$1 n=$2 partitionID=$3 rootBoot=$4 executor=$5 exposeRPC=${6:-}
  local port=$((evmValidatorPortStart + i - 1))

  local bootnodes="$rootBoot"
  if [ "$#" -ge 7 ]; then
    bootnodes=$7
  else
    for j in $(seq 1 "$n"); do
      if [ "$j" != "$i" ]; then
        bootnodes+=",$(evm_validator_addr "$j")"
      fi
    done
  fi

  local executorArgs=()
  local shardConfArgs=(--shard-conf "test-nodes/shard-conf-${partitionID}_0.json")
    if [ "$executor" == "engine-api" ]; then
    local engineURLVar="EVM_ENGINE_URL_$i" ethURLVar="EVM_ETH_URL_$i"
    local engineURL="${!engineURLVar:-http://127.0.0.1:8551}"
    local ethURL="${!ethURLVar:-http://127.0.0.1:8545}"
    executorArgs=(--engine-url "$engineURL" --eth-url "$ethURL" --jwt-secret "test-nodes/evm$i/jwt.hex")
	if [ -n "${EVM_ENGINE_FEE_COLLECTOR:-}" ]; then
      executorArgs+=(--engine-fee-collector "$EVM_ENGINE_FEE_COLLECTOR")
	fi
	if [ -n "${EVM_EXECUTION_JOURNAL_ROOT:-}" ]; then
	  executorArgs+=(--execution-journal "$EVM_EXECUTION_JOURNAL_ROOT/evm$i.db")
	fi
	if [ -n "${EVM_GENESIS_FILE:-}" ]; then
	  if [ -z "${EVM_FULL_SHARD_CONF:-}" ]; then
	    echo "EVM_GENESIS_FILE requires EVM_FULL_SHARD_CONF" >&2
	    return 1
	  fi
	  executorArgs+=(--genesis "$EVM_GENESIS_FILE")
	  executorArgs+=(--execution-journal "test-nodes/evm$i/execution-journal.db")
	  shardConfArgs=(--full-shard-conf "$EVM_FULL_SHARD_CONF")
	fi
	if [ -n "${EVM_ARCHIVE_ROOT:-}" ]; then
	  local replicaCount=0 peerID
	  # Bounded at 32 to tolerate one-at-a-time authority restarts while archive
	  # replicas catch up; a persistent publication stall still fails loudly. A lane that stops and restores validators on purpose
	  # (the H3 rotation lane) raises it with EVM_JOURNAL_CANDIDATES: with two replicas down the frontier cannot advance for the
	  # whole acknowledgement window.
	  executorArgs+=(--archive-store "$EVM_ARCHIVE_ROOT/evm$i" --archive-prune --journal-candidates "${EVM_JOURNAL_CANDIDATES:-32}")
	  # EVM_ARCHIVE_REPLICA_POOL (ids) names the candidates after a validator-set change: a retired validator is not a valid replica
	  # of the installed assignment, and the node refuses to start naming one.
	  for j in ${EVM_ARCHIVE_REPLICA_POOL:-$(seq 2 "$n")}; do
	    [ "$j" = "$i" ] && continue
	    peerID=$(evm_validator_id "$j") || return 1
	    executorArgs+=(--archive-replica "$peerID")
	    replicaCount=$((replicaCount + 1))
	    [ "$replicaCount" -lt 2 ] || break
	  done
	fi
  fi

  # Expanded as ${arr[@]+"${arr[@]}"} below, and $6 defaulted above, so this function works under
  # `set -u`. macOS's /bin/bash 3.2 treats "${empty[@]}" as an unbound variable, which aborted the
  # function mid-way for a `set -u` caller: the node was never started and nothing said so.
  # scripts/chaos-evm.sh never hit it because it does not set -u; scripts/reth-chaos.sh does.
  local rpcArgs=()
  if [ "$exposeRPC" == "rpc" ]; then
    rpcArgs=(--rpc-server-address "$(evm_validator_rpc_addr "$i")")
  fi

  local signingArgs=()
  if [ "${SIGNING:-local}" = authority ]; then
    signingArgs=(--signing-authority-socket "test-nodes/auth$i/client.sock" \
      --signing-authority-credential "test-nodes/auth$i/client.cred")
  fi

  local profileArgs=()
  if [ "${M2_PROFILE2:-0}" = 1 ]; then
    if [ -z "${EVM_GENESIS_FILE:-}" ]; then
      echo "M2_PROFILE2 requires the checked execution journal origin" >&2
      return 1
    fi
    profileArgs=(--trust-history-profile-2)
  fi

  # The registry layout only matters to the engine-api executor; resolve it from the run's persisted file.
  local layoutArgs=()
  if [ "$executor" = engine-api ] && [ -n "${EVM_B1_PROFILE:-}" ]; then
    # Fresh-B1 deployment (DN-B): the profile selects registry layout 3; the artifact is pinned in b1registry, not a layout file.
    layoutArgs=(--b1-profile "$EVM_B1_PROFILE")
  elif [ "$executor" = engine-api ]; then
    registry_layout_require || return 1
    layoutArgs=(--registry-layout "$(registry_layout)")
  fi

  build/ubft shard-node run --home "test-nodes/evm$i" --executor "$executor" \
    --address "/ip4/127.0.0.1/tcp/$port" --bootnodes "$bootnodes" \
    --trust-base test-nodes/trust-base.json \
    ${shardConfArgs[@]+"${shardConfArgs[@]}"} \
    --log-format text --log-level "${EVM_VALIDATOR_LOG_LEVEL:-info}" \
    ${executorArgs[@]+"${executorArgs[@]}"} ${rpcArgs[@]+"${rpcArgs[@]}"} \
    ${signingArgs[@]+"${signingArgs[@]}"} \
    ${profileArgs[@]+"${profileArgs[@]}"} ${layoutArgs[@]+"${layoutArgs[@]}"} \
    >> "test-nodes/evm$i/debug.log" 2>&1 &
  echo $! > "test-nodes/evm$i/pid"
}

# --- ownership -------------------------------------------------------------------------------
#
# Teardown stops only what this checkout started. A process is this checkout's only if it is alive,
# runs the expected command, AND has this checkout as its working directory (every node and client
# the scripts here start is started from the repository root). A pid file alone is not proof: the
# integer in it may be stale and reused by anything — on a shared host, another checkout's node. And
# a command name alone is not proof either: stop-evm.sh -a once stopped every `build/ubft root-node`
# on the machine, which on a shared host includes other people's root chains.

# proc_cwd <pid> prints the working directory of a process, or nothing.
function proc_cwd() {
  if [ -d "/proc/$1" ]; then
    readlink "/proc/$1/cwd" 2>/dev/null
  else
    lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1
  fi
}

# owned_pid <pid> <command-regex> succeeds only if <pid> is alive, its command line matches the
# regex, and its working directory is this checkout.
function owned_pid() {
  local pid=$1 pattern=$2
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  ps -o command= -p "$pid" 2>/dev/null | grep -qE -- "$pattern" || return 1
  [ "$(proc_cwd "$pid")" = "$(pwd -P)" ]
}

# owned_pids <command-regex> prints every process of this checkout whose command line matches, pid
# file or not — the nodes a pid file was never written for, or was lost for.
function owned_pids() {
  local p
  for p in $(pgrep -f -- "$1" 2>/dev/null); do
    owned_pid "$p" "$1" && echo "$p"
  done
  return 0
}

# stop_pidfile <pidfile> <command-regex> [signal] signals the process a pid file records only if it
# is this checkout's (see owned_pid), and removes the pid file either way: a stale one is never
# acted on, and never left for the next caller to act on.
function stop_pidfile() {
  local pidfile=$1 pattern=$2 sig=${3:-TERM} pid
  [ -f "$pidfile" ] || return 0
  pid=$(cat "$pidfile" 2>/dev/null)
  if owned_pid "$pid" "$pattern"; then
    kill "-$sig" "$pid" 2>/dev/null
  fi
  rm -f "$pidfile"
  return 0
}

# stop_evm_validators - stop every started validator by its recorded pid, if it is still this
# checkout's
function stop_evm_validators() {
  local pidfile
  for pidfile in test-nodes/evm*/pid; do
    stop_pidfile "$pidfile" 'ubft shard-node run'
  done
  return 0
}

# stop_root_nodes - stop this checkout's root nodes: those with a recorded pid, and any other
# `ubft root-node` whose working directory is this checkout (nodes started before pids were
# recorded). Never a root node by name alone.
function stop_root_nodes() {
  local pidfile p
  for pidfile in test-nodes/root*/pid; do
    stop_pidfile "$pidfile" 'ubft root-node'
  done
  for p in $(owned_pids 'ubft root-node'); do
    kill "$p" 2>/dev/null
  done
  return 0
}

# stop_one_evm_validator - kill validator $1 by its recorded pid, e.g. for
# scripts/chaos-evm.sh's kill-leader/kill-follower scenarios. $2 selects the
# signal (default TERM; pass KILL for an unclean kill, simulating a crash
# rather than a graceful shutdown).
function stop_one_evm_validator() {
  local i=$1 sig=${2:-TERM}
  local pidfile="test-nodes/evm$i/pid"
  [ -f "$pidfile" ] || { echo "no pid file for validator $i (already stopped?)" >&2; return 1; }
  # a validator brought back by `shard-node restore` is as much this validator as one started by `run`
  stop_pidfile "$pidfile" 'ubft shard-node (run|restore)' "$sig"
}
