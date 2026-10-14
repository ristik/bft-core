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
rethEngineBase=18551 rethEthBase=18545 rethP2PBase=30401 rootRpcPort=25866
case "${DNB_AGG_SHARDS:-1}" in 1|2) ;; *) echo "DNB_AGG_SHARDS must be 1 or 2" >&2; exit 2 ;; esac
. scripts/lib/reth-pin.sh   # definitions only: urethB1GenesisCommitment
source scripts/lib/agg-lib.sh   # the aggregator shard(s) and the bridge deployment, shared with the any-age lane (definitions only)
: "${URETH_BIN:?set URETH_BIN to the pinned unicity-reth}"
# The binary is attested, never built here: URETH_SHA256 (the attested file hash) and URETH_COMMIT (the full commit its --version reports)
# and URETH_PROVENANCE (the build's provenance directory: commit.txt is the pin, sha256.txt records the digest, as for the T6 harness) are
# REQUIRED for the two-shard lane and checked in `up` and again before any restart; a missing or mismatching record fails closed. The result,
# with the provenance path, is kept in test-nodes/ureth-attestation.json.
verify_ureth() {
  local sha ver commit
  sha=$(shasum -a 256 "$URETH_BIN" | cut -d' ' -f1)
  ver=$("$URETH_BIN" --version 2>&1) || true
  commit=$(printf '%s\n' "$ver" | sed -n 's/^Commit SHA: //p' | head -1)
  if [ "$aggShards" = 2 ]; then : "${URETH_SHA256:?set URETH_SHA256 to the attested sha256 of URETH_BIN}" "${URETH_COMMIT:?set URETH_COMMIT to the attested full ureth commit}" "${URETH_PROVENANCE:?set URETH_PROVENANCE to the build provenance directory}"; fi
  if [ -n "${URETH_PROVENANCE:-}" ]; then
    [ -f "$URETH_PROVENANCE/commit.txt" ] && [ -f "$URETH_PROVENANCE/sha256.txt" ] || { echo "URETH_PROVENANCE $URETH_PROVENANCE lacks commit.txt or sha256.txt" >&2; exit 1; }
    [ "$(tr -d '[:space:]' <"$URETH_PROVENANCE/commit.txt")" = "${URETH_COMMIT:-}" ] || { echo "provenance $URETH_PROVENANCE does not name commit ${URETH_COMMIT:-<unset>}" >&2; exit 1; }
    grep -q "^$sha " "$URETH_PROVENANCE/sha256.txt" || { echo "provenance $URETH_PROVENANCE does not record sha256 $sha" >&2; exit 1; }
  fi
  if [ -n "${URETH_SHA256:-}" ] && [ "$sha" != "$URETH_SHA256" ]; then echo "URETH_BIN sha256 $sha != attested $URETH_SHA256" >&2; exit 1; fi
  if [ -n "${URETH_COMMIT:-}" ] && [ "$commit" != "$URETH_COMMIT" ]; then echo "URETH_BIN reports commit '$commit' != attested $URETH_COMMIT" >&2; exit 1; fi
  python3 - "$URETH_BIN" "$sha" "$commit" "$ver" "${URETH_PROVENANCE:-}" <<'PY'
import json, sys
json.dump({"path": sys.argv[1], "sha256": sys.argv[2], "commit": sys.argv[3], "version": sys.argv[4], "provenance": sys.argv[5]}, open("test-nodes/ureth-attestation.json", "w"), indent=2)
PY
  info "ureth $commit sha256 $sha verified"
}
fee=${DNB_FEE_COLLECTOR:-0x000000000000000000000000000000000000dead}
# Restarted validators vote again only with an independent signing record (#105): SIGNING=authority keeps one per validator in a separate process that is not restarted.
export M2_PROFILE2=1 SIGNING=${DNB_SIGNING:-authority}

info() { echo "dnb: $*"; }
rpc() { curl -sS --max-time 10 -X POST "$1" -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"; }

down() {
  for p in test-nodes/auth*/pid; do [ -f "$p" ] && stop_pidfile "$p" 'ubft signing-authority' || true; done
  for p in test-nodes/reth*/pid; do [ -f "$p" ] && stop_pidfile "$p" 'unicity-reth|reth.* node' || true; done
  stop_aggs
  stop_evm_validators 2>/dev/null || true
  stop_root_nodes 2>/dev/null || true
}

up() {
  [ -x build/ubft ] || { echo "build/ubft missing (go build -o build/ubft ./cli/ubft)" >&2; exit 1; }
  rm -rf test-nodes; mkdir test-nodes
  verify_ureth
  info "identities and shard topology"
  init_root_nodes "$rootValidators" >/dev/null
  init_evm_validators "$validators" >/dev/null
  if [ "$SIGNING" = authority ]; then init_evm_authorities "$validators" "$partitionID" >/dev/null; fi
  generate_evm_shard_conf "$validators" "$partitionID" "$chainID" 5000 exec >/dev/null
  conf=test-nodes/shard-conf-${partitionID}_0.json

  info "B1 profile, funded genesis, identities"
  build/ubft engine-api b1-profile --shard-conf "$conf" --trust-base test-nodes/trust-base.json --max-epochs-per-update "${DNB_MAX_EPOCHS:-2}" --delta-ev "${DNB_DELTA_EV:-31}" --delta-hold "${DNB_DELTA_HOLD:-32}" --out test-nodes/b1-profile.json | tee test-nodes/b1-profile.out
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
  ureth_flags="$ureth_flags --unicity.genesis-commitment $(URETH_GENESIS_SPEC=test-nodes/evm-genesis-finalized.json urethB1GenesisCommitment)" || exit 1

  if [ "${DNB_AGG:-1}" = 1 ]; then agg_prepare_confs; fi

  # DNB_PREP_ONLY=1: stop here, after every offline input exists (a lane dry run that starts no process and takes no port).
  if [ -n "${DNB_PREP_ONLY:-}" ]; then info "prep only: genesis, profile, identities and aggregator shard configurations generated"; return 0; fi
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
  if [ "${DNB_AGG:-1}" = 1 ]; then start_aggs || exit 1; fi
  info "up; roots rpc 127.0.0.1:25866, reth eth $rethEthBase.., engine $rethEngineBase.."
}

# Restarts: SIGTERM one process of the running devnet and start it again from its own state.
start_reth() { # N: start (or restart) validator N's ureth on its datadir
  local i=$1 ureth_flags; ureth_flags=$(sed -n 's/^ureth flags: *//p' test-nodes/b1-profile.out); ureth_flags="$ureth_flags --unicity.genesis-commitment $(URETH_GENESIS_SPEC=test-nodes/evm-genesis-finalized.json urethB1GenesisCommitment)"
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
  verify_ureth
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
  verify_ureth
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

status() {
  for i in $(seq 1 "$validators"); do
    printf 'reth%s block=%s\n' "$i" "$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_blockNumber '[]' | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo down)"
  done
  curl -fsS http://127.0.0.1:$rootRpcPort/api/v1/roundInfo 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print('root round',d['roundNumber'])" || echo "root rpc down"
}

vault() { BRIDGE_IDENTITIES=test-nodes/genesis-identities.json bridge_deploy_vault; }
config() { BRIDGE_FULL_CONF=test-nodes/evm-full-shard-conf.json bridge_write_config; }

case "${1:-}" in restart-agg) restart_agg "${2:-}" ;; restart-all) restart_all_validators ;; restart-validator) restart_validator "${2:?validator number}" ;; all) up && { [ -n "${DNB_PREP_ONLY:-}" ] || { vault && config; }; } ;; config) config ;; vault) vault ;; up) up ;; down) down ;; status) status ;; *) echo "usage: $0 up|down|status" >&2; exit 2 ;; esac
