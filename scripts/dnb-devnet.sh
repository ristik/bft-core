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

validators=4 rootValidators=4 partitionID=8 chainID=${DNB_CHAIN_ID:-31337}
rethEngineBase=18551 rethEthBase=18545 rethP2PBase=30401
: "${URETH_BIN:?set URETH_BIN to the pinned unicity-reth}"
fee=${DNB_FEE_COLLECTOR:-0x000000000000000000000000000000000000dead}
export M2_PROFILE2=1 SIGNING=local

info() { echo "dnb: $*"; }
rpc() { curl -sS --max-time 10 -X POST "$1" -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"; }

down() {
  for p in test-nodes/reth*/pid; do [ -f "$p" ] && stop_pidfile "$p" 'unicity-reth|reth.* node' || true; done
  stop_evm_validators 2>/dev/null || true
  stop_root_nodes 2>/dev/null || true
}

up() {
  [ -x build/ubft ] || { echo "build/ubft missing (go build -o build/ubft ./cli/ubft)" >&2; exit 1; }
  rm -rf test-nodes; mkdir test-nodes
  info "identities and shard topology"
  init_root_nodes "$rootValidators" >/dev/null
  init_evm_validators "$validators" >/dev/null
  generate_evm_shard_conf "$validators" "$partitionID" "$chainID" 5000 exec >/dev/null
  conf=test-nodes/shard-conf-${partitionID}_0.json

  info "B1 profile, funded genesis, identities"
  build/ubft engine-api b1-profile --shard-conf "$conf" --trust-base test-nodes/trust-base.json --out test-nodes/b1-profile.json | tee test-nodes/b1-profile.out
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
  ureth_flags=$(sed -n 's/^ureth flags: *//p' test-nodes/b1-profile.out)

  info "start one ureth per validator"
  for i in $(seq 1 "$validators"); do
    mkdir -p "test-nodes/reth$i"
    openssl rand -hex 32 >"test-nodes/evm$i/jwt.hex"
    # shellcheck disable=SC2086
    "$URETH_BIN" node --chain test-nodes/evm-genesis-finalized.json --datadir "test-nodes/reth$i/dd" \
      --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" --authrpc.addr 127.0.0.1 --authrpc.port $((rethEngineBase + i - 1)) \
      --http --http.addr 127.0.0.1 --http.port $((rethEthBase + i - 1)) --http.api eth,net,web3,admin,debug --rpc.eth-proof-window 64 \
      --port $((rethP2PBase + i - 1)) --disable-discovery --ipcdisable --engine.persistence-threshold 64 \
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
  export EVM_GENESIS_FILE=test-nodes/evm-genesis-finalized.json EVM_FULL_SHARD_CONF=$conf EVM_B1_PROFILE=test-nodes/b1-profile.json EVM_ENGINE_FEE_COLLECTOR=$fee
  for i in $(seq 1 "$validators"); do
    export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((rethEngineBase + i - 1))" "EVM_ETH_URL_$i=http://127.0.0.1:$((rethEthBase + i - 1))"
  done
  ./start-evm.sh -r -a -e engine-api -v "$validators" >test-nodes/start-evm.log 2>&1
  info "up; roots rpc 127.0.0.1:25866, reth eth $rethEthBase.., engine $rethEngineBase.."
}

status() {
  for i in $(seq 1 "$validators"); do
    printf 'reth%s block=%s\n' "$i" "$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" eth_blockNumber '[]' | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo down)"
  done
  curl -fsS http://127.0.0.1:25866/api/v1/roundInfo 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print('root round',d['roundNumber'])" || echo "root rpc down"
}

case "${1:-}" in up) up ;; down) down ;; status) status ;; *) echo "usage: $0 up|down|status" >&2; exit 2 ;; esac
