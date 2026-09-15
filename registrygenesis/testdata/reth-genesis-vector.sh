#!/usr/bin/env bash
# Produces reth-genesis-vector.json: what the pinned reth reports for genesis-vector.json, the genesis file
# registrygenesis generates for the #153 §5.4 configuration with the merged registry artifact.
#
# It initializes reth from the file, starts it with networking and discovery disabled, and records the
# genesis block hash from `reth init`, the block-0 hash and raw header over RPC, and eth_getProof for
# a_sr and the 22 slot keys requested by block hash (EIP-1898). Nothing is sent to a network. The node is
# stopped by its own PID. This shows what the pinned client computes and serves at genesis; it says
# nothing about proof availability for later blocks, which the next unit measures.
#
# Usage: reth-genesis-vector.sh <reth binary> <scratch directory>   (curl and jq on PATH)
set -euo pipefail

reth=${1:?reth binary}
work=${2:?scratch directory}
here="$(cd "$(dirname "$0")" && pwd)"
genesis="$here/genesis-vector.json"
out="$here/reth-genesis-vector.json"
http_port=18645
rpc="http://127.0.0.1:$http_port"
a_sr=0xff00000000000000000000000000000000000002

rm -rf "$work/data"
mkdir -p "$work"
"$reth" init --chain "$genesis" --datadir "$work/data" >"$work/init.log" 2>&1
init_hash=$(sed -e 's/\x1b\[[0-9;]*m//g' "$work/init.log" | sed -n 's/.*Genesis block written hash=\(0x[0-9a-f]\{64\}\).*/\1/p' | tail -1)
[ -n "$init_hash" ] || { echo "reth init reported no genesis hash" >&2; cat "$work/init.log" >&2; exit 1; }

"$reth" node --chain "$genesis" --datadir "$work/data" \
	--disable-discovery --max-outbound-peers 0 --max-inbound-peers 0 --port 30399 \
	--http --http.addr 127.0.0.1 --http.port "$http_port" --http.api eth,debug \
	--authrpc.port 18651 --ipcdisable >"$work/node.log" 2>&1 &
node_pid=$!
trap 'kill "$node_pid" 2>/dev/null || true; wait "$node_pid" 2>/dev/null || true' EXIT

call() { curl -sf -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$rpc"; }
for _ in $(seq 1 120); do
	call eth_chainId '[]' >/dev/null 2>&1 && break
	sleep 0.5
done

block=$(call eth_getBlockByNumber '["0x0",false]' | jq -c .result)
hash=$(jq -r .hash <<<"$block")
header=$(call debug_getRawHeader "[\"$hash\"]" | jq -r .result)
keys=$(jq -c '[.slotKeys[].key]' "$here/../seal-registry-v1.json")
proof=$(call eth_getProof "[\"$a_sr\",$keys,{\"blockHash\":\"$hash\"}]" | jq -c .result)

jq -n \
	--arg generator "$("$reth" --version | head -2 | tr '\n' ' ')" \
	--arg initHash "$init_hash" \
	--arg rpcHash "$hash" \
	--arg stateRoot "$(jq -r .stateRoot <<<"$block")" \
	--arg header "$header" \
	--argjson proof "$proof" \
	'{generator: $generator, initGenesisHash: $initHash, rpcBlock0Hash: $rpcHash, stateRoot: $stateRoot,
	  header: $header, proof: $proof}' >"$out"
echo "wrote $out genesis $init_hash"
