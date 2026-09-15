#!/usr/bin/env bash
# Produces reth-genesis-vector.json: what the pinned reth reports for genesis-vector.json, the genesis file
# registrygenesis generates for the #153 §5.4 configuration with the merged registry artifact.
#
# It initializes reth from the file, starts it with discovery and peers disabled, and records the genesis
# block hash from `reth init`, the block-0 hash and state root, the raw header, and eth_getProof for a_sr and
# the 22 slot keys requested by block hash (EIP-1898). Nothing is sent to a network. This shows what the
# pinned client computes and serves at genesis; it says nothing about proof availability for later blocks.
#
# Evidence is accepted only from the process this run started (review of #157):
#   - the binary must report the pinned commit, before and over RPC (web3_clientVersion);
#   - nothing may answer on the RPC port before the node starts;
#   - the node must stay alive through every call, and the listener on the port must be its PID;
#   - every JSON-RPC response must carry no error and a result of the expected type and length, and the
#     init and RPC genesis hashes must agree.
# The vector is written to a temporary file in the same directory and moved over the retained vector only
# after all checks pass, so a failed run leaves the previous vector unchanged. registrygenesis's
# TestRethVectorScript* tests exercise the refusals offline with stand-in executables.
#
# Usage: reth-genesis-vector.sh <reth binary> <scratch directory>
# Requires curl, jq and lsof on PATH. RETH_VECTOR_HTTP_PORT (default 18645) and RETH_VECTOR_READY_SECONDS
# (default 60) may be overridden.
set -euo pipefail

pinned_commit=189c0df32617afc488e0f091dbface1bd72cceb4
reth=${1:?reth binary}
work=${2:?scratch directory}
here="$(cd "$(dirname "$0")" && pwd)"
genesis="$here/genesis-vector.json"
out="$here/reth-genesis-vector.json"
http_port=${RETH_VECTOR_HTTP_PORT:-18645}
ready_seconds=${RETH_VECTOR_READY_SECONDS:-60}
rpc="http://127.0.0.1:$http_port"
a_sr=0xff00000000000000000000000000000000000002
node_pid=""
tmp_out=""

fail() {
	echo "reth-genesis-vector: $*" >&2
	exit 1
}

cleanup() {
	if [ -n "$node_pid" ]; then
		kill "$node_pid" 2>/dev/null || true
		wait "$node_pid" 2>/dev/null || true
	fi
	if [ -n "$tmp_out" ]; then
		rm -f "$tmp_out"
	fi
}
trap cleanup EXIT

for tool in curl jq lsof; do
	command -v "$tool" >/dev/null || fail "$tool is required"
done

# The pin, before anything runs.
version=$("$reth" --version 2>&1) || fail "$reth --version failed"
grep -q "Commit SHA: $pinned_commit\$" <<<"$version" || fail "$reth is not the pinned build $pinned_commit: $version"

# Nothing may already answer on the RPC port.
if curl -s -m 2 -o /dev/null "$rpc"; then
	fail "something already answers on $rpc; refusing to take evidence from it"
fi
if [ -n "$(lsof -nP -iTCP:"$http_port" -sTCP:LISTEN -t 2>/dev/null || true)" ]; then
	fail "port $http_port already has a listener"
fi

rm -rf "$work/data"
mkdir -p "$work"
"$reth" init --chain "$genesis" --datadir "$work/data" >"$work/init.log" 2>&1 || fail "reth init failed: $(tail -5 "$work/init.log")"
init_hash=$(sed -e 's/\x1b\[[0-9;]*m//g' "$work/init.log" | sed -n 's/.*Genesis block written hash=\(0x[0-9a-f]\{64\}\).*/\1/p' | tail -1)
[ -n "$init_hash" ] || fail "reth init reported no genesis hash"

"$reth" node --chain "$genesis" --datadir "$work/data" \
	--disable-discovery --max-outbound-peers 0 --max-inbound-peers 0 --port 30399 \
	--http --http.addr 127.0.0.1 --http.port "$http_port" --http.api eth,debug,web3 \
	--authrpc.port 18651 --ipcdisable >"$work/node.log" 2>&1 &
node_pid=$!

alive() {
	kill -0 "$node_pid" 2>/dev/null || fail "the node this run started (pid $node_pid) is not running: $(tail -5 "$work/node.log")"
}

# owned requires the only listener on the port to be this run's node.
owned() {
	local listeners
	listeners=$(lsof -nP -iTCP:"$http_port" -sTCP:LISTEN -t 2>/dev/null | sort -u | tr '\n' ' ' || true)
	[ "$listeners" = "$node_pid " ] || fail "the listener on port $http_port is '$listeners', not this run's node $node_pid"
}

# call prints the result of a JSON-RPC call, refusing transport failures, JSON-RPC errors and null results.
call() {
	local response
	alive
	response=$(curl -s -m 10 -H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$rpc") || fail "$1: no response from $rpc"
	jq -e 'type == "object" and .jsonrpc == "2.0" and (has("error") | not) and has("result") and .result != null' \
		<<<"$response" >/dev/null 2>&1 || fail "$1: not a successful JSON-RPC result: $response"
	jq -c .result <<<"$response"
	alive
}

ready=""
for _ in $(seq 1 $((ready_seconds * 2))); do
	alive
	if [ -n "$(lsof -nP -iTCP:"$http_port" -sTCP:LISTEN -t 2>/dev/null || true)" ]; then
		ready=1
		break
	fi
	sleep 0.5
done
[ -n "$ready" ] || fail "the node did not listen on port $http_port within $ready_seconds seconds"
owned

# reth reports reth/v<version>-<short commit>/<target>; the short commit must be a prefix of the pin, at
# least 7 hex digits long (the pinned build reports 189c0df).
client=$(call web3_clientVersion '[]' | jq -r .)
client_sha=$(sed -n 's#^reth/v[^/]*-\([0-9a-f]\{7,40\}\)/.*$#\1#p' <<<"$client")
if [ -z "$client_sha" ] || [ "${pinned_commit#"$client_sha"}" = "$pinned_commit" ]; then
	fail "web3_clientVersion '$client' does not name $pinned_commit"
fi

hash32='^0x[0-9a-f]{64}$'
block=$(call eth_getBlockByNumber '["0x0",false]')
jq -e --arg re "$hash32" '(.hash | test($re)) and (.stateRoot | test($re)) and .number == "0x0"' <<<"$block" >/dev/null 2>&1 ||
	fail "eth_getBlockByNumber(0) result is malformed: $block"
hash=$(jq -r .hash <<<"$block")
state_root=$(jq -r .stateRoot <<<"$block")
[ "$hash" = "$init_hash" ] || fail "RPC block 0 hash $hash differs from the reth init hash $init_hash"

header=$(call debug_getRawHeader "[\"$hash\"]" | jq -r .)
[[ $header =~ ^0x([0-9a-f][0-9a-f])+$ ]] || fail "debug_getRawHeader result is not hex bytes: $header"

keys=$(jq -c '[.slotKeys[].key]' "$here/../seal-registry-v1.json")
proof=$(call eth_getProof "[\"$a_sr\",$keys,{\"blockHash\":\"$hash\"}]")
jq -e --arg a "$a_sr" --argjson keys "$keys" '
	(.address | ascii_downcase) == $a
	and (.accountProof | type == "array" and length > 0 and all(.[]; type == "string" and test("^0x([0-9a-f][0-9a-f])+$")))
	and (.storageProof | type == "array" and length == ($keys | length))
	and ([.storageProof[].key] == $keys)
	and all(.storageProof[]; .proof | type == "array" and all(.[]; type == "string" and test("^0x([0-9a-f][0-9a-f])+$")))
' <<<"$proof" >/dev/null 2>&1 || fail "eth_getProof result is malformed or not for $a_sr and the 22 keys"

owned
alive

tmp_out=$(mktemp "$here/.reth-genesis-vector.XXXXXX")
jq -n \
	--arg generator "$(tr '\n' ' ' <<<"$version")" \
	--arg client "$client" \
	--arg initHash "$init_hash" \
	--arg rpcHash "$hash" \
	--arg stateRoot "$state_root" \
	--arg header "$header" \
	--argjson proof "$proof" \
	'{generator: $generator, clientVersion: $client, initGenesisHash: $initHash, rpcBlock0Hash: $rpcHash,
	  stateRoot: $stateRoot, header: $header, proof: $proof}' >"$tmp_out"
jq -e '.initGenesisHash == .rpcBlock0Hash and (.proof | type == "object")' "$tmp_out" >/dev/null || fail "assembled vector failed its final check"
mv "$tmp_out" "$out"
tmp_out=""
echo "wrote $out genesis $init_hash"
