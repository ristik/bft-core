#!/usr/bin/env bash
# Produces reth-funded-genesis-vector.json: what the pinned reth reports for the finalized
# funded-genesis-vector.json, including the selected funded and code/storage allocations.
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
# TestRethFundedVectorScript* tests exercise the refusals offline with stand-in executables.
#
# Usage: reth-funded-genesis-vector.sh <reth binary> <scratch directory>
# Requires curl, jq and lsof on PATH. RETH_VECTOR_HTTP_PORT (default 18645),
# RETH_VECTOR_AUTH_PORT (default 18651), RETH_VECTOR_P2P_PORT (default 30399) and
# RETH_VECTOR_READY_SECONDS (default 60) may be overridden.
set -euo pipefail

pinned_commit=189c0df32617afc488e0f091dbface1bd72cceb4
reth=${1:?reth binary}
work=${2:?scratch directory}
here="$(cd "$(dirname "$0")" && pwd)"
genesis="$here/funded-genesis-vector.json"
out="$here/reth-funded-genesis-vector.json"
http_port=${RETH_VECTOR_HTTP_PORT:-18645}
auth_port=${RETH_VECTOR_AUTH_PORT:-18651}
p2p_port=${RETH_VECTOR_P2P_PORT:-30399}
ready_seconds=${RETH_VECTOR_READY_SECONDS:-60}
rpc="http://127.0.0.1:$http_port"
a_sr=0xff00000000000000000000000000000000000002
funded=0x1000000000000000000000000000000000000001
nonce_account=0x1000000000000000000000000000000000000002
code_account=0x2000000000000000000000000000000000000001
storage_key=0x0000000000000000000000000000000000000000000000000000000000000001
node_pid=""
tmp_out=""

fail() {
	echo "reth-funded-genesis-vector: $*" >&2
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
	--disable-discovery --max-outbound-peers 0 --max-inbound-peers 0 --port "$p2p_port" \
	--http --http.addr 127.0.0.1 --http.port "$http_port" --http.api eth,debug,web3 \
	--authrpc.port "$auth_port" --ipcdisable >"$work/node.log" 2>&1 &
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
	jq -e -s 'length == 1 and (.[0] | type == "object" and .jsonrpc == "2.0" and .id == 1 and
		(has("error") | not) and has("result") and .result != null)' \
		<<<"$response" >/dev/null 2>&1 || fail "$1: not a successful JSON-RPC result: $response"
	jq -c -s '.[0].result' <<<"$response"
	alive
}

quantity() {
	local value
	value=$(tr '[:upper:]' '[:lower:]' <<<"$1")
	[[ $value =~ ^0x[0-9a-f]+$ ]] || fail "$2 is not a hex quantity: $1"
	value=$(sed 's/^0x0*/0x/' <<<"$value")
	[ "$value" != "0x" ] || value=0x0
	printf '%s' "$value"
}

bytes_value() {
	local value
	value=$(tr '[:upper:]' '[:lower:]' <<<"$1")
	[[ $value =~ ^0x([0-9a-f][0-9a-f])*$ ]] || fail "$2 is not even-length hex bytes: $1"
	printf '%s' "$value"
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

accounts='{}'
capture_account() {
	local address=$1 with_storage=$2 expected_balance expected_nonce expected_code
	local actual_balance actual_nonce actual_code expected_storage actual_storage='{}'
	jq -e --arg a "$address" '.alloc | type == "object" and has($a) and (.[$a] | type == "object")' "$genesis" >/dev/null ||
		fail "finalized genesis has no allocation object for $address"
	jq -e --arg a "$address" '.alloc[$a] | has("balance") and (.balance | type == "string")' "$genesis" >/dev/null ||
		fail "finalized genesis has no explicit string balance for $address"
	expected_balance=$(jq -er --arg a "$address" '.alloc[$a].balance' "$genesis") || fail "finalized genesis has no readable balance for $address"
	expected_nonce=$(jq -er --arg a "$address" '.alloc[$a].nonce // "0x0"' "$genesis") || fail "finalized genesis has no readable nonce for $address"
	expected_code=$(jq -er --arg a "$address" '.alloc[$a].code // "0x"' "$genesis") || fail "finalized genesis has no readable code for $address"
	expected_balance=$(quantity "$expected_balance" "finalized balance for $address")
	expected_nonce=$(quantity "$expected_nonce" "finalized nonce for $address")
	expected_code=$(bytes_value "$expected_code" "finalized code for $address")

	actual_balance=$(call eth_getBalance "[\"$address\",{\"blockHash\":\"$hash\"}]" | jq -er .) || fail "eth_getBalance result for $address is not a string"
	actual_nonce=$(call eth_getTransactionCount "[\"$address\",{\"blockHash\":\"$hash\"}]" | jq -er .) || fail "eth_getTransactionCount result for $address is not a string"
	actual_code=$(call eth_getCode "[\"$address\",{\"blockHash\":\"$hash\"}]" | jq -er .) || fail "eth_getCode result for $address is not a string"
	actual_balance=$(quantity "$actual_balance" "eth_getBalance result for $address")
	actual_nonce=$(quantity "$actual_nonce" "eth_getTransactionCount result for $address")
	actual_code=$(bytes_value "$actual_code" "eth_getCode result for $address")
	[ "$actual_balance" = "$expected_balance" ] || fail "balance for $address is $actual_balance, finalized genesis requires $expected_balance"
	[ "$actual_nonce" = "$expected_nonce" ] || fail "nonce for $address is $actual_nonce, finalized genesis requires $expected_nonce"
	[ "$actual_code" = "$expected_code" ] || fail "code for $address is $actual_code, finalized genesis requires $expected_code"

	if [ "$with_storage" = 1 ]; then
		expected_storage=$(jq -er --arg a "$address" --arg k "$storage_key" '.alloc[$a].storage | select(type == "object" and (keys == [$k])) | .[$k]' "$genesis") ||
			fail "finalized storage for $address must contain exactly $storage_key"
		expected_storage=$(tr '[:upper:]' '[:lower:]' <<<"$expected_storage")
		[[ $expected_storage =~ ^0x[0-9a-f]{64}$ ]] || fail "finalized storage value for $address at $storage_key is not a 32-byte word: $expected_storage"
		local value
		value=$(call eth_getStorageAt "[\"$address\",\"0x1\",{\"blockHash\":\"$hash\"}]" | jq -er .) || fail "eth_getStorageAt result for $address is not a string"
		value=$(tr '[:upper:]' '[:lower:]' <<<"$value")
		[[ $value =~ ^0x[0-9a-f]{64}$ ]] || fail "eth_getStorageAt result for $address at $storage_key is not a 32-byte word: $value"
		[ "$value" = "$expected_storage" ] || fail "storage for $address at $storage_key is $value, finalized genesis requires $expected_storage"
		actual_storage=$(jq -n --arg k "$storage_key" --arg v "$value" '{($k):$v}')
	else
		jq -e --arg a "$address" '(.alloc[$a].storage // {}) == {}' "$genesis" >/dev/null || fail "finalized genesis has unqueried storage for $address"
	fi

	accounts=$(jq -c --arg a "$address" --arg balance "$actual_balance" --arg nonce "$actual_nonce" \
		--arg code "$actual_code" --argjson storage "$actual_storage" \
		'. + {($a): {balance:$balance, nonce:$nonce, code:$code, storage:$storage}}' <<<"$accounts")
}

capture_account "$funded" 0
capture_account "$nonce_account" 0
capture_account "$code_account" 1

owned
alive

tmp_out=$(mktemp "$here/.reth-funded-genesis-vector.XXXXXX")
jq -n \
	--arg generator "$(tr '\n' ' ' <<<"$version")" \
	--arg client "$client" \
	--arg initHash "$init_hash" \
	--arg rpcHash "$hash" \
	--arg stateRoot "$state_root" \
	--arg header "$header" \
	--argjson proof "$proof" \
	--argjson accounts "$accounts" \
	'{generator: $generator, clientVersion: $client, initGenesisHash: $initHash, rpcBlock0Hash: $rpcHash,
	  stateRoot: $stateRoot, header: $header, proof: $proof, accounts: $accounts}' >"$tmp_out"
jq -e '.initGenesisHash == .rpcBlock0Hash and (.proof | type == "object") and (.accounts | length == 3)' "$tmp_out" >/dev/null || fail "assembled vector failed its final check"
mv "$tmp_out" "$out"
tmp_out=""
echo "wrote $out genesis $init_hash"
