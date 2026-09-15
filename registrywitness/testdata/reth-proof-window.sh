#!/usr/bin/env bash
# Measures historical-proof availability on the pinned reth and writes reth-proof-window.json.
#
# For each proof window in RETH_WINDOW_WINDOWS (default "0 3"), it starts reth in dev mode on
# registrygenesis/testdata/genesis-vector.json with a fixed block time, so the head advances without a
# consensus client, and repeatedly requests block 1 and genesis BY HASH: eth_getProof, debug_getRawHeader
# and eth_getBlockByHash. Each proof request is bracketed by eth_blockNumber, and a sample is kept only
# when the head did not move during the request, so its distance is exact. It also records the responses
# for a block hash the client does not have, and the header and proof of block 1 and genesis taken inside
# the window, as vectors for registrywitness.
#
# The run fails, and the previous file is kept, unless for every window: every kept sample at distance
# <= window returned a proof, every kept sample at distance > window was refused with reth's proof-window
# error, samples exist at distance == window and window + 1 for block 1, and header and block lookups by
# hash succeeded at every distance. This is dev-mode evidence about the proof window of an archive node; it
# says nothing about pruned nodes (--full, --minimal) or about restarts.
#
# Evidence is accepted only from the process each run started, with the rules of
# registrygenesis/testdata/reth-genesis-vector.sh (review of #157): pinned --version and
# web3_clientVersion, no pre-existing listener, node alive and owning the port, validated JSON-RPC results,
# and publication through a temporary file. Every call's output is assigned before use, so a refusal
# inside a call always stops the script.
#
# Usage: reth-proof-window.sh <reth binary> <scratch directory>
# Requires curl, jq and lsof on PATH. Overrides: RETH_WINDOW_HTTP_PORT (18745), RETH_WINDOW_READY_SECONDS
# (60), RETH_WINDOW_BLOCK_TIME (2s), RETH_WINDOW_WINDOWS ("0 3"), RETH_WINDOW_SAMPLE_SLEEP (0.25).
set -euo pipefail

pinned_commit=189c0df32617afc488e0f091dbface1bd72cceb4
reth=${1:?reth binary}
work=${2:?scratch directory}
here="$(cd "$(dirname "$0")" && pwd)"
genesis="$here/../../registrygenesis/testdata/genesis-vector.json"
artifact="$here/../../registrygenesis/seal-registry-v1.json"
out="$here/reth-proof-window.json"
http_port=${RETH_WINDOW_HTTP_PORT:-18745}
ready_seconds=${RETH_WINDOW_READY_SECONDS:-60}
block_time=${RETH_WINDOW_BLOCK_TIME:-2s}
windows=${RETH_WINDOW_WINDOWS:-0 3}
sample_sleep=${RETH_WINDOW_SAMPLE_SLEEP:-0.25}
rpc="http://127.0.0.1:$http_port"
a_sr=0xff00000000000000000000000000000000000002
unknown_hash=0x1111111111111111111111111111111111111111111111111111111111111111
window_message="distance to target block exceeds maximum proof window"
node_pid=""
tmp_out=""

fail() {
	echo "reth-proof-window: $*" >&2
	exit 1
}

stop_node() {
	if [ -n "$node_pid" ]; then
		kill "$node_pid" 2>/dev/null || true
		wait "$node_pid" 2>/dev/null || true
		node_pid=""
	fi
}

cleanup() {
	stop_node
	[ -z "$tmp_out" ] || rm -f "$tmp_out"
}
trap cleanup EXIT

for tool in curl jq lsof; do
	command -v "$tool" >/dev/null || fail "$tool is required"
done
[ -f "$genesis" ] || fail "genesis file $genesis not found"
[ -f "$artifact" ] || fail "artifact $artifact not found"

version=$("$reth" --version 2>&1) || fail "$reth --version failed"
grep -q "Commit SHA: $pinned_commit\$" <<<"$version" || fail "$reth is not the pinned build $pinned_commit: $version"

alive() {
	kill -0 "$node_pid" 2>/dev/null || fail "the node this run started (pid $node_pid) is not running: $(tail -5 "$work/node.log" 2>/dev/null)"
}

owned() {
	local listeners
	listeners=$(lsof -nP -iTCP:"$http_port" -sTCP:LISTEN -t 2>/dev/null | sort -u | tr '\n' ' ' || true)
	[ "$listeners" = "$node_pid " ] || fail "the listener on port $http_port is '$listeners', not this run's node $node_pid"
}

# raw_call prints the whole JSON-RPC response object after checking the envelope: a result (which may be
# null, meaning not found) or an error object with a numeric code. The caller decides what each means.
raw_call() {
	local response
	alive
	response=$(curl -s -m 10 -H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$rpc") || fail "$1: no response from $rpc"
	jq -e 'type == "object" and .jsonrpc == "2.0" and (has("result") != has("error")) and (has("result") or ((.error | type == "object") and (.error.code | type == "number")))' \
		<<<"$response" >/dev/null 2>&1 || fail "$1: not a JSON-RPC result or error object: $response"
	alive
	printf '%s' "$response"
}

# call prints the non-null result of a call that must succeed.
call() {
	local response
	response=$(raw_call "$1" "$2") || exit 1
	jq -e 'has("result") and .result != null' <<<"$response" >/dev/null || fail "$1: no result: $response"
	jq -c .result <<<"$response"
}

# head_number sets HEAD to the current block number.
head_number() {
	local result n
	result=$(call eth_blockNumber '[]') || exit 1
	n=$(jq -r . <<<"$result")
	[[ $n =~ ^0x[0-9a-f]+$ ]] || fail "eth_blockNumber result is not a quantity: $n"
	HEAD=$((n))
}

# block_hash_at sets BLOCK_HASH to the hash of block $1.
block_hash_at() {
	local block
	block=$(call eth_getBlockByNumber "[\"$(printf '0x%x' "$1")\",false]") || exit 1
	jq -e '(.hash | test("^0x[0-9a-f]{64}$")) and (.number | test("^0x[0-9a-f]+$"))' <<<"$block" >/dev/null 2>&1 ||
		fail "eth_getBlockByNumber($1) result is malformed: $block"
	BLOCK_HASH=$(jq -r .hash <<<"$block")
}

keys=$(jq -c '[.slotKeys[].key]' "$artifact")
proof_params() { printf '["%s",%s,{"blockHash":"%s"}]' "$a_sr" "$keys" "$1"; }

valid_proof() {
	jq -e --arg a "$a_sr" --argjson keys "$keys" '
		(.address | ascii_downcase) == $a
		and (.accountProof | type == "array" and length > 0 and all(.[]; type == "string" and test("^0x([0-9a-f][0-9a-f])+$")))
		and ([.storageProof[].key] == $keys)
		and all(.storageProof[]; .proof | type == "array" and all(.[]; type == "string" and test("^0x([0-9a-f][0-9a-f])+$")))
	' <<<"$1" >/dev/null 2>&1
}

runs='[]'
client=""
genesis_hash=""
unknown_json=""
vectors='{}'

for window in $windows; do
	[[ $window =~ ^[0-9]+$ ]] || fail "window '$window' is not a non-negative integer"
	if curl -s -m 2 -o /dev/null "$rpc"; then
		fail "something already answers on $rpc; refusing to take evidence from it"
	fi
	if [ -n "$(lsof -nP -iTCP:"$http_port" -sTCP:LISTEN -t 2>/dev/null || true)" ]; then
		fail "port $http_port already has a listener"
	fi

	rm -rf "$work/data"
	mkdir -p "$work"
	"$reth" node --dev --dev.block-time "$block_time" --chain "$genesis" --datadir "$work/data" \
		--disable-discovery --max-outbound-peers 0 --max-inbound-peers 0 --port 30499 \
		--http --http.addr 127.0.0.1 --http.port "$http_port" --http.api eth,debug,web3 \
		--authrpc.port 18751 --ipcdisable --rpc.eth-proof-window "$window" >"$work/node.log" 2>&1 &
	node_pid=$!

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

	client_result=$(call web3_clientVersion '[]')
	client=$(jq -r . <<<"$client_result")
	client_sha=$(sed -n 's#^reth/v[^/]*-\([0-9a-f]\{7,40\}\)/.*$#\1#p' <<<"$client")
	if [ -z "$client_sha" ] || [ "${pinned_commit#"$client_sha"}" = "$pinned_commit" ]; then
		fail "web3_clientVersion '$client' does not name $pinned_commit"
	fi

	block_hash_at 0
	g=$BLOCK_HASH
	if [ -z "$genesis_hash" ]; then
		genesis_hash=$g
	fi
	[ "$g" = "$genesis_hash" ] || fail "genesis hash $g differs between runs ($genesis_hash)"

	if [ -z "$unknown_json" ]; then
		unknown_header=$(raw_call debug_getRawHeader "[\"$unknown_hash\"]")
		unknown_proof=$(raw_call eth_getProof "$(proof_params "$unknown_hash")")
		unknown_block=$(raw_call eth_getBlockByHash "[\"$unknown_hash\",false]")
		unknown_json=$(jq -n --arg h "$unknown_hash" --argjson header "$unknown_header" --argjson proof "$unknown_proof" \
			--argjson block "$unknown_block" '{hash: $h, rawHeader: $header, proof: $proof, blockByHash: $block}')
		for part in rawHeader proof blockByHash; do
			jq -e --arg p "$part" '.[$p] | has("error") or .result == null' <<<"$unknown_json" >/dev/null ||
				fail "the client returned $part for a block hash it cannot have: $unknown_json"
		done
	fi

	# Wait for block 1, then sample until the head is window + 3 blocks past it.
	deadline=$(($(date +%s) + ready_seconds * 2))
	head_number
	while [ "$HEAD" -lt 1 ]; do
		[ "$(date +%s)" -lt "$deadline" ] || fail "the dev miner did not produce block 1"
		sleep "$sample_sleep"
		head_number
	done
	block_hash_at 1
	b1=$BLOCK_HASH

	samples='[]'
	stop_at=$((1 + window + 3))
	deadline=$(($(date +%s) + ready_seconds * 4))
	while :; do
		for target in "1:$b1" "0:$g"; do
			number=${target%%:*}
			hash=${target#*:}
			head_number
			h1=$HEAD
			response=$(raw_call eth_getProof "$(proof_params "$hash")")
			head_number
			h2=$HEAD
			header_response=$(raw_call debug_getRawHeader "[\"$hash\"]")
			block_response=$(raw_call eth_getBlockByHash "[\"$hash\",false]")
			[ "$h1" = "$h2" ] || continue
			distance=$((h1 - number))
			if jq -e 'has("result") and .result != null' <<<"$response" >/dev/null; then
				result=$(jq -c .result <<<"$response")
				valid_proof "$result" || fail "eth_getProof($hash) at distance $distance is malformed: $result"
				outcome=proof
				name=$([ "$number" = 1 ] && echo block1 || echo genesis)
				if ! jq -e --arg n "$name" 'has($n)' <<<"$vectors" >/dev/null; then
					header=$(jq -r .result <<<"$header_response")
					vectors=$(jq -c --arg n "$name" --arg h "$hash" --arg header "$header" --argjson p "$result" \
						'. + {($n): {hash: $h, header: $header, proof: $p}}' <<<"$vectors")
				fi
			else
				jq -e --arg m "$window_message" '.error.code == -32602 and .error.message == $m' <<<"$response" >/dev/null ||
					fail "eth_getProof($hash) at distance $distance returned an unexpected response: $response"
				outcome=refused
			fi
			jq -e '(.result | type == "string" and test("^0x([0-9a-f][0-9a-f])+$"))' <<<"$header_response" >/dev/null ||
				fail "debug_getRawHeader($hash) at distance $distance failed: $header_response"
			jq -e --arg h "$hash" '.result.hash == $h' <<<"$block_response" >/dev/null ||
				fail "eth_getBlockByHash($hash) at distance $distance failed: $block_response"
			samples=$(jq -c --argjson n "$number" --argjson d "$distance" --arg o "$outcome" \
				'. + [{target: $n, distance: $d, outcome: $o}]' <<<"$samples")
		done
		head_number
		[ "$HEAD" -ge "$stop_at" ] && break
		[ "$(date +%s)" -lt "$deadline" ] || fail "the head did not reach $stop_at in time"
		sleep "$sample_sleep"
	done
	owned

	summary=$(jq -c 'group_by([.target, .distance, .outcome])
		| map({target: .[0].target, distance: .[0].distance, outcome: .[0].outcome, samples: length})' <<<"$samples")
	jq -e --argjson w "$window" '
		all(.[]; (.distance <= $w and .outcome == "proof") or (.distance > $w and .outcome == "refused"))
		and any(.[]; .target == 1 and .distance == $w and .outcome == "proof")
		and any(.[]; .target == 1 and .distance == ($w + 1) and .outcome == "refused")' <<<"$summary" >/dev/null ||
		fail "window $window: samples do not show proofs exactly up to the window with both boundary distances observed: $summary"

	runs=$(jq -c --argjson w "$window" --arg bt "$block_time" --arg b1 "$b1" --argjson s "$summary" \
		'. + [{window: $w, blockTime: $bt, block1: $b1, observed: $s}]' <<<"$runs")
	stop_node
done

jq -e 'has("block1") and has("genesis")' <<<"$vectors" >/dev/null || fail "no in-window proof was captured for block 1 and genesis"

tmp_out=$(mktemp "$here/.reth-proof-window.XXXXXX")
jq -n \
	--arg generator "$(tr '\n' ' ' <<<"$version")" \
	--arg client "$client" \
	--arg genesis "$genesis_hash" \
	--argjson runs "$runs" \
	--argjson unknown "$unknown_json" \
	--argjson vectors "$vectors" \
	--arg message "$window_message" \
	'{generator: $generator, clientVersion: $client, genesisHash: $genesis, proofWindowError: {code: -32602, message: $message},
	  runs: $runs, unknownBlock: $unknown, vectors: $vectors}' >"$tmp_out"
jq -e '(.runs | length) > 0 and (.vectors.block1.proof | type == "object") and (.vectors.genesis.proof | type == "object")' "$tmp_out" >/dev/null ||
	fail "assembled measurement failed its final check"
mv "$tmp_out" "$out"
tmp_out=""
echo "wrote $out"
