#!/usr/bin/env bash
# Generates anvil-registry-proof.json: an eth_getProof result and raw header for the SealRegistry, produced by
# anvil (Foundry; alloy-trie and revm), an implementation independent of go-ethereum's trie package.
#
# The registry account carries the real sealRegistry/v1 runtime code from ristik/unicity-pos-contracts
# (artifacts/seal-registry-v1.json) and the §9.4 post-state words of docs/design/f4a-seal-registry-contract.md,
# with named digests replaced by Keccak-256 of their names. It is installed with anvil_setCode and
# anvil_setStorageAt and committed by mining one Cancun block. This is proof-format evidence only: it says
# nothing about proof history on a running reth node.
#
# Usage: anvil-vector.sh <path to seal-registry-v1.json>   (anvil, cast and jq on PATH)
set -euo pipefail

artifact=${1:?path to seal-registry-v1.json}
out="$(cd "$(dirname "$0")" && pwd)/anvil-registry-proof.json"
port=18745
rpc="http://127.0.0.1:$port"
a_sr=0xff00000000000000000000000000000000000002

anvil --port "$port" --hardfork cancun --chain-id 1337 --silent &
anvil_pid=$!
trap 'kill "$anvil_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
	cast chain-id --rpc-url "$rpc" >/dev/null 2>&1 && break
	sleep 0.2
done

name_hash() { cast keccak "$1"; }
u() { cast to-uint256 "$1"; }

declare -A word=(
	[layoutVersion]=$(u 1)
	[genesisCommitment]=0x071a4f34498689e1f26353434c92f763ddaaba8de9cc634aa68af6e1bf65eab8
	[config.shardConfHash]=0x3a2c73649214e56d5e98d1c2d06cff56e7a5d67037a25bcf0e43fcaff8987a6b
	[assignment.rootEpoch]=$(u 1)
	[clock.rootRound]=$(u 9)
	[origin.rootEpoch]=$(u 1)
	[origin.timestamp]=$(u 1700000004)
	[origin.treeRoot]=$(name_hash U9)
	[origin.identity]=$(name_hash O9)
	[origin.trHash]=$(name_hash T9)
	[round.authorized]=$(u 4)
	[input.commitment]=$(name_hash X4)
	[certified.round]=$(u 2)
	[certified.stateHash]=$(name_hash S2)
	[certified.hasBlockHash]=$(u 1)
	[certified.blockHash]=$(name_hash B2)
	[phase]=$(u 2)
	[outcomes.round]=$(u 4)
	[outcomes.commitment]=$(name_hash R4)
)
names=(
	layoutVersion genesisCommitment config.shardConfHash assignment.epoch assignment.rootEpoch
	clock.rootRound origin.rootEpoch origin.timestamp origin.treeRoot origin.identity origin.trHash
	round.authorized input.commitment certified.round certified.stateHash certified.hasBlockHash
	certified.blockHash phase outcomes.round outcomes.commitment transition.cursor inbox.consumed
	transition.bodyID transition.genesisID transition.frozenID transition.commitID
	transition.frozenParent transition.successorTR
)

code=$(jq -r .runtimeBytecode "$artifact")
cast rpc --rpc-url "$rpc" anvil_setCode "$a_sr" "$code" >/dev/null

keys=()
words='{}'
for name in "${names[@]}"; do
	key=$(cast keccak "unicity.seal-registry.v1/$name")
	keys+=("\"$key\"")
	if [ -n "${word[$name]:-}" ]; then
		cast rpc --rpc-url "$rpc" anvil_setStorageAt "$a_sr" "$key" "${word[$name]}" >/dev/null
		words=$(jq -c --arg n "$name" --arg v "${word[$name]}" '. + {($n): $v}' <<<"$words")
	fi
done
cast rpc --rpc-url "$rpc" evm_mine >/dev/null

block=$(cast rpc --rpc-url "$rpc" eth_getBlockByNumber latest false)
hash=$(jq -r .hash <<<"$block")
header=$(cast block "$hash" --rpc-url "$rpc" --raw)
key_list="[$(IFS=,; echo "${keys[*]}")]"
proof=$(cast rpc --rpc-url "$rpc" eth_getProof "$a_sr" "$key_list" "{\"blockHash\":\"$hash\"}")

jq -n \
	--arg generator "$(anvil --version | head -1)" \
	--arg codeHash "$(cast keccak "$code")" \
	--arg hash "$hash" \
	--arg number "$(jq -r .number <<<"$block")" \
	--arg header "$header" \
	--argjson words "$words" \
	--argjson proof "$proof" \
	'{generator: $generator, hardfork: "cancun", registryCodeHash: $codeHash, blockHash: $hash,
	  blockNumber: $number, header: $header, words: $words, proof: $proof}' >"$out"
echo "wrote $out block $hash"
