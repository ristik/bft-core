#!/bin/bash
root_nodes=3
validators=4
partition_id=8
chain_id=31337
t2_timeout=5000
proof_type=exec
# exit on error
set -e

usage() {
  echo "Generate 'test-nodes' structure for an EVM shard: root chain + N shard validators."
  echo "Usage: $0 [-h usage] [-r number of root nodes] [-v number of validators]"
  echo "          [-p partition id] [-c EVM chain id] [-t T2 timeout ms] [-P proof_type]"
  echo
  echo "Mirrors setup-nodes.sh but also generates shard validator identities, the EVM"
  echo "shard conf, and (via 'ubft engine-api genesis') a reth-compatible genesis.json"
  echo "derived from that shard conf — see docs/engine-api-adapter-plan.md."
  exit 0
}

while getopts "hr:v:p:c:t:P:" o; do
  case "${o}" in
  r) root_nodes=${OPTARG} ;;
  v) validators=${OPTARG} ;;
  p) partition_id=${OPTARG} ;;
  c) chain_id=${OPTARG} ;;
  t) t2_timeout=${OPTARG} ;;
  P) proof_type=${OPTARG} ;;
  h | *) usage ;;
  esac
done

echo "clearing 'test-nodes' directory and building Unicity"
make clean build
mkdir test-nodes

source helper.sh

init_root_nodes "$root_nodes"
init_evm_validators "$validators"
generate_evm_shard_conf "$validators" "$partition_id" "$chain_id" "$t2_timeout" "$proof_type"
generate_evm_genesis "$partition_id"

generate_log_configuration "test-nodes/*/"

echo
echo "EVM shard ready: $root_nodes root node(s), $validators validator(s), partition $partition_id, chain_id $chain_id, proof_type=$proof_type"
echo "next: ./start-evm.sh -r -a -e fake -v $validators     (or -e engine-api once reth is running)"
