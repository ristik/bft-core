#!/bin/bash

# exit on error
set -e

source helper.sh

executor=fake
partition_id=8
validators=4
start_roots=false
start_vals=false

usage() {
  echo "Usage: $0 [-h usage] [-r start root nodes] [-a start EVM shard validators]"
  echo "          [-e fake|engine-api] [-p partition id] [-v number of validators]"
  echo
  echo "Starts what setup-evm-nodes.sh generated. Root nodes come up first (needed for"
  echo "validators to handshake against), then validators. -e engine-api assumes reth"
  echo "is already running per-validator on the ports recorded in each test-nodes/evmN/"
  echo "(see docs/engine-api-adapter-plan.md's port table) — this script does not start"
  echo "reth itself."
  exit 0
}

[ $# -eq 0 ] && usage

while getopts "hrae:p:v:" o; do
  case "${o}" in
  r) start_roots=true ;;
  a) start_vals=true ;;
  e) executor=${OPTARG} ;;
  p) partition_id=${OPTARG} ;;
  v) validators=${OPTARG} ;;
  h | *) usage ;;
  esac
done

if [ "$start_roots" == true ]; then
  echo -n "starting root nodes..." && start_root_nodes
  if [ "$start_vals" == true ]; then
    wait_for_root_chain_settle
  fi
fi

if [ "$start_vals" == true ]; then
  rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")
  echo "starting $validators EVM shard validators (executor=$executor)..."
  start_evm_validators "$validators" "$partition_id" "$rootBoot" "$executor"
fi
