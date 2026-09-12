#!/bin/bash
# exit on error
set -e

source helper.sh

usage() { echo "Usage: $0 [-h usage] [-a stop everything this checkout started: root nodes + EVM validators]"; exit 0; }

[ $# -eq 0 ] && usage

while getopts "ha" o; do
  case "${o}" in
  a)
    # This checkout's nodes only — by recorded pid or working directory, never by name alone (see
    # "ownership" in helper.sh). Scripts that tear down a devnet call this from inside their own
    # cleanup, so a machine-wide sweep here stopped other checkouts' root chains on a shared host.
    echo "stopping EVM shard validators..."
    stop_evm_validators
    for p in $(owned_pids 'ubft shard-node run'); do kill "$p" 2>/dev/null || true; done
    echo "stopping root nodes..."
    stop_root_nodes
    ;;
  h | *) usage ;;
  esac
done
