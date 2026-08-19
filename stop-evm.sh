#!/bin/bash
# exit on error
set -e

source helper.sh

usage() { echo "Usage: $0 [-h usage] [-a stop everything: root nodes + EVM validators]"; exit 0; }

[ $# -eq 0 ] && usage

while getopts "ha" o; do
  case "${o}" in
  a)
    echo "stopping EVM shard validators..."
    stop_evm_validators
    echo "stopping root nodes..."
    PID=$(ps -eaf | grep "build/ubft root-node" | grep -v grep | awk '{print $2}')
    if [ -n "$PID" ]; then
      kill $PID
    fi
    ;;
  h | *) usage ;;
  esac
done
