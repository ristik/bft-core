#!/bin/bash
# exit on error
set -e

# run from the checkout's root: stops the ubft processes of THIS checkout only (see stop below)
cd "$(dirname "$0")"
source helper.sh

function stop() {
  local program=""
  case $1 in
    all)
      program="build/ubft"
      ;;
    root)
      program="build/ubft root-node"
      ;;
    *)
      echo "error: unknown argument $1" >&2
      return 1
    ;;
  esac

  # only this checkout's processes (helper.sh: owned_pids): the command line names "$program" for every checkout on the machine
  # (nodes are started as build/ubft from the checkout's root), so a process is stopped only if its working directory is this checkout
  local PID
  PID=$(owned_pids "$program" | tr '\n' ' ')
  if [ -n "${PID// /}" ]; then
    echo "killing ${PID% }"
    kill $PID
    return 0
  fi
  echo "program not running"
}

usage() { echo "Usage: $0 [-h usage] [-a stop all] [-r stop root]"; exit 0; }

# stop requires an argument
[ $# -eq 0 ] && usage

# handle arguments
while getopts "har" o; do
  case "${o}" in
  a) #kill all
    stop "all"
    ;;
  r)
    stop "root"
    ;;
  h | *) # help.
    usage && exit 0
    ;;
  esac
done
