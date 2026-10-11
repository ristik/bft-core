#!/bin/bash
# exit on error
set -e

# run from the checkout's root: stops the ubft processes of THIS checkout only (see stop below)
cd "$(dirname "$0")"

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

  # only this checkout's processes: the command line names "$program" for every checkout on the machine (nodes are started as
  # build/ubft from the checkout's root), so a process is stopped only if its working directory is this checkout
  local here pid cwd PID=""
  here=$(pwd -P)
  for pid in $(ps -eaf | grep "$program" | grep -v grep | awk '{print $2}'); do   # global-kill-ok: each pid is kept only if its working directory is this checkout
    if [ -d "/proc/$pid" ]; then
      cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)
    else
      cwd=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)
    fi
    [ "$cwd" = "$here" ] && PID="$PID $pid"
  done
  if [ -n "$PID" ]; then
    echo "killing$PID"
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
