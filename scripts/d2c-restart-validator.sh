#!/bin/bash
# Restart only the shard process. Its reth and signing authority keep their state and PIDs.
set -euo pipefail
source helper.sh
i=${1:?validator index required}
old=$(cat "test-nodes/evm$i/pid")
owned_pid "$old" 'ubft shard-node run' || { echo "validator $i pid $old is not owned by this lane" >&2; exit 1; }
stop_one_evm_validator "$i" TERM
for _ in $(seq 1 100); do
  owned_pid "$old" 'ubft shard-node run' || break
  sleep 0.1
done
owned_pid "$old" 'ubft shard-node run' && { echo "validator $i did not exit after SIGTERM" >&2; exit 1; }
echo "D2C_RESTART_BOUNDARY old=$old" >>"test-nodes/evm$i/debug.log"
rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")
start_one_evm_validator "$i" 4 8 "$rootBoot" engine-api
new=$(cat "test-nodes/evm$i/pid")
echo "restarted validator $i shard pid $old -> $new; reth and authority unchanged"
