#!/bin/bash
# M2a final lane invokes stop before Handoff 1 and restore after Handoff 2.
# H4_WAIT_BLOCKS=N (default 0): the restore stage first waits until surviving validator 2 has certified-executed at least N blocks
# beyond its height at the stop (H4_WAIT_TIMEOUT seconds, default 1800), and requires the restored pin to be at least N blocks
# past the stop height. The lane's proof window is 64, so N >= 65 makes validator 1 miss more than the window.
set -euo pipefail
source helper.sh
. scripts/lib/reth-pin.sh
stage=${1:?stop or restore required}
evidence=test-nodes/h4-replaced
mkdir -p "$evidence"

survivor_height() {
  local hex
  hex=$(curl -sS --max-time 5 -X POST http://127.0.0.1:18546 -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null |
    python3 -c 'import json,sys; print(int(json.load(sys.stdin)["result"], 16))' 2>/dev/null) || return 1
  echo "$hex"
}

pid_is_running() {
  local pid=$1 state
  kill -0 "$pid" 2>/dev/null || return 1
  state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')
  [ -n "$state" ] && [[ "$state" != Z* ]]
}

stop_and_wait() {
  local pid=$1 label=$2 pattern=$3
  for _ in $(seq 1 300); do
    if ! pid_is_running "$pid" || ! owned_pid "$pid" "$pattern"; then
      echo "$label pid=$pid exited after SIGTERM"
      return 0
    fi
    sleep 0.1
  done
  echo "$label pid=$pid did not exit within 30s after SIGTERM; sending SIGKILL" >&2
  owned_pid "$pid" "$pattern" || { echo "$label pid=$pid is no longer owned by this checkout; refusing SIGKILL" >&2; return 1; }
  kill -KILL "$pid" 2>/dev/null || true
  for _ in $(seq 1 300); do
    if ! pid_is_running "$pid" || ! owned_pid "$pid" "$pattern"; then
      echo "$label pid=$pid exited after SIGKILL"
      return 0
    fi
    sleep 0.1
  done
  echo "$label pid=$pid is still running after SIGKILL; refusing to wipe data" >&2
  return 1
}

case "$stage" in
  stop)
    authPid=$(cat test-nodes/auth1/pid)
    owned_pid "$authPid" 'ubft signing-authority run'
    build/ubft signing-authority status --operator-socket test-nodes/auth1/operator.sock \
      --operator-credential test-nodes/auth1/operator.cred >"$evidence/authority-before.json"
    cp test-nodes/evm1/keys.json "$evidence/keys.json"
    cp test-nodes/evm1/jwt.hex "$evidence/jwt.hex"
    cp test-nodes/evm1/debug.log "$evidence/evm1-before-wipe.log"
    evmPid=$(cat test-nodes/evm1/pid)
    rethPid=$(cat test-nodes/reth1/pid)
    owned_pid "$evmPid" 'ubft shard-node run' || { echo "validator 1 BFT pid $evmPid is not owned by this checkout" >&2; exit 1; }
    owned_pid "$rethPid" 'reth.* node' || { echo "validator 1 EL pid $rethPid is not owned by this checkout" >&2; exit 1; }
    # Shutdown can take a while; observers must know validator 1 is expected to be unreachable from now on.
    survivor_height >"$evidence/stop-height.txt" || { echo "cannot read surviving validator 2's height" >&2; exit 1; }
    echo 'H4_STOPPING' >"$evidence/stopping.txt"
    kill -TERM "$evmPid" 2>/dev/null || true
    kill -TERM "$rethPid" 2>/dev/null || true
    stop_and_wait "$evmPid" 'validator 1 BFT' 'ubft shard-node run' || exit 1
    stop_and_wait "$rethPid" 'validator 1 EL' 'reth.* node' || exit 1
    rm -f test-nodes/evm1/pid test-nodes/reth1/pid
    echo "$authPid" >"$evidence/authority-pid"
    # The restored shard uses a fresh home. Preserve only identity, JWT and evidence;
    # remove both data directories only after both validator processes have exited.
    rm -rf test-nodes/evm1 test-nodes/reth1/dd
    mkdir -p test-nodes/evm1 test-nodes/reth1
    echo 'H4_STOPPED_AND_BFT_EL_WIPED' >"$evidence/stop.txt"
    echo "stopped validator 1; wiped BFT and EL data; authority pid=$authPid survives"
    ;;
  restore)
    waitBlocks=${H4_WAIT_BLOCKS:-0}
    case "$waitBlocks" in '' | *[!0-9]*) echo "H4_WAIT_BLOCKS must be a non-negative integer" >&2; exit 2 ;; esac
    if [ "$waitBlocks" -gt 0 ]; then
      stopHeight=$(cat "$evidence/stop-height.txt")
      waitDeadline=$((SECONDS + ${H4_WAIT_TIMEOUT:-1800}))
      while :; do
        head=$(survivor_height || echo "$stopHeight")
        [ "$head" -ge $((stopHeight + waitBlocks)) ] && break
        [ "$SECONDS" -lt "$waitDeadline" ] || { echo "survivors did not reach $((stopHeight + waitBlocks)) (at $head) within the wait budget" >&2; exit 1; }
        sleep 2
      done
      echo "H4_WAITED_BLOCKS stop=$stopHeight survivor=$head wait=$waitBlocks"
    fi
    authPid=$(cat "$evidence/authority-pid")
    owned_pid "$authPid" 'ubft signing-authority run'
    [ "$(cat test-nodes/auth1/pid)" = "$authPid" ]
    rm -f test-nodes/evm1/execution-journal.db test-nodes/evm1/execution-journal.db.trust \
      test-nodes/evm1/shard-node-luc.json
    rm -rf test-nodes/reth1/dd test-nodes/h4-archives/evm1 "$evidence/journal.db" "$evidence/journal.db.trust" "$evidence/archive"
    echo 'H4_DISKS_WIPED' >>test-nodes/evm1/debug.log
    registry_layout_require || exit 1
    "$URETH_BIN" node --chain "$EVM_GENESIS_FILE" --datadir test-nodes/reth1/dd \
      --authrpc.jwtsecret "$evidence/jwt.hex" --authrpc.addr 127.0.0.1 --authrpc.port 18551 \
      --http --http.addr 127.0.0.1 --http.port 18545 --http.api eth,net,web3,admin,debug \
      --rpc.eth-proof-window 64 --port 30401 --disable-discovery --ipcdisable \
      --engine.persistence-threshold "${D2C_PERSISTENCE_THRESHOLD:-64}" --builder.gaslimit 30000000 \
      $(urethPinUnicityFlags) >"$evidence/reth.log" 2>&1 &
    echo $! >test-nodes/reth1/pid
    for _ in $(seq 1 120); do
      if curl -sS --max-time 2 -X POST http://127.0.0.1:18545 -H 'Content-Type: application/json' \
          -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null | grep -q '"result":"0x0"'; then
        break
      fi
      sleep 1
    done
    curl -sS --max-time 2 -X POST http://127.0.0.1:18545 -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | grep -q '"result":"0x0"'
    echo 'H4_FRESH_EL_GENESIS' >>"$evidence/restore.log"
    # Discovery is disabled, so reintroduce the replacement client to surviving peers.
    for j in 2 3 4; do
      enode=$(curl -sS --max-time 5 -X POST "http://127.0.0.1:$((18544+j))" \
        -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"admin_nodeInfo","params":[]}' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["enode"])')
      curl -sS --max-time 5 -X POST http://127.0.0.1:18545 -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_addPeer\",\"params\":[\"$enode\"]}" >/dev/null
    done
    pinTrustBase=test-nodes/trust-base.json
    restoreProfile2Args=()
    if [ "${M2_PROFILE2:-0}" = 1 ]; then
      restoreProfile2Args+=(--trust-history-profile-2)
    fi
    go run ./scripts/h4-restore-pin test-nodes/h4-archives/evm2 "$pinTrustBase" "$evidence/tip" >"$evidence/pin.txt"
    bodyID=$(tr ' ' '\n' <"$evidence/pin.txt" | sed -n 's/^bodyID=//p')
    if [ "$waitBlocks" -gt 0 ]; then
      pinHeight=$(tr ' ' '\n' <"$evidence/pin.txt" | sed -n 's/^height=//p')
      missed=$((pinHeight - stopHeight))
      echo "H4_MISSED_BLOCKS=$missed stop=$stopHeight pin=$pinHeight proofWindow=64" | tee -a "$evidence/restore.log"
      [ "$missed" -ge "$waitBlocks" ] || { echo "restored pin is only $missed blocks past the stop; wanted $waitBlocks" >&2; exit 1; }
    fi
    rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")
    bootnodes=$(evm_bootnodes_for_peers "$rootBoot" 1 2 3 4)
    # Keep the journal bounded but leave room for a replica's one-at-a-time
    # authority-advance restart and durable archive acknowledgement catch-up.
    build/ubft shard-node restore --home "$evidence" --executor engine-api \
      --address "/ip4/127.0.0.1/tcp/$evmValidatorPortStart" --bootnodes "$bootnodes" \
      --trust-base test-nodes/trust-base.json --full-shard-conf "$EVM_FULL_SHARD_CONF" \
      --genesis "$EVM_GENESIS_FILE" --engine-url http://127.0.0.1:18551 \
      --eth-url http://127.0.0.1:18545 --jwt-secret "$evidence/jwt.hex" \
      --engine-fee-collector "$EVM_ENGINE_FEE_COLLECTOR" --registry-layout "$(registry_layout)" \
      --execution-journal "$evidence/journal.db" --archive-store "$evidence/archive" --archive-prune \
      ${restoreProfile2Args[@]+"${restoreProfile2Args[@]}"} \
      --journal-candidates 32 --archive-replica "$(evm_validator_id 2)" \
      --archive-replica "$(evm_validator_id 3)" \
      --signing-authority-socket test-nodes/auth1/client.sock \
      --signing-authority-credential test-nodes/auth1/client.cred \
      --tip-uc "$evidence/tip.uc.cbor" --tip-tr "$evidence/tip.tr.cbor" --trust-body-id "$bodyID" \
      --log-format text --log-level info >>"$evidence/restore.log" 2>&1 &
    echo $! >"$evidence/pid"
    echo "restore started pid=$(cat "$evidence/pid"); $(cat "$evidence/pin.txt")"
    ;;
  *) echo "unknown stage: $stage" >&2; exit 2 ;;
esac
