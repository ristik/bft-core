#!/bin/bash
# The D1 monitor invokes stop at B5 and restore after at least B15.
set -euo pipefail
source helper.sh
. scripts/lib/reth-pin.sh
stage=${1:?stop or restore required}
evidence=test-nodes/h4-replaced
mkdir -p "$evidence"
case "$stage" in
  stop)
    authPid=$(cat test-nodes/auth1/pid)
    owned_pid "$authPid" 'ubft signing-authority run'
    build/ubft signing-authority status --operator-socket test-nodes/auth1/operator.sock \
      --operator-credential test-nodes/auth1/operator.cred >"$evidence/authority-before.json"
    cp test-nodes/evm1/keys.json "$evidence/keys.json"
    cp test-nodes/evm1/jwt.hex "$evidence/jwt.hex"
    stop_one_evm_validator 1 TERM
    stop_pidfile test-nodes/reth1/pid 'reth.* node' TERM
    echo "$authPid" >"$evidence/authority-pid"
    echo 'H4_STOPPED_AT_B5' >>test-nodes/evm1/debug.log
    echo "stopped validator 1 BFT and EL; authority pid=$authPid survives"
    ;;
  restore)
    authPid=$(cat "$evidence/authority-pid")
    owned_pid "$authPid" 'ubft signing-authority run'
    [ "$(cat test-nodes/auth1/pid)" = "$authPid" ]
    rm -f test-nodes/evm1/execution-journal.db test-nodes/evm1/execution-journal.db.trust \
      test-nodes/evm1/shard-node-luc.json
    rm -rf test-nodes/reth1/dd test-nodes/h4-archives/evm1 "$evidence/journal.db" "$evidence/journal.db.trust" "$evidence/archive"
    echo 'H4_DISKS_WIPED' >>test-nodes/evm1/debug.log
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
    go run ./scripts/h4-restore-pin test-nodes/h4-archives/evm2 test-nodes/trust-base.json "$evidence/tip" >"$evidence/pin.txt"
    bodyID=$(tr ' ' '\n' <"$evidence/pin.txt" | sed -n 's/^bodyID=//p')
    rootBoot=$(boot_node test-nodes/root1 "$rootPortStart")
    bootnodes="$rootBoot"
    for j in 2 3 4; do bootnodes+=",$(evm_validator_addr "$j")"; done
    build/ubft shard-node restore --home "$evidence" --executor engine-api \
      --address "/ip4/127.0.0.1/tcp/$evmValidatorPortStart" --bootnodes "$bootnodes" \
      --trust-base test-nodes/trust-base.json --full-shard-conf "$EVM_FULL_SHARD_CONF" \
      --genesis "$EVM_GENESIS_FILE" --engine-url http://127.0.0.1:18551 \
      --eth-url http://127.0.0.1:18545 --jwt-secret "$evidence/jwt.hex" \
      --engine-fee-collector "$EVM_ENGINE_FEE_COLLECTOR" \
      --execution-journal "$evidence/journal.db" --archive-store "$evidence/archive" --archive-prune \
      --journal-candidates 8 --archive-replica "$(evm_validator_id 2)" \
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
