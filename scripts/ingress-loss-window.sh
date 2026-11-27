#!/usr/bin/env bash
# Sourced by reth-paired-devnet.sh for the #998 acceptance window.
source scripts/lib/q4-lib.sh

loss_load_prepare() {
  local i part shard home
  for i in 0 1 2; do
    part=${loss_parts[$i]} shard=${loss_shards[$i]} home="test-nodes/load$i"
    build/ubft shard-node init --home "$home" -g >/dev/null &&
      build/ubft shard-conf generate --home "$home" --network-id 3 --partition-id "$part" \
        --partition-type-id "$part" --shard-id "$shard" --epoch 0 --epoch-start 1 \
        --t2-timeout "$((2500 + i*2500))" --partition-params proof_type=aggregator_rsmt_v1 \
        --node-info "$home/node-info.json" &&
      cp "$home/shard-conf-${part}_0.json" "test-nodes/shard-conf-load$i.json" || return 1
  done
}

loss_parts=(9 9 10)
loss_shards=(0x40 0xc0 0x80)
loss_key_bits=(0 1 -1)
loss_load_pids=()

loss_load_stop() {
  local pid
  for pid in "${loss_load_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
}

loss_event() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$*" | tee -a "$Q4_SHIM_DIR/window.log"; }
loss_eth() { echo "http://127.0.0.1:$((rethEthBase + $1 - 1))"; }
loss_block() { rpc "$(loss_eth "$1")" eth_getBlockByNumber '["latest",false]' | jq -er '.result.hash'; }
loss_receipt() { rpc "$(loss_eth "$1")" eth_getTransactionReceipt "[\"$2\"]" | jq -er '.result | select(.status == "0x1") | .blockHash'; }

loss_gate() {
  local body=$1 i
  local -a pids=()
  for i in 1 2 3 4 5; do
    q4_shard_ctl "$i" "$body" &
    pids+=("$!")
  done
  local status=0 pid
  for pid in "${pids[@]}"; do wait "$pid" || status=1; done
  return "$status"
}

loss_wait() {
  local seconds=$1 label=$2
  shift 2
  local until=$((SECONDS + seconds))
  while ((SECONDS < until)); do
    "$@" && return 0
    sleep 0.2
  done
  fail "$label (waited ${seconds}s)" >&2
  return 1
}

loss_stopped() { ! kill -0 "$1" 2>/dev/null; }

loss_load_ready() {
  [ -e "$Q4_SHIM_DIR/load0.ready" ] && [ -e "$Q4_SHIM_DIR/load1.ready" ] && [ -e "$Q4_SHIM_DIR/load2.ready" ]
}

loss_drop_seen() {
  python3 scripts/ingress-loss-evidence.py select "$Q4_SHIM_DIR" 2>/dev/null
}

loss_receipts_at() {
  local i
  for i in "$@"; do
    [ "$(loss_receipt "$i" "$loss_tx")" = "$loss_target" ] || return 1
  done
}

loss_followers_at() {
  local i
  for i in "$@"; do
    [ "$(loss_block "$i")" = "$loss_target" ] || return 1
  done
}

loss_repeat_proposed() {
  python3 scripts/ingress-loss-evidence.py proposal test-nodes "$1" 2>/dev/null
}

loss_run() {
  local roots= i tx expected= loss_target loss_tx drop_seen loss_round dropped_block first_drop repeat_root
  mkdir -p "$Q4_SHIM_DIR"
  for i in 1 2 3 4 5; do
    roots+=${roots:+,}$(boot_node "test-nodes/root$i" "$((rootPortStart+i-1))")
  done
  loss_event "profile roots=5 evm=5 request_threshold=3; load-only shards 9/0x40, 9/0xc0, 10/0x80; 10000 pre-state leaves, 1000 insertions each"
  for i in 0 1 2; do
    "$INGRESS_LOSS_LOAD_BIN" -conf "test-nodes/shard-conf-load$i.json" -keys "test-nodes/load$i/keys.json" \
      -roots "$roots" -key-bit "${loss_key_bits[$i]}" -ready "$Q4_SHIM_DIR/load$i.ready" -start "$Q4_SHIM_DIR/batch.start" \
      -stop "$Q4_SHIM_DIR/batch.stop" \
      >"$Q4_SHIM_DIR/load$i.log" 2>&1 &
    loss_load_pids+=("$!")
  done
  loss_wait 60 "load shard pre-states were not certified" loss_load_ready || return 1

  # Peer the subject's executor while keeping its shard process under lane control.
  local -a enodes=()
  for i in 1 2 3 4; do
    enodes[$i]=$(rpc "$(loss_eth "$i")" admin_nodeInfo '[]' | jq -er '.result.enode') || return 1
    rpc "$(loss_eth 5)" admin_addPeer "[\"${enodes[$i]}\"]" | jq -e '.result == true' >/dev/null || return 1
  done
  loss_target=$(loss_block 1) || return 1
  loss_wait 60 "bootstrap did not apply to every validator" loss_followers_at 1 2 3 4 5 || return 1
  loss_gate "{'rules':[{'name':'evm-loss','direction':'in','partition':8,'types':['request'],'action':'drop'}]}" || return 1
  loss_event "all root ingress gates armed"
  touch "$Q4_SHIM_DIR/batch.start" || return 1
  loss_event "started f8batch traffic before seeding the EVM attempt"
  export EVM_VALIDATOR_LOG_LEVEL=debug
  for i in 1 2 3 4 5; do
    tx=$(lane_go_run evmtx -send -eth-url "$(loss_eth "$i")" -chain-id "$postM2aChainID" -nonce 3) || return 1
    [[ "$tx" = 0x* && ( -z "$expected" || "$tx" = "$expected" ) ]] || return 1
    expected=$tx
  done
  loss_event "pending transaction $tx seeded at all five validators"
  drop_seen=$(loss_wait 35 "no ingress received a fully dropped request quorum" loss_drop_seen) || return 1
  read -r loss_round dropped_block first_drop <<< "$drop_seen"
  [[ "$loss_round" =~ ^[0-9]+$ && "$dropped_block" =~ ^[0-9a-f]{64}$ ]] || return 1
  loss_target=$(loss_block 5) || return 1
  local before=$loss_target
  local lag_pid
  lag_pid=$(cat test-nodes/evm5/pid) || return 1
  stop_pidfile test-nodes/evm5/pid 'ubft.*shard-node run'
  loss_wait 10 "validator 5 is still running" loss_stopped "$lag_pid" || return 1
  loss_event "validator 5 stopped at $before; its reth stays running"

  for i in 1 2 3 4 5; do
    jq -e '.held | length == 0' "$Q4_SHIM_DIR/root$i/shard-status.json" >/dev/null || return 1
  done
  loss_event "dropped request quorum round=$loss_round block=0x$dropped_block; gates held no requests"
  repeat_root=$(loss_wait 30 "no EVM T2 proposal after the first drop" loss_repeat_proposed "$first_drop") || return 1
  loss_gate "{'rules':[{'name':'lost-round','direction':'in','partition':8,'types':['request'],'round':$loss_round,'action':'drop'}]}" || return 1
  loss_event "fresh EVM ingress reopened after the T2 proposal; round $loss_round remains dropped"

  local until=$((SECONDS + 60))
  loss_target=
  while ((SECONDS < until)); do
    loss_target=$(loss_receipt 1 "$tx") && break
    sleep 0.2
  done
  [ -n "$loss_target" ] || { fail "pending transaction was not applied"; return 1; }
  loss_tx=$tx
  loss_wait 30 "available executors did not apply the same block" loss_receipts_at 1 2 3 4 || return 1
  loss_event "available validators applied transaction=$tx block=$loss_target"
  touch "$Q4_SHIM_DIR/batch.stop" || return 1
  [ "$(loss_block 5)" = "$before" ] || { fail "validator 5 had already applied the decision"; return 1; }
  rpc "$(loss_eth 5)" eth_getBlockByHash "[\"$loss_target\",false]" | jq -e 'has("result") and .result == null' >/dev/null ||
    { fail "validator 5's reth already has the missed block"; return 1; }

  # Keep one execution peer unavailable throughout catch-up. The other peers retain the block.
  local peer_pid shard_pid
  shard_pid=$(cat test-nodes/evm4/pid) || return 1
  stop_pidfile test-nodes/evm4/pid 'ubft shard-node run'
  loss_wait 10 "shard peer 4 remains running" loss_stopped "$shard_pid" || return 1
  peer_pid=$(cat test-nodes/reth4/pid) || return 1
  stop_pidfile test-nodes/reth4/pid "$(reth_node_pattern "$URETH_BIN")"
  loss_wait 10 "execution peer 4 remains running" loss_stopped "$peer_pid" || return 1
  loss_event "starting validator 5 with execution peer 4 unavailable"
  start_one_evm_validator 5 5 8 "$(boot_node test-nodes/root1 "$rootPortStart")" engine-api || return 1
  loss_wait 60 "validator 5 did not apply the missed block with peer 4 down" loss_receipts_at 5 || return 1
  grep -E 'certificate admitted.*source=peer_recovery.*block='"${loss_target#0x}"' ' test-nodes/evm5/debug.log >/dev/null ||
    { fail "validator 5 did not log journal recovery of the transaction block"; return 1; }
  loss_event "validator 5 applied the missed transaction=$tx block=$loss_target"

  for i in 0 1 2; do
    wait "${loss_load_pids[$i]}" || return 1
    grep 'batch certified' "$Q4_SHIM_DIR/load$i.log" | tail -1 || return 1
  done
  loss_load_pids=()
  python3 scripts/ingress-loss-evidence.py verify "$Q4_SHIM_DIR" test-nodes "$loss_round" "$dropped_block" \
    "${before#0x}" "${loss_target#0x}" "$tx" "$repeat_root" | tee -a "$Q4_SHIM_DIR/window.log"
}
