# Sourced by reth-paired-devnet.sh after the first paid certified block.
# Uses the same four real shard validators and their running ureth instances.
source scripts/lib/m2-handoff-lib.sh
cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
read -r m2_epoch_slot m2_cursor_slot < <(go run ./scripts/m2slots)
for initialHash in $(printf '%b' "$txHashes"); do
  initialReady=false
  for i in $(seq 1 90); do
    initialReceipt=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionReceipt "[\"$initialHash\"]")
    initialBlock=$(echo "$initialReceipt" | pyget "['result']['blockHash']")
    if [ "$(echo "$initialReceipt" | pyget "['result']['status']")" = 0x1 ] &&
       [ -n "$initialBlock" ] && [ "$initialBlock" != None ] &&
       grep -Eq "msg=\"certificate admitted\" block=${initialBlock#0x} .*rootEpoch=1([[:space:]]|$)" test-nodes/evm1/debug.log; then
      initialReady=true; break
    fi
    sleep 2
  done
  $initialReady || return 1
done
M2_NEXT_NONCE=${M2_NEXT_NONCE:-3}
if [ "${M2A_FINAL_RESTORE:-0}" = 1 ]; then
  m2a_head=$(rpc "http://127.0.0.1:$((rethEthBase+1))" eth_blockNumber '[]' | pyget "['result']")
  while [ -n "$m2a_head" ] && [ "$((m2a_head))" -lt 5 ]; do
    m2_send_paid 1 "$M2_NEXT_NONCE" || return 1
    m2a_head=$(rpc "http://127.0.0.1:$((rethEthBase+1))" eth_blockNumber '[]' | pyget "['result']")
  done
  bash scripts/h4-restore-probe.sh stop || return 1
  export M2A_VALIDATOR1_WIPED=1
fi
m2_handoff 2 4 5 '1 2 3 4' "$(m2_root_addr 4)" \
  'http://127.0.0.1:25866,http://127.0.0.1:25867,http://127.0.0.1:25868,http://127.0.0.1:25869' || return 1
if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
  echo "F8 mixed lane completed one root handoff while all aggregator shards remained active"
  return 0
fi
m2_handoff 3 3 6 '1 2 3 5' "$(m2_root_addr 3)" \
  'http://127.0.0.1:25866,http://127.0.0.1:25867,http://127.0.0.1:25868,http://127.0.0.1:25870' || return 1
if [ "${M2A_FINAL_RESTORE:-0}" = 1 ]; then
  bash scripts/h4-restore-probe.sh restore || return 1
  ln -sf ../h4-replaced/restore.log test-nodes/evm1/debug.log
  restoreLog=test-nodes/h4-replaced/restore.log
  restored=false
  for waitStep in $(seq 1 180); do
    if grep -Eq 'handoff activated.*rootEpoch=2' "$restoreLog" &&
       grep -Eq 'handoff activated.*rootEpoch=3' "$restoreLog" &&
       grep -q 'submitting block certification request' "$restoreLog" &&
       grep -Eq 'msg="certificate admitted" .*rootEpoch=3([[:space:]]|$)' "$restoreLog"; then
      restored=true; break
    fi
    if ! kill -0 "$(cat test-nodes/h4-replaced/pid)" 2>/dev/null; then
      echo 'restored validator exited before catch-up' >&2; tail -60 "$restoreLog" >&2; return 1
    fi
    sleep 1
  done
  $restored || { echo 'restore did not verify both handoff epochs and resume signing' >&2; tail -60 "$restoreLog" >&2; return 1; }
  build/ubft signing-authority status --operator-socket test-nodes/auth1/operator.sock \
    --operator-credential test-nodes/auth1/operator.cred >test-nodes/h4-replaced/authority-after.json || return 1
  before=$(python3 -c 'import json;print(json.load(open("test-nodes/h4-replaced/authority-before.json"))["reservedRound"])')
  after=$(python3 -c 'import json;print(json.load(open("test-nodes/h4-replaced/authority-after.json"))["reservedRound"])')
  [ "$after" -gt "$before" ] || { echo "restored signer did not advance authority high-water: $before -> $after" >&2; return 1; }
  export M2A_VALIDATOR1_RESTORED=1
  m2_send_paid 3 "$M2_NEXT_NONCE" || return 1
  echo "RESTORE PASS: epochs 2 and 3 activated; authority high-water $before -> $after"
fi
