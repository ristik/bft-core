# Sourced by reth-paired-devnet.sh after the first paid certified block.
# Uses the same four real shard validators and their running ureth instances.
source scripts/lib/m2-handoff-lib.sh
# The fresh-B1 layout has one handoff: a same-members root epoch advance through the Q3 flow (V3 candidate, a readiness receipt from every entity, propose).
# A root-only key rotation is not a coupled validator-set change and is not a mode of this lane; the coupled rotation is the H3 lane's.
echo "M2 handoffs: same members, Q3 flow (fresh-B1 registry)"

cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
read -r m2_epoch_slot m2_cursor_slot m2_shard_epoch_slot < <(go run ./scripts/m2slots)
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
# The next nonce of the funded account is whatever the chain says it is: three seeded transactions in block 1 leave it at 3, and a lane that sent more before this
# point (the F8 probes send one) leaves it higher.
m2FundedNonce=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionCount "[\"$(go run ./scripts/evmtx -address)\",\"pending\"]" | pyget "['result']") || m2FundedNonce=
case "$m2FundedNonce" in 0x*) M2_NEXT_NONCE=${M2_NEXT_NONCE:-$((m2FundedNonce))} ;; *) M2_NEXT_NONCE=${M2_NEXT_NONCE:-3} ;; esac
if [ "${M2A_FINAL_RESTORE:-0}" = 1 ]; then
  m2a_head=$(rpc "http://127.0.0.1:$((rethEthBase+1))" eth_blockNumber '[]' | pyget "['result']")
  while [ -n "$m2a_head" ] && [ "$((m2a_head))" -lt 5 ]; do
    m2_send_paid 1 "$M2_NEXT_NONCE" || return 1
    m2a_head=$(rpc "http://127.0.0.1:$((rethEthBase+1))" eth_blockNumber '[]' | pyget "['result']")
  done
  m2_wait_certified_idle 1 || return 1
fi
m2_config_only_handoff 2 '1 2 3 4' \
  'http://127.0.0.1:25866,http://127.0.0.1:25867,http://127.0.0.1:25868,http://127.0.0.1:25869' || return 1
if [ "${F8_MIXED_LANE:-0}" = 1 ]; then
  echo "F8 mixed lane completed one root handoff while all aggregator shards remained active"
  return 0
fi
m2_config_only_handoff 3 '1 2 3 4' \
  'http://127.0.0.1:25866,http://127.0.0.1:25867,http://127.0.0.1:25868,http://127.0.0.1:25869' || return 1
if [ "${M2A_FINAL_RESTORE:-0}" = 1 ]; then
  # M2a final restore on the fresh-B1 layout. A V3 handoff needs a readiness receipt from EVERY successor entity, so validator 1 is wiped after the second
  # handoff (not before the first): it comes back from nothing but its signing authority, the genesis trust base and a surviving validator's archive, and
  # must verify BOTH activations (root epochs 2 and 3) on the way, since the activations are not archived as bundles and the restore pin names the V3 body.
  evidence=test-nodes/h4-replaced
  mkdir -p "$evidence"
  build/ubft signing-authority status --operator-socket test-nodes/auth1/operator.sock \
    --operator-credential test-nodes/auth1/operator.cred >"$evidence/authority-before.json" || return 1
  H3_ARCHIVES=test-nodes/h4-archives
  H3_RESTORE_TRUST_BASE=test-nodes/trust-base.json
  H3_ONLINE="2 3 4"
  export H4_RESTORE_BODY_IDS="3=$(tr -d '[:space:]' <"$Q3_DIR/v3-body-id-m2e3.txt")"
  export M2A_VALIDATOR1_WIPED=1
  h3_restore_validator 1 2 || return 1
  restoreLog=test-nodes/evm1/debug.log
  restored=false
  # H4_RESTORE_WAIT_SECONDS (default 180): a restore that replays many blocks needs longer
  for waitStep in $(seq 1 "${H4_RESTORE_WAIT_SECONDS:-300}"); do
    if grep -Eq 'handoff activated.*rootEpoch=2' "$restoreLog" &&
       grep -Eq 'handoff activated.*rootEpoch=3' "$restoreLog" &&
       grep -q 'submitting block certification request' "$restoreLog" &&
       grep -Eq 'msg="certificate admitted" .*rootEpoch=3([[:space:]]|$)' "$restoreLog"; then
      restored=true; break
    fi
    if ! kill -0 "$(cat test-nodes/evm1/pid)" 2>/dev/null; then
      echo 'restored validator exited before catch-up' >&2; tail -60 "$restoreLog" >&2; return 1
    fi
    sleep 1
  done
  $restored || { echo 'restore did not verify both handoff epochs and resume signing' >&2; tail -60 "$restoreLog" >&2; return 1; }
  build/ubft signing-authority status --operator-socket test-nodes/auth1/operator.sock \
    --operator-credential test-nodes/auth1/operator.cred >"$evidence/authority-after.json" || return 1
  before=$(python3 -c 'import json;print(json.load(open("test-nodes/h4-replaced/authority-before.json"))["reservedRound"])')
  after=$(python3 -c 'import json;print(json.load(open("test-nodes/h4-replaced/authority-after.json"))["reservedRound"])')
  [ "$after" -gt "$before" ] || { echo "restored signer did not advance authority high-water: $before -> $after" >&2; return 1; }
  export M2A_VALIDATOR1_RESTORED=1
  m2_send_paid 3 "$M2_NEXT_NONCE" || return 1
  m2_wait_certified_idle 3 || return 1
  echo "RESTORE PASS: epochs 2 and 3 activated; authority high-water $before -> $after"
fi
