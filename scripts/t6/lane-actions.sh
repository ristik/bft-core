#!/usr/bin/env bash
# T6-only callbacks used from the existing paired profile-2 lane.

# Hardhat/Anvil account 1 is a public disposable key. It funds only this placeholder-genesis
# rehearsal's treasury address and must never be used for a production manifest.
T6_TREASURY_TEST_KEY=59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

t6_start_finality_monitor() {
  local i rpc_list= status_list= log_list=
  for i in 1 2 3 4; do
    rpc_list+="${rpc_list:+,}http://127.0.0.1:$((rethEthBase+i-1))"
    status_list+="${status_list:+,}http://127.0.0.1:$((evmRPCPortStart+i-1))"
    log_list+="${log_list:+,}test-nodes/evm$i/debug.log"
  done
  rm -f test-nodes/post-m2a-evidence/t6-finality-stop test-nodes/post-m2a-evidence/t6-finality-ready
  python3 scripts/t6/finality-rpc.py watch \
    --rpc-urls "$rpc_list" --status-urls "$status_list" --log-paths "$log_list" \
    --validators 4 --out test-nodes/post-m2a-evidence/t6-finality-monitor.jsonl \
    --ready-file test-nodes/post-m2a-evidence/t6-finality-ready \
    --stop-file test-nodes/post-m2a-evidence/t6-finality-stop \
    --offline-marker test-nodes/h4-replaced/stop.txt \
    --restore-log test-nodes/h4-replaced/restore.log \
    --minimum-runtime 10 --minimum-samples 3 \
    >test-nodes/post-m2a-evidence/t6-finality-monitor.log 2>&1 &
  T6_FINALITY_MONITOR_PID=$!
  for _ in $(seq 1 60); do
    [ -s test-nodes/post-m2a-evidence/t6-finality-ready ] && {
      pass "finalized-state monitor is sampling all four validator RPCs"
      return 0
    }
    kill -0 "$T6_FINALITY_MONITOR_PID" 2>/dev/null || {
      cat test-nodes/post-m2a-evidence/t6-finality-monitor.log >&2
      fail "finality monitor exited before all validator endpoints were checked"
      return 1
    }
    sleep 1
  done
  fail "finality monitor did not establish four read-only RPC samples within 60s"
  return 1
}

t6_stop_finality_monitor() {
  [ -n "${T6_FINALITY_MONITOR_PID:-}" ] || { fail "finality monitor was never started"; return 1; }
  touch test-nodes/post-m2a-evidence/t6-finality-stop
  if ! wait "$T6_FINALITY_MONITOR_PID"; then
    cat test-nodes/post-m2a-evidence/t6-finality-monitor.log >&2
    fail "finalized-state monitor observed an unsafe or unreadable RPC state"
    return 1
  fi
  unset T6_FINALITY_MONITOR_PID
  pass "finalized-state monitor passed every sample through the validator restore"
}

t6_finalized_wallet_check() {
  local output=$1 signer treasury_signer wuct collector beneficiary balance_selector supply_selector credit_selector balance_data
  signer=$(go run ./scripts/evmtx -address) || return 1
  treasury_signer=$(go run ./scripts/evmtx -private-key "$T6_TREASURY_TEST_KEY" -address) || return 1
  wuct=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["addresses"]["wuct"])
PY
  ) || return 1
  collector=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["addresses"]["feeCollector"])
PY
  ) || return 1
  beneficiary=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
m=json.load(open(sys.argv[1],encoding="utf-8"))
print(next(a["beneficiary"] for a in m["allocations"] if a["purpose"] == "ecosystem_vesting"))
PY
  ) || return 1
  balance_selector=$(go run ./scripts/evmtx -method-selector 'balanceOf(address)') || return 1
  supply_selector=$(go run ./scripts/evmtx -method-selector 'totalSupply()') || return 1
  credit_selector=$(go run ./scripts/evmtx -method-selector 'treasuryCredit()') || return 1
  balance_data="${balance_selector}$(printf '%024s' '' | tr ' ' 0)${signer#0x}"
  python3 scripts/t6/finality-rpc.py wallet \
    --rpc-url "http://127.0.0.1:$rethEthBase" --status-url "http://127.0.0.1:$evmRPCPortStart" \
    --log-path test-nodes/evm1/debug.log --wallet "$signer" --beneficiary "$beneficiary" \
    --treasury "$treasury_signer" --wuct "$wuct" --balance-of-data "$balance_data" \
    --total-supply-data "$supply_selector" --fee-collector "$collector" \
    --treasury-credit-data "$credit_selector" --expected-wuct 3000000000000000000 \
    --expected-supply 3000000000000000000 --expected-treasury-credit 0 \
    --minimum-beneficiary-balance 300000000000000000000000000 --out "$output"
}

t6_exercise_f7() {
  local initcode lock_contract lock_hash lock_topic trust archive block_hash tx_index log_index emitter topic
  local extracted=0
  initcode=$(go run ./scripts/evmtx -lock-initcode) || return 1
  lock_contract=$(go run ./scripts/evmtx -create-address -nonce "$M2_NEXT_NONCE") || return 1
  post_m2a_send_transaction "$M2_NEXT_NONCE" -create -data "$initcode" -gas-limit 200000 -value 0 || return 1
  post_m2a_wait_certified_receipt "$POST_M2A_TX_HASH" 1 || return 1
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
  lock_topic=$(go run ./scripts/evmtx -event-topic 'Locked(uint256)') || return 1
  post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$lock_contract" -value 42 -gas-limit 100000 || return 1
  lock_hash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$lock_hash" 1 || return 1
  if ! python3 - "$POST_M2A_RECEIPT" "$lock_contract" "$lock_topic" <<'PY'
import json,sys
r=json.loads(sys.argv[1])["result"]
logs=[x for x in r.get("logs",[]) if x.get("address","").lower()==sys.argv[2].lower()
      and x.get("topics",[""])[0].lower()==sys.argv[3].lower()]
if r.get("status")!="0x1" or len(logs)!=1 or int(logs[0].get("data","0x0"),16)!=42:
    raise SystemExit("F7 lock receipt does not prove the 42-wei Locked event")
PY
  then
    fail "F7 lock receipt failed event verification"; return 1
  fi
  python3 - "$POST_M2A_RECEIPT" "$lock_contract" "$lock_hash" "$lock_topic" \
    >test-nodes/post-m2a-evidence/f7-lock-pin.json <<'PY'
import json,sys
r=json.loads(sys.argv[1])["result"]
pin={"blockHash":r["blockHash"],"blockNumber":int(r["blockNumber"],16),
     "txIndex":int(r["transactionIndex"],16),"logIndex":int(r["logs"][0]["logIndex"],16),
     "contract":sys.argv[2],"transactionHash":sys.argv[3],"topic":sys.argv[4]}
json.dump(pin,sys.stdout,separators=(",",":")); print()
PY
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t6-f7-lock.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
  pass "deployed and certified the fixed-nonce F7 demo contract and 42-wei Locked event"

  trust=test-nodes/post-m2a-evidence/t6-trust-base-epoch1.json
  archive=test-nodes/h4-archives/evm1
  [ -s test-nodes/trust-base.json ] && [ -d "$archive" ] || {
    fail "epoch-1 trust base or H4 local archive directory is missing"; return 1;
  }
  cp test-nodes/trust-base.json "$trust"
  read -r block_hash tx_index log_index emitter topic < <(python3 - test-nodes/post-m2a-evidence/f7-lock-pin.json <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding="utf-8"))
print(p["blockHash"],p["txIndex"],p["logIndex"],p["contract"],p["topic"])
PY
  )
  for _ in $(seq 1 45); do
    if build/f7-mintproof-extract extract --archive "$archive" --block-hash "$block_hash" \
      --tx-index "$tx_index" --log-index "$log_index" --emitter "$emitter" --topic "$topic" \
      --out test-nodes/post-m2a-evidence/t6-f7-locked.cbor \
      >test-nodes/post-m2a-evidence/t6-f7-extract.log 2>&1; then
      extracted=1
      break
    fi
    sleep 2
  done
  [ "$extracted" = 1 ] || {
    cat test-nodes/post-m2a-evidence/t6-f7-extract.log >&2
    fail "receipt-complete F7 archive record did not become available before the handoffs"; return 1;
  }
  pass "extracted the F7 offline bundle before root handoff"
  if command -v sandbox-exec >/dev/null 2>&1; then
    env -i PATH="$PATH" sandbox-exec -p '(version 1) (allow default) (deny network*)' \
      build/f7-mintproof-verify --bundle test-nodes/post-m2a-evidence/t6-f7-locked.cbor \
      --trust-base "$trust" --mode locked >test-nodes/post-m2a-evidence/t6-f7-verify.json || {
        fail "offline F7 verification failed before root handoff"; return 1;
      }
  else
    env -i PATH="$PATH" HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
      ALL_PROXY=http://127.0.0.1:9 build/f7-mintproof-verify \
      --bundle test-nodes/post-m2a-evidence/t6-f7-locked.cbor --trust-base "$trust" \
      --mode locked >test-nodes/post-m2a-evidence/t6-f7-verify.json || {
        fail "offline F7 verification failed before root handoff"; return 1;
      }
  fi
  python3 - test-nodes/post-m2a-evidence/t6-f7-verify.json test-nodes/post-m2a-evidence/f7-lock-pin.json <<'PY' || {
import json,sys
verified=json.load(open(sys.argv[1],encoding="utf-8"))
pin=json.load(open(sys.argv[2],encoding="utf-8"))
if verified.get("status")!="PASS" or verified.get("blockHash","").lower()!=pin["blockHash"].lower():
    raise SystemExit("offline verifier result does not match certified F7 block")
PY
    fail "offline F7 verifier output failed block-hash cross-check"; return 1;
  }
  pass "offline F7 bundle verified against the epoch-1 trust base before handoff"
}

t6_exercise_contracts() {
  local wuct collector signer treasury_signer deposit_amount withdraw_amount deposit_topic withdraw_topic
  local selector data_word data deposit_hash withdraw_hash split_hash treasury_hash treasury_topic
  local credit_selector credit_before credit_decimal treasury_paid treasury_before treasury_after
  wuct=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["addresses"]["wuct"])
PY
  ) || return 1
  collector=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["addresses"]["feeCollector"])
PY
  ) || return 1
  signer=$(go run ./scripts/evmtx -address) || return 1
  treasury_signer=$(go run ./scripts/evmtx -private-key "$T6_TREASURY_TEST_KEY" -address) || return 1
  deposit_amount=5000000000000000000
  withdraw_amount=2000000000000000000

  deposit_topic=$(go run ./scripts/evmtx -event-topic 'Deposit(address,uint256)') || return 1
  post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$wuct" -call 'deposit()' \
    -gas-limit 150000 -value "$deposit_amount" || return 1
  deposit_hash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$deposit_hash" 1 || return 1
  if ! python3 - "$POST_M2A_RECEIPT" "$wuct" "$deposit_topic" "$deposit_amount" <<'PY'
import json,sys
r=json.loads(sys.argv[1])["result"]
logs=[x for x in r.get("logs",[]) if x.get("address","").lower()==sys.argv[2].lower()
      and x.get("topics",[""])[0].lower()==sys.argv[3].lower()]
if r.get("status")!="0x1" or len(logs)!=1 or int(logs[0].get("data","0x0"),16)!=int(sys.argv[4]):
    raise SystemExit("certified WUCT deposit does not match the requested amount")
PY
  then
    fail "WUCT deposit receipt failed event verification"; return 1
  fi
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t6-wuct-deposit.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
  pass "placeholder-manifest wallet wrapped 5 WUCT from native coin"

  withdraw_topic=$(go run ./scripts/evmtx -event-topic 'Withdrawal(address,uint256)') || return 1
  selector=$(go run ./scripts/evmtx -method-selector 'withdraw(uint256)') || return 1
  printf -v data_word '%064x' "$withdraw_amount"
  data="${selector}${data_word}"
  post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$wuct" -data "$data" \
    -gas-limit 150000 -value 0 || return 1
  withdraw_hash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$withdraw_hash" 1 || return 1
  if ! python3 - "$POST_M2A_RECEIPT" "$wuct" "$withdraw_topic" "$withdraw_amount" <<'PY'
import json,sys
r=json.loads(sys.argv[1])["result"]
logs=[x for x in r.get("logs",[]) if x.get("address","").lower()==sys.argv[2].lower()
      and x.get("topics",[""])[0].lower()==sys.argv[3].lower()]
if r.get("status")!="0x1" or len(logs)!=1 or int(logs[0].get("data","0x0"),16)!=int(sys.argv[4]):
    raise SystemExit("certified WUCT withdrawal does not match the requested amount")
PY
  then
    fail "WUCT withdrawal receipt failed event verification"; return 1
  fi
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t6-wuct-withdraw.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
  pass "placeholder-manifest wallet unwrapped 2 WUCT back to native coin"

  post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$collector" -call 'split()' \
    -gas-limit 200000 -value 0 || return 1
  split_hash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$split_hash" 1 || return 1
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t6-fee-split.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
  credit_selector=$(go run ./scripts/evmtx -method-selector 'treasuryCredit()') || return 1
  credit_before=$(rpc "http://127.0.0.1:$rethEthBase" eth_call \
    "[{\"to\":\"$collector\",\"data\":\"$credit_selector\"},\"finalized\"]" | pyget "['result']") || return 1
  credit_decimal=$(python3 -c "print(int('$credit_before',16))") || return 1
  [ "$credit_decimal" -gt 0 ] || { fail "certified FeeCollector split created no treasury credit"; return 1; }
  pass "certified FeeCollector split created a nonzero treasury liability"

  treasury_topic=$(go run ./scripts/evmtx -event-topic 'TreasuryWithdrawn(address,uint256)') || return 1
  treasury_before=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBalance \
    "[\"$treasury_signer\",\"finalized\"]" | pyget "['result']") || return 1
  post_m2a_send_transaction 0 -private-key "$T6_TREASURY_TEST_KEY" -to "$collector" \
    -call 'withdraw()' -gas-limit 200000 -value 0 || return 1
  treasury_hash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$treasury_hash" 1 || return 1
  treasury_after=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBalance \
    "[\"$treasury_signer\",\"finalized\"]" | pyget "['result']") || return 1
  treasury_paid=$(python3 - "$POST_M2A_RECEIPT" "$collector" "$treasury_topic" "$treasury_signer" \
    "$credit_decimal" "$treasury_before" "$treasury_after" <<'PY'
import json,sys
r=json.loads(sys.argv[1])["result"]
if r.get("status")!="0x1": raise SystemExit("treasury withdrawal receipt is not successful")
logs=[x for x in r.get("logs",[]) if x.get("address","").lower()==sys.argv[2].lower()
      and x.get("topics",[""])[0].lower()==sys.argv[3].lower()]
if len(logs)!=1 or len(logs[0].get("topics",[]))<2 or logs[0]["topics"][1].lower()[-40:]!=sys.argv[4].lower().removeprefix("0x"):
    raise SystemExit("TreasuryWithdrawn event is missing or names a different treasury")
amount=int(logs[0].get("data","0x0"),16)
if amount!=int(sys.argv[5]) or amount<=0: raise SystemExit("withdrawn amount differs from certified treasury credit")
gas_cost=int(r["gasUsed"],16)*int(r["effectiveGasPrice"],16)
delta=int(sys.argv[7],16)-int(sys.argv[6],16)
if delta!=amount-gas_cost:
    raise SystemExit(f"treasury balance delta {delta} differs from pull credit less withdrawal gas {amount-gas_cost}")
print(amount)
PY
  ) || { fail "treasury withdrawal did not reconcile with its certified credit"; return 1; }
  python3 - "$POST_M2A_RECEIPT" "$treasury_before" "$treasury_after" "$treasury_paid" \
    >test-nodes/post-m2a-evidence/t6-treasury-withdraw.json <<'PY'
import json,sys
receipt=json.loads(sys.argv[1])["result"]
amount=int(sys.argv[4]); gas=int(receipt["gasUsed"],16)*int(receipt["effectiveGasPrice"],16)
json.dump({"receipt":receipt,"treasuryBalanceBefore":sys.argv[2],"treasuryBalanceAfter":sys.argv[3],
           "pullCreditWei":str(amount),"gasCostWei":str(gas),
           "netBalanceIncreaseWei":str(amount-gas)},sys.stdout,indent=2); print()
PY
  pass "placeholder-manifest treasury withdrew its certified $treasury_paid wei pull credit"

  t6_finalized_wallet_check test-nodes/post-m2a-evidence/t6-wallet-finalized-before-handoff.json || return 1
  pass "wallet and exchange-style reads used certified finalized state"
  python3 - "$POST_M2A_CLAIM_TX" "$deposit_hash" "$withdraw_hash" "$split_hash" "$treasury_hash" "$treasury_paid" \
    "$signer" "$treasury_signer" "$wuct" "$collector" \
    >test-nodes/post-m2a-evidence/t6-contract-actions.json <<'PY'
import json,sys
out={"claimTransactionHash":sys.argv[1],
     "wuct":{"depositTransactionHash":sys.argv[2],"depositWei":"5000000000000000000",
              "withdrawTransactionHash":sys.argv[3],"withdrawWei":"2000000000000000000",
              "finalBalanceWei":"3000000000000000000"},
     "feeCollector":{"splitTransactionHash":sys.argv[4],"treasuryWithdrawTransactionHash":sys.argv[5],
                      "treasuryPaidWei":sys.argv[6]},
     "wallet":sys.argv[7],"treasury":sys.argv[8],"wuctAddress":sys.argv[9],"feeCollectorAddress":sys.argv[10]}
json.dump(out,sys.stdout,indent=2); print()
PY
  pass "T6 claim, wrap/unwrap, treasury withdrawal, and F7 actions were recorded"
}
