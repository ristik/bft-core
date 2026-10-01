#!/usr/bin/env bash
# Optional callbacks sourced by reth-paired-devnet.sh for queued evidence lanes.
# The caller holds the devnet lock when executing a runner; sourcing this file never locks or starts nodes.
# shellcheck disable=SC2154 # These lane variables are initialized by reth-paired-devnet.sh before source.

post_m2a_default_manifest=registrygenesis/testdata/allocation-build-v1.example.json
if [ "$postM2aMode" = t1 ] || [ "$postM2aMode" = t4 ]; then
  POST_M2A_FEE_COLLECTOR=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["feeBeneficiary"])
PY
  ) || return 1
  URETH_PIN_FEE_COLLECTOR_OVERRIDE=$POST_M2A_FEE_COLLECTOR
  export POST_M2A_FEE_COLLECTOR URETH_PIN_FEE_COLLECTOR_OVERRIDE
fi

post_m2a_compile_manifest_genesis() {
  local signer
  signer=$(go run ./scripts/evmtx -address) || return 1
  python3 - "$post_m2a_default_manifest" "$signer" test-nodes/post-m2a-allocation-build-v1.json <<'PY' || return 1
import json, sys
from decimal import Decimal

source, signer, target = sys.argv[1:]
manifest = json.load(open(source, encoding="utf-8"))
bootstrap = [item for item in manifest["allocations"]
             if item.get("purpose") == "bootstrap_validator_gas" and item.get("kind") == "eoa"]
if len(bootstrap) != 3:
    raise SystemExit(f"expected the three default bootstrap allocations, got {len(bootstrap)}")
if any(item["recipient"].lower() == signer.lower() for item in manifest["allocations"]):
    raise SystemExit("test signer already appears in the default allocation manifest")
# Default recipients are placeholders without private keys. Replace only one bootstrap recipient
# with scripts/evmtx's public test key; amounts, S0, contracts, schedules and fee ratio stay default.
placeholder = bootstrap[-1]["recipient"].lower()
bootstrap[-1]["recipient"] = signer
budgets = [item for item in manifest["bootstrapGasBudgets"]
           if item["recipient"].lower() == placeholder]
if len(budgets) != 1:
    raise SystemExit("expected the default gas budget for the third bootstrap EOA")
budgets[0]["recipient"] = signer
total = sum((Decimal(item["amount"]) for item in manifest["allocations"]), Decimal(0))
if total != Decimal(manifest["nativeSupply"]):
    raise SystemExit(f"manifest allocations sum to {total}, expected {manifest['nativeSupply']}")
with open(target, "w", encoding="utf-8") as out:
    json.dump(manifest, out, indent=2)
    out.write("\n")
print(f"evidence bootstrap EOA={signer}; unchanged native supply={total}")
PY
  build/ubft engine-api export-manifest --manifest test-nodes/post-m2a-allocation-build-v1.json \
    --out test-nodes/post-m2a-allocation-build-v1.exported.json || return 1
  build/ubft engine-api genesis --shard-conf "test-nodes/shard-conf-${partitionID}_0.json" \
    --manifest test-nodes/post-m2a-allocation-build-v1.exported.json \
    --out test-nodes/evm-genesis-finalized-funded.json \
    --full-shard-conf test-nodes/evm-full-shard-conf-v2.json --registry-layout "$(registry_layout)" || return 1
}

post_m2a_wait_initial_transactions() {
  local hash receipt block status ready
  while IFS= read -r hash; do
    [ -n "$hash" ] || continue
    ready=false
    for _ in $(seq 1 120); do
      receipt=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionReceipt "[\"$hash\"]") || receipt=
      block=$(printf '%s' "$receipt" | pyget "['result']['blockHash']" || true)
      status=$(printf '%s' "$receipt" | pyget "['result']['status']" || true)
      if [ "$status" = 0x1 ] && [ -n "$block" ] && [ "$block" != None ] &&
        grep -Eq "msg=\"certificate admitted\" block=${block#0x} .*rootEpoch=1([[:space:]]|$)" test-nodes/evm1/debug.log; then
        ready=true
        break
      fi
      sleep 1
    done
    $ready || { fail "bootstrap transaction $hash did not certify in root epoch 1"; return 1; }
  done < <(printf '%b' "$txHashes")
  M2_NEXT_NONCE=3
  pass "all three typed bootstrap transfers certified before the evidence transaction"
}

post_m2a_send_transaction() {
  local nonce=$1
  shift
  local expected='' sent='' i
  for i in $(seq 1 "$validators"); do
    sent=$(go run ./scripts/evmtx -send -eth-url "http://127.0.0.1:$((rethEthBase + i - 1))" \
      -chain-id "$postM2aChainID" -nonce "$nonce" "$@" 2>&1) || {
      fail "validator $i rejected evidence transaction at nonce $nonce: $sent"
      return 1
    }
    [[ "$sent" = 0x* ]] || { fail "evmtx returned no transaction hash at nonce $nonce: $sent"; return 1; }
    [ -z "$expected" ] || [ "$expected" = "$sent" ] || {
      fail "validators derived different evidence transaction hashes at nonce $nonce"
      return 1
    }
    expected=$sent
  done
  POST_M2A_TX_HASH=$expected
}

post_m2a_wait_certified_receipt() {
  local txHash=$1 epoch=$2 receipt status block
  for _ in $(seq 1 180); do
    receipt=$(rpc "http://127.0.0.1:$rethEthBase" eth_getTransactionReceipt "[\"$txHash\"]") || receipt=
    status=$(printf '%s' "$receipt" | pyget "['result']['status']" || true)
    block=$(printf '%s' "$receipt" | pyget "['result']['blockHash']" || true)
    if [ "$status" = 0x1 ] && [ -n "$block" ] && [ "$block" != None ] &&
      grep -Eq "msg=\"certificate admitted\" block=${block#0x} .*rootEpoch=$epoch([[:space:]]|$)" test-nodes/evm1/debug.log; then
      POST_M2A_RECEIPT=$receipt
      return 0
    fi
    sleep 1
  done
  fail "transaction $txHash was not successful and certified in root epoch $epoch"
  return 1
}

post_m2a_t4_exercise_contracts() {
  local artifacts=${POST_M2A_T4_ARTIFACT_DIR:-}
  [ -s "$artifacts/SameTransactionSelfDestructToSelf.bin" ] &&
    [ -s "$artifacts/ExistingSelfDestruct.bin" ] || {
      fail "pinned-solc T4 fixture bytecode is missing"; return 1;
    }
  local wuct collector beneficiary burnValue ordinaryValue depositAmount withdrawAmount
  local burnCode ordinaryCode beneficiaryWord burnNonce burnContract ordinaryNonce ordinaryContract
  local wuctWithdrawTopic withdrawSelector withdrawWord withdrawData splitTopic depositTopic
  local burnHash ordinaryDeployHash depositHash withdrawHash destroyHash splitHash
  wuct=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["addresses"]["wuct"])
PY
  ) || return 1
  collector=$POST_M2A_FEE_COLLECTOR
  beneficiary=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
m=json.load(open(sys.argv[1],encoding="utf-8"))
print(next(a["beneficiary"] for a in m["allocations"] if a["purpose"] == "ecosystem_vesting"))
PY
  ) || return 1
  burnValue=1200000
  ordinaryValue=2400000
  depositAmount=10000000
  withdrawAmount=4000000
  mkdir -p test-nodes/post-m2a-evidence/t4-contract-actions

  burnNonce=$M2_NEXT_NONCE
  burnContract=$(go run ./scripts/evmtx -create-address -nonce "$burnNonce") || return 1
  burnCode=$(tr -d '[:space:]' <"$artifacts/SameTransactionSelfDestructToSelf.bin") || return 1
  post_m2a_send_transaction "$burnNonce" -create -data "$burnCode" -gas-limit 300000 -value "$burnValue" || return 1
  burnHash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$burnHash" 1 || return 1
  if ! python3 - "$POST_M2A_RECEIPT" "$burnContract" <<'PY'
import json,sys
receipt=json.loads(sys.argv[1])["result"]
if receipt.get("status") != "0x1" or receipt.get("contractAddress","").lower() != sys.argv[2].lower():
    raise SystemExit("same-transaction CREATE/SELFDESTRUCT receipt is not successful or address-bound")
PY
  then
    fail "same-transaction selfdestruct-to-self deployment was not certified"; return 1
  fi
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t4-contract-actions/burn-create.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))

  ordinaryNonce=$M2_NEXT_NONCE
  ordinaryContract=$(go run ./scripts/evmtx -create-address -nonce "$ordinaryNonce") || return 1
  beneficiaryWord=$(python3 - "$beneficiary" <<'PY'
import sys
address=sys.argv[1].removeprefix("0x").lower()
if len(address)!=40: raise SystemExit("ordinary SELFDESTRUCT beneficiary is not an address")
print(address.rjust(64,"0"))
PY
  ) || return 1
  ordinaryCode=$(tr -d '[:space:]' <"$artifacts/ExistingSelfDestruct.bin") || return 1
  ordinaryCode="${ordinaryCode}${beneficiaryWord}"
  post_m2a_send_transaction "$ordinaryNonce" -create -data "$ordinaryCode" -gas-limit 350000 -value "$ordinaryValue" || return 1
  ordinaryDeployHash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$ordinaryDeployHash" 1 || return 1
  if ! python3 - "$POST_M2A_RECEIPT" "$ordinaryContract" <<'PY'
import json,sys
receipt=json.loads(sys.argv[1])["result"]
if receipt.get("status") != "0x1" or receipt.get("contractAddress","").lower() != sys.argv[2].lower():
    raise SystemExit("ordinary SELFDESTRUCT fixture deployment receipt is not successful or address-bound")
PY
  then
    fail "ordinary SELFDESTRUCT fixture deployment failed"; return 1
  fi
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t4-contract-actions/ordinary-create.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))

  depositTopic=$(go run ./scripts/evmtx -event-topic 'Deposit(address,uint256)') || return 1
  post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$wuct" -call 'deposit()' -gas-limit 150000 -value "$depositAmount" || return 1
  depositHash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$depositHash" 1 || return 1
  if ! python3 - "$POST_M2A_RECEIPT" "$wuct" "$depositTopic" "$depositAmount" <<'PY'
import json,sys
receipt=json.loads(sys.argv[1])["result"]
logs=[log for log in receipt.get("logs",[]) if log.get("address","").lower()==sys.argv[2].lower()
      and log.get("topics",[""])[0].lower()==sys.argv[3].lower()]
if receipt.get("status")!="0x1" or len(logs)!=1 or int(logs[0].get("data","0x0"),16)!=int(sys.argv[4]):
    raise SystemExit("nonzero WUCT Deposit event was not emitted with the requested amount")
PY
  then
    fail "nonzero WUCT deposit receipt did not match the expected amount"; return 1
  fi
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t4-contract-actions/wuct-deposit.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))

  wuctWithdrawTopic=$(go run ./scripts/evmtx -event-topic 'Withdrawal(address,uint256)') || return 1
  withdrawSelector=$(go run ./scripts/evmtx -method-selector 'withdraw(uint256)') || return 1
  printf -v withdrawWord '%064x' "$withdrawAmount"
  withdrawData="${withdrawSelector}${withdrawWord}"
  post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$wuct" -data "$withdrawData" -gas-limit 150000 -value 0 || return 1
  withdrawHash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$withdrawHash" 1 || return 1
  if ! python3 - "$POST_M2A_RECEIPT" "$wuct" "$wuctWithdrawTopic" "$withdrawAmount" <<'PY'
import json,sys
receipt=json.loads(sys.argv[1])["result"]
logs=[log for log in receipt.get("logs",[]) if log.get("address","").lower()==sys.argv[2].lower()
      and log.get("topics",[""])[0].lower()==sys.argv[3].lower()]
if receipt.get("status")!="0x1" or len(logs)!=1 or int(logs[0].get("data","0x0"),16)!=int(sys.argv[4]):
    raise SystemExit("nonzero WUCT Withdrawal event was not emitted with the requested amount")
PY
  then
    fail "nonzero WUCT withdrawal receipt did not match the expected amount"; return 1
  fi
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t4-contract-actions/wuct-withdraw.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))

  post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$ordinaryContract" -call 'destroy()' -gas-limit 150000 -value 0 || return 1
  destroyHash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$destroyHash" 1 || return 1
  [ "$(printf '%s' "$POST_M2A_RECEIPT" | pyget "['result']['status']")" = 0x1 ] || {
    fail "ordinary SELFDESTRUCT transaction did not succeed"; return 1;
  }
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t4-contract-actions/ordinary-destroy.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))

  splitTopic=$(go run ./scripts/evmtx -event-topic 'Split(uint256,uint256,uint256)') || return 1
  post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$collector" -call 'split()' -gas-limit 200000 -value 0 || return 1
  splitHash=$POST_M2A_TX_HASH
  post_m2a_wait_certified_receipt "$splitHash" 1 || return 1
  if ! python3 - "$POST_M2A_RECEIPT" "$collector" "$splitTopic" <<'PY'
import json,sys
receipt=json.loads(sys.argv[1])["result"]
logs=[log for log in receipt.get("logs",[]) if log.get("address","").lower()==sys.argv[2].lower()
      and log.get("topics",[""])[0].lower()==sys.argv[3].lower()]
if receipt.get("status")!="0x1" or len(logs)!=1:
    raise SystemExit("FeeCollector split() receipt lacks its event")
data=logs[0].get("data","").removeprefix("0x")
if len(data)!=192: raise SystemExit("FeeCollector Split event has malformed data")
unallocated,credit,reward=(int(data[i:i+64],16) for i in (0,64,128))
if unallocated<=0 or credit+reward!=unallocated or credit+reward<=0:
    raise SystemExit(f"split produced no nonzero liabilities or wrong totals: {unallocated}, {credit}, {reward}")
PY
  then
    fail "FeeCollector split did not create nonzero, fully-backed liabilities"; return 1
  fi
  printf '%s\n' "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t4-contract-actions/collector-split.receipt.json
  M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))

  if ! POST_M2A_T4_COMPILER_VERSION=$(cat "$artifacts/solc-version.txt") \
    POST_M2A_T4_BURN_CONTRACT=$burnContract POST_M2A_T4_BURN_TX=$burnHash POST_M2A_T4_BURN_VALUE=$burnValue \
    POST_M2A_T4_ORDINARY_CONTRACT=$ordinaryContract POST_M2A_T4_ORDINARY_DEPLOY_TX=$ordinaryDeployHash \
    POST_M2A_T4_ORDINARY_DESTROY_TX=$destroyHash POST_M2A_T4_ORDINARY_VALUE=$ordinaryValue \
    POST_M2A_T4_BENEFICIARY=$beneficiary POST_M2A_T4_WUCT=$wuct \
    POST_M2A_T4_WUCT_DEPOSIT_TX=$depositHash POST_M2A_T4_WUCT_DEPOSIT=$depositAmount \
    POST_M2A_T4_WUCT_WITHDRAW_TX=$withdrawHash POST_M2A_T4_WUCT_WITHDRAW=$withdrawAmount \
    POST_M2A_T4_COLLECTOR=$collector POST_M2A_T4_SPLIT_TX=$splitHash \
    python3 - <<'PY' >test-nodes/post-m2a-evidence/t4-contract-actions.json
import json,os,sys
out={
 "compiler":os.environ["POST_M2A_T4_COMPILER_VERSION"],
 "selfdestructToSelf":{"contract":os.environ["POST_M2A_T4_BURN_CONTRACT"],"transactionHash":os.environ["POST_M2A_T4_BURN_TX"],"valueWei":os.environ["POST_M2A_T4_BURN_VALUE"]},
 "ordinarySelfdestruct":{"contract":os.environ["POST_M2A_T4_ORDINARY_CONTRACT"],"deployTransactionHash":os.environ["POST_M2A_T4_ORDINARY_DEPLOY_TX"],"destroyTransactionHash":os.environ["POST_M2A_T4_ORDINARY_DESTROY_TX"],"valueWei":os.environ["POST_M2A_T4_ORDINARY_VALUE"],"beneficiary":os.environ["POST_M2A_T4_BENEFICIARY"]},
 "wuct":{"address":os.environ["POST_M2A_T4_WUCT"],"depositTransactionHash":os.environ["POST_M2A_T4_WUCT_DEPOSIT_TX"],"depositWei":os.environ["POST_M2A_T4_WUCT_DEPOSIT"],"withdrawTransactionHash":os.environ["POST_M2A_T4_WUCT_WITHDRAW_TX"],"withdrawWei":os.environ["POST_M2A_T4_WUCT_WITHDRAW"],"expectedTotalSupplyWei":str(int(os.environ["POST_M2A_T4_WUCT_DEPOSIT"])-int(os.environ["POST_M2A_T4_WUCT_WITHDRAW"]))},
 "feeCollector":{"address":os.environ["POST_M2A_T4_COLLECTOR"],"splitTransactionHash":os.environ["POST_M2A_T4_SPLIT_TX"]}}
json.dump(out,sys.stdout,indent=2); print()
PY
  then
    fail "could not write the T4 contract action manifest"
    return 1
  fi
  pass "deployed the Cancun same-transaction burn and ordinary SELFDESTRUCT fixtures"
  pass "nonzero WUCT deposit/withdrawal and FeeCollector split() liabilities were certified"
}

post_m2a_after_bootstrap() {
  post_m2a_wait_initial_transactions || return 1
  mkdir -p test-nodes/post-m2a-evidence
  if [ "$postM2aMode" = f7 ]; then
    local initcode deployHash contract lockHash receipt emitter topic
    initcode=$(go run ./scripts/evmtx -lock-initcode) || return 1
    post_m2a_send_transaction "$M2_NEXT_NONCE" -create -data "$initcode" -gas-limit 200000 -value 0 || return 1
    deployHash=$POST_M2A_TX_HASH
    post_m2a_wait_certified_receipt "$deployHash" 1 || return 1
    [ "$(printf '%s' "$POST_M2A_RECEIPT" | pyget "['result']['type']")" = 0x2 ] || {
      fail "lock contract deployment did not use an EIP-1559 typed transaction"; return 1;
    }
    contract=$(go run ./scripts/evmtx -create-address -nonce "$M2_NEXT_NONCE") || return 1
    M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
    topic=$(go run ./scripts/evmtx -event-topic 'Locked(uint256)') || return 1
    post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$contract" -value 42 -gas-limit 100000 || return 1
    lockHash=$POST_M2A_TX_HASH
    post_m2a_wait_certified_receipt "$lockHash" 1 || return 1
    receipt=$POST_M2A_RECEIPT
    emitter=$contract
    if ! python3 - "$receipt" "$contract" "$topic" <<'PY'
import json, sys
receipt, emitter, topic = json.loads(sys.argv[1])["result"], sys.argv[2].lower(), sys.argv[3].lower()
if receipt.get("type") != "0x2" or len(receipt.get("logs", [])) != 1:
    raise SystemExit("lock receipt must be a type-2 transaction with exactly one event")
log = receipt["logs"][0]
if log["address"].lower() != emitter or not log["topics"] or log["topics"][0].lower() != topic:
    raise SystemExit("lock receipt lacks the expected contract event")
if int(log["data"], 16) != 42:
    raise SystemExit("lock event did not commit the locked 42-wei asset amount")
PY
    then
      fail "the typed lock receipt does not contain the expected contract event"
      return 1
    fi
    python3 - "$receipt" "$emitter" "$lockHash" "$topic" \
      >test-nodes/post-m2a-evidence/f7-lock-pin.json <<'PY'
import json,sys
receipt=json.loads(sys.argv[1])["result"]
pin={"blockHash":receipt["blockHash"],"blockNumber":int(receipt["blockNumber"],16),
 "txIndex":int(receipt["transactionIndex"],16),"logIndex":int(receipt["logs"][0]["logIndex"],16),
 "contract":sys.argv[2],"transactionHash":sys.argv[3],"topic":sys.argv[4]}
json.dump(pin,sys.stdout,separators=(",",":")); print()
PY
    M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
    pass "deployed the payable lock contract with a typed receipt"
    pass "locked 42 wei; recorded (blockHash, txIndex, logIndex) from the certified real ureth receipt"
  else
    local vault beneficiary sender collector beforeBeneficiary afterBeneficiary beforeCollector afterCollector
    local claimHash claimBlock claimNumber afterBlock
    vault=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["addresses"]["ecosystemVesting"])
PY
    ) || return 1
    beneficiary=$(python3 - "$post_m2a_default_manifest" <<'PY'
import json,sys
m=json.load(open(sys.argv[1],encoding="utf-8"))
print(next(a["beneficiary"] for a in m["allocations"] if a["purpose"] == "ecosystem_vesting"))
PY
    ) || return 1
    sender=$(go run ./scripts/evmtx -address) || return 1
    collector=$POST_M2A_FEE_COLLECTOR
    beforeBeneficiary=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBalance "[\"$beneficiary\",\"latest\"]" | pyget "['result']") || return 1
    beforeCollector=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBalance "[\"$collector\",\"latest\"]" | pyget "['result']") || return 1
    post_m2a_send_transaction "$M2_NEXT_NONCE" -to "$vault" -call 'release()' -gas-limit 200000 -value 0 || return 1
    claimHash=$POST_M2A_TX_HASH
    post_m2a_wait_certified_receipt "$claimHash" 1 || return 1
    [ "$(printf '%s' "$POST_M2A_RECEIPT" | pyget "['result']['type']")" = 0x2 ] || {
      fail "vesting claim did not use an EIP-1559 typed transaction"; return 1;
    }
    claimBlock=$(printf '%s' "$POST_M2A_RECEIPT" | pyget "['result']['blockHash']")
    claimNumber=$(printf '%s' "$POST_M2A_RECEIPT" | pyget "['result']['blockNumber']")
    afterBlock=$(printf '%s' "$claimNumber" | python3 -c 'import sys; print(hex(int(sys.stdin.read().strip(),16)))')
    afterBeneficiary=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBalance "[\"$beneficiary\",\"$afterBlock\"]" | pyget "['result']") || return 1
    afterCollector=$(rpc "http://127.0.0.1:$rethEthBase" eth_getBalance "[\"$collector\",\"$afterBlock\"]" | pyget "['result']") || return 1
    if ! python3 - "$beforeBeneficiary" "$afterBeneficiary" "$beforeCollector" "$afterCollector" "$POST_M2A_RECEIPT" <<'PY'
import json,sys
before_b,after_b,before_c,after_c=map(lambda x:int(x,16),sys.argv[1:5])
receipt=json.loads(sys.argv[5])["result"]
principal=300000000000000000000000000
if receipt.get("status") != "0x1" or receipt.get("type") != "0x2":
    raise SystemExit("first claim receipt is not successful type 2")
if after_b-before_b != principal:
    raise SystemExit(f"due-at-start claim credited {after_b-before_b}, expected {principal}")
if after_c <= before_c:
    raise SystemExit("the real priority-fee rule did not credit the FeeCollector")
PY
    then
      fail "the vesting receipt or fee balances violate the expected claim accounting"
      return 1
    fi
    POST_M2A_SENDER=$sender POST_M2A_VAULT=$vault POST_M2A_BENEFICIARY=$beneficiary \
      POST_M2A_COLLECTOR=$collector POST_M2A_CLAIM_BLOCK_HASH=$claimBlock \
      POST_M2A_CLAIM_BLOCK_NUMBER=$claimNumber POST_M2A_CLAIM_TX=$claimHash \
      POST_M2A_BENEFICIARY_BEFORE=$beforeBeneficiary POST_M2A_BENEFICIARY_AFTER=$afterBeneficiary \
      POST_M2A_COLLECTOR_BEFORE=$beforeCollector POST_M2A_COLLECTOR_AFTER=$afterCollector \
      python3 - "$POST_M2A_RECEIPT" >test-nodes/post-m2a-evidence/t1-claim.json <<'PY'
import json,os,sys
result=json.loads(sys.argv[1])["result"]
out={"receipt":result,"sender":os.environ["POST_M2A_SENDER"],"vault":os.environ["POST_M2A_VAULT"],
 "beneficiary":os.environ["POST_M2A_BENEFICIARY"],"feeCollector":os.environ["POST_M2A_COLLECTOR"],
 "claimBlockHash":os.environ["POST_M2A_CLAIM_BLOCK_HASH"],"claimBlockNumber":os.environ["POST_M2A_CLAIM_BLOCK_NUMBER"],
 "transactionHash":os.environ["POST_M2A_CLAIM_TX"],
 "balances":{"beneficiaryBefore":os.environ["POST_M2A_BENEFICIARY_BEFORE"],
 "beneficiaryAfter":os.environ["POST_M2A_BENEFICIARY_AFTER"],"feeCollectorBefore":os.environ["POST_M2A_COLLECTOR_BEFORE"],
 "feeCollectorAfter":os.environ["POST_M2A_COLLECTOR_AFTER"]}}
json.dump(out,sys.stdout,indent=2); print()
PY
    M2_NEXT_NONCE=$((M2_NEXT_NONCE + 1))
    pass "default-manifest ecosystem vesting release succeeded as a typed transaction in root epoch 1"
    pass "beneficiary received the exact due principal and FeeCollector received the priority fee"
  fi
  if [ "$postM2aMode" = t4 ]; then
    post_m2a_t4_exercise_contracts || return 1
  fi
}

post_m2a_after_lane() {
  local statusFile=test-nodes/post-m2a-evidence/operator-status.json
  build/ubft shard-node status --url "http://127.0.0.1:$evmRPCPortStart" --timeout 10s \
    >"$statusFile" 2>test-nodes/post-m2a-evidence/operator-status.txt || {
      fail "read-only operator status command failed after the handoff lane"; return 1;
    }
  if ! python3 - "$statusFile" "$postM2aMode" test-nodes/post-m2a-evidence/f7-lock-pin.json <<'PY'
import json,sys
status=json.load(open(sys.argv[1],encoding="utf-8")); mode=sys.argv[2]
minimum_epoch = 1 if mode == "t4" else 2
handoff_missing = mode != "t4" and not status.get("activatedHandoffs")
if status.get("currentRootEpoch",0) < minimum_epoch or handoff_missing:
    raise SystemExit("operator status shows no committed/activated root handoff")
if mode == "f7":
    pin=json.load(open(sys.argv[3],encoding="utf-8"))
    frontier=status.get("pruneFrontier")
    if not frontier or int(frontier.get("height",0)) < int(pin["blockNumber"]):
        raise SystemExit("archive prune frontier has not crossed the locked block")
    replicas=status.get("replicas",[])
    if len(replicas) < 2 or any(int(item.get("lastAcknowledgedHeight",0)) < int(frontier["height"]) for item in replicas[:2]):
        raise SystemExit("two configured replicas have not durably acknowledged the prune frontier")
PY
  then
    fail "handoff/frontier/replica evidence did not satisfy the lane predicates"
    return 1
  fi
  if [ "$postM2aMode" = t4 ]; then
    pass "operator status confirms root epoch 1; handoff skipped for the audit lane"
  else
    pass "operator status confirms the root handoff was activated"
  fi
  if [ "$postM2aMode" = f7 ]; then
    pass "receipt-complete local archive and two replica acknowledgements cover a pruned frontier"
  fi
  if [ "$postM2aMode" = t4 ]; then
    python3 scripts/post-m2a-t4-rpc-capture.py --url "http://127.0.0.1:$rethEthBase" \
      --nodes test-nodes --trace-dir test-nodes/post-m2a-evidence/t4-traces \
      --output test-nodes/post-m2a-evidence/t4-rpc-accounting.json || {
        fail "could not capture certified block headers and SELFDESTRUCT trace coverage"; return 1;
      }
    pass "certified block history and incrementally captured per-block SELFDESTRUCT trace coverage captured"
  fi
}
