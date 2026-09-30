#!/usr/bin/env python3
"""Capture certified headers, receipts, full state, and Cancun SELFDESTRUCT evidence for T4."""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


ZERO_ADDRESS = "0x" + "00" * 20
WUCT_SUPPLY_SLOT = "0x" + "00" * 31 + "02"
COLLECTOR_CREDIT_SLOT = "0x" + "00" * 31 + "01"
COLLECTOR_REWARD_SLOT = "0x" + "00" * 31 + "02"


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        decoded = json.loads(response.read())
    if decoded.get("error"):
        raise RuntimeError(f"{method} returned {decoded['error']}")
    if "result" not in decoded:
        raise RuntimeError(f"{method} returned no result")
    return decoded["result"]


def rpc_quantity(value, field):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"{field} is not an RPC hex quantity")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise RuntimeError(f"{field} is not an RPC hex quantity") from exc


def capture_fee_receipt(url, block, transaction, number, index):
    tx_hash = transaction.get("hash")
    if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
        raise RuntimeError(f"block {number} transaction {index} has an invalid hash")
    receipt = rpc(url, "eth_getTransactionReceipt", [tx_hash])
    if not isinstance(receipt, dict):
        raise RuntimeError(f"block {number} transaction {tx_hash} has no receipt")
    if (str(receipt.get("transactionHash", "")).lower() != tx_hash.lower()
            or str(receipt.get("blockHash", "")).lower() != str(block["hash"]).lower()
            or rpc_quantity(receipt.get("blockNumber"), "receipt blockNumber") != number
            or rpc_quantity(receipt.get("transactionIndex"), "receipt transactionIndex") != index):
        raise RuntimeError(f"block {number} transaction {tx_hash} receipt is bound to different coordinates")

    base_fee = rpc_quantity(block.get("baseFeePerGas"), f"block {number} baseFeePerGas")
    gas_used = rpc_quantity(receipt.get("gasUsed"), f"receipt {tx_hash} gasUsed")
    effective = rpc_quantity(receipt.get("effectiveGasPrice"), f"receipt {tx_hash} effectiveGasPrice")
    if gas_used <= 0:
        raise RuntimeError(f"block {number} transaction {tx_hash} has zero receipt gas")

    if transaction.get("maxPriorityFeePerGas") is not None:
        tip_cap = rpc_quantity(transaction.get("maxPriorityFeePerGas"), f"transaction {tx_hash} maxPriorityFeePerGas")
        fee_cap = rpc_quantity(transaction.get("maxFeePerGas"), f"transaction {tx_hash} maxFeePerGas")
        if fee_cap < base_fee:
            raise RuntimeError(f"block {number} transaction {tx_hash} fee cap is below its base fee")
        tip = min(tip_cap, fee_cap - base_fee)
    else:
        if effective < base_fee:
            raise RuntimeError(f"block {number} transaction {tx_hash} effective gas price is below its base fee")
        tip = effective - base_fee
    if effective - tip != base_fee:
        raise RuntimeError(f"block {number} transaction {tx_hash} effective gas price minus tip does not equal base fee")
    fee = {
        "transactionHash": tx_hash.lower(),
        "gasUsed": hex(gas_used),
        "effectiveGasPrice": hex(effective),
        "priorityFeePerGas": hex(tip),
    }
    return fee, receipt


def call_targets(struct_logs):
    targets = set()
    for step in struct_logs:
        op = str(step.get("op", "")).upper()
        if op in {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}:
            stack = step.get("stack")
            if not isinstance(stack, list) or len(stack) < 2:
                raise RuntimeError(f"{op} trace omits the EVM stack needed for account coverage")
            try:
                word = int(str(stack[-2]), 16)
            except ValueError as exc:
                raise RuntimeError(f"{op} trace has a malformed target stack word") from exc
            targets.add(f"0x{word & ((1 << 160) - 1):040x}")
    return targets


def bound_struct_logs(trace_item, tx_hash, number):
    if not isinstance(trace_item, dict):
        raise RuntimeError(f"block {number} has a malformed transaction trace")
    if str(trace_item.get("txHash", "")).lower() != tx_hash.lower():
        raise RuntimeError(f"block {number} trace is not bound to transaction {tx_hash}")
    result = trace_item.get("result")
    logs = result.get("structLogs") if isinstance(result, dict) else None
    if not isinstance(logs, list):
        raise RuntimeError(f"block {number} transaction {tx_hash} lacks a complete structLogs trace")
    return logs


def selfdestruct_observations(transactions, receipts, traces, number):
    observations = []
    for tx in transactions:
        tx_hash = tx["hash"].lower()
        logs = bound_struct_logs(traces[tx_hash], tx_hash, number)
        for step in logs:
            if str(step.get("op", "")).upper() not in {"CREATE", "CREATE2"}:
                continue
            raise RuntimeError(f"block {number} has an internal CREATE/CREATE2; account inventory is incomplete")
        for step in logs:
            if str(step.get("op", "")).upper() != "SELFDESTRUCT":
                continue
            if step.get("depth") != 1:
                raise RuntimeError(f"block {number} transaction {tx_hash} has nested SELFDESTRUCT; actor identity is unbound")
            stack = step.get("stack")
            if not isinstance(stack, list) or not stack:
                raise RuntimeError(f"block {number} transaction {tx_hash} SELFDESTRUCT omits its beneficiary stack word")
            try:
                beneficiary = f"0x{int(str(stack[-1]), 16) & ((1 << 160) - 1):040x}"
            except ValueError as exc:
                raise RuntimeError(f"block {number} transaction {tx_hash} has a malformed SELFDESTRUCT beneficiary") from exc
            receipt = receipts[tx_hash]
            created = tx.get("to") is None
            contract = receipt.get("contractAddress") if created else tx.get("to")
            if not isinstance(contract, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", contract):
                raise RuntimeError(f"block {number} transaction {tx_hash} SELFDESTRUCT actor is unknown")
            contract = contract.lower()
            burned = 0
            value = rpc_quantity(tx.get("value", "0x0"), f"transaction {tx_hash} value")
            if created and beneficiary.lower() == contract:
                burned = value
            observations.append({
                "transactionHash": tx_hash,
                "contract": contract,
                "beneficiary": beneficiary.lower(),
                "createdInSameTransaction": created,
                "opcode": "SELFDESTRUCT",
                "burnedAmount": hex(burned),
            })
    return observations


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="validator 1's pinned ureth eth/debug endpoint")
    parser.add_argument("--nodes", required=True, type=Path, help="paired lane test-nodes directory")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--trace-dir", required=True, type=Path,
                        help="incremental per-block traces captured by d1-monitor while bindings were live")
    parser.add_argument("--eth-base", type=int, default=18545)
    parser.add_argument("--validators", type=int, default=4)
    args = parser.parse_args()
    try:
        heads = []
        for index in range(args.validators):
            head = rpc(f"http://127.0.0.1:{args.eth_base + index}", "eth_blockNumber", [])
            heads.append(int(head, 16))
        if len(set(heads)) != 1:
            raise RuntimeError(f"validator execution heads disagree: {heads}")
        tip = heads[0]
        print(f"PASS: all {args.validators} ureth nodes agree at block {tip}")

        genesis = rpc(args.url, "eth_getBlockByNumber", ["0x0", False])
        if not genesis or not genesis.get("hash"):
            raise RuntimeError("genesis header is unavailable")
        genesis_hash = genesis["hash"].lower()
        previous_hash = genesis_hash
        latest = rpc(args.url, "eth_getBlockByNumber", [hex(tip), False])
        if not latest or not latest.get("hash"):
            raise RuntimeError("certified execution tip header is unavailable")
        final_hash = latest["hash"].lower()
        for index in range(args.validators):
            log = args.nodes / f"evm{index + 1}" / "debug.log"
            content = log.read_text(errors="replace")
            if not re.search(rf'msg="certificate admitted" block={re.escape(final_hash[2:])}(?:\s|$)', content):
                raise RuntimeError(f"validator {index + 1} has no certificate-admitted line for tip {final_hash}")
        print(f"PASS: block {tip} {final_hash} is certified in every validator log")

        chain_genesis = json.loads(Path("test-nodes/evm-genesis-finalized-funded.json").read_text())
        manifest = json.loads(Path("test-nodes/post-m2a-allocation-build-v1.json").read_text())
        claim_record = json.loads(Path("test-nodes/post-m2a-evidence/t1-claim.json").read_text())
        actions = json.loads(Path("test-nodes/post-m2a-evidence/t4-contract-actions.json").read_text())
        claim_hash = claim_record["transactionHash"].lower()
        known_accounts = {address.lower() for address in chain_genesis["alloc"]}
        storage_slots = {address.lower(): set(account.get("storage", {}))
                         for address, account in chain_genesis["alloc"].items()}
        beneficiaries = [entry["beneficiary"] for entry in manifest["allocations"] if entry.get("beneficiary")]
        known_accounts.update(address.lower() for address in beneficiaries)
        wuct = manifest["addresses"]["wuct"].lower()
        collector = manifest["addresses"]["feeCollector"].lower()
        storage_slots.setdefault(wuct, set()).add(WUCT_SUPPLY_SLOT)
        storage_slots.setdefault(collector, set()).update({COLLECTOR_CREDIT_SLOT, COLLECTOR_REWARD_SLOT})
        for entry in manifest["allocations"]:
            if entry.get("purpose", "").endswith("vesting"):
                storage_slots.setdefault(entry["recipient"].lower(), set()).update(
                    {"0x" + "00" * 32, "0x" + "00" * 31 + "01"})

        action_transactions = {
            actions["selfdestructToSelf"]["transactionHash"].lower(),
            actions["ordinarySelfdestruct"]["deployTransactionHash"].lower(),
            actions["ordinarySelfdestruct"]["destroyTransactionHash"].lower(),
            actions["wuct"]["depositTransactionHash"].lower(),
            actions["wuct"]["withdrawTransactionHash"].lower(),
            actions["feeCollector"]["splitTransactionHash"].lower(),
        }
        blocks = []
        block_by_tx = {}
        transaction_count = 0
        transfer_count = 0
        claim_seen = False
        fee_burn = 0
        all_selfdestructs = []
        for number in range(1, tip + 1):
            block = rpc(args.url, "eth_getBlockByNumber", [hex(number), True])
            if not block or not block.get("hash") or block.get("parentHash", "").lower() != previous_hash:
                raise RuntimeError(f"block {number} is missing or breaks the parent-hash chain")
            if block.get("blobGasUsed") is None:
                raise RuntimeError(f"block {number} omits Cancun blobGasUsed")
            miner = block.get("miner") or block.get("author") or ZERO_ADDRESS
            if not isinstance(miner, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", miner):
                raise RuntimeError(f"block {number} has an invalid fee-beneficiary address")
            known_accounts.add(miner.lower())
            withdrawals = block.get("withdrawals")
            if withdrawals is None:
                raise RuntimeError(f"block {number} omits the withdrawals list")
            transactions = block.get("transactions")
            if not isinstance(transactions, list):
                raise RuntimeError(f"block {number} omits its full transaction list")
            trace_path = args.trace_dir / f"block-{number:06d}.json"
            try:
                trace_record = json.loads(trace_path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"block {number} lacks incremental trace coverage: {exc}") from exc
            if not isinstance(trace_record, dict):
                raise RuntimeError(f"block {number} trace coverage is uncovered: record is not an object")
            trace = trace_record.get("trace")
            if (trace_record.get("number") != number
                    or str(trace_record.get("blockHash", "")).lower() != block["hash"].lower()
                    or not isinstance(trace_record.get("validator"), int)
                    or not 1 <= trace_record["validator"] <= args.validators
                    or not isinstance(trace, list)
                    or len(trace) != len(transactions)):
                raise RuntimeError(f"block {number} trace coverage is missing, incomplete or bound to another block")
            traces = {}
            for transaction, trace_item in zip(transactions, trace):
                if not isinstance(transaction, dict):
                    raise RuntimeError(f"block {number} has a malformed transaction entry")
                tx_hash = transaction.get("hash", "").lower()
                if not tx_hash or tx_hash in traces:
                    raise RuntimeError(f"block {number} has a missing or duplicate transaction hash")
                traces[tx_hash] = trace_item
            trace_hashes = [str(item.get("txHash", "")).lower() if isinstance(item, dict) else ""
                            for item in trace]
            if set(trace_hashes) != set(traces) or len(set(trace_hashes)) != len(trace_hashes):
                raise RuntimeError(f"block {number} trace transaction hashes do not cover the block")
            for trace_item in trace:
                item_hash = str(trace_item.get("txHash", "")).lower() if isinstance(trace_item, dict) else ""
                if item_hash not in traces:
                    raise RuntimeError(f"block {number} has a trace for an unknown transaction {item_hash}")
                known_accounts.update(call_targets(bound_struct_logs(trace_item, item_hash, number)))
            receipts = {}
            fee_receipts = []
            for transaction_index, transaction in enumerate(transactions):
                transaction_count += 1
                fee, receipt = capture_fee_receipt(args.url, block, transaction, number, transaction_index)
                fee_receipts.append(fee)
                tx_hash = transaction["hash"].lower()
                receipts[tx_hash] = receipt
                block_by_tx[tx_hash] = (number, block, transaction)
                if tx_hash == claim_hash:
                    claim_seen = True
                sender = transaction.get("from")
                recipient = transaction.get("to")
                if not isinstance(sender, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", sender):
                    raise RuntimeError(f"block {number} transaction {tx_hash} has no valid sender")
                known_accounts.add(sender.lower())
                if recipient is not None:
                    if not isinstance(recipient, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", recipient):
                        raise RuntimeError(f"block {number} transaction {tx_hash} has an invalid recipient")
                    known_accounts.add(recipient.lower())
                elif receipt.get("contractAddress"):
                    known_accounts.add(receipt["contractAddress"].lower())
                if recipient and recipient.lower() == "0x00000000000000000000000000000000000000ff":
                    transfer_count += 1
            for tx_hash in action_transactions.intersection(receipts):
                receipt = receipts[tx_hash]
                if receipt.get("status") != "0x1":
                    raise RuntimeError(f"T4 action transaction {tx_hash} did not succeed")
            observations = selfdestruct_observations(transactions, receipts, traces, number)
            all_selfdestructs.extend(observations)
            ordinary_gas = sum(int(receipt["gasUsed"], 16) for receipt in fee_receipts)
            header_gas = rpc_quantity(block["gasUsed"], f"block {number} gasUsed")
            if ordinary_gas > header_gas:
                raise RuntimeError(f"block {number} receipt gas exceeds gross header gas")
            system_gas = header_gas - ordinary_gas
            fee_burn += rpc_quantity(block["baseFeePerGas"], f"block {number} baseFeePerGas") * ordinary_gas
            blocks.append({
                "number": number,
                "hash": block["hash"].lower(),
                "parentHash": block["parentHash"].lower(),
                "difficulty": block.get("difficulty", "0x0"),
                "baseFeePerGas": block["baseFeePerGas"],
                "gasUsed": block["gasUsed"],
                "transactionCount": len(transactions),
                "feeReceipts": fee_receipts,
                "blobGasUsed": block["blobGasUsed"],
                "withdrawalsCount": len(withdrawals),
                "selfdestructTracesComplete": True,
                "selfdestructs": observations,
            })
            if number <= 3:
                print(f"T4 fee coverage B{number}: {len(fee_receipts)} ordinary receipt(s), "
                      f"{ordinary_gas} paid gas + {system_gas} system gas", flush=True)
            previous_hash = block["hash"].lower()
        if previous_hash != final_hash:
            raise RuntimeError("last accounting header does not equal the certified tip")
        if not claim_seen:
            raise RuntimeError(f"the successful vesting claim {claim_hash} is not in the certified block history")
        if transaction_count < 4 or transfer_count < 3:
            raise RuntimeError(f"expected bootstrap and handoff transfers; saw {transaction_count} txs and {transfer_count} transfer-to-0xff txs")
        if fee_burn <= 0:
            raise RuntimeError("no base-fee burn was observed in the certified block history")
        if len(all_selfdestructs) != 2:
            raise RuntimeError(f"expected exactly two controlled SELFDESTRUCT records, observed {len(all_selfdestructs)}")

        burn_action = actions["selfdestructToSelf"]
        ordinary_action = actions["ordinarySelfdestruct"]
        by_tx = {record["transactionHash"]: record for record in all_selfdestructs}
        burn = by_tx.get(burn_action["transactionHash"].lower())
        if (not burn or burn["contract"].lower() != burn_action["contract"].lower()
                or burn["beneficiary"].lower() != burn_action["contract"].lower()
                or not burn["createdInSameTransaction"]
                or int(burn["burnedAmount"], 16) != int(burn_action["valueWei"])):
            raise RuntimeError("same-transaction CREATE/SELFDESTRUCT-to-self did not produce its expected native burn")
        ordinary_destroy = by_tx.get(ordinary_action["destroyTransactionHash"].lower())
        if (not ordinary_destroy or ordinary_destroy["contract"].lower() != ordinary_action["contract"].lower()
                or ordinary_destroy["beneficiary"].lower() != ordinary_action["beneficiary"].lower()
                or ordinary_destroy["createdInSameTransaction"] or int(ordinary_destroy["burnedAmount"], 16) != 0):
            raise RuntimeError("ordinary SELFDESTRUCT was not recorded as a transfer without a permitted burn")
        if ordinary_action["deployTransactionHash"].lower() not in block_by_tx:
            raise RuntimeError("ordinary SELFDESTRUCT fixture deployment is absent from certified history")
        burn_block = block_by_tx[burn_action["transactionHash"].lower()][0]
        ordinary_deploy_block = block_by_tx[ordinary_action["deployTransactionHash"].lower()][0]
        ordinary_destroy_block = block_by_tx[ordinary_action["destroyTransactionHash"].lower()][0]
        if not ordinary_deploy_block < ordinary_destroy_block:
            raise RuntimeError("ordinary SELFDESTRUCT deployment and destruction are not in separate ordered transactions")
        burn_address = burn_action["contract"].lower()
        ordinary_address = ordinary_action["contract"].lower()
        burn_code = rpc(args.url, "eth_getCode", [burn_address, hex(tip)]).lower()
        burn_balance = rpc_quantity(rpc(args.url, "eth_getBalance", [burn_address, hex(tip)]), "burned fixture balance")
        burn_code_at_creation_block = rpc(args.url, "eth_getCode", [burn_address, hex(burn_block)]).lower()
        burn_balance_at_creation_block = rpc_quantity(rpc(args.url, "eth_getBalance", [burn_address, hex(burn_block)]),
                                                      "same-transaction burn fixture balance")
        ordinary_code_deployed = rpc(args.url, "eth_getCode", [ordinary_address, hex(ordinary_deploy_block)]).lower()
        ordinary_code_tip = rpc(args.url, "eth_getCode", [ordinary_address, hex(tip)]).lower()
        ordinary_balance_deployed = rpc_quantity(rpc(args.url, "eth_getBalance", [ordinary_address, hex(ordinary_deploy_block)]), "ordinary fixture deployment balance")
        ordinary_balance_tip = rpc_quantity(rpc(args.url, "eth_getBalance", [ordinary_address, hex(tip)]), "ordinary fixture final balance")
        if (burn_code != "0x" or burn_balance != 0 or burn_code_at_creation_block != "0x"
                or burn_balance_at_creation_block != 0):
            raise RuntimeError("Cancun same-transaction selfdestruct did not remove its new account and balance")
        if not ordinary_code_deployed or ordinary_code_deployed == "0x" or ordinary_code_tip != ordinary_code_deployed:
            raise RuntimeError("Cancun ordinary SELFDESTRUCT did not preserve the already-deployed contract code")
        if ordinary_balance_deployed != int(ordinary_action["valueWei"]) or ordinary_balance_tip != 0:
            raise RuntimeError("ordinary SELFDESTRUCT did not transfer the fixture's full balance")
        beneficiary_before = rpc_quantity(rpc(args.url, "eth_getBalance", [ordinary_action["beneficiary"],
                                                                             hex(ordinary_destroy_block - 1)]),
                                          "ordinary SELFDESTRUCT beneficiary balance before transfer")
        beneficiary_after = rpc_quantity(rpc(args.url, "eth_getBalance", [ordinary_action["beneficiary"],
                                                                            hex(ordinary_destroy_block)]),
                                         "ordinary SELFDESTRUCT beneficiary balance after transfer")
        if beneficiary_after - beneficiary_before != int(ordinary_action["valueWei"]):
            raise RuntimeError("ordinary SELFDESTRUCT beneficiary did not receive the contract's full balance")

        deposit_hash = actions["wuct"]["depositTransactionHash"].lower()
        withdraw_hash = actions["wuct"]["withdrawTransactionHash"].lower()
        split_hash = actions["feeCollector"]["splitTransactionHash"].lower()
        for tx_hash in (deposit_hash, withdraw_hash, split_hash):
            if tx_hash not in block_by_tx:
                raise RuntimeError(f"T4 WUCT/FeeCollector action {tx_hash} is absent from certified history")
        expected_wuct_supply = int(actions["wuct"]["expectedTotalSupplyWei"])
        actual_wuct_supply = rpc_quantity(rpc(args.url, "eth_getStorageAt", [wuct, WUCT_SUPPLY_SLOT, hex(tip)]), "WUCT totalSupply")
        wuct_native_balance = rpc_quantity(rpc(args.url, "eth_getBalance", [wuct, hex(tip)]), "WUCT native custody")
        if actual_wuct_supply != expected_wuct_supply or expected_wuct_supply <= 0:
            raise RuntimeError(f"WUCT final totalSupply is {actual_wuct_supply}, expected nonzero {expected_wuct_supply}")
        if wuct_native_balance < actual_wuct_supply:
            raise RuntimeError("WUCT native balance does not cover its minted totalSupply")
        collector_credit = rpc_quantity(rpc(args.url, "eth_getStorageAt", [collector, COLLECTOR_CREDIT_SLOT, hex(tip)]), "FeeCollector treasuryCredit")
        collector_reward = rpc_quantity(rpc(args.url, "eth_getStorageAt", [collector, COLLECTOR_REWARD_SLOT, hex(tip)]), "FeeCollector rewardPot")
        collector_balance = rpc_quantity(rpc(args.url, "eth_getBalance", [collector, hex(tip)]), "FeeCollector native balance")
        if collector_credit + collector_reward <= 0 or collector_credit + collector_reward > collector_balance:
            raise RuntimeError("FeeCollector split did not leave nonzero, backed liabilities")
        print(f"PASS: captured {tip} hash-linked headers, {transaction_count} transactions, claim and {fee_burn} wei base-fee burn")
        print(f"PASS: Cancun same-transaction selfdestruct burned {burn['burnedAmount']} wei; ordinary SELFDESTRUCT transferred {ordinary_action['valueWei']} wei and retained code")
        print(f"PASS: WUCT supply/custody {actual_wuct_supply}/{wuct_native_balance}; FeeCollector liabilities {collector_credit + collector_reward}/{collector_balance}")

        state_accounts = {}
        for address in sorted(known_accounts):
            balance = rpc(args.url, "eth_getBalance", [address, hex(tip)])
            code = rpc(args.url, "eth_getCode", [address, hex(tip)])
            slots = {}
            for slot in sorted(storage_slots.get(address, set())):
                value = rpc(args.url, "eth_getStorageAt", [address, slot, hex(tip)])
                slots[slot.lower()] = value.lower()
            state_accounts[address] = {"balance": balance.lower(), "code": code.lower(), "storage": slots}
        if not state_accounts:
            raise RuntimeError("full-state account inventory is empty")
        print(f"PASS: state balances/code and every required storage slot collected for {len(state_accounts)} controlled accounts")

        evidence = {
            "version": "unicity/supply-audit-snapshot/v2",
            "contractsCommit": "e7eb3216549b772a9e1df2b1214976d7dd9e6e62",
            "genesisHash": genesis_hash,
            "certifiedBlock": {"number": tip, "hash": final_hash, "certified": True},
            "fullState": True,
            "addresses": {
                "wuct": manifest["addresses"]["wuct"],
                "feeCollector": manifest["addresses"]["feeCollector"],
                "vestingVaults": [entry["recipient"] for entry in manifest["allocations"]
                                  if entry["purpose"].endswith("vesting")],
            },
            "accounts": state_accounts,
            "blocks": blocks,
        }
        t4_observations = {
            "t4Observations": {
                "burnedNewContract": {"transactionHash": burn["transactionHash"], "contract": burn["contract"],
                                      "amountWei": burn["burnedAmount"],
                                      "codeAtCreationBlock": burn_code_at_creation_block,
                                      "balanceAtCreationBlockWei": str(burn_balance_at_creation_block),
                                      "codeAtTip": burn_code, "balanceAtTipWei": str(burn_balance)},
                "ordinarySelfdestruct": {"transactionHash": ordinary_destroy["transactionHash"],
                                          "contract": ordinary_address, "beneficiary": ordinary_destroy["beneficiary"],
                                          "transferredWei": ordinary_action["valueWei"],
                                          "codeAtDeployment": ordinary_code_deployed, "codeAtTip": ordinary_code_tip,
                                          "balanceAtDeploymentWei": str(ordinary_balance_deployed),
                                          "balanceAtTipWei": str(ordinary_balance_tip),
                                          "beneficiaryBalanceDeltaWei": str(beneficiary_after - beneficiary_before)},
                "wuct": {"expectedTotalSupplyWei": str(expected_wuct_supply), "actualTotalSupplyWei": str(actual_wuct_supply),
                         "nativeBalanceWei": str(wuct_native_balance), "depositWei": actions["wuct"]["depositWei"],
                         "withdrawWei": actions["wuct"]["withdrawWei"]},
                "feeCollector": {"treasuryCreditWei": str(collector_credit), "rewardPotWei": str(collector_reward),
                                 "totalLiabilitiesWei": str(collector_credit + collector_reward),
                                 "nativeBalanceWei": str(collector_balance)},
            }
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
        print(f"PASS: saved T4 accounting source {args.output}")
        observations_path = args.output.with_name("t4-observations.json")
        observations_path.write_text(json.dumps(t4_observations, indent=2) + "\n")
        print(f"PASS: saved T4 supplemental observations {observations_path}")
    except (OSError, ValueError, RuntimeError, urllib.error.URLError, KeyError, TypeError) as exc:
        return fail(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
