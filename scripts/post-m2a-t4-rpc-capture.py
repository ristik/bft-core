#!/usr/bin/env python3
"""Capture certified-block headers and explicit trace coverage for the T4 snapshot."""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


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


def contains_selfdestruct(value):
    if isinstance(value, dict):
        for key in ("op", "opcode"):
            if str(value.get(key, "")).upper() == "SELFDESTRUCT":
                return True
        return any(contains_selfdestruct(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_selfdestruct(item) for item in value)
    return False


def contains_creation(value):
    if isinstance(value, dict):
        if str(value.get("op", value.get("opcode", ""))).upper() in {"CREATE", "CREATE2"}:
            return True
        return any(contains_creation(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_creation(item) for item in value)
    return False


def call_targets(value):
    targets = set()
    if isinstance(value, dict):
        op = str(value.get("op", value.get("opcode", ""))).upper()
        if op in {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}:
            stack = value.get("stack")
            if not isinstance(stack, list) or len(stack) < 2:
                raise RuntimeError(f"{op} trace omits the EVM stack needed for account coverage")
            try:
                word = int(str(stack[-2]), 16)
            except ValueError as exc:
                raise RuntimeError(f"{op} trace has a malformed target stack word") from exc
            targets.add(f"0x{word & ((1 << 160) - 1):040x}")
        for item in value.values():
            targets.update(call_targets(item))
    elif isinstance(value, list):
        for item in value:
            targets.update(call_targets(item))
    return targets


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="validator 1's pinned ureth eth/debug endpoint")
    parser.add_argument("--nodes", required=True, type=Path, help="paired lane test-nodes directory")
    parser.add_argument("--output", required=True, type=Path)
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
        claim_hash = claim_record["transactionHash"].lower()
        known_accounts = {address.lower() for address in chain_genesis["alloc"]}
        storage_slots = {address.lower(): set(account.get("storage", {}))
                         for address, account in chain_genesis["alloc"].items()}
        beneficiaries = [entry["beneficiary"] for entry in manifest["allocations"]
                         if entry.get("beneficiary")]
        known_accounts.update(address.lower() for address in beneficiaries)
        storage_slots.setdefault(manifest["addresses"]["wuct"].lower(), set()).add("0x" + "00" * 31 + "02")
        storage_slots.setdefault(manifest["addresses"]["feeCollector"].lower(), set()).update(
            {"0x" + "00" * 31 + "01", "0x" + "00" * 31 + "02"})
        for entry in manifest["allocations"]:
            if entry.get("purpose", "").endswith("vesting"):
                storage_slots.setdefault(entry["recipient"].lower(), set()).update(
                    {"0x" + "00" * 31 + "00", "0x" + "00" * 31 + "01"})

        blocks = []
        transaction_count = 0
        transfer_count = 0
        claim_seen = False
        fee_burn = 0
        for number in range(1, tip + 1):
            block = rpc(args.url, "eth_getBlockByNumber", [hex(number), True])
            if not block or not block.get("hash") or block.get("parentHash", "").lower() != previous_hash:
                raise RuntimeError(f"block {number} is missing or breaks the parent-hash chain")
            if block.get("blobGasUsed") is None:
                raise RuntimeError(f"block {number} omits Cancun blobGasUsed")
            withdrawals = block.get("withdrawals")
            if withdrawals is None:
                raise RuntimeError(f"block {number} omits the withdrawals list")
            transactions = block.get("transactions")
            if not isinstance(transactions, list):
                raise RuntimeError(f"block {number} omits its full transaction list")
            trace = rpc(args.url, "debug_traceBlockByNumber", [hex(number), {}])
            if not isinstance(trace, list) or len(trace) != len(transactions):
                raise RuntimeError(f"block {number} trace count does not match its transaction count")
            if contains_selfdestruct(trace):
                raise RuntimeError(f"block {number} contains SELFDESTRUCT; this lane only accepts complete empty trace sets")
            if contains_creation(trace):
                raise RuntimeError(f"block {number} contains CREATE/CREATE2; this controlled account inventory is no longer complete")
            known_accounts.update(call_targets(trace))
            miner = block.get("miner") or block.get("author") or "0x" + "00" * 20
            if not isinstance(miner, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", miner):
                raise RuntimeError(f"block {number} has an invalid fee-beneficiary address")
            known_accounts.add(miner.lower())
            for transaction in transactions:
                if not isinstance(transaction, dict):
                    raise RuntimeError(f"block {number} has a malformed transaction entry")
                transaction_count += 1
                if transaction.get("hash", "").lower() == claim_hash:
                    claim_seen = True
                sender = transaction.get("from")
                recipient = transaction.get("to")
                if not sender or not recipient:
                    raise RuntimeError(f"block {number} contains a transaction without a sender or with contract creation")
                known_accounts.add(sender.lower())
                known_accounts.add(recipient.lower())
                if recipient.lower() == "0x00000000000000000000000000000000000000ff":
                    transfer_count += 1
            fee_burn += int(block["baseFeePerGas"], 16) * int(block["gasUsed"], 16)
            blocks.append({
                "number": number,
                "hash": block["hash"].lower(),
                "parentHash": block["parentHash"].lower(),
                "difficulty": block.get("difficulty", "0x0"),
                "baseFeePerGas": block["baseFeePerGas"],
                "gasUsed": block["gasUsed"],
                "blobGasUsed": block["blobGasUsed"],
                "withdrawalsCount": len(withdrawals),
                "selfdestructTracesComplete": True,
                "selfdestructs": [],
            })
            previous_hash = block["hash"].lower()
        if previous_hash != final_hash:
            raise RuntimeError("last accounting header does not equal the certified tip")
        if not claim_seen:
            raise RuntimeError(f"the successful vesting claim {claim_hash} is not in the certified block history")
        if transaction_count < 4 or transfer_count < 3:
            raise RuntimeError(f"expected bootstrap and handoff transfers; saw {transaction_count} txs and {transfer_count} transfer-to-0xff txs")
        if fee_burn <= 0:
            raise RuntimeError("no base-fee burn was observed in the certified block history")
        print(f"PASS: captured {tip} hash-linked headers, {transaction_count} transactions, claim and {fee_burn} wei base-fee burn")
        print("PASS: complete traces show no CREATE/CREATE2/SELFDESTRUCT; account inventory includes genesis allocations, tx endpoints, internal-call targets and vesting beneficiaries")

        state_accounts = {}
        for address in sorted(known_accounts):
            balance = rpc(args.url, "eth_getBalance", [address, hex(tip)])
            code = rpc(args.url, "eth_getCode", [address, hex(tip)])
            slots = {}
            for slot in sorted(storage_slots.get(address, set())):
                value = rpc(args.url, "eth_getStorageAt", [address, slot, hex(tip)])
                # Preserve zero values for slots the auditor must read (e.g. WUCT supply and
                # FeeCollector liabilities); absence would mean incomplete evidence, not zero.
                slots[slot.lower()] = value.lower()
            state_accounts[address] = {"balance": balance.lower(), "code": code.lower(), "storage": slots}
        if not state_accounts:
            raise RuntimeError("full-state account inventory is empty")
        print(f"PASS: state balances/code and every required storage slot collected for {len(state_accounts)} controlled accounts")

        evidence = {
            "version": "unicity/supply-audit-snapshot/v1",
            "contractsCommit": "e7eb3216549b772a9e1df2b1214976d7dd9e6e62",
            "genesisHash": genesis_hash,
            "certifiedBlock": {"number": tip, "hash": final_hash, "certified": True},
            "fullState": True,
            "addresses": {
                "wuct": manifest["addresses"]["wuct"],
                "feeCollector": manifest["addresses"]["feeCollector"],
                "vestingVaults": [
                    entry["recipient"] for entry in manifest["allocations"]
                    if entry["purpose"].endswith("vesting")
                ],
            },
            "accounts": state_accounts,
            "blocks": blocks,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
        print(f"PASS: saved T4 accounting source {args.output}")
    except (OSError, ValueError, RuntimeError, urllib.error.URLError, KeyError) as exc:
        return fail(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
