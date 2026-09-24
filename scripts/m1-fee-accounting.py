#!/usr/bin/env python3
"""Audit the paid block's fee debits and the positive base-fee floor across a reth restart."""

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

ETH_BASE = 18545
COLLECTOR = "0x000000000000000000000000000000000000dead"


def rpc(node, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{ETH_BASE + node - 1}", body, {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=4) as response:
        answer = json.load(response)
    if "error" in answer:
        raise RuntimeError(f"node {node} {method}: {answer['error']}")
    return answer["result"]


def block(node, height):
    result = rpc(node, "eth_getBlockByNumber", [hex(height), False])
    if result is None:
        raise RuntimeError(f"node {node} has no block B{height}")
    return result


def quantity(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"invalid quantity {value!r}")
    return int(value, 16)


def check_before(args):
    hashes = [line.strip() for line in Path(args.tx_hashes).read_text().splitlines() if line.strip()]
    if len(hashes) != 3:
        raise RuntimeError(f"expected three paid transaction hashes, got {len(hashes)}")

    block_hashes = [block(node, 1)["hash"].lower() for node in range(1, 5)]
    if len(set(block_hashes)) != 1:
        raise RuntimeError(f"validators disagree on paid child B1: {block_hashes}")
    heads = [quantity(rpc(node, "eth_blockNumber", [])) for node in range(1, 5)]
    common_height = min(heads)
    if common_height < args.restart_height:
        raise RuntimeError(f"fresh certified head B{common_height} is below restart target B{args.restart_height}")
    common_hashes = [block(node, common_height)["hash"].lower() for node in range(1, 5)]
    if len(set(common_hashes)) != 1:
        raise RuntimeError(f"validators disagree at pre-restart B{common_height}: {common_hashes}")
    parent = block(1, 0)
    child = block(1, 1)
    base_fee = quantity(child["baseFeePerGas"])
    if base_fee != args.floor:
        raise RuntimeError(f"B1 did not reach the configured floor: baseFee={base_fee}, floor={args.floor}")

    receipts = []
    for tx_hash in hashes:
        receipt = rpc(1, "eth_getTransactionReceipt", [tx_hash])
        if receipt is None or quantity(receipt["blockNumber"]) != 1 or quantity(receipt["status"]) != 1:
            raise RuntimeError(f"paid transaction {tx_hash} lacks a successful B1 receipt: {receipt}")
        tx = rpc(1, "eth_getTransactionByHash", [tx_hash])
        if tx is None or tx["blockHash"].lower() != child["hash"].lower():
            raise RuntimeError(f"paid transaction {tx_hash} does not belong to the certified B1 hash")
        if "effectiveGasPrice" not in receipt:
            raise RuntimeError(f"receipt {tx_hash} omits effectiveGasPrice")
        receipts.append((quantity(receipt["gasUsed"]), quantity(receipt["effectiveGasPrice"]),
                         quantity(tx["value"])))

    senders = {rpc(1, "eth_getTransactionByHash", [tx_hash])["from"].lower() for tx_hash in hashes}
    if len(senders) != 1:
        raise RuntimeError(f"paid transactions do not share one funded sender: {senders}")
    sender = next(iter(senders))
    collector = COLLECTOR.lower()
    parent_number = "0x0"
    child_number = "0x1"
    sender_before = quantity(rpc(1, "eth_getBalance", [sender, parent_number]))
    sender_after = quantity(rpc(1, "eth_getBalance", [sender, child_number]))
    collector_before = quantity(rpc(1, "eth_getBalance", [collector, parent_number]))
    collector_after = quantity(rpc(1, "eth_getBalance", [collector, child_number]))
    sender_debit = sender_before - sender_after
    collector_credit = collector_after - collector_before
    total_gas = sum(gas for gas, _, _ in receipts)
    value_total = sum(value for _, _, value in receipts)
    expected_sender_debit = value_total + sum(gas * price for gas, price, _ in receipts)
    expected_tip = sum(gas * (price - base_fee) for gas, price, _ in receipts)
    expected_burn = total_gas * base_fee
    inferred_burn = sender_debit - value_total - collector_credit

    if sender_debit != expected_sender_debit:
        raise RuntimeError(f"sender debit {sender_debit} != value+gas*price {expected_sender_debit}")
    if collector_credit != expected_tip:
        raise RuntimeError(f"collector credit {collector_credit} != gas*(price-baseFee) {expected_tip}")
    if inferred_burn != expected_burn:
        raise RuntimeError(f"inferred burn {inferred_burn} != gas*baseFee {expected_burn}")
    print(f"M1 fee accounting PASS: B1={child['hash']} txs=3 gasUsed={total_gas} baseFee={base_fee} "
          f"senderDebit={sender_debit} collectorCredit={collector_credit} burn={inferred_burn}")
    floor_at = check_floor(args.floor, 0, common_height, 4)
    if floor_at != 1:
        raise RuntimeError(f"floor should first be reached at paid block B1, observed B{floor_at}")
    Path(args.nodes, "m1-fee-pre-restart-head.txt").write_text(f"{common_height}\n")
    print(f"M1 pre-restart certified head agrees at B{common_height}; base fee held at floor through that head")


def check_floor(floor, start, end, nodes):
    floor_at = None
    for height in range(start, end + 1):
        base_fees = [quantity(block(node, height)["baseFeePerGas"]) for node in range(1, nodes + 1)]
        if min(base_fees) < floor:
            raise RuntimeError(f"base fee below positive floor at B{height}: {base_fees} < {floor}")
        if len(set(base_fees)) != 1:
            raise RuntimeError(f"validators disagree on base fee at B{height}: {base_fees}")
        if height > 0 and base_fees[0] != floor:
            raise RuntimeError(f"base fee did not hold at floor at B{height}: {base_fees[0]} != {floor}")
        if base_fees[0] == floor:
            floor_at = height if floor_at is None else floor_at
    return floor_at


def check_after(args):
    deadline = time.monotonic() + args.timeout
    ready = False
    while time.monotonic() < deadline:
        try:
            [rpc(node, "eth_chainId", []) for node in range(1, 5)]
            ready = True
            break
        except (OSError, urllib.error.URLError, TimeoutError, RuntimeError):
            time.sleep(0.25)
    if not ready:
        raise RuntimeError("four validator execution RPCs did not become available after reth restart")

    goal = args.restart_height + args.further_heights
    common_height = None
    while time.monotonic() < deadline:
        try:
            heads = [quantity(rpc(node, "eth_blockNumber", [])) for node in range(1, 5)]
            candidate = min(heads)
            hashes = [block(node, candidate)["hash"].lower() for node in range(1, 5)]
            if candidate >= goal and len(set(hashes)) == 1:
                common_height = candidate
                break
        except (OSError, urllib.error.URLError, TimeoutError, RuntimeError, KeyError):
            pass
        time.sleep(0.5)
    if common_height is None:
        raise RuntimeError(f"validators did not agree at a common head >= B{goal} after the restart")

    floor_at = check_floor(args.floor, 0, common_height, 4)
    if floor_at is None:
        raise RuntimeError(f"positive fee floor {args.floor} was never reached by B{common_height}")
    # Every post-restart height must have a positive-height certificate admission on all validators.
    admission_heights = []
    for node in range(1, 5):
        log = Path(args.nodes) / f"evm{node}" / "debug.log"
        text = log.read_text(errors="replace")
        heights = set()
        for line in text.splitlines():
            if 'msg="certificate admitted"' not in line:
                continue
            fields = dict(part.split("=", 1) for part in line.split() if "=" in part)
            if fields.get("height", "0").isdigit():
                height = int(fields["height"])
                if args.restart_height < height <= common_height:
                    heights.add(height)
        fresh = sorted(heights)
        if len(fresh) < args.further_heights:
            raise RuntimeError(f"validator {node} has only {len(fresh)} post-restart certificate heights: {fresh}")
        admission_heights.append(fresh)
    print(f"M1 fee floor PASS: floor={args.floor} reached=B{floor_at} held through B{common_height}; "
          f"reth1 restarted after B{args.restart_height}; heads agree; post-restart admissions={admission_heights}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("before-restart", "after-restart"))
    parser.add_argument("--nodes", default="test-nodes")
    parser.add_argument("--tx-hashes")
    parser.add_argument("--floor", type=int, required=True)
    parser.add_argument("--restart-height", type=int, default=10)
    parser.add_argument("--further-heights", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.phase == "before-restart":
        if not args.tx_hashes:
            parser.error("before-restart requires --tx-hashes")
        check_before(args)
    else:
        check_after(args)


if __name__ == "__main__":
    main()
