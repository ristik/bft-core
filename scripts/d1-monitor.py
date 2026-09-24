#!/usr/bin/env python3
"""Observe every canonical height of the four real execution clients in the D1 lane."""

import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path


def rpc(port, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}", body, {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        answer = json.load(resp)
    if "error" in answer:
        raise RuntimeError(f"{method} on {port}: {answer['error']}")
    return answer["result"]


def tail(path, lines=35):
    try:
        return "\n".join(Path(path).read_text(errors="replace").splitlines()[-lines:])
    except OSError as exc:
        return str(exc)


def field(line, name):
    match = re.search(rf"(?:^| ){re.escape(name)}=([^ ]+)", line)
    return match.group(1) if match else None


def execution_evidence(nodes, height, block_hash, commitment):
    derived = []
    partition_rounds = []
    root_rounds = []
    for i in range(1, 5):
        lines = (Path(nodes) / f"evm{i}" / "debug.log").read_text().splitlines()
        verified = [line for line in lines if 'msg="verified execution payload"' in line
                    and field(line, "blockHash") == block_hash[2:]
                    and field(line, "status") == "VALID"]
        if not verified:
            raise RuntimeError(f"validator {i} lacks VALID verification for B{height}")
        partition_round = field(verified[-1], "round")
        certified = [line for line in lines if 'msg="certificate admitted"' in line
                     and field(line, "height") == str(height)
                     and field(line, "round") == partition_round
                     and field(line, "block") == block_hash[2:]]
        if not certified:
            raise RuntimeError(f"validator {i} lacks root certificate for B{height} / round {partition_round}")
        root_input = field(verified[-1], "rootInput")
        if not root_input or field(verified[-1], "commitment") != commitment[2:]:
            raise RuntimeError(f"validator {i} v2 bytes/commitment missing or inconsistent at B{height}")
        derived.append(root_input)
        partition_rounds.append(partition_round)
        root_rounds.append(field(certified[-1], "rootRound"))
    if len(set(derived)) != 1 or len(set(partition_rounds)) != 1 or len(set(root_rounds)) != 1:
        raise RuntimeError(f"validator v2 derivation or certificate round disagrees at B{height}")
    return derived[0], partition_rounds[0], root_rounds[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", default="test-nodes")
    parser.add_argument("--validators", type=int, default=4)
    parser.add_argument("--blocks", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    if args.validators != 4 or args.blocks < 10:
        parser.error("D1 requires four validators and at least ten blocks")

    start = time.monotonic()
    prior = None
    print("height hash parent stateRoot commitment txs heads partitionRound rootRound elapsed_s", flush=True)
    for height in range(1, args.blocks + 1):
        deadline = start + args.timeout
        while time.monotonic() < deadline:
            try:
                heads = [int(rpc(18545 + i, "eth_blockNumber", []), 16) for i in range(4)]
                if min(heads) >= height:
                    break
            except (OSError, ValueError, RuntimeError) as exc:
                print(f"height {height}: RPC pending: {exc}", flush=True)
            time.sleep(0.5)
        else:
            print(f"D1 FAIL: stalled before height {height}; heads={locals().get('heads')}")
            for i in range(1, 5):
                print(f"--- evm{i} ---\n{tail(f'{args.nodes}/evm{i}/debug.log')}")
                print(f"--- reth{i} ---\n{tail(f'{args.nodes}/reth{i}/reth.log')}")
            return 1

        blocks = [rpc(18545 + i, "eth_getBlockByNumber", [hex(height), False]) for i in range(4)]
        if any(block is None for block in blocks):
            print(f"D1 FAIL: height {height} absent on a paired reth", flush=True)
            return 1
        fields = ("number", "hash", "parentHash", "stateRoot", "extraData")
        if any(tuple(block[field] for field in fields) != tuple(blocks[0][field] for field in fields) for block in blocks[1:]):
            print(f"D1 FAIL: canonical disagreement at height {height}: {blocks}", flush=True)
            return 1
        block = blocks[0]
        if int(block["number"], 16) != height or (prior and block["parentHash"] != prior):
            print(f"D1 FAIL: discontinuity at height {height}: {block}", flush=True)
            return 1
        prior = block["hash"]
        try:
            root_input, partition_round, root_round = execution_evidence(
                args.nodes, height, block["hash"], block["extraData"]
            )
        except (OSError, RuntimeError) as exc:
            print(f"D1 FAIL: B{height} lacks cross-validator certificate/v2 evidence: {exc}", flush=True)
            return 1
        print(
            height, block["hash"], block["parentHash"], block["stateRoot"],
            block["extraData"], len(block["transactions"]), ",".join(map(str, heads)),
            partition_round, root_round, round(time.monotonic() - start, 3), flush=True,
        )
        print(f"v2 B{height} bytes={root_input} (same on all four validators)", flush=True)
    print("D1 observed consecutive canonical blocks on all four reth clients", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
