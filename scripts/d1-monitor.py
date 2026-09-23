#!/usr/bin/env python3
"""Observe every canonical height of the four real execution clients in the D1 lane."""

import argparse
import json
import re
import subprocess
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


def request_in_quorum(line, node_id):
    match = re.search(r'requestNodeIDs="([^"]*)"', line)
    return bool(match and node_id in match.group(1).split())


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


def authority_status(nodes, validator):
    home = Path(nodes) / f"auth{validator}"
    output = subprocess.check_output([
        "build/ubft", "signing-authority", "status",
        "--operator-socket", str(home / "operator.sock"),
        "--operator-credential", str(home / "operator.cred"),
    ], text=True)
    return json.loads(output)


def restart_validator(nodes, validator, signing):
    log = Path(nodes) / f"evm{validator}" / "debug.log"
    before = authority_status(nodes, validator) if signing == "authority" else None
    node_id = subprocess.check_output(["build/ubft", "node-id", "--home", str(Path(nodes) / f"evm{validator}")], text=True).splitlines()[-1]
    authority_pid = (Path(nodes) / f"auth{validator}" / "pid").read_text().strip() if before else None
    reth_pid = (Path(nodes) / f"reth{validator}" / "pid").read_text().strip()
    output = subprocess.check_output(["bash", "scripts/d2c-restart-validator.sh", str(validator)], text=True)
    markers = [i for i, line in enumerate(log.read_text().splitlines()) if "D2C_RESTART_BOUNDARY" in line]
    if not markers:
        raise RuntimeError("restart helper did not mark the boundary after the old shard exited")
    mark = markers[-1] + 1
    root_marks = []
    for i in range(1, 4):
        root_lines = (Path(nodes) / f"root{i}" / "debug.log").read_text().splitlines()
        root_markers = [j for j, line in enumerate(root_lines) if "D2C_RESTART_BOUNDARY" in line]
        if not root_markers:
            raise RuntimeError(f"restart helper did not mark root {i} after the old shard exited")
        root_marks.append(root_markers[-1] + 1)
    print(f"D2C probe: {output.strip()}; retained reth pid={reth_pid}, authority pid={authority_pid}", flush=True)
    return mark, before, reth_pid, authority_pid, root_marks, node_id


def check_restart(nodes, validator, signing, probe):
    mark, before, reth_pid, authority_pid, root_marks, node_id = probe
    lines = (Path(nodes) / f"evm{validator}" / "debug.log").read_text().splitlines()[mark:]
    if not any("resumed from persisted certificate" in line for line in lines):
        raise RuntimeError("restarted shard did not restore its persisted certificate")
    submissions = [line for line in lines if "submitting block certification request" in line]
    certificates = [line for line in lines if 'msg="accepted certificate"' in line]
    if not certificates:
        raise RuntimeError("restarted shard accepted no subsequent certificate")
    if (Path(nodes) / f"reth{validator}" / "pid").read_text().strip() != reth_pid:
        raise RuntimeError("reth PID changed during the shard-only probe")
    if signing == "authority":
        if (Path(nodes) / f"auth{validator}" / "pid").read_text().strip() != authority_pid:
            raise RuntimeError("signing authority PID changed during the shard-only probe")
        after = authority_status(nodes, validator)
        if after["signingKeyFingerprint"] != before["signingKeyFingerprint"] or after["generation"] != before["generation"]:
            raise RuntimeError("authority key or client session changed during the shard-only probe")
        if not submissions or after["reservedRound"] <= before["reservedRound"] or not after["responseRetained"]:
            raise RuntimeError(f"authority did not sign and submit after restart: before={before}, after={after}, submissions={len(submissions)}")
        if any("the certification request was not signed" in line for line in lines):
            raise RuntimeError("restarted validator logged a signing refusal")
        submitted_rounds = {field(line, "round") for line in submissions}
        quorum_proofs = []
        for i, root_mark in enumerate(root_marks, start=1):
            root_lines = (Path(nodes) / f"root{i}" / "debug.log").read_text().splitlines()[root_mark:]
            quorum_proofs.extend(line for line in root_lines
                                 if "reached consensus" in line and request_in_quorum(line, node_id)
                                 and field(line, "requestRound") in submitted_rounds)
        if not quorum_proofs:
            raise RuntimeError("no later root quorum included the restarted validator's signed request")
        print(f"D2C PASS: authority pid {authority_pid} retained its key and signed round "
              f"{after['reservedRound']} after restart; {len(submissions)} requests, "
              f"{len(quorum_proofs)} root quorum proofs containing its signature, and "
              f"{len(certificates)} subsequent certificates observed", flush=True)
    else:
        if submissions:
            raise RuntimeError(f"local-key restart submitted {len(submissions)} requests")
        print(f"D2C PASS: local-key restart logged MarkRestored and remained NON-VOTING "
              f"through {len(certificates)} subsequent certificates", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", default="test-nodes")
    parser.add_argument("--validators", type=int, default=4)
    parser.add_argument("--blocks", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--restart-validator", type=int, default=0)
    parser.add_argument("--signing", choices=("local", "authority"), default="local")
    args = parser.parse_args()
    if args.validators != 4 or args.blocks < 10:
        parser.error("D1 requires four validators and at least ten blocks")

    start = time.monotonic()
    prior = None
    probe = None
    probe_started = None
    target = args.blocks
    print("height hash parent stateRoot commitment txs heads partitionRound rootRound elapsed_s", flush=True)
    height = 1
    while height <= target:
        deadline = min(start + args.timeout, probe_started + 180) if probe_started else start + args.timeout
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
        if args.restart_validator and height == 5:
            try:
                probe = restart_validator(args.nodes, args.restart_validator, args.signing)
                probe_started = time.monotonic()
            except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
                print(f"D2C FAIL: could not restart validator {args.restart_validator}: {exc}", flush=True)
                return 1
            # At B5 the cluster may already be ahead. Require fresh certified heights after the
            # restart rather than counting only blocks produced before the probe.
            target = max(target, max(heads) + 3)
        height += 1
    if probe:
        try:
            check_restart(args.nodes, args.restart_validator, args.signing, probe)
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"D2C FAIL: {exc}", flush=True)
            return 1
    print("D1 observed consecutive canonical blocks on all four reth clients", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
