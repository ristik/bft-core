#!/usr/bin/env python3
"""Observe every canonical height of the four real execution clients in the D1 lane."""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
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


def certificate_admissions(lines):
    admission = re.compile(
        r'msg="certificate admitted".*?\bblock=([0-9a-f]{64})\s+'
        r'height=(\d+)\s+round=(\d+)\s+rootRound=(\d+)(?:\s|$)'
    )
    found = []
    for line in lines:
        match = admission.search(line)
        if match:
            block, height, round_number, root_round = match.groups()
            height = int(height)
            if height > 0:
                found.append({"block": block, "height": height,
                              "round": round_number, "rootRound": root_round,
                              "line": line})
    return found


def execution_evidence(nodes, height, block_hash, commitment, validators):
    derived = []
    partition_rounds = []
    root_rounds = []
    if len(validators) < 3:
        raise RuntimeError(f"only {len(validators)} survivor(s); a quorum of three is required")
    for i in validators:
        lines = (Path(nodes) / f"evm{i}" / "debug.log").read_text().splitlines()
        verified = [line for line in lines if 'msg="verified execution payload"' in line
                    and field(line, "blockHash") == block_hash[2:]
                    and field(line, "status") == "VALID"]
        if not verified:
            raise RuntimeError(f"validator {i} lacks VALID verification for B{height}")
        partition_round = field(verified[-1], "round")
        certified = [entry for entry in certificate_admissions(lines)
                     if entry["height"] == height
                     and entry["round"] == partition_round
                     and entry["block"] == block_hash[2:].lower()]
        if not certified:
            raise RuntimeError(f"validator {i} lacks positive-height certificate admission for "
                               f"B{height} / block {block_hash[2:]} / round {partition_round}")
        root_input = field(verified[-1], "rootInput")
        if not root_input or field(verified[-1], "commitment") != commitment[2:]:
            raise RuntimeError(f"validator {i} v2 bytes/commitment missing or inconsistent at B{height}")
        derived.append(root_input)
        partition_rounds.append(partition_round)
        root_rounds.append(certified[-1]["rootRound"])
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


def assert_expected_impaired_refusal(nodes, scenario, impaired):
    marker = Path(nodes) / "d2c-expected-refusal"
    if not marker.exists():
        raise RuntimeError(f"validator {impaired} has no recorded expected refusal for {scenario}")
    detail = marker.read_text(errors="replace").strip()
    if not detail.startswith(f"{scenario}:") or len(detail.split(":", 1)[-1].strip()) == 0:
        raise RuntimeError(f"impaired validator refusal record does not match {scenario}: {detail!r}")
    print(f"D1 impaired validator {impaired} expected refusal confirmed separately: {detail}", flush=True)


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
    restored = [line for line in lines if 'msg="execution journal restored"' in line]
    restored = [line for line in restored
                if re.fullmatch(r"[0-9a-f]{64}", field(line, "block") or "")
                and (field(line, "height") or "").isdigit()
                and int(field(line, "height")) > 0
                and field(line, "round") is not None
                and field(line, "rootRound") is not None]
    if not restored:
        raise RuntimeError("restarted shard did not restore an authenticated execution-journal observation")
    submissions = [line for line in lines if "submitting block certification request" in line]
    certificates = certificate_admissions(lines)
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
        proof_deadline = time.monotonic() + 15
        while time.monotonic() < proof_deadline and not quorum_proofs:
            for i, root_mark in enumerate(root_marks, start=1):
                root_lines = (Path(nodes) / f"root{i}" / "debug.log").read_text().splitlines()[root_mark:]
                quorum_proofs.extend(line for line in root_lines
                                     if "reached consensus" in line and request_in_quorum(line, node_id)
                                     and field(line, "requestRound") in submitted_rounds)
            if not quorum_proofs:
                time.sleep(0.2)
        if not quorum_proofs:
            raise RuntimeError("no later root quorum included the restarted validator's signed request")
        print(f"D2C PASS: authority pid {authority_pid} retained its key and signed round "
              f"{after['reservedRound']} after restart; {len(submissions)} requests, "
              f"{len(quorum_proofs)} root quorum proofs containing its signature, and "
              f"{len(certificates)} subsequent positive-height certificate admissions observed", flush=True)
    else:
        if submissions:
            raise RuntimeError(f"local-key restart submitted {len(submissions)} requests")
        print(f"D2C PASS: local-key restart logged MarkRestored and remained NON-VOTING "
              f"through {len(certificates)} subsequent positive-height certificate admissions", flush=True)


def check_fault_rejoins(nodes, scenario, final_height, final_hash, recovery_started):
    """Wait for each restarted validator to restore, associate, advance, sign, and agree."""
    restarted = []
    for validator in range(1, 5):
        path = Path(nodes) / f"evm{validator}" / "debug.log"
        lines = path.read_text(errors="replace").splitlines()
        marker = f"D2C_RESTART_BOUNDARY scenario={scenario} "
        boundaries = [i for i, line in enumerate(lines) if line.startswith(marker)]
        if not boundaries:
            continue
        restarted.append(validator)
        expected_hash = final_hash.removeprefix("0x").lower()
        timeout = float(os.environ.get("D2C_REJOIN_TIMEOUT", "180"))
        deadline = recovery_started + timeout
        last_state = {}
        while True:
            lines = path.read_text(errors="replace").splitlines()
            boundaries = [i for i, line in enumerate(lines) if line.startswith(marker)]
            after = lines[boundaries[-1] + 1:]
            restored_indexes = [i for i, line in enumerate(after)
                                if 'msg="execution journal restored"' in line]
            admissions = certificate_admissions(after)
            admission_indexes = [after.index(entry["line"]) for entry in admissions]
            valid_payloads = {}
            for index, line in enumerate(after):
                if ('msg="verified execution payload"' in line and field(line, "status") == "VALID"
                        and field(line, "blockHash") and field(line, "round")):
                    valid_payloads[(field(line, "blockHash").lower(), field(line, "round"))] = index
            association_indexes = [valid_payloads[(entry["block"], entry["round"])]
                                   for entry in admissions
                                   if (entry["block"], entry["round"]) in valid_payloads]
            recovery_indexes = restored_indexes + association_indexes
            qualifying_admissions = [index for index in admission_indexes
                                     if any(recovery_index < index for recovery_index in recovery_indexes)]
            recovery_boundary = min(recovery_indexes) if recovery_indexes else None
            peer_associations = [entry for entry in admissions
                                 if field(entry["line"], "source") == "peer_recovery"]
            if peer_associations:
                first_association = min(peer_associations, key=lambda entry: entry["height"])
            else:
                first_association = next((entry for entry in admissions
                                          if (entry["block"], entry["round"]) in valid_payloads), None)
            later_heights = ({entry["height"] for entry in admissions
                              if first_association and entry["height"] > first_association["height"]})
            signed = [(i, line) for i, line in enumerate(after)
                      if 'msg="certification request signed"' in line
                      and (field(line, "round") or "").isdigit()
                      and recovery_boundary is not None and i > recovery_boundary]
            head = None
            block = None
            head_error = None
            try:
                port = 18544 + validator
                head = int(rpc(port, "eth_blockNumber", []), 16)
                block = rpc(port, "eth_getBlockByNumber", [hex(final_height), False])
            except (OSError, ValueError, RuntimeError) as exc:
                head_error = str(exc)
            agrees = (head is not None and head >= final_height and block
                      and block.get("hash", "").removeprefix("0x").lower() == expected_hash)
            # Also require agreement at the live head, so a stale common prefix cannot satisfy
            # rejoin after the recovering process has fallen behind the survivor quorum.
            live_hashes = {}
            for peer in range(1, 5):
                try:
                    peer_head = int(rpc(18544 + peer, "eth_blockNumber", []), 16)
                    peer_block = rpc(18544 + peer, "eth_getBlockByNumber", [hex(peer_head), False])
                    if peer_block:
                        peer_hash = peer_block.get("hash", "").removeprefix("0x").lower()
                        live_hashes.setdefault((peer_head, peer_hash), []).append(peer)
                except (OSError, ValueError, RuntimeError):
                    pass
            live_quorum = max(live_hashes.items(), key=lambda item: len(item[1])) if live_hashes else None
            live_agrees = bool(live_quorum and len(live_quorum[1]) >= 3
                               and live_quorum[0] in live_hashes
                               and (head, (block or {}).get("hash", "").removeprefix("0x").lower()) == live_quorum[0])
            last_state = {"restored": bool(restored_indexes), "admissions": len(admissions),
                          "admissionsAfterRecovery": len(qualifying_admissions),
                          "firstAssociationHeight": first_association and first_association["height"],
                          "furtherCertifiedHeights": sorted(later_heights),
                          "signed": len(signed), "head": head,
                          "liveHeadAgreement": live_agrees,
                          "blockHash": block and block.get("hash"), "headError": head_error}
            if (recovery_indexes and qualifying_admissions and first_association
                    and len(later_heights) >= 3 and signed and agrees and live_agrees):
                break
            if time.monotonic() >= deadline:
                if not recovery_indexes:
                    reason = "has neither journal-restoration nor peer-recovery association evidence"
                elif not qualifying_admissions:
                    reason = "has no positive-height certificate admission after journal restoration/recovery association"
                elif not signed:
                    reason = "has no signed certification request after journal restoration or recovery association"
                elif not first_association or len(later_heights) < 3:
                    reason = (f"has fewer than three further fresh certified heights after its first positive-height "
                              f"association; first={first_association and first_association['height']}, "
                              f"further={sorted(later_heights)}")
                elif not live_agrees:
                    reason = "does not agree with the fresh survivor head quorum"
                else:
                    reason = (f"did not agree at final B{final_height}; head={head}, "
                              f"block={block and block.get('hash')}, expected={final_hash}, rpcError={head_error}")
                raise RuntimeError(f"{scenario}: restarted validator {validator} {reason}; "
                                   f"observed={last_state}")
            time.sleep(0.5)
        print(f"D2C rejoin evidence: {scenario} validator={validator}; "
          f"restorationOrAssociation={len(recovery_indexes)}; positiveAdmissions={len(admissions)}; "
          f"firstAssociation=B{first_association['height']}; furtherCertifiedHeights={len(later_heights)}; "
          f"signedRequests={len(signed)}; head=B{head}; liveHeadAgreement={live_agrees}; "
          f"agreesAt=B{final_height} hash={final_hash}", flush=True)
    if not restarted:
        raise RuntimeError(f"{scenario}: no restarted-validator boundary was recorded")


def check_proof_corrupt_recovery(nodes, recovery_started):
    path = Path(nodes) / "evm1" / "debug.log"
    deadline = recovery_started + float(os.environ.get("D2C_REJOIN_TIMEOUT", "180"))
    while True:
        lines = path.read_text(errors="replace").splitlines()
        markers = [i for i, line in enumerate(lines) if line.startswith("D2C_PROOF_CORRUPT_PASS ")]
        if not markers:
            raise RuntimeError("proof-corrupt: proxy pass boundary was not recorded")
        after = lines[markers[-1] + 1:]
        admissions = certificate_admissions(after)
        associations = [entry for entry in admissions if field(entry["line"], "source") == "peer_recovery"]
        if not associations:
            associations = [entry for entry in admissions
                            if any('msg="verified execution payload"' in line
                                   and field(line, "status") == "VALID"
                                   and field(line, "blockHash") == entry["block"]
                                   and field(line, "round") == entry["round"] for line in after)]
        first = min(associations, key=lambda entry: entry["height"]) if associations else None
        further = {entry["height"] for entry in admissions if first and entry["height"] > first["height"]}
        signed = [line for line in after if 'msg="certification request signed"' in line
                  and (field(line, "round") or "").isdigit()]
        agreed = False
        try:
            head = int(rpc(18545, "eth_blockNumber", []), 16)
            block = rpc(18545, "eth_getBlockByNumber", [hex(head), False])
            others = []
            for validator in (2, 3, 4):
                other_head = int(rpc(18544 + validator, "eth_blockNumber", []), 16)
                other = rpc(18544 + validator, "eth_getBlockByNumber", [hex(other_head), False])
                others.append((other_head, other.get("hash", "").removeprefix("0x").lower()))
            agreed = (head, block.get("hash", "").removeprefix("0x").lower()) in others
        except (OSError, RuntimeError, KeyError, TypeError, ValueError):
            head = None
        if first and len(further) >= 3 and signed and agreed:
            print(f"D2C[proof-corrupt] recovery measured after pass: firstAssociation=B{first['height']}; "
                  f"furtherCertifiedHeights={len(further)}; signedRequests={len(signed)}; "
                  f"head=B{head}; liveHeadAgreement=true", flush=True)
            return max(entry["height"] for entry in admissions), len(signed)
        if time.monotonic() >= deadline:
            raise RuntimeError("proof-corrupt: validator 1 missed bounded recovery requirements after pass; "
                               f"firstAssociation={first and first['height']}; "
                               f"furtherCertifiedHeights={sorted(further)}; signedRequests={len(signed)}; "
                               f"liveHeadAgreement={agreed}; head={head}")
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", default="test-nodes")
    parser.add_argument("--validators", type=int, default=4)
    parser.add_argument("--blocks", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--restart-validator", type=int, default=0)
    parser.add_argument("--signing", choices=("local", "authority"), default="local")
    parser.add_argument("--fault-scenario", choices=("pair-term", "pair-kill", "ureth-kill",
                        "all-kill", "leader-kill", "proof-outage", "proof-corrupt",
                        "missing-body", "wrong-genesis"), default="")
    args = parser.parse_args()
    if args.validators != 4 or args.blocks < 10:
        parser.error("D1 requires four validators and at least ten blocks")

    impaired = 1 if args.fault_scenario in {"missing-body", "wrong-genesis", "proof-corrupt"} else 0
    survivors = [i for i in range(1, 5) if i != impaired] if impaired else [1, 2, 3, 4]
    required_quorum = 3
    if impaired:
        print(f"D1 expected refusal: validator {impaired}; fresh survivor quorum={survivors}", flush=True)
    else:
        print(f"D1 fresh survivor quorum: any three of validators {survivors}", flush=True)

    start = time.monotonic()
    prior = None
    probe = None
    probe_started = None
    target = args.blocks
    print("height hash parent stateRoot commitment txs heads partitionRound rootRound elapsed_s", flush=True)
    height = 1
    while height <= target:
        deadline = min(start + args.timeout, probe_started + 180) if probe_started else start + args.timeout
        sample_ids = []
        last_sample = {}
        last_report = 0.0
        while time.monotonic() < deadline:
            current = {}
            sample_ids = []
            for i in range(1, 5):
                try:
                    sampled_height = int(rpc(18544 + i, "eth_blockNumber", []), 16)
                    sampled_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                    current[i] = {"height": sampled_height, "time": sampled_at, "error": None}
                    if i in survivors and sampled_height >= height:
                        sample_ids.append(i)
                except (OSError, ValueError, RuntimeError) as exc:
                    sampled_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                    current[i] = {"height": None, "time": sampled_at, "error": str(exc)}
            last_sample = current
            now = time.monotonic()
            if len(sample_ids) >= required_quorum:
                break
            if now - last_report >= 5:
                vector = ", ".join(
                    f"v{i}={sample['height']}@{sample['time']}" if sample["error"] is None
                    else f"v{i}=UNAVAILABLE@{sample['time']}({sample['error']})"
                    for i, sample in current.items()
                )
                print(f"height {height}: fresh samples [{vector}]; survivor quorum "
                      f"{len(sample_ids)}/{required_quorum}", flush=True)
                last_report = now
            time.sleep(0.5)
        else:
            vector = ", ".join(
                f"v{i}={sample['height']}@{sample['time']}" if sample["error"] is None
                else f"v{i}=UNAVAILABLE@{sample['time']}({sample['error']})"
                for i, sample in last_sample.items()
            )
            print(f"D1 FAIL: fresh survivor quorum stalled before height {height}; "
                  f"samples=[{vector}]; survivors={survivors}; required={required_quorum}", flush=True)
            for i in range(1, 5):
                print(f"--- evm{i} ---\n{tail(f'{args.nodes}/evm{i}/debug.log')}")
                print(f"--- reth{i} ---\n{tail(f'{args.nodes}/reth{i}/reth.log')}")
            return 1

        blocks_by_id = {}
        for i in sample_ids:
            try:
                blocks_by_id[i] = rpc(18544 + i, "eth_getBlockByNumber", [hex(height), False])
            except (OSError, ValueError, RuntimeError) as exc:
                print(f"height {height}: v{i} block sample unavailable after its fresh head sample: {exc}", flush=True)
        blocks_by_id = {i: block for i, block in blocks_by_id.items() if block is not None}
        if len(blocks_by_id) < required_quorum:
            print(f"D1 FAIL: fewer than three fresh survivor blocks at height {height}; "
                  f"validators={sorted(blocks_by_id)}", flush=True)
            return 1
        fields = ("number", "hash", "parentHash", "stateRoot", "extraData")
        groups = {}
        for i, block in blocks_by_id.items():
            key = tuple(block[field] for field in fields)
            groups.setdefault(key, []).append((i, block))
        quorum = max(groups.values(), key=len)
        if len(quorum) < required_quorum:
            print(f"D1 FAIL: no matching fresh survivor quorum at height {height}; "
                  f"samples={[(i, b.get('hash'), b.get('parentHash')) for i, b in blocks_by_id.items()]}", flush=True)
            return 1
        block_ids = [i for i, _ in quorum]
        block = quorum[0][1]
        if int(block["number"], 16) != height or (prior and block["parentHash"] != prior):
            print(f"D1 FAIL: discontinuity at height {height}: {block}", flush=True)
            return 1
        prior = block["hash"]
        try:
            root_input, partition_round, root_round = execution_evidence(
                args.nodes, height, block["hash"], block["extraData"], block_ids
            )
        except (OSError, RuntimeError) as exc:
            print(f"D1 FAIL: B{height} lacks cross-validator certificate/v2 evidence: {exc}", flush=True)
            return 1
        print(
            height, block["hash"], block["parentHash"], block["stateRoot"],
            block["extraData"], len(block["transactions"]),
            ",".join(f"{i}:{last_sample[i]['height']}@{last_sample[i]['time']}" for i in block_ids),
            partition_round, root_round, round(time.monotonic() - start, 3), flush=True,
        )
        print(f"v2 B{height} bytes={root_input} (same across quorum validators)", flush=True)
        if args.restart_validator and height == 5:
            try:
                probe = restart_validator(args.nodes, args.restart_validator, args.signing)
                probe_started = time.monotonic()
            except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
                print(f"D2C FAIL: could not restart validator {args.restart_validator}: {exc}", flush=True)
                return 1
            # At B5 the cluster may already be ahead. Require fresh certified heights after the
            # restart rather than counting only blocks produced before the probe.
            target = max(target, max(last_sample[i]["height"] for i in block_ids) + 3)
        if args.fault_scenario and height == 5:
            try:
                output = subprocess.check_output([
                    "python3", "scripts/d2c-fault-control.py", args.fault_scenario,
                    str(height), str(partition_round),
                ], text=True, stderr=subprocess.STDOUT, timeout=150)
                print(output, end="", flush=True)
                probe_started = time.monotonic()
            except subprocess.CalledProcessError as exc:
                if exc.output:
                    print(exc.output, end="", flush=True)
                print(f"D2C[{args.fault_scenario}] FAIL(injection/relaunch error: {exc})", flush=True)
                return 1
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                print(f"D2C[{args.fault_scenario}] FAIL(injection/relaunch error: {exc})", flush=True)
                return 1
            target = max(target, max(last_sample[i]["height"] for i in block_ids) + 3)
        height += 1
    rejoin_scenarios = {"pair-term", "pair-kill", "ureth-kill", "all-kill", "leader-kill"}
    if args.fault_scenario in rejoin_scenarios:
        try:
            check_fault_rejoins(args.nodes, args.fault_scenario, target, prior, probe_started)
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"D2C FAIL: {exc}", flush=True)
            return 1
    if args.fault_scenario == "proof-corrupt":
        try:
            recovered_height, signed_count = check_proof_corrupt_recovery(args.nodes, probe_started)
            result_path = Path(args.nodes) / "d2c-proof-corrupt-result.json"
            result = json.loads(result_path.read_text())
            print(f"D2C[proof-corrupt] EXPECTED-FAIL(mutated uncached proof parent={result['parentHash']} "
                  f"rejected as invalid; no derived snapshot or signed request used its snapshotID; "
                  f"validator 1 recovered after pass with {recovered_height} positive-height admissions "
                  f"and {signed_count} signed requests)", flush=True)
        except (OSError, RuntimeError, KeyError, ValueError) as exc:
            print(f"D2C FAIL: {exc}", flush=True)
            return 1
    if probe:
        try:
            check_restart(args.nodes, args.restart_validator, args.signing, probe)
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"D2C FAIL: {exc}", flush=True)
            return 1
    if impaired and args.fault_scenario != "proof-corrupt":
        try:
            assert_expected_impaired_refusal(args.nodes, args.fault_scenario, impaired)
        except OSError as exc:
            print(f"D1 FAIL: could not verify impaired validator refusal: {exc}", flush=True)
            return 1
        except RuntimeError as exc:
            print(f"D1 FAIL: {exc}", flush=True)
            return 1
    print(f"D1 observed consecutive canonical blocks with a fresh survivor quorum of "
          f"{required_quorum} through B{target}; survivors={survivors}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
