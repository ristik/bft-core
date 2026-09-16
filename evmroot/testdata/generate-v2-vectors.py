#!/usr/bin/env python3
"""Generate independent canonical-root-input v2 byte vectors.

Uses only Python's standard library. It deliberately does not import the Go
model, a CBOR package, or bft-go-base. Run with --check to verify the retained
JSON is exactly reproducible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


OUT = Path(__file__).with_name("v2-vectors.json")
ZERO32 = bytes(32)
S0 = bytes.fromhex("a0" * 32)
S1 = bytes.fromhex("a1" * 32)
S2 = bytes.fromhex("a2" * 32)
B0 = bytes.fromhex("b0" * 32)
B1 = bytes.fromhex("b1" * 32)
B2 = bytes.fromhex("b2" * 32)
TREE = bytes.fromhex("c0" * 32)
CONF = bytes.fromhex("d0" * 32)
STAT = bytes.fromhex("e0" * 32)
FEE = bytes.fromhex("f0" * 32)


def head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("negative values are outside this profile")
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + value.to_bytes(8, "big")
    raise ValueError("integer exceeds uint64")


def cbor(value: Any) -> bytes:
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        raise TypeError("booleans are not canonical tuple constituents")
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    raise TypeError(f"unsupported CBOR type {type(value)!r}")


def digest(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def hx(raw: bytes) -> str:
    return "0x" + raw.hex()


def jsonify(value: Any) -> Any:
    if isinstance(value, bytes):
        return hx(value)
    if isinstance(value, list):
        return [jsonify(item) for item in value]
    return value


def word(value: int | bool | bytes) -> str:
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        return hx(value.to_bytes(32, "big"))
    if len(value) != 32:
        raise ValueError("ABI projection bytes must be one word")
    return hx(value)


def technical(round_: int, leader: str, stat: bytes = STAT, fee: bytes = FEE) -> list[Any]:
    return [round_, 0, leader, stat, fee]


def make_vector(
    name: str,
    kind: str,
    root_round: int,
    reference_time: int,
    ir_round: int,
    previous: bytes | None,
    state: bytes | None,
    block: bytes | None,
    tr: list[Any],
    parent: bytes,
    ir_timestamp: int | None = None,
) -> dict[str, Any]:
    if ir_timestamp is None:
        ir_timestamp = 0 if kind == "bootstrap" else reference_time
    ir = [ir_round, 0, previous, state, ir_timestamp, block]
    tr_hash = digest(cbor(tr))
    origin = [3, root_round, 1, reference_time, TREE, ir, tr_hash, CONF]
    root_input = [2, 3, 0x45564D00, b"", tr[0], 0, tr[1], parent, origin, tr, []]
    origin_raw = cbor(origin)
    input_raw = cbor(root_input)
    bootstrap = kind == "bootstrap"
    certified_round = 0 if bootstrap else ir_round
    projected_state = ZERO32 if bootstrap else state
    has_block = False if bootstrap else block is not None
    projected_block = block if has_block else ZERO32
    null_fields = [
        field
        for field, value in (
            ("origin.inputRecord.previousHash", previous),
            ("origin.inputRecord.hash", state),
            ("origin.inputRecord.blockHash", block),
        )
        if value is None
    ]
    return {
        "name": name,
        "class": kind,
        "source": {
            "version": 2,
            "networkId": 3,
            "partitionId": 0x45564D00,
            "shardId": "0x",
            "authorizedRound": tr[0],
            "certifiedEpoch": 0,
            "authorizedEpoch": tr[1],
            "parentHash": hx(parent),
            "rootRound": root_round,
            "rootEpoch": 1,
            "referenceTime": reference_time,
            "unicityTreeRoot": hx(TREE),
            "inputRecord": {
                "round": ir_round,
                "epoch": 0,
                "previousHash": None if previous is None else hx(previous),
                "hash": None if state is None else hx(state),
                "timestamp": ir[4],
                "blockHash": None if block is None else hx(block),
            },
            "trHash": hx(tr_hash),
            "shardConfHash": hx(CONF),
            "technical": {
                "round": tr[0], "epoch": tr[1], "leader": tr[2],
                "statHash": hx(tr[3]), "feeHash": hx(tr[4]),
            },
            "transitions": [],
        },
        "origin": {
            "fields": jsonify(origin),
            "cbor": hx(origin_raw),
            "identity": hx(digest(origin_raw)),
        },
        "rootInput": {
            "fields": jsonify(root_input),
            "cbor": hx(input_raw),
            "commitment": hx(digest(input_raw)),
        },
        "encodingAssertions": {
            "nullFields": {field: "0xf6" for field in null_fields},
            "shardIdEmptyBytes": "0x40",
        },
        "syscallWords": {
            "certifiedRound": word(certified_round),
            "stateHash": word(projected_state),
            "hasBlockHash": word(has_block),
            "blockHash": word(projected_block),
        },
    }


def invalid(name: str, reason: str, previous: Any, state: Any, block: Any, ir_round: int) -> dict[str, Any]:
    return {
        "name": name,
        "reason": reason,
        "source": {
            "inputRecord": {
                "round": ir_round,
                "epoch": 0,
                "previousHash": previous,
                "hash": state,
                "timestamp": 0,
                "blockHash": block,
            }
        },
    }


def build() -> dict[str, Any]:
    vectors = [
        make_vector("bootstrap_authorized_1", "bootstrap", 1, 1_681_971_084, 0, None, None, None,
                    technical(1, "evm-node-1"), B0),
        make_vector("bootstrap_after_timeout_nonconsecutive_assignment", "bootstrap", 4, 1_681_971_099,
                    0, None, None, None, technical(7, "evm-node-2", bytes.fromhex("e1" * 32), bytes.fromhex("f1" * 32)), B0),
        make_vector("first_certified", "first-certified", 5, 1_681_971_104, 1, None, S1, B1,
                    technical(2, "evm-node-1"), B1),
        make_vector("first_certified_repeat_later_root_new_assignment", "first-certified", 8, 1_681_971_119,
                    1, None, S1, B1, technical(5, "evm-node-2", bytes.fromhex("e2" * 32), bytes.fromhex("f2" * 32)), B1,
                    ir_timestamp=1_681_971_104),
        make_vector("first_certified_same_as_genesis_state", "first-certified", 6, 1_681_971_109,
                    1, None, S0, B1, technical(3, "evm-node-1"), B1),
        make_vector("ordinary_quiet", "ordinary", 9, 1_681_971_124, 2, S1, S1, None,
                    technical(3, "evm-node-1"), B1),
        make_vector("ordinary_successful", "ordinary", 10, 1_681_971_129, 3, S1, S2, B2,
                    technical(4, "evm-node-2"), B2),
    ]
    invalid_shapes = [
        invalid("bootstrap_empty_bytes_are_not_null", "present empty bytes are not canonical absence", "0x", None, None, 0),
        invalid("bootstrap_fabricated_state", "bootstrap must retain the genuine nil/nil/nil input record", None, hx(S0), None, 0),
        invalid("bootstrap_with_block", "bootstrap cannot name an executed block", None, None, hx(B0), 0),
        invalid("first_certified_without_state", "first-certified state must be exactly 32 bytes", None, None, hx(B1), 1),
        invalid("first_certified_without_block", "first-certified must name B1", None, hx(S1), None, 1),
        invalid("ordinary_null_previous", "ordinary previous state must be exactly 32 bytes", None, hx(S1), None, 2),
        invalid("ordinary_quiet_with_block", "ordinary equal states require a null block hash", hx(S1), hx(S1), hx(B1), 2),
        invalid("ordinary_changed_without_block", "ordinary unequal states require a 32-byte block hash", hx(S1), hx(S2), None, 3),
    ]
    return {
        "format": "unicity-evm-root-input-v2-reference-vectors",
        "profileVersion": 2,
        "hash": "SHA-256",
        "domain": "SHA-256(CBOR); no additional tuple tag or domain is encoded",
        "note": "Byte-level reference vectors only; they do not assert certificate signatures or trust validity.",
        "encoding": {
            "cbor": "RFC 8949 deterministic, shortest integers, definite lengths",
            "null": "0xf6",
            "emptyBytes": "0x40",
            "technicalRecordHash": "SHA-256(CBOR([round, epoch, leader, statHash, feeHash]))",
            "originOrder": ["networkId", "rootRound", "rootEpoch", "referenceTime", "unicityTreeRoot", "inputRecord", "trHash", "shardConfHash"],
            "rootInputOrder": ["version", "networkId", "partitionId", "shardId", "authorizedRound", "certifiedEpoch", "authorizedEpoch", "parentHash", "origin", "technical", "transitions"],
            "syscallWordOrder": ["certifiedRound", "stateHash", "hasBlockHash", "blockHash"],
        },
        "vectors": vectors,
        "invalidShapes": invalid_shapes,
    }


def sanity(document: dict[str, Any]) -> None:
    vectors = {vector["name"]: vector for vector in document["vectors"]}
    first = vectors["first_certified"]["source"]["inputRecord"]
    repeated = vectors["first_certified_repeat_later_root_new_assignment"]["source"]["inputRecord"]
    if first != repeated:
        raise AssertionError("first-certified repeat did not preserve the exact input record")
    if cbor(None) != b"\xf6" or cbor(b"") != b"\x40":
        raise AssertionError("null and empty bytes are not encoded distinctly")
    commitments = [vector["rootInput"]["commitment"] for vector in document["vectors"]]
    if len(commitments) != len(set(commitments)):
        raise AssertionError("distinct vector root inputs unexpectedly share a commitment")
    for vector in document["vectors"]:
        if vector["source"]["version"] != 2 or len(bytes.fromhex(vector["source"]["parentHash"][2:])) != 32:
            raise AssertionError(f"{vector['name']}: invalid executable v2 parent")


def rendered() -> bytes:
    document = build()
    sanity(document)
    return (json.dumps(document, indent=2, sort_keys=False) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the retained vector differs")
    args = parser.parse_args()
    data = rendered()
    if args.check:
        if not OUT.exists() or OUT.read_bytes() != data:
            raise SystemExit(f"{OUT} is stale; run {Path(__file__).name}")
        print(f"verified {OUT} sha256={hashlib.sha256(data).hexdigest()}")
        return
    OUT.write_bytes(data)
    print(f"wrote {OUT} sha256={hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
