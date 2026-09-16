#!/usr/bin/env python3
"""Generate the fixed F6 frontier CBOR/hash encoding vector with stdlib only."""
import hashlib
import json
from pathlib import Path


def head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor(value):
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    raise TypeError(type(value))


origin = bytes([0x11]) * 32
nonce = bytes([0x22]) * 32
context = [5, 0xFF0001, bytes.fromhex("80"), bytes([0x33]) * 32, 1, origin]
pair_tuple = ["root-bootstrap-admission/pair", 1, bytes.fromhex("0102"), bytes.fromhex("0304"), bytes.fromhex("0506"), context]
pair_id = hashlib.sha256(cbor(pair_tuple)).digest()
qc = bytes.fromhex("aabb")
preimage = ["root-bootstrap-admission/frontier", 1, context, nonce, "node-A", pair_id, hashlib.sha256(qc).digest()]
request = [1, context, nonce]

out = {
    "_note": "Encoding-only vector: IR, seal, TR, and QC bytes are opaque synthetic components, not valid certificates.",
    "context_cbor": cbor(context).hex(),
    "request_cbor": cbor(request).hex(),
    "pair_tuple_cbor": cbor(pair_tuple).hex(),
    "pair_identity": pair_id.hex(),
    "preimage_cbor": cbor(preimage).hex(),
}
Path(__file__).with_name("frontier_signing_vectors.json").write_text(json.dumps(out, indent=2) + "\n")
