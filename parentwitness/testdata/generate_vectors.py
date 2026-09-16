#!/usr/bin/env python3
"""Generate independent canonical CBOR vectors for parent-registry-witness/v1."""
import hashlib, json
from pathlib import Path

OUT = Path(__file__).with_name("v1-vectors.json")

def head(major, n):
    if n < 24: return bytes([(major << 5) | n])
    if n <= 0xff: return bytes([(major << 5) | 24, n])
    if n <= 0xffff: return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n <= 0xffffffff: return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")

def cbor(v):
    if v is None: return b"\xf6"
    if isinstance(v, int): return head(0, v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    raise TypeError(type(v))

address = "ff00000000000000000000000000000000000002"
context = [3, 8, bytes.fromhex("80"), bytes.fromhex("11"*32), bytes.fromhex(address), bytes.fromhex("22"*32), bytes.fromhex("33"*32), bytes.fromhex("44"*32), 0, 1]
block = bytes.fromhex("55"*32)
request = [1, context, block]
outcomes = ["found", "unavailable", "busy", "unsupported-version", "wrong-context", "invalid-request"]
responses = []
for code, name in enumerate(outcomes):
    evidence = [b"\x01", [], [[] for _ in range(22)]] if code == 0 else None
    value = [1, context, block, code, "" if code == 0 else name, evidence]
    responses.append({"name": name, "outcome": code, "cbor": "0x" + cbor(value).hex()})

doc = {
    "protocolID": "/unicity/shard-parent-registry-witness/1.0.0",
    "version": 1,
    "schema": {"request": ["version", "context", "blockHash"], "response": ["version", "context", "blockHash", "outcome", "detail", "evidenceOrNull"], "context": ["networkID", "partitionID", "shardID", "fullShardConfHash", "registryAddress", "registryCodeHash", "genesisCommitment", "evmGenesisHash", "shardEpoch", "rootEpoch"], "evidence": ["header", "accountProof", "storageProofs"]},
    "source": {"networkID": 3, "partitionID": 8, "shardID": "0x80", "fullShardConfHash": "0x"+"11"*32, "registryAddress": "0x"+address, "registryCodeHash": "0x"+"22"*32, "genesisCommitment": "0x"+"33"*32, "evmGenesisHash": "0x"+"44"*32, "shardEpoch": 0, "rootEpoch": 1, "blockHash": "0x"+"55"*32},
    "request": {"cbor": "0x" + cbor(request).hex()},
    "responses": responses,
    "generatorSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
}

text = json.dumps(doc, indent=2) + "\n"
if __import__("sys").argv[1:] == ["--check"]:
    if OUT.read_text() != text: raise SystemExit("generated vector differs")
    print("verified", OUT)
else:
    OUT.write_text(text); print("wrote", OUT)
