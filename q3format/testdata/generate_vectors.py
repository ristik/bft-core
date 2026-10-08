#!/usr/bin/env python3
"""Independent generator of the q3format golden vectors (vectors.json).

A second implementation of the canonical encoding: a minimal RFC 8949 section 4.2.1 encoder for unsigned integers, byte
strings, text strings, definite arrays and null. It shares no code with the Go package, so a byte-for-byte match in
TestVectors is evidence the bytes are canonical and not an artefact of one library. Run: python3 generate_vectors.py > vectors.json
"""
import hashlib, json

def head(major, n):
    m = major << 5
    if n < 24: return bytes([m | n])
    if n < 1 << 8: return bytes([m | 24, n])
    if n < 1 << 16: return bytes([m | 25]) + n.to_bytes(2, "big")
    if n < 1 << 32: return bytes([m | 26]) + n.to_bytes(4, "big")
    return bytes([m | 27]) + n.to_bytes(8, "big")

def enc(v):
    if v is None: return b"\xf6"
    if isinstance(v, bool): raise TypeError("no booleans")
    if isinstance(v, int): return head(0, v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list): return head(4, len(v)) + b"".join(enc(x) for x in v)
    raise TypeError(type(v))

sha = lambda b: hashlib.sha256(b).digest()

# the fixture: secp256k1 generator multiples G..4G as compressed keys; weights (6,1,1,1), W=9, threshold 7
KEYS = ["0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"]
WEIGHTS = [6, 1, 1, 1]
NETWORK, GENESIS, EPOCH, A_MIN = 5, bytes([7]) * 32, 2, 20
PRIOR_ID = bytes([0x11]) * 32

config = [2, NETWORK, GENESIS, 2, 2, "D3", "root-wrr-v1", "mirrored-root-v1", "unit-v1"]
config_enc = enc(["UNICITY_Q3_PROTOCOL_CONFIG", config])
to_v3 = lambda version, ident: sha(enc(["UNICITY_TRUSTBASE_TO_V3", NETWORK, 1, version, ident]))
predecessor = to_v3(1, PRIOR_ID)
members = [["s%d" % (i + 1), "n%d" % (i + 1), bytes.fromhex(KEYS[i]), WEIGHTS[i]] for i in range(4)]
body = [3, NETWORK, EPOCH, A_MIN, members, 7, bytes([0x22]) * 32, bytes([0x33]) * 32, predecessor, config]
body_enc = enc(["UNICITY_TRUSTBASE_V3", body])
body_id = sha(body_enc)
ATTEMPT, CANDIDATE = 3, bytes([0x44]) * 32
receipt = enc(["UNICITY_Q3_READINESS_V1", 1, NETWORK, GENESIS, predecessor, ATTEMPT, CANDIDATE, body_id, sha(config_enc), "n1"])

LINK = [body_enc, [EPOCH, 25, body_id, bytes([0x99]) * 32, 1, PRIOR_ID], [bytes([0x55]) * 32, bytes([0x66]) * 32, bytes([0x44]) * 32], bytes([0xab]) * 16, []]
envelope = enc(["UNICITY_Q3_EXECUTION_PROOF", 1, bytes([0x01]) * 8, [b"t1", b"t2"], bytes([0x88]) * 32, None, [LINK]])

print(json.dumps({
    "configEncoding": config_enc.hex(), "configIdentity": sha(config_enc).hex(),
    "bodyEncoding": body_enc.hex(), "bodyIdentity": body_id.hex(),
    "predecessorFromV1": predecessor.hex(),
    "receiptMessage": receipt.hex(), "receiptMessageHash": sha(receipt).hex(),
    "envelope": envelope.hex(),
}, indent=2))
