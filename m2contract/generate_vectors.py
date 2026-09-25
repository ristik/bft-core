#!/usr/bin/env python3
"""Independent stdlib-only deterministic CBOR/SHA-256 M2 contract oracle."""
import hashlib
import json
import sys
from pathlib import Path

OUT = Path(__file__).with_name('testdata').joinpath('vectors.json')

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    if n < 2**32: return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')
    return bytes([major << 5 | 27]) + n.to_bytes(8, 'big')

def cbor(v):
    if v is None: return b"\xf6"
    if isinstance(v, int): return head(0, v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b''.join(map(cbor, v))
    raise TypeError(type(v))

def digest(v): return hashlib.sha256(cbor(v)).digest()
def hx(v): return v.hex()

anchor = bytes.fromhex('a1'*32)
first = digest(['UNICITY_TRUSTBASE_V1_TO_V2', 3, 4, anchor])
legacy = bytes.fromhex('f63207575830a59dece6e1b59ecbc46faa865492715252d5a846a6996bde98ba')
keys = [bytes([2+i])*33 for i in range(4)]
unsorted_members = [[f'stake-{i}', f'node-{i}', keys[i], 1] for i in [2, 0, 3, 1]]
members = sorted(unsorted_members, key=lambda member: member[1].encode('utf-8'))
body = [2, 3, 5, 70, members, 3, bytes.fromhex('c3'*32), bytes.fromhex('d4'*32), first]
body_id = digest(body)
body2 = [2, 3, 6, 160, members, 3, bytes.fromhex('e5'*32), bytes.fromhex('f6'*32), body_id]
profile = [30_000_000, 2_000_000, 1_000_000, 2, 8]
collector = bytes.fromhex('12'*20)
config = ['UNICITY_EXECUTION_CONFIG_V2', 2, legacy, *profile, collector]

def rendered(v):
    if isinstance(v, bytes): return hx(v)
    if isinstance(v, list): return [rendered(x) for x in v]
    return v

def encoded(v): return {'fields': rendered(v), 'cbor': hx(cbor(v)), 'identity': hx(digest(v))}

doc = {
 'format': 'unicity-m2-wp1-contract-v1',
 'encoding': 'RFC 8949 deterministic CBOR, SHA-256; no signatures or witnesses in body',
 'anchor': {'network': 3, 'epoch': 4, 'start': 0, 'end': 120, 'hashIncludingSigs': hx(anchor)},
 'firstPredecessor': hx(first),
 'openAnchor': encoded(['UNICITY_V1_TRUST_ANCHOR_INTERVAL', 1, 3, 4, anchor, 0, None]),
 'closedAnchor': encoded(['UNICITY_V1_TRUST_ANCHOR_INTERVAL', 1, 3, 4, anchor, 0, 120]),
 'inputMemberOrder': [m[1] for m in unsorted_members],
 'body': encoded(body), 'body2': encoded(body2),
 'interval': encoded(['UNICITY_ACTIVATED_TRUST_INTERVAL', 1, body_id, 120, bytes.fromhex('77'*32), 200]),
 'openInterval': encoded(['UNICITY_ACTIVATED_TRUST_INTERVAL', 1, digest(body2), 200, bytes.fromhex('88'*32), None]),
 'activation': {'bodyIdentity': hx(body_id), 'earliest': 70, 'actual': 120, 'end': 200, 'commitID': '77'*32},
 'activation2': {'bodyIdentity': hx(digest(body2)), 'earliest': 160, 'actual': 200, 'end': 260, 'commitID': '88'*32},
 'quorumSubsets': [['node-0','node-1','node-2'], ['node-0','node-1','node-3'], ['node-1','node-2','node-3']],
 'executionConfig': encoded(config),
 'changedFeeProfile': encoded(['UNICITY_EXECUTION_CONFIG_V2', 2, legacy, 30_000_000, 2_000_000, 2_000_000, 2, 8, collector]),
 'changedCollector': encoded(['UNICITY_EXECUTION_CONFIG_V2', 2, legacy, *profile, bytes.fromhex('34'*20)]),
 'legacyFixture': {'executionConfigIdentity': 'f63207575830a59dece6e1b59ecbc46faa865492715252d5a846a6996bde98ba', 'genesisOriginIdentity': '030c8f48abdcfba2a393b0422726d1e492272edaa5e7044af846281055b5b33e'},
}
raw = (json.dumps(doc, indent=2) + '\n').encode()
if len(sys.argv)>1 and sys.argv[1]=='--check':
    if OUT.read_bytes()!=raw: raise SystemExit('vectors differ; run generator to update')
else:
    OUT.parent.mkdir(exist_ok=True); OUT.write_bytes(raw)
