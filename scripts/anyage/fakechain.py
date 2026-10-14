#!/usr/bin/env python3
"""A stub `cast` for anyage_selftest_ack: answers `storage`, `block`, `call`, `rpc eth_getBlockReceipts` and `block-number` from a scenario built in this file
(a registry whose imported tip goes 1 -> 3 in ONE block built on the frozen parent), and forwards keccak / abi-encode / to-dec to the real cast.
Scenario knobs through the environment: FAKE_BAD=parent|cursor|tip makes the matching claim false."""
import json, os, subprocess, sys

REAL = os.environ.get("FAKE_REAL_CAST", "cast")
CACHE = {}

def real(*a):
    return subprocess.check_output([REAL, *a], text=True).strip()

def fixed(name):
    k = ("f", name)
    if k not in CACHE: CACHE[k] = real("keccak", "unicity.seal-registry/" + name)
    return CACHE[k]

def entry(e, f):
    k = ("e", e, f)
    if k not in CACHE:
        enc = real("abi-encode", "f(bytes32,uint256,uint256)", fixed("b1.entry"), str(e), str(f))
        CACHE[k] = real("keccak", enc)
    return CACHE[k]

ACK, G, FROZEN_NUM = 5, 1, 4
HASH = lambda n: "0x" + ("%064x" % (0xA0000 + n))
BAD = os.environ.get("FAKE_BAD", "")

def state(block):
    """slot -> int for one block"""
    tip = 3 if block >= ACK else 1
    w = {fixed("b1.format"): 2, fixed("b1.initialized"): 1, fixed("b1.genesisEpoch"): G, fixed("b1.importedTipEpoch"): tip,
         fixed("b1.originReady"): 1, fixed("origin.rootEpoch"): tip, fixed("clock.rootRound"): (100 + block) if block < ACK else (260 + block)}
    starts = {1: 7, 2: 200, 3: 250}
    for e in range(G, tip + 1):
        closed = e < tip
        w[entry(e, 0)] = 1; w[entry(e, 4)] = starts[e]; w[entry(e, 9)] = 4
        w[entry(e, 5)] = starts[e + 1] if closed else 0; w[entry(e, 6)] = 1 if closed else 0
    return w

def cursor(block):
    n = count(block)
    c0 = 2
    return c0 if block < ACK else min(8, n - c0) + c0 + (1 if BAD == "cursor" else 0)
def count(block): return 5 if block < ACK else 9

a = sys.argv[1:]
cmd = a[0] if a else ""
def opt(name):
    return a[a.index(name) + 1] if name in a else None

if cmd in ("keccak", "abi-encode", "to-dec"):
    print(real(*a))
elif cmd == "storage":
    slot, block = a[2], int(opt("--block"))
    print("0x%064x" % state(block).get(slot, 0))
elif cmd == "block-number":
    print(ACK + 1)
elif cmd == "block":
    n = int(a[1])
    h = HASH(n) if not (BAD == "parent" and n == ACK - 1) else HASH(999)
    if "--field" in a: print(h)
    else: print(json.dumps({"number": n, "hash": h, "transactions": []}))
elif cmd == "call":
    sig, block = a[2], int(opt("--block"))
    print(cursor(block) if "recordCursor" in sig else count(block))
elif cmd == "rpc":
    print(json.dumps([]))
else:
    sys.exit("fakechain: unsupported " + " ".join(a))
