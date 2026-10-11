#!/usr/bin/env python3
"""Decoders for the raw `cast call` answers the P85 lane reads (no ABI JSON: the answers are fixed-layout words).

  record      stdin: the return of registry.recordAt(uint64) (a RootRecord with dynamic `data`)
              -> "<index> <kind> <progress> <ucTime> <data word 0> <data word 1>"
  assignment  stdin: the return of custody.assignments(bytes32) (the public getter: sixteen static words, the exposure list omitted)
              -> one line of JSON
  word        stdin: one ABI word (or a call that returns one) -> the integer
  selftest    exercises the decoders on hand-built encodings
"""
import json
import sys

ASSIGNMENT_FIELDS = ["state", "lineage", "rootEpoch", "evmEpoch", "offset", "firstRound", "offsetSet", "hKnown", "hRound", "closed",
                     "pClose", "tClose", "closureKey", "exposureDigest", "keyDigest", "policyID"]


def words(hexstr):
    h = hexstr.strip()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) % 64 != 0 or not h:
        raise SystemExit("not whole ABI words: %r" % hexstr[:80])
    return [h[i:i + 64] for i in range(0, len(h), 64)]


def num(w):
    return int(w, 16)


def record(hexstr):
    w = words(hexstr)
    if num(w[0]) != 0x20:
        raise SystemExit("record: unexpected head offset")
    s = w[1:]  # the struct: index, recordID, predecessor, kind, progress, ucTime, data offset
    index, kind, progress, uc, off = num(s[0]), num(s[3]), num(s[4]), num(s[5]), num(s[6])
    base = off // 32  # the data length word, relative to the struct start
    length = num(s[base])
    data = "".join(s[base + 1:])[: length * 2]
    w0 = data[0:64] if length >= 32 else ""
    w1 = data[64:128] if length >= 64 else ""
    return "%d %d %d %d %s %s" % (index, kind, progress, uc, "0x" + w0 if w0 else "-", "0x" + w1 if w1 else "-")


def assignment(hexstr):
    w = words(hexstr)
    if len(w) != len(ASSIGNMENT_FIELDS):
        raise SystemExit("assignment: %d words, want %d" % (len(w), len(ASSIGNMENT_FIELDS)))
    out = {}
    for name, word in zip(ASSIGNMENT_FIELDS, w):
        out[name] = ("0x" + word) if name in ("lineage", "closureKey", "exposureDigest", "keyDigest") else num(word)
    return json.dumps(out, sort_keys=True)


def selftest():
    def word(v):
        return "%064x" % v
    a = ["01" * 32, "02" * 32]
    data = bytes.fromhex(a[0] + a[1] + "00" * 32)
    enc = "0x" + word(0x20) + word(7) + "aa" * 32 + "bb" * 32 + word(4) + word(718) + word(1791721) + word(0xe0) + word(len(data)) + data.hex()
    got = record(enc).split()
    assert got == ["7", "4", "718", "1791721", "0x" + a[0], "0x" + a[1]], got
    vals = [2, 5, 1, 1, 100, 101, 1, 1, 130, 1, 140, 1100, 9, 8, 7, 3]
    enc = "0x" + "".join(word(v) for v in vals)
    j = json.loads(assignment(enc))
    assert j["state"] == 2 and j["pClose"] == 140 and j["tClose"] == 1100 and j["closed"] == 1 and j["policyID"] == 3, j
    for bad in ("0x", "0x12"):
        try:
            record(bad)
        except SystemExit:
            continue
        raise AssertionError("accepted %r" % bad)
    print("chain_decode selftest ok")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "selftest":
        selftest()
    elif cmd == "record":
        print(record(sys.stdin.read()))
    elif cmd == "assignment":
        print(assignment(sys.stdin.read()))
    elif cmd == "word":
        print(num(words(sys.stdin.read())[0]))
    else:
        raise SystemExit(__doc__)
