#!/usr/bin/env python3
"""Epoch 2's signed trust-base entry is exactly the committee VR installed (VR_UTB, scripts/vr-utb-steps.sh).

usage: vr-utb-committee.py MEMBERS_FILE COMMITTEE_HEX OUT
  MEMBERS_FILE   `utb-evidence members --epoch 2` of the aggregator's verified history
  COMMITTEE_HEX  `cast call VR 'committee()'` after the Boundary (ABI: offset, length, then ten words per Member; VRTypes.sol)
Each VR member's rootNodeWord and rootKeyHash (keccak256 of the root node id and of its consensus key) must match exactly one entry member, no entry member
may be left over, and the weights must be the VR members' weights. Prints what it compared into OUT; exits non-zero on any difference.
"""
import re
import subprocess
import sys


def keccak(data: bytes) -> str:
    return subprocess.run(["cast", "keccak", "0x" + data.hex()], check=True, capture_output=True, text=True).stdout.strip().lower()


def main():
    members_file, hex_file, out = sys.argv[1:4]
    entry = []
    for line in open(members_file):
        m = re.match(r"member (\S+) weight (\d+) key 0x([0-9a-f]+)$", line.strip())
        if m:
            entry.append((m.group(1), int(m.group(2)), bytes.fromhex(m.group(3))))
    raw = open(hex_file).read().strip().removeprefix("0x")
    words = [raw[i:i + 64] for i in range(0, len(raw), 64)]
    if int(words[0], 16) != 32:
        sys.exit("unexpected committee() encoding")
    n = int(words[1], 16)
    vr = []
    for k in range(n):
        w = words[2 + 10 * k: 12 + 10 * k]
        vr.append(dict(id=int(w[0], 16), weight=int(w[2], 16), raw=int(w[3], 16), node="0x" + w[4], key="0x" + w[5]))
    lines = ["VR committee: %d members; epoch 2 entry: %d members" % (n, len(entry))]
    if n != len(entry):
        sys.exit(lines[0] + ": the counts differ")
    left = list(entry)
    for v in vr:
        hit = [e for e in left if keccak(e[0].encode()) == v["node"] and keccak(e[2]) == v["key"]]
        if len(hit) != 1:
            sys.exit("VR member %d (node word %s, key hash %s) matches %d entry members" % (v["id"], v["node"], v["key"], len(hit)))
        e = hit[0]
        left.remove(e)
        if e[1] not in (v["weight"], v["raw"]):
            sys.exit("VR member %d: entry weight %d, VR weight %d, raw weight %d" % (v["id"], e[1], v["weight"], v["raw"]))
        lines.append("id %d = %s: key and node id match, entry weight %d (VR weight %d, raw %d)" % (v["id"], e[0], e[1], v["weight"], v["raw"]))
    if left:
        sys.exit("entry members not in VR's committee: %s" % [e[0] for e in left])
    lines.append("exactly the committee VR installed")
    open(out, "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


main()
