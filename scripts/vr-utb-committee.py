#!/usr/bin/env python3
"""Epoch 2's signed trust-base entry is exactly the committee VR installed (VR_UTB, scripts/vr-utb-steps.sh).

usage: vr-utb-committee.py MEMBERS_FILE COMMITTEE_HEX OUT
  MEMBERS_FILE   `utb-evidence members --epoch 2` of the aggregator's verified history
  COMMITTEE_HEX  `cast call VR 'committee()'` after the Boundary (ABI: offset, length, then ten words per Member; VRTypes.sol)
Each VR member's rootNodeWord and rootKeyHash (keccak256 of the root node id and of its consensus key) must match exactly one entry member, no entry member
may be left over, and the weights must be the VR members' effective weights and the threshold floor(2 x sum / 3) + 1. Prints what it compared into OUT; exits non-zero on any difference.
"""
import re
import subprocess
import sys


def keccak(data: bytes) -> str:
    return subprocess.run(["cast", "keccak", "0x" + data.hex()], check=True, capture_output=True, text=True).stdout.strip().lower()


def compare(entry, threshold, vr, hash_fn=keccak):
    """entry: [(nodeId, weight, key bytes)], vr: [dict(id, weight, raw, node, key)]. Returns the report lines or raises SystemExit.
    The entry's weight is VR's EFFECTIVE weight (what the production handoff gives the root and the EVM validator); a raw-weight match is not accepted."""
    lines = ["VR committee: %d members; epoch 2 entry: %d members" % (len(vr), len(entry))]
    if len(vr) != len(entry):
        sys.exit(lines[0] + ": the counts differ")
    left = list(entry)
    for v in vr:
        hit = [e for e in left if hash_fn(e[0].encode()) == v["node"] and hash_fn(e[2]) == v["key"]]
        if len(hit) != 1:
            sys.exit("VR member %d (node word %s, key hash %s) matches %d entry members" % (v["id"], v["node"], v["key"], len(hit)))
        e = hit[0]
        left.remove(e)
        if e[1] != v["weight"]:
            sys.exit("VR member %d: entry weight %d, VR effective weight %d (raw weight %d)" % (v["id"], e[1], v["weight"], v["raw"]))
        lines.append("id %d = %s: key and node id match, entry weight %d = VR effective weight (raw %d)" % (v["id"], e[0], e[1], v["raw"]))
    if left:
        sys.exit("entry members not in VR's committee: %s" % [e[0] for e in left])
    want = sum(v["weight"] for v in vr) * 2 // 3 + 1
    if threshold != want:
        sys.exit("the entry's threshold is %d, floor(2 x sum(weight) / 3) + 1 = %d" % (threshold, want))
    lines.append("threshold %d = floor(2 x %d / 3) + 1" % (threshold, sum(v["weight"] for v in vr)))
    lines.append("exactly the committee VR installed")
    return lines


def main():
    members_file, hex_file, out = sys.argv[1:4]
    entry, threshold = [], None
    for line in open(members_file):
        m = re.match(r"member (\S+) weight (\d+) key 0x([0-9a-f]+)$", line.strip())
        if m:
            entry.append((m.group(1), int(m.group(2)), bytes.fromhex(m.group(3))))
        t = re.match(r"epoch \d+ start \d+ threshold (\d+) members \d+$", line.strip())
        if t:
            threshold = int(t.group(1))
    if threshold is None:
        sys.exit("no threshold line in " + members_file)
    raw = open(hex_file).read().strip().removeprefix("0x")
    words = [raw[i:i + 64] for i in range(0, len(raw), 64)]
    if int(words[0], 16) != 32:
        sys.exit("unexpected committee() encoding")
    vr = []
    for k in range(int(words[1], 16)):
        w = words[2 + 10 * k: 12 + 10 * k]
        vr.append(dict(id=int(w[0], 16), weight=int(w[2], 16), raw=int(w[3], 16), node="0x" + w[4], key="0x" + w[5]))
    lines = compare(entry, threshold, vr)
    open(out, "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
