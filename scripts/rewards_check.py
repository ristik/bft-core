#!/usr/bin/env python3
"""T8 lane check of the operator reward pool (unicity-pos-contracts RewardPool) against the chain, at one pinned block.

    rewards_check.py check --rpc URL --cast CAST --pool 0x.. --custody 0x.. --registry 0x.. --election 0x.. --policy 0x.. --genesis-assignment 0x.. \
                           --initial-funding WEI [--extra-funding WEI] [--block N]

It reads the pool's timeline (its segments), cross-checks every segment boundary with custody's own record of the assignment (offset), recomputes every
interval and credit from scratch (the grid, the owner's end, the rate, the committed weights, floor division, exhaustion, dust) and compares the result
with the pool's cursor, available funding, total credits and each payee's credit. The recomputation shares no code with the contract.
Exit 0 and one `REWARDS-CHECK ok ...` line on agreement.
"""
import argparse
import json
import subprocess
import sys

GRID = 1000
RATE_UNITS = 1000


def model(segments, progress, tail_open, start, rate, available, members_of):
    """segments: [(assignment, start, end|None)] in order; members_of(assignment) -> [(weight, payee)]. Returns (credits, next_start, available, intervals).
    Intervals are half-open [a, b), b the earliest of the owner's end and the next grid point, closed only up to `progress`; the tail (no end) only when
    no election result is open (tail_open False)."""
    credits, intervals = {}, 0
    a = start
    seg = 0
    while True:
        while seg < len(segments) and segments[seg][2] is not None and a >= segments[seg][2]:
            seg += 1
        if seg >= len(segments):
            break
        owner, s_start, s_end = segments[seg]
        if a < s_start:
            raise AssertionError(f"timeline gap: the next interval starts at {a}, the owner at {s_start}")
        if s_end is None and tail_open:
            break
        b = (a - start) // GRID * GRID + GRID + start
        if s_end is not None and s_end < b:
            b = s_end
        if b > progress or b <= a:
            break
        nominal = rate * (b - a) // RATE_UNITS
        budget = min(nominal, available)
        available -= budget
        members = members_of(owner)
        total = sum(w for w, _ in members)
        distributed = 0
        if budget:
            assert total > 0, "zero total weight"
            for w, payee in members:
                share = budget * w // total
                credits[payee] = credits.get(payee, 0) + share
                distributed += share
        available += budget - distributed
        a = b
        intervals += 1
    return credits, a, available, intervals


def words(hexstr):
    h = hexstr.strip()
    assert h.startswith("0x"), h
    h = h[2:]
    assert len(h) % 64 == 0, f"not whole words: {h[:80]}"
    return [int(h[i:i + 64], 16) for i in range(0, len(h), 64)]


class Chain:
    def __init__(self, rpc, cast, block):
        self.rpc, self.cast, self.block = rpc, cast, block

    def call(self, to, sig, *args):
        out = subprocess.run([self.cast, "call", "--rpc-url", self.rpc, "--block", str(self.block), to, sig, *map(str, args)],
                             text=True, capture_output=True)
        if out.returncode:
            raise SystemExit(f"cast call {to} {sig} failed: {out.stderr.strip()}")
        return out.stdout.strip()

    def raw(self, to, sig, *args):
        # no return type in the signature: cast prints the ABI-encoded answer
        return words(self.call(to, sig, *args))


def addr_of(word):
    return "0x" + format(word, "064x")[24:]


def check(a):
    block = a.block
    if block is None:
        block = int(subprocess.run([a.cast, "block-number", "--rpc-url", a.rpc], text=True, capture_output=True, check=True).stdout.strip())
    c = Chain(a.rpc, a.cast, block)
    n = c.raw(a.pool, "segmentCount()")[0]
    segments = []
    for i in range(n):
        w = c.raw(a.pool, "segmentAt(uint256)", i)
        assignment, start, end, ended = "0x" + format(w[0], "064x"), w[1], w[2], bool(w[3])
        segments.append((assignment, start, end if ended else None))
    # every boundary the pool took from the records is the one custody holds for the assignment it names
    for i, (assignment, start, _) in enumerate(segments):
        asg = c.raw(a.custody, "assignments(bytes32)", assignment)
        offset, offset_set = asg[4], bool(asg[6])
        assert offset_set, f"segment {i}: custody has not activated {assignment}"
        assert start == offset, f"segment {i} starts at {start}, custody holds offset {offset} for {assignment}"
    assert segments[0][0] == a.genesis_assignment.lower(), "segment 0 is not the genesis assignment"
    for i in range(len(segments) - 1):
        assert segments[i][2] is not None, f"segment {i} is not the last yet has no end"
        assert segments[i][2] == segments[i + 1][1], f"segment {i} ends at {segments[i][2]}, segment {i + 1} starts at {segments[i + 1][1]}"

    def members_of(assignment):
        ids = c.raw(a.custody, "assignmentExposures(bytes32)", assignment)
        count = ids[1]
        out = []
        for k in range(count):
            e = c.raw(a.custody, "exposures(bytes32)", "0x" + format(ids[2 + k], "064x"))
            out.append((e[3], addr_of(e[7])))
        return out

    progress = c.raw(a.registry, "progress()")[0]
    tail_open = c.raw(a.election, "openResult()")[0] != 0
    rate = c.raw(a.policy, "currentRewardRate()")[0]
    start = c.raw(a.pool, "START()")[0]
    funded = a.initial_funding + a.extra_funding
    credits, next_start, available, intervals = model(segments, progress, tail_open, start, rate, funded, members_of)

    got_next, got_avail, got_total = c.raw(a.pool, "nextStart()")[0], c.raw(a.pool, "available()")[0], c.raw(a.pool, "totalCredits()")[0]
    assert got_next == next_start, f"nextStart {got_next}, recomputed {next_start}"
    assert got_avail == available, f"available {got_avail}, recomputed {available}"
    assert got_total == sum(credits.values()), f"totalCredits {got_total}, recomputed {sum(credits.values())}"
    for payee, want in sorted(credits.items()):
        have = c.raw(a.pool, "credits(address)", payee)[0]
        assert have == want, f"credit of {payee}: {have}, recomputed {want}"
    bal = int(subprocess.run([a.cast, "balance", "--rpc-url", a.rpc, "--block", str(block), a.pool], text=True, capture_output=True, check=True).stdout.strip())
    assert bal >= got_avail + got_total, f"the pool holds {bal}, it has allocated {got_avail + got_total}"
    print("REWARDS-CHECK ok " + json.dumps({"block": block, "segments": len(segments), "intervals": intervals, "nextStart": got_next, "progress": progress,
          "tailOpen": tail_open, "available": got_avail, "totalCredits": got_total, "surplus": bal - got_avail - got_total, "payees": len(credits)}))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    for name in ("rpc", "cast", "pool", "custody", "registry", "election", "policy", "genesis-assignment"):
        c.add_argument("--" + name, required=True)
    c.add_argument("--initial-funding", type=int, required=True)
    c.add_argument("--extra-funding", type=int, default=0)
    c.add_argument("--block", type=int)
    a = p.parse_args()
    try:
        check(a)
    except AssertionError as e:
        sys.exit(f"REWARDS-CHECK FAILED: {e}")


if __name__ == "__main__":
    main()
