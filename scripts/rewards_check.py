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


class ReplayError(AssertionError):
    pass


def replay(events, segments, members_of, start, snapshots, genesis_funding):
    """X4: the pool's life replayed event by event, so funding that arrives AFTER intervals closed is accounted for as it happened (the one-block recompute above
    assumes every wei was there from the start). events: ordered dicts {kind: fund|close|claim, ...}; close has segment, start, end, rate, budget, distributed;
    snapshots: [(effectiveProgress, rate)] indexed by policy id (index 0 unused: ids start at 1). Every close is checked against what the model derives from the segments
    and the funding available at that moment: an interval closed while the pool was empty stays at budget 0 (no backfill when funds arrive later). Returns the
    final state and counters; raises ReplayError at the first disagreement."""
    available, total, credits = genesis_funding, 0, {}
    nxt, seg, cursor, count = start, 0, 1, len(snapshots) - 1   # policy ids start at 1: the pool's rateCursor is 1 at construction
    stats = {"intervals": 0, "zeroBudget": 0, "paid": 0, "fundings": 0, "claims": 0, "exhaustedAt": None, "refilledAfterExhaustion": False, "dust": 0}
    for ev in events:
        if ev["kind"] == "fund":
            available += ev["amount"]
            stats["fundings"] += 1
            if stats["exhaustedAt"] is not None:
                stats["refilledAfterExhaustion"] = True
        elif ev["kind"] == "claim":
            if credits.get(ev["payee"], 0) < ev["amount"]:
                raise ReplayError(f"{ev['payee']} claimed {ev['amount']} with credit {credits.get(ev['payee'], 0)}")
            credits[ev["payee"]] -= ev["amount"]
            total -= ev["amount"]
            stats["claims"] += 1
        elif ev["kind"] == "close":
            while seg < len(segments) and segments[seg][2] is not None and nxt >= segments[seg][2]:
                seg += 1
            if seg >= len(segments):
                raise ReplayError(f"an interval closed at {ev['start']} with no owner left")
            owner, s_start, s_end = segments[seg]
            if ev["segment"] != seg or ev["start"] != nxt:
                raise ReplayError(f"interval starts at {ev['start']} (segment {ev['segment']}), the model has {nxt} (segment {seg}): the timeline is not contiguous")
            while cursor < count and snapshots[cursor + 1][0] <= nxt:
                cursor += 1
            end = (nxt - start) // GRID * GRID + GRID + start
            if s_end is not None and s_end < end:
                end = s_end
            if cursor < count and snapshots[cursor + 1][0] < end:
                end = snapshots[cursor + 1][0]
            rate = snapshots[cursor][1]
            if ev["end"] != end or ev["rate"] != rate:
                raise ReplayError(f"interval [{nxt}, {ev['end']}) at rate {ev['rate']}: the model has end {end} and rate {rate}")
            nominal = rate * (end - nxt) // RATE_UNITS
            budget = min(nominal, available)
            members = members_of(owner)
            tw = sum(w for w, _ in members)
            shares = [(payee, budget * w // tw) for w, payee in members] if budget else []
            distributed = sum(s for _, s in shares)
            if ev["budget"] != budget or ev["distributed"] != distributed:
                raise ReplayError(f"interval [{nxt}, {end}): budget {ev['budget']} distributed {ev['distributed']}, the model with {available} available has {budget} / {distributed}")
            available += -budget + (budget - distributed)
            for payee, s in shares:
                credits[payee] = credits.get(payee, 0) + s
            total += distributed
            stats["dust"] += budget - distributed
            stats["intervals"] += 1
            if budget == 0:
                stats["zeroBudget"] += 1
                if stats["exhaustedAt"] is None and nominal > 0:
                    stats["exhaustedAt"] = end
            else:
                stats["paid"] += 1
            nxt = end
        else:
            raise ReplayError(f"unknown event {ev['kind']}")
    return {"available": available, "totalCredits": total, "credits": credits, "nextStart": nxt, "stats": stats}


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


def topic(cast, sig):
    return subprocess.run([cast, "keccak", sig], text=True, capture_output=True, check=True).stdout.strip().lower()


def fetch_events(a, c):
    """The pool's Funded / IntervalClosed / Claimed logs up to the pinned block, in (block, log index) order, decoded."""
    sigs = {topic(a.cast, "Funded(address,uint256)"): "fund", topic(a.cast, "IntervalClosed(uint256,uint64,uint64,uint128,uint256,uint256)"): "close",
            topic(a.cast, "Claimed(address,address,uint256)"): "claim"}
    out = subprocess.run([a.cast, "logs", "--rpc-url", a.rpc, "--address", a.pool, "--from-block", "0", "--to-block", str(c.block), "--json"],
                         text=True, capture_output=True)
    if out.returncode:
        raise SystemExit(f"cast logs failed: {out.stderr.strip()}")
    logs = json.loads(out.stdout or "[]")
    logs.sort(key=lambda l: (int(l["blockNumber"], 16), int(l["logIndex"], 16)))
    events = []
    for l in logs:
        kind = sigs.get(l["topics"][0].lower())
        if kind is None:
            continue
        w = words(l["data"])
        if kind == "fund":
            events.append({"kind": "fund", "amount": w[0], "block": int(l["blockNumber"], 16)})
        elif kind == "claim":
            events.append({"kind": "claim", "payee": addr_of(int(l["topics"][1], 16)), "amount": w[0], "block": int(l["blockNumber"], 16)})
        else:
            events.append({"kind": "close", "segment": int(l["topics"][1], 16), "start": w[0], "end": w[1], "rate": w[2], "budget": w[3], "distributed": w[4],
                           "block": int(l["blockNumber"], 16)})
    return events


def replay_check(a):
    block = a.block
    if block is None:
        block = int(subprocess.run([a.cast, "block-number", "--rpc-url", a.rpc], text=True, capture_output=True, check=True).stdout.strip())
    c = Chain(a.rpc, a.cast, block)
    n = c.raw(a.pool, "segmentCount()")[0]
    segments = []
    for i in range(n):
        w = c.raw(a.pool, "segmentAt(uint256)", i)
        segments.append(("0x" + format(w[0], "064x"), w[1], w[2] if w[3] else None))
    assert segments[0][0] == a.genesis_assignment.lower(), "segment 0 is not the genesis assignment"

    def members_of(assignment):
        ids = c.raw(a.custody, "assignmentExposures(bytes32)", assignment)
        return [(c.raw(a.custody, "exposures(bytes32)", "0x" + format(ids[2 + k], "064x"))[3],
                 addr_of(c.raw(a.custody, "exposures(bytes32)", "0x" + format(ids[2 + k], "064x"))[7])) for k in range(ids[1])]

    count = c.raw(a.policy, "currentPolicyID()")[0]
    snaps = [(0, 0)]   # index 0 unused
    for i in range(1, count + 1):
        w = c.raw(a.policy, "snapshotAt(uint32)", i)   # Policy (10 words), rewardRate, hash, effectiveProgress, effectiveTime
        snaps.append((w[12], w[10]))
    start = c.raw(a.pool, "START()")[0]
    events = fetch_events(a, c)
    state = replay(events, segments, members_of, start, snaps, a.initial_funding)
    got = {"available": c.raw(a.pool, "available()")[0], "totalCredits": c.raw(a.pool, "totalCredits()")[0], "nextStart": c.raw(a.pool, "nextStart()")[0]}
    for k in got:
        assert got[k] == state[k], f"{k}: the chain has {got[k]}, the replay {state[k]}"
    for payee, want in sorted(state["credits"].items()):
        have = c.raw(a.pool, "credits(address)", payee)[0]
        assert have == want, f"credit of {payee}: {have}, replayed {want}"
    s = state["stats"]
    if a.min_paid is not None:
        assert s["paid"] >= a.min_paid, f"{s['paid']} paid intervals, {a.min_paid} required"
    if a.require_exhaustion:
        assert s["exhaustedAt"] is not None and s["zeroBudget"] >= 1, "the pool never ran dry (no zero-budget interval with a positive nominal budget)"
    if a.require_refill:
        assert s["refilledAfterExhaustion"], "no funding arrived after the pool ran dry"
        last_zero = max((e["end"] for e in events if e["kind"] == "close" and e["budget"] == 0), default=0)
        assert any(e["kind"] == "close" and e["budget"] > 0 and e["start"] >= last_zero for e in events), "no interval was paid after the last empty one"
    print("REWARDS-REPLAY ok " + json.dumps(dict(s, block=block, events=len(events), segments=len(segments), nextStart=got["nextStart"], available=got["available"],
                                                 totalCredits=got["totalCredits"], payees=len(state["credits"]))))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    for name in ("rpc", "cast", "pool", "custody", "registry", "election", "policy", "genesis-assignment"):
        c.add_argument("--" + name, required=True)
    c.add_argument("--initial-funding", type=int, required=True)
    c.add_argument("--extra-funding", type=int, default=0)
    c.add_argument("--block", type=int)
    r = sub.add_parser("replay")
    for name in ("rpc", "cast", "pool", "custody", "registry", "election", "policy", "genesis-assignment"):
        r.add_argument("--" + name, required=True)
    r.add_argument("--initial-funding", type=int, required=True)
    r.add_argument("--block", type=int)
    r.add_argument("--min-paid", type=int)
    r.add_argument("--require-exhaustion", action="store_true")
    r.add_argument("--require-refill", action="store_true")
    a = p.parse_args()
    try:
        replay_check(a) if a.cmd == "replay" else check(a)
    except AssertionError as e:
        sys.exit(f"REWARDS-{a.cmd.upper()} FAILED: {e}")


if __name__ == "__main__":
    main()
