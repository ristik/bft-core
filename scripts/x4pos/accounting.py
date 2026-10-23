#!/usr/bin/env python3
"""X4 B5: the accounting checker of the PoS campaign (design section 3/5): periodic snapshots of the same accumulated state are checked for monotone cursors,
pool/custody conservation and no duplicate payment, and the FIRST failing invariant is reported with the snapshot it fails at.

    accounting.py check SNAPSHOTS.jsonl [--out accounting.json]

A snapshot is one JSON object per line, written by a collector during the run (the collector is not part of this file; this checker only reads):

    {"t": <seconds since start, strictly increasing>, "block": <EVM block, non-decreasing>,
     "cursors": {"<name>": <integer>, ...},              # record / reward / evidence cursors; each is non-decreasing across snapshots
     "pool":    {"funded": W, "paid": W, "balance": W},    # cumulative wei funded into / paid out of the reward pool and what it holds now
     "custody": {"deposited": W, "withdrawn": W, "slashed": W, "held": W, "balance": W},   # cumulative in / out; held = lots + credits still owed; balance = the account (optional)
     "payments": [["<interval>", "<payee>", W], ...]}      # every payment made up to this snapshot, cumulative (a payment is never rewritten or repeated)

Invariants (each a named failure, first one wins):
  schema        a snapshot is missing a field or carries a non-integer / negative amount
  order         t strictly increases, block never decreases
  cursor        a cursor never decreases and never disappears (a cursor that is new in a later snapshot is fine)
  cumulative    the cumulative totals (pool funded/paid, custody deposited/withdrawn/slashed) never decrease; balance and held may move either way
  pool          funded == paid + balance
  custody       deposited == withdrawn + held (the pinned custody: a slashed amount leaves its lot as a bounty / treasury CREDIT, so it is inside held until claimed and inside
                withdrawn after; adding `slashed` would count it twice), slashed <= deposited, and when a balance is given balance >= held (the surplus is not negative)
  payments      the cumulative payment list only grows by appending; no (interval, payee) is paid twice; sum(payments) == pool.paid
Exit status: 0 PASS, 1 FAIL (first failing invariant in the output), 2 INCOMPLETE (fewer than two snapshots: nothing can be compared)."""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

FIELDS = {"pool": ("funded", "paid", "balance"), "custody": ("deposited", "withdrawn", "slashed", "held")}


class Fail(Exception):
    def __init__(self, invariant, index, detail):
        super().__init__(f"{invariant} at snapshot {index}: {detail}")
        self.invariant, self.index, self.detail = invariant, index, detail


def amount(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def check_schema(i, s):
    if not isinstance(s, dict):
        raise Fail("schema", i, "not an object")
    for k in ("t", "block"):
        if not amount(s.get(k)):
            raise Fail("schema", i, f"{k} is not a non-negative integer")
    cur = s.get("cursors")
    if not isinstance(cur, dict) or not all(amount(v) for v in cur.values()):
        raise Fail("schema", i, "cursors is not an object of non-negative integers")
    for sec, names in FIELDS.items():
        o = s.get(sec)
        if not isinstance(o, dict) or not all(amount(o.get(n)) for n in names):
            raise Fail("schema", i, f"{sec} lacks a non-negative integer among {list(names)}")
    pays = s.get("payments")
    if not isinstance(pays, list) or not all(isinstance(p, list) and len(p) == 3 and isinstance(p[0], str) and isinstance(p[1], str) and amount(p[2]) for p in pays):
        raise Fail("schema", i, "payments is not a list of [interval, payee, wei]")


def check(snaps):
    prev = None
    for i, s in enumerate(snaps):
        check_schema(i, s)
        if s["pool"]["funded"] != s["pool"]["paid"] + s["pool"]["balance"]:
            raise Fail("pool", i, f"funded {s['pool']['funded']} != paid {s['pool']['paid']} + balance {s['pool']['balance']}")
        c = s["custody"]
        if c["deposited"] != c["withdrawn"] + c["held"]:
            raise Fail("custody", i, f"deposited {c['deposited']} != withdrawn {c['withdrawn']} + held {c['held']}")
        if c["slashed"] > c["deposited"]:
            raise Fail("custody", i, f"slashed {c['slashed']} exceeds deposited {c['deposited']}")
        if "balance" in c and (not amount(c["balance"]) or c["balance"] < c["held"]):
            raise Fail("custody", i, f"the custody balance {c['balance']} is below what it holds {c['held']}")
        keys = [(p[0], p[1]) for p in s["payments"]]
        dup = sorted(k for k, n in Counter(keys).items() if n > 1)
        if dup:
            raise Fail("payments", i, f"paid twice: {dup[0]}")
        if sum(p[2] for p in s["payments"]) != s["pool"]["paid"]:
            raise Fail("payments", i, f"the payments sum to {sum(p[2] for p in s['payments'])}, the pool says paid {s['pool']['paid']}")
        if prev is not None:
            if s["t"] <= prev["t"] or s["block"] < prev["block"]:
                raise Fail("order", i, f"t {prev['t']}->{s['t']}, block {prev['block']}->{s['block']}")
            for name, v in prev["cursors"].items():
                if name not in s["cursors"]:
                    raise Fail("cursor", i, f"cursor {name} disappeared")
                if s["cursors"][name] < v:
                    raise Fail("cursor", i, f"cursor {name} went back {v}->{s['cursors'][name]}")
            for sec, name in (("pool", "funded"), ("pool", "paid"), ("custody", "deposited"), ("custody", "withdrawn"), ("custody", "slashed")):
                if s[sec][name] < prev[sec][name]:
                    raise Fail("cumulative", i, f"{sec}.{name} went back {prev[sec][name]}->{s[sec][name]}")
            if s["payments"][:len(prev["payments"])] != prev["payments"]:
                raise Fail("payments", i, "the earlier payments were rewritten, not appended to")
        prev = s


def run(path):
    snaps = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if line.strip():
            try:
                snaps.append(json.loads(line))
            except ValueError as e:
                return {"status": "FAIL", "firstFailure": {"invariant": "schema", "snapshot": n - 1, "detail": f"line {n} is not JSON: {e}"}, "snapshots": len(snaps)}
    try:
        check(snaps)
    except Fail as f:
        return {"status": "FAIL", "firstFailure": {"invariant": f.invariant, "snapshot": f.index, "detail": f.detail}, "snapshots": len(snaps)}
    if len(snaps) < 2:
        return {"status": "INCOMPLETE", "reason": "fewer than two snapshots: nothing to compare", "snapshots": len(snaps)}
    last = snaps[-1]
    return {"status": "PASS", "snapshots": len(snaps), "spanSeconds": last["t"] - snaps[0]["t"], "payments": len(last["payments"]), "cursors": last["cursors"]}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("snapshots")
    c.add_argument("--out")
    a = p.parse_args(argv)
    rep = run(a.snapshots)
    text = json.dumps(rep, indent=1, sort_keys=True)
    if a.out:
        Path(a.out).write_text(text + "\n")
    print(text)
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[rep["status"]]


if __name__ == "__main__":
    sys.exit(main())
