#!/usr/bin/env python3
"""X4 B5: the snapshot collector of the PoS campaign. Appends ONE line of the accounting checker's schema (accounting.py) to a snapshots file, read from the chain with `cast`
at one pinned block. Names are those of the pinned contracts (unicity-pos-contracts b17829ca: CustodyStorage.sol, StakeCustody.sol, RewardPool.sol); nothing here has run against a
live chain yet, so a wrong event shape shows up as a failed cross-check below, never as a quiet pass.

    collect.py snapshot --rpc URL --cast CAST --custody ADDR --pool ADDR --from-block N --t SECONDS [--genesis-funding WEI] --out snapshots.jsonl

Reads at block B (cast block-number, then every call and log scan pinned to B):
  custody  deposited = sum lots(i).initial over every lot; slashed = sum lots(i).penalized; held = totalFree + totalEncumbered + totalDraining + totalCredits (credits are
           owed and still inside custody); withdrawn = sum CreditClaimed(.., .., amount); balance = the custody account's balance.
           Cross-check (the collector exits 1 and says so if it differs): withdrawn == sum over released lots (category 4) of (initial - penalized) + slashed - totalCredits.
  pool     funded = --genesis-funding + sum Funded(.., amount). In the P85 lanes the pool's funding is a genesis ALLOC (balance == rewardFunding at block 0, deployment.json), so no
           Funded log exists for it: the caller passes it explicitly (default 0, right only for a pool funded by calls to fund(), whose Funded logs are then in the sum); paid = sum Claimed(.., .., amount); balance = the pool account's balance.
  payments one entry per pool Claimed event: ["<tx hash>:<log index>", payee, amount]. The pool pays no per-interval amount through a claim, so the (interval, payee) of the checker
           is the event id here: its duplicate rule then catches a repeated log, not a repeated economic payment. That limit is stated in the README.
  cursors  {"nextLotID": n} only: the contracts' other cursors are not read yet.
An event amount is the last 32-byte word of the log's data (or the last topic when there is no data); a wrong guess breaks the cross-check, the pool's funded == paid + balance or
the custody identity of accounting.py. Every check is an explicit raise (python -O safe)."""
import argparse
import json
import subprocess
import sys

CAST_TIMEOUT = 60
LOTS = "lots(uint256)(uint64,uint64,uint128,uint128,uint128,uint8,uint16,uint32,uint64,uint64,uint64,uint64,uint64)"   # as scripts/x4pos/exit_check.py reads it
FUNDED, CLAIMED, CREDIT_CLAIMED = "Funded(address,uint256)", "Claimed(address,address,uint256)", "CreditClaimed(address,address,uint256)"


class CollectError(Exception):
    pass


def need(cond, message):
    if not cond:
        raise CollectError(message)


def cast(a, *args):
    try:
        out = subprocess.run([a.cast, *args], text=True, capture_output=True, timeout=CAST_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise CollectError(f"cast {args[0]} timed out after {CAST_TIMEOUT} s")
    need(out.returncode == 0, f"cast {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return out.stdout


def call(a, block, to, sig, *args):
    out = cast(a, "call", "--rpc-url", a.rpc, "--block", str(block), to, sig, *map(str, args))
    return [int(l.split()[0]) for l in out.strip().splitlines() if l.strip()]


def logs(a, block, address, sig):
    out = cast(a, "logs", "--rpc-url", a.rpc, "--address", address, "--from-block", str(a.from_block), "--to-block", str(block), "--json", sig)
    try:
        rows = json.loads(out or "[]")
    except ValueError as e:
        raise CollectError(f"cast logs {sig} did not print JSON: {e}")
    need(isinstance(rows, list), f"cast logs {sig} did not print a list")
    return rows


def word(h):
    return int(h, 16)


def amount_of(row):
    data = row.get("data", "0x")[2:]
    if data:
        need(len(data) % 64 == 0, "log data is not a whole number of words")
        return word(data[-64:])
    need(row.get("topics"), "log has neither data nor topics")
    return word(row["topics"][-1])


def payee_of(row):
    topics, data = row["topics"], row.get("data", "0x")[2:]
    w = topics[1] if len(topics) > 1 else data[:64]
    need(w, "log has no payee word")
    return "0x" + w[2:][-40:] if w.startswith("0x") else "0x" + w[-40:]


def snapshot(a):
    block = int(cast(a, "block-number", "--rpc-url", a.rpc).strip())
    nxt = call(a, block, a.custody, "nextLotID()(uint256)")[0]
    lots = []
    i = 1
    while i <= nxt + 1:   # nextLotID is the last assigned id (lotID = ++nextLotID): walk until an unassigned (all-zero) slot, one past the last, to see none is missing or extra
        v = call(a, block, a.custody, LOTS, i)
        need(len(v) == 13, f"lots({i}) returned {len(v)} values, not 13")
        if v[0] == 0:
            break
        lots.append({"identity": v[0], "initial": v[2], "remaining": v[3], "penalized": v[4], "category": v[5]})
        i += 1
    need(len(lots) == nxt, f"nextLotID is {nxt} but {len(lots)} lots exist")
    free, enc, drain, credits = (call(a, block, a.custody, f"{n}()(uint256)")[0] for n in ("totalFree", "totalEncumbered", "totalDraining", "totalCredits"))
    deposited, slashed = sum(l["initial"] for l in lots), sum(l["penalized"] for l in lots)
    withdrawn = sum(amount_of(r) for r in logs(a, block, a.custody, CREDIT_CLAIMED))
    held = free + enc + drain + credits
    released = sum(l["initial"] - l["penalized"] for l in lots if l["category"] == 4)
    notes = []
    if withdrawn != released + slashed - credits:
        notes.append(f"withdrawn by CreditClaimed events {withdrawn} != released lots {released} + slashed {slashed} - credits {credits}")
    funded_rows, claim_rows = logs(a, block, a.pool, FUNDED), logs(a, block, a.pool, CLAIMED)
    pays = [[f"{r['transactionHash']}:{word(str(r['logIndex'])) if isinstance(r['logIndex'], str) else r['logIndex']}", payee_of(r), amount_of(r)] for r in claim_rows]
    snap = {"t": a.t, "block": block, "cursors": {"nextLotID": nxt},
            "pool": {"funded": a.genesis_funding + sum(amount_of(r) for r in funded_rows), "paid": sum(p[2] for p in pays), "balance": int(cast(a, "balance", "--rpc-url", a.rpc, "--block", str(block), a.pool).split()[0])},
            "custody": {"deposited": deposited, "withdrawn": withdrawn, "slashed": slashed, "held": held, "balance": int(cast(a, "balance", "--rpc-url", a.rpc, "--block", str(block), a.custody).split()[0])},
            "payments": pays}
    if notes:
        snap["collectorNotes"] = notes
    with open(a.out, "a") as f:
        f.write(json.dumps(snap, sort_keys=True) + "\n")
    need(not notes, "; ".join(notes))
    return snap


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot")
    for k in ("rpc", "cast", "custody", "pool", "out"):
        s.add_argument("--" + k, required=True)
    s.add_argument("--from-block", type=int, required=True, help="the contracts' deploy block: genesis lots are in no event")
    s.add_argument("--genesis-funding", type=int, default=0, help="wei the pool held at block 0 as a genesis alloc (deployment.json rewardFunding); it emits no Funded log")
    s.add_argument("--t", type=int, required=True, help="seconds since the campaign start (strictly increasing across snapshots)")
    a = p.parse_args(argv)
    try:
        snap = snapshot(a)
    except CollectError as e:
        print(f"collect: {e}", file=sys.stderr)
        return 1
    print(json.dumps({"block": snap["block"], "payments": len(snap["payments"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
