#!/usr/bin/env python3
"""X4 #58 step B3b: the exit assertions of the PoS campaign, read from custody with `cast` (design: briefs/x4-retirement-control-design.md; arch ruling (c): the proposer
builds the Retirement control, so an exit is `requestRetirement` on chain, then waiting for `RetirementImported`, then maturity, then the claim).

    exit_check.py state    --rpc URL --cast CAST --custody ADDR --id N [--generation G]
    exit_check.py refusal  --rpc URL --cast CAST --custody ADDR --id N [--generation G] [--from ADDR]
    exit_check.py matured  --rpc URL --cast CAST --custody ADDR --id N --before STATE.json
    exit_check.py claimed  --rpc URL --cast CAST --custody ADDR --id N --recipient ADDR --recipient-before WEI --credit WEI

`state` prints one JSON object (position, retirement info, live exposures, every lot of the generation, the withdrawal credit). `refusal` asks `mature` whether it would
succeed NOW (eth_call) and names the custody error it reverts with: a missing Retirement (`RetirementNotImported`) is NOT an evidence hold (`EvidenceHoldPending`) and
not a time/round gate; the lane must be able to tell them apart. Exit status 0 = a refusal that is one of the lawful early reasons was observed; `--allow-success`
makes a mature-now answer exit 0 as well. `matured` and `claimed` assert exact amounts. Every check is an explicit raise (python -O safe).
"""
import argparse
import json
import re
import subprocess
import sys

LAWFUL_EARLY = ("RoundGateNotMet", "TimeGateNotMet", "EvidenceGateNotMet", "EvidenceHoldPending")
ERRORS = LAWFUL_EARLY + ("RetirementNotImported", "LotStillReferenced", "RecordsPending", "LotAlreadyReleased", "LotUnknown", "BatchTooLarge", "EmptyBatch")


CAST_TIMEOUT = 60   # a wedged execution client must be an error the lane can log, not a wait that never ends


class ExitError(Exception):
    pass


def need(cond, message):
    if not cond:
        raise ExitError(message)


def cast(a, *args):
    try:
        return subprocess.run([a.cast, *args], text=True, capture_output=True, timeout=CAST_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ExitError(f"cast {args[0]} timed out after {CAST_TIMEOUT} s (the execution client does not answer)")


def call(a, sig, *args, frm=None, block=None):
    opts = ["--rpc-url", a.rpc] + (["--from", frm] if frm else []) + (["--block", str(block)] if block is not None else [])
    out = cast(a, "call", *opts, a.custody, sig, *map(str, args))
    if out.returncode:
        raise ExitError(f"cast call {sig} failed: {out.stderr.strip()}")
    return [l.split()[0] for l in out.stdout.strip().splitlines() if l.strip()]


def selector(a, name):
    out = cast(a, "sig", f"{name}()")
    need(out.returncode == 0, f"cast sig {name} failed: {out.stderr.strip()}")
    return out.stdout.strip().lower()


def lots_of(a, ident, generation):
    raw = cast(a, "call", "--rpc-url", a.rpc, a.custody, "generationLots(uint64,uint64)(uint256[])", str(ident), str(generation))
    need(raw.returncode == 0, f"generationLots failed: {raw.stderr.strip()}")
    return [int(x) for x in re.findall(r"\d+", raw.stdout.split("[", 1)[-1])] if "[" in raw.stdout else []


def read_state(a):
    pos = call(a, "positions(uint64)(address,address,bytes32,bytes32,uint64,uint64,uint32,uint32,bool)", a.id)
    owner, withdrawal, generation, requested = pos[0], pos[1], int(pos[4]), pos[8] == "true"
    gen = generation if a.generation is None else a.generation
    info = call(a, "retirements(uint64,uint64)(bool,uint64,uint64)", a.id, gen)
    lots = []
    for lot in lots_of(a, a.id, gen):
        l = call(a, "lots(uint256)(uint64,uint64,uint128,uint128,uint128,uint8,uint16,uint32,uint64,uint64,uint64,uint64,uint64)", lot)
        lots.append({"id": lot, "initial": int(l[2]), "remaining": int(l[3]), "penalized": int(l[4]), "category": int(l[5]), "refCount": int(l[7]),
                     "holdUntil": int(l[10]), "evidenceUntil": int(l[11]), "timeUntil": int(l[12])})
    return {"id": a.id, "generation": gen, "currentGeneration": generation, "owner": owner, "withdrawal": withdrawal, "retirementRequested": requested,
            "imported": info[0] == "true", "pRet": int(info[1]), "tRet": int(info[2]), "liveExposures": int(call(a, "liveExposures(uint64,uint64)(uint32)", a.id, gen)[0]),
            "lots": lots, "credit": int(call(a, "credit(address)(uint256)", withdrawal)[0])}


def refusal(a):
    st = read_state(a)
    need(st["lots"], f"identity {a.id} generation {st['generation']} has no lots")
    ids = "[" + ",".join(str(l["id"]) for l in st["lots"]) + "]"
    out = cast(a, "call", "--rpc-url", a.rpc, "--from", a.sender or st["withdrawal"], a.custody, "mature(uint256[])", ids)
    if out.returncode == 0:
        return {"outcome": "mature-now", "reason": None}
    text = out.stderr + out.stdout
    by_selector = {selector(a, n): n for n in ERRORS}
    m = re.search(r"0x[0-9a-fA-F]{8}", text)
    name = next((n for n in ERRORS if n in text), None) or (by_selector.get(m.group(0).lower()) if m else None)
    need(name is not None, f"mature reverted with an error this check does not know: {text.strip()[:300]}")
    return {"outcome": "refused", "reason": name, "lawfulEarly": name in LAWFUL_EARLY}


def cmd_state(a):
    print(json.dumps(read_state(a), sort_keys=True))


def cmd_refusal(a):
    r = refusal(a)
    print(json.dumps(r, sort_keys=True))
    if r["outcome"] == "mature-now":
        need(a.allow_success, "mature would succeed now (the exit has matured)")
    else:
        need(r["lawfulEarly"], f"mature is refused for {r['reason']}, which is not a lawful early-claim reason (a missing Retirement is not an evidence hold or a gate)")


def cmd_matured(a):
    before = json.load(open(a.before))
    now = read_state(a)
    expect = sum(l["remaining"] for l in before["lots"])
    need(all(l["category"] == 4 and l["remaining"] == 0 for l in now["lots"]), "a lot of the generation is not released with remaining 0")
    need(now["credit"] - before["credit"] == expect, f"the withdrawal credit grew by {now['credit'] - before['credit']}, the lots' remaining principal was {expect}")
    print(json.dumps({"creditDelta": expect, "lots": len(now["lots"])}))


def cmd_claimed(a):
    now = read_state(a)
    out = cast(a, "balance", "--rpc-url", a.rpc, a.recipient)
    need(out.returncode == 0, f"cast balance failed: {out.stderr.strip()}")
    bal = int(out.stdout.strip())
    need(bal - a.recipient_before == a.credit, f"the recipient received {bal - a.recipient_before}, the credit was {a.credit}")
    need(now["credit"] == 0, f"the withdrawal address still holds credit {now['credit']}")
    print(json.dumps({"received": a.credit}))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("state", cmd_state), ("refusal", cmd_refusal), ("matured", cmd_matured), ("claimed", cmd_claimed)):
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        for k in ("rpc", "cast", "custody"):
            s.add_argument("--" + k, required=True)
        s.add_argument("--id", type=int, required=True)
        s.add_argument("--generation", type=int)
        if name == "refusal":
            s.add_argument("--sender")
            s.add_argument("--allow-success", action="store_true")
        if name == "matured":
            s.add_argument("--before", required=True)
        if name == "claimed":
            s.add_argument("--recipient", required=True)
            s.add_argument("--recipient-before", type=int, required=True)
            s.add_argument("--credit", type=int, required=True)
    a = p.parse_args(argv)
    try:
        a.fn(a)
    except ExitError as e:
        print(f"EXIT-CHECK FAILED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
