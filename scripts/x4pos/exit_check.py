#!/usr/bin/env python3
"""X4 #58 step B3b: the exit assertions of the PoS campaign, read from custody with `cast` (design: briefs/x4-retirement-control-design.md; arch ruling (c): the proposer
builds the Retirement control, so an exit is `requestRetirement` on chain, then waiting for `RetirementImported`, then maturity, then the claim).

    exit_check.py state    --rpc URL --cast CAST --custody ADDR --id N [--generation G]
    exit_check.py refusal  --rpc URL --cast CAST --custody ADDR --id N [--generation G] [--from ADDR]
    exit_check.py matured  --rpc URL --cast CAST --custody ADDR --id N --before STATE.json
    exit_check.py claimed  --rpc URL --cast CAST --custody ADDR --id N --recipient ADDR --recipient-before WEI --credit WEI
    exit_check.py terms    --rpc URL --cast CAST --custody ADDR --id N [--generation G] [--sender ADDR]

`state` prints one JSON object (position, retirement info, live exposures, every lot of the generation, the withdrawal credit). `refusal` asks `mature` whether it would
succeed NOW (eth_call) and names the custody error it reverts with: a missing Retirement (`RetirementNotImported`) is NOT an evidence hold (`EvidenceHoldPending`) and
not a time/round gate; the lane must be able to tell them apart. Exit status 0 = a refusal that is one of the lawful early reasons was observed; `--allow-success`
makes a mature-now answer exit 0 as well. `matured` and `claimed` assert exact amounts. Every check is an explicit raise (python -O safe).

`terms` (#1297/#1298) lists the closed terms that still wait for their report anchors: custody refuses `mature` with `TermAnchorPending` while any lot of
the exit has a closed term whose anchors were not captured. Anchoring is permissionless (`custody.anchorTerm(assignmentID, hRecordID, terminalRoot)`, no
keeper or relay): the exiting party's tooling sends it. The words come from the term's authenticated Closure record (`roots.recordAt`, kind 4), and each term
is previewed with an eth_call: `ready` terms can be anchored now, the others name the refusal (`SuccessorNotInstalled`: the successor root epoch is not
installed yet). It prints nothing to do when no lot of the exit waits (`lotUnanchoredTerms` is zero, or the contracts predate anchoring). Read-only;
a term anchored meanwhile drops out of the list, so sending what it lists is idempotent.
"""
import argparse
import json
import re
import subprocess
import sys

# TermAnchorPending is lawful too: a closed term of the exit waits for its permissionless anchorTerm (`terms` lists it), not a missing record
LAWFUL_EARLY = ("RoundGateNotMet", "TimeGateNotMet", "EvidenceGateNotMet", "EvidenceHoldPending", "TermAnchorPending")
TERM_ERRORS = ("TermNotPending", "SuccessorNotInstalled", "ClosureOpeningMismatch", "NotInitialized")
CLOSURE_KIND = 4   # RecordKind.Closure; its data is abi.encode(assignmentID, hRound, hRecordID, terminalRoot, exposureDigest, keyHistoryDigest)
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


def call(a, sig, *args, frm=None, block=None, to=None):
    opts = ["--rpc-url", a.rpc] + (["--from", frm] if frm else []) + (["--block", str(block)] if block is not None else [])
    out = cast(a, "call", *opts, to or a.custody, sig, *map(str, args))
    if out.returncode:
        raise ExitError(f"cast call {sig} failed: {out.stderr.strip()}")
    return [l.split()[0] for l in out.stdout.strip().splitlines() if l.strip()]


def revert_name(a, text, names):
    """The custody error a revert names: by name in cast's text, else by its selector."""
    by_selector = {selector(a, n): n for n in names}
    m = re.search(r"0x[0-9a-fA-F]{8}", text)
    return next((n for n in names if n in text), None) or (by_selector.get(m.group(0).lower()) if m else None)


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
    name = revert_name(a, text, ERRORS)
    need(name is not None, f"mature reverted with an error this check does not know: {text.strip()[:300]}")
    return {"outcome": "refused", "reason": name, "lawfulEarly": name in LAWFUL_EARLY}


def closures(a, roots):
    """{assignmentID: (hRecordID, terminalRoot)} from every authenticated Closure record (the first one of a term; a repeat is identical)."""
    out = {}
    for i in range(int(call(a, "recordCount()(uint64)", to=roots)[0])):
        raw = cast(a, "call", "--rpc-url", a.rpc, roots, "recordAt(uint64)((uint64,bytes32,bytes32,uint8,uint64,uint64,bytes))", str(i))
        need(raw.returncode == 0, f"recordAt({i}) failed: {raw.stderr.strip()}")
        fields = [f.strip().split()[0] for f in raw.stdout.strip().strip("()").split(",")]
        need(len(fields) == 7, f"recordAt({i}) is not a root record: {raw.stdout.strip()[:200]}")
        if int(fields[3]) != CLOSURE_KIND:
            continue
        data = fields[6][2:]
        need(len(data) == 6 * 64, f"record {i} is a Closure whose data is not six words")
        words = ["0x" + data[k * 64:(k + 1) * 64] for k in range(6)]
        out.setdefault(words[0].lower(), (words[2].lower(), words[3].lower()))
    return out


def pending_terms(a):
    """The closed terms that still wait for their report anchors, each previewed: {"supported", "blockedLots", "terms": [...]}."""
    st = read_state(a)
    blocked = []
    for lot in st["lots"]:
        if lot["category"] == 4:
            continue
        raw = cast(a, "call", "--rpc-url", a.rpc, a.custody, "lotUnanchoredTerms(uint256)(uint32)", str(lot["id"]))
        if raw.returncode:   # contracts that predate #1297 have no anchors: nothing to do
            return {"supported": False, "blockedLots": [], "terms": []}
        if int(raw.stdout.split()[0]):
            blocked.append(lot["id"])
    out = {"supported": True, "blockedLots": blocked, "terms": []}
    if not blocked:
        return out
    roots = call(a, "roots()(address)")[0]
    sender = a.sender or st["withdrawal"]
    for aid, (h, t) in sorted(closures(a, roots).items()):
        if call(a, "termAnchors(bytes32)(bytes32,bytes32,uint64,uint64,bool)", aid)[4] == "true":
            continue
        if call(a, "assignments(bytes32)(uint8,bytes32,uint64,uint64,uint64,uint64,bool,bool,uint64,bool,uint64,uint64,bytes32,bytes32,bytes32,uint32)", aid)[9] != "true":
            continue   # a Closure custody has not applied yet (RecordsPending is another refusal)
        pre = cast(a, "call", "--rpc-url", a.rpc, "--from", sender, a.custody, "anchorTerm(bytes32,bytes32,bytes32)", aid, h, t)
        term = {"assignmentID": aid, "hRecordID": h, "terminalRoot": t, "ready": pre.returncode == 0, "reason": None}
        if pre.returncode:
            term["reason"] = revert_name(a, pre.stderr + pre.stdout, TERM_ERRORS)
            need(term["reason"] is not None, f"anchorTerm({aid}) reverted with an error this check does not know: {(pre.stderr + pre.stdout).strip()[:300]}")
            if term["reason"] == "TermNotPending":
                continue   # anchored meanwhile
        out["terms"].append(term)
    return out


def cmd_terms(a):
    print(json.dumps(pending_terms(a), sort_keys=True))


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
    for name, fn in (("state", cmd_state), ("refusal", cmd_refusal), ("matured", cmd_matured), ("claimed", cmd_claimed), ("terms", cmd_terms)):
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        for k in ("rpc", "cast", "custody"):
            s.add_argument("--" + k, required=True)
        s.add_argument("--id", type=int, required=True)
        s.add_argument("--generation", type=int)
        if name in ("refusal", "terms"):
            s.add_argument("--sender")
        if name == "refusal":
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
