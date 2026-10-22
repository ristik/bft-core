#!/usr/bin/env python3
"""S4 (#57) assertions: the named checks of the live slashing exercise, each printing `PASS: s4: ...` or exiting non-zero with the reason.

  journals  the pair is in no single journal; the scan over both finds exactly one offence for (offender key, epoch, round); observer counters show no gap
  snapshot  a JSON snapshot of the chain state the effects are judged by (cast calls pinned to one block)
  calldata  the submitted transaction carries the original vote and seal signatures of the committing statement (decoded, compared with the harness' statements)
  effects   the certified EVM effects of admission and settlement against an independent arithmetic from the policy terms
  refusal   a control call is refused with the contract's own error

Chain reads go through `cast` (Foundry). Everything here is read-only; nothing signs or sends.
"""
import argparse
import json
import os
import subprocess
import sys

CAST = os.environ.get("P85_CAST") or "cast"
BPS = 10_000


def fail(msg):
    print("FAIL: s4: " + msg, file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print("PASS: s4: " + msg)


def run(*args):
    r = subprocess.run([CAST, *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("cast %s: %s" % (" ".join(args[:3]), (r.stderr or r.stdout).strip()[:300]))
    return r.stdout


def data_of(text):
    obj = json.loads(text)
    if isinstance(obj, dict) and "data" in obj:
        obj = obj["data"]
    return obj


def call(rpc, to, sig, *args, block=None):
    cmd = ["call", "--json", "--rpc-url", rpc]
    if block is not None:
        cmd += ["--block", str(block)]
    cmd += [to, sig, *[str(a) for a in args]]
    return data_of(run(*cmd))


def num(v):
    if isinstance(v, str):
        v = v.split(" ")[0]
        return int(v, 16) if v.startswith("0x") else int(v)
    return int(v)


# ---- pure rules (unit-tested) -------------------------------------------------------------------------------------------------------------------------

def expected_settlement(policy, lots, case_budget_total=None):
    """The debits, bounties and treasury credits StakeCustody.applyPenalty produces for the lots in ascending order.

    policy: dict(penaltyBps, lifetimeCapBps, bountyBps, bountyCap); lots: list of dict(initial, remaining, penalized, capBps) in the exposure's order.
    budget = floor(sum(initial) * penaltyBps / 10000); per lot debit = min(budget left, initial*capBps/10000 - penalized); the bounty is the increment of
    min(cumulative debit * bountyBps / 10000, bountyCap); the treasury gets the rest of the debit.
    """
    total = sum(l["initial"] for l in lots)
    budget = total * policy["penaltyBps"] // BPS if case_budget_total is None else case_budget_total
    left, cum, paid_bounty, rows = budget, 0, 0, []
    for l in lots:
        cap_room = l["initial"] * l["capBps"] // BPS - l["penalized"]
        debit = min(left, cap_room) if cap_room > 0 else 0
        bounty = treasury = 0
        if debit:
            cum += debit
            total_bounty = min(cum * policy["bountyBps"] // BPS, policy["bountyCap"])
            bounty = total_bounty - paid_bounty
            paid_bounty = total_bounty
            treasury = debit - bounty
        left -= debit
        rows.append({"debit": debit, "bounty": bounty, "treasury": treasury,
                     "remaining": l["remaining"] - debit, "penalized": l["penalized"] + debit})
    return {"budget": budget, "rows": rows, "debit": sum(r["debit"] for r in rows), "bounty": sum(r["bounty"] for r in rows),
            "treasury": sum(r["treasury"] for r in rows)}


def h(x):
    x = x.lower()
    return x[2:] if x.startswith("0x") else x


def offender_pairs(scan, key):
    """The offences of a scan (`ubft evidence scan`) which are the offender's: all of them when no key is given (the single-offender lane), else only those whose key is `key`
    (a lane with several offenders in the same journals: the second offence must not be confused with the first)."""
    pairs = scan["Pairs"] or []
    return [p for p in pairs if h(p["Key"]) == h(key)] if key else pairs


def parse_stats(line):
    """`... msg="evidence observer stats" kept=N rejected=N dropped=N failed=N healthy=true` -> dict."""
    out = {}
    for key in ("kept", "rejected", "dropped", "failed", "healthy"):
        i = line.find(" %s=" % key)
        if i < 0:
            raise ValueError("no %s in %r" % (key, line[:120]))
        out[key] = line[i + len(key) + 2:].split()[0]
    return {k: (v == "true" if k == "healthy" else int(v)) for k, v in out.items()}


# ---- journals -----------------------------------------------------------------------------------------------------------------------------------------

def cmd_journals(a):
    delivery = json.load(open(a.delivery))
    st = json.load(open(a.statements))
    sa, sb, both = (json.load(open(p)) for p in (a.scan_a, a.scan_b, a.scan_both))
    if offender_pairs(sa, a.offender_key) or offender_pairs(sb, a.offender_key):
        fail("a single observer's journal already holds the pair: a=%r b=%r" % (sa["Pairs"], sb["Pairs"]))
    ok("the pair is in no single journal (scan of each copy alone: 0 offences; slots %d and %d)" % (sa["Slots"], sb["Slots"]))
    pairs = offender_pairs(both, a.offender_key)
    if len(pairs) != 1:
        fail("the scan over both journals reports %d offences, wanted exactly one" % len(pairs))
    p = pairs[0]
    if p["Epoch"] != delivery["epoch"] or p["Round"] != delivery["round"] or p["Author"] != delivery["offenderNode"]:
        fail("the offence is %s epoch %s round %s, not the delivered %s epoch %s round %s" % (p["Author"], p["Epoch"], p["Round"], delivery["offenderNode"], delivery["epoch"], delivery["round"]))
    if a.offender_key and h(p["Key"]) != h(a.offender_key):
        fail("the offence key %s is not the offender's %s" % (p["Key"], a.offender_key))
    digests = {h(s["digest"]) for s in st["statements"]}
    if {h(p["DigestA"]), h(p["DigestB"])} != digests:
        fail("the offence's statement digests are not the two the harness signed")
    if both["Gaps"] != 0:
        fail("the merged export declares %d gaps" % both["Gaps"])
    ok("exactly one offence for (offender key, epoch %d, round %d) over both journals, the two harness statements, no export gap" % (p["Epoch"], p["Round"]))
    if not delivery["halfB"]["stale"]:
        fail("half B was not stale at its receiver")
    ok("the stale half is present: half B (round %d) reached root %d at root round %d" % (delivery["round"], delivery["halfB"]["root"], delivery["halfB"]["rootRoundAtSend"]))
    for path in a.stats:
        line = open(path).read().strip()
        if not line:
            fail("no observer stats line in %s" % path)
        s = parse_stats(line)
        if s["dropped"] or s["failed"] or not s["healthy"]:
            fail("observer counters show a gap in %s: %r" % (path, s))
        if s["kept"] < 1:
            fail("the observer kept nothing in %s" % path)
    ok("observer counters show no gap (dropped 0, failed 0, healthy) on both observer roots")


# ---- snapshot / effects -------------------------------------------------------------------------------------------------------------------------------

LOT_SIG = "lots(uint256)(uint64,uint64,uint128,uint128,uint128,uint8,uint16,uint32,uint64,uint64,uint64,uint64,uint64)"
LOT_FIELDS = ["id", "generation", "initial", "remaining", "penalized", "category", "capBps", "refCount", "holdRetirement", "timeFloor", "holdUntil", "evidenceUntil", "timeUntil"]
POLICY_SIG = "policyTerms(bytes32)(uint16,uint16,uint16,uint128,uint64,uint64,uint64,uint64,uint64,uint64)"
POLICY_FIELDS = ["penaltyBps", "lifetimeCapBps", "bountyBps", "bountyCap", "evidenceWindow", "suffixEvidenceWindow", "holdNormal", "holdSuffix", "holdRetirement", "timeFloor"]
RELEASE_SIG = "releaseState(uint256)(bool,uint32,bool,uint64,uint64,uint64,uint32)"
RELEASE_FIELDS = ["released", "references", "retirementImported", "roundUntil", "evidenceUntil", "timeUntil", "holds"]


def tuple_of(v, fields):
    if len(v) != len(fields):
        raise RuntimeError("expected %d values, got %d: %r" % (len(fields), len(v), v))
    return {f: (x if isinstance(x, bool) else num(x)) for f, x in zip(fields, v)}


def cmd_snapshot(a):
    rpc = a.rpc
    block = num(run("block-number", "--rpc-url", rpc).strip())
    c = lambda to, sig, *args: call(rpc, to, sig, *args, block=block)
    exp = c(a.custody, "exposures(bytes32)(bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32,address,bool,uint32)", a.exposure)
    assignment = exp[0]
    lots_ids = [num(x) for x in c(a.custody, "exposureLots(bytes32)(uint256[])", a.exposure)[0]]
    other = [int(x) for x in a.other_lot]
    snap = {"block": block, "exposure": a.exposure, "assignment": assignment, "id": num(exp[1]), "lots": {}, "reporter": a.reporter}
    snap["policy"] = tuple_of(c(a.custody, POLICY_SIG, assignment), POLICY_FIELDS)
    for lid in lots_ids + other:
        lot = tuple_of(c(a.custody, LOT_SIG, lid), LOT_FIELDS)
        rel = tuple_of(c(a.evidence, RELEASE_SIG, lid), RELEASE_FIELDS)
        lot["holds"] = rel["holds"]
        lot["retirementImported"] = rel["retirementImported"]
        lot["pendingHolds"] = num(c(a.evidence, "pendingHolds(uint256)(uint32)", lid)[0])
        snap["lots"][str(lid)] = lot
    snap["exposureLots"] = lots_ids
    snap["otherLots"] = other
    snap["creditReporter"] = num(c(a.custody, "credit(address)(uint256)", a.reporter)[0])
    treasury = c(a.custody, "treasury()(address)")[0]
    snap["treasury"] = treasury
    snap["creditTreasury"] = num(c(a.custody, "credit(address)(uint256)", treasury)[0])
    snap["totalCredits"] = num(c(a.custody, "totalCredits()(uint256)")[0])
    snap["excluded"] = c(a.evidence, "excluded(uint64)(bool)", snap["id"])[0] is True
    if a.offence:
        snap["offenceSeen"] = c(a.evidence, "offenceSeen(bytes32)(bool)", a.offence)[0] is True
    if a.case:
        info = c(a.evidence, "caseInfo(bytes32)(bytes32,bytes32,uint64,address,uint256,uint256,uint32,uint32)", a.case)
        snap["case"] = {"offenceID": info[0], "exposureID": info[1], "id": num(info[2]), "reporter": info[3], "budget": num(info[4]), "debited": num(info[5]),
                        "cursor": num(info[6]), "lotCount": num(info[7])}
        snap["caseDebited"] = num(c(a.custody, "caseDebited(bytes32)(uint256)", a.case)[0])
    json.dump(snap, open(a.out, "w"), indent=2)
    print("snapshot at block %d: %d exposure lots, %d other lots" % (block, len(lots_ids), len(other)))


# what an evidence case may change on a lot: its debit and its hold. A lot's reference count is not part of it: the lane's next election (opened after the
# recovery) references the honest lots in the same window.
CASE_FIELDS = ("initial", "remaining", "penalized", "category", "capBps", "holds", "pendingHolds", "retirementImported")


def core(lot):
    return {k: lot[k] for k in CASE_FIELDS}


def cmd_effects(a):
    before, admitted, settled = (json.load(open(p)) for p in (a.before, a.admitted, a.settled))
    ids = [str(i) for i in before["exposureLots"]]
    if not ids:
        fail("the offender's exposure holds no lot")
    pol = before["policy"]
    lots = [before["lots"][i] for i in ids]
    # before: no hold on anything, no credit for the reporter, no case
    for i in ids + [str(x) for x in before["otherLots"]]:
        if before["lots"][i]["holds"] != 0 or before["lots"][i]["pendingHolds"] != 0:
            fail("lot %s carries a hold before the evidence was submitted" % i)
    if before.get("offenceSeen"):
        fail("the offence was already seen before the submission")
    # admission
    if not admitted.get("offenceSeen"):
        fail("offenceSeen is false after the admission")
    ok("EvidenceAccepted: offenceSeen is true, the case exists (reporter %s)" % admitted["case"]["reporter"])
    exp = expected_settlement(pol, lots)
    if admitted["case"]["budget"] != exp["budget"]:
        fail("the case budget %d is not floor(sum(initial) * penaltyBps / 10000) = %d" % (admitted["case"]["budget"], exp["budget"]))
    ok("the case budget %d equals the independent arithmetic: floor(%d * %d / 10000)" % (exp["budget"], sum(l["initial"] for l in lots), pol["penaltyBps"]))
    for i in ids:
        lot_a = admitted["lots"][i]
        if lot_a["holds"] != 1 or lot_a["pendingHolds"] != 1:
            fail("lot %s has %d holds after admission, wanted exactly one" % (i, lot_a["holds"]))
        if lot_a["remaining"] != before["lots"][i]["remaining"] or lot_a["penalized"] != before["lots"][i]["penalized"]:
            fail("lot %s was debited at admission: only settlement debits" % i)
        if lot_a["retirementImported"] != before["lots"][i]["retirementImported"]:
            fail("lot %s: the retirement state changed at admission" % i)
    ok("holds installed on exactly the attributable lots %s (one each, no debit yet, retirement state unchanged: a missing Retirement is not an evidence hold)" % ",".join(ids))
    for i in [str(x) for x in before["otherLots"]]:
        if admitted["lots"][i]["holds"] != 0 or core(admitted["lots"][i]) != core(before["lots"][i]):
            fail("the unrelated lot %s changed at admission: %r -> %r" % (i, before["lots"][i], admitted["lots"][i]))
    ok("unrelated lots %s are untouched and hold-free (an unrelated withdrawal is not blocked by this case)" % ",".join(str(x) for x in before["otherLots"]))
    if not admitted.get("excluded"):
        fail("the offender's identity is not excluded from the election after admission")
    # settlement
    c = settled["case"]
    if c["cursor"] != c["lotCount"] or c["lotCount"] != len(ids):
        fail("settlement incomplete: cursor %d of %d" % (c["cursor"], c["lotCount"]))
    for n, i in enumerate(ids):
        want = exp["rows"][n]
        got = settled["lots"][i]
        if got["remaining"] != want["remaining"] or got["penalized"] != want["penalized"]:
            fail("lot %s: remaining/penalized %d/%d, independent arithmetic %d/%d" % (i, got["remaining"], got["penalized"], want["remaining"], want["penalized"]))
        if got["holds"] != 0 or got["pendingHolds"] != 0:
            fail("lot %s still holds %d after settlement" % (i, got["holds"]))
    ok("exact historical lot debit once: %s debited %s (remaining %s), holds removed" % (",".join(ids), ",".join(str(r["debit"]) for r in exp["rows"]), ",".join(str(r["remaining"]) for r in exp["rows"])))
    if c["debited"] != exp["debit"] or settled["caseDebited"] != exp["debit"]:
        fail("the case debited %d (custody %d), arithmetic %d" % (c["debited"], settled["caseDebited"], exp["debit"]))
    dr = settled["creditReporter"] - before["creditReporter"]
    dt = settled["creditTreasury"] - before["creditTreasury"]
    if dr != exp["bounty"] or dt != exp["treasury"]:
        fail("credits: reporter +%d treasury +%d, arithmetic bounty %d treasury %d" % (dr, dt, exp["bounty"], exp["treasury"]))
    if dr > pol["bountyCap"]:
        fail("the bounty %d exceeds the cap %d" % (dr, pol["bountyCap"]))
    ok("capped bounty to the reporter (+%d, cap %d) and treasury credit (+%d) equal the policy arithmetic; total credits +%d = the debit" % (dr, pol["bountyCap"], dt, settled["totalCredits"] - before["totalCredits"]))
    for i in [str(x) for x in before["otherLots"]]:
        if core(settled["lots"][i]) != core(before["lots"][i]):
            fail("the honest lot %s changed across the case: %r -> %r" % (i, before["lots"][i], settled["lots"][i]))
    ok("honest lots %s unchanged across the whole case" % ",".join(str(x) for x in before["otherLots"]))


def cmd_resolve(a):
    key = bytes.fromhex(h(a.key))
    want = h(run("keccak", "0x" + key.hex()).strip())
    for aid in a.assignment:
        asg = call(a.rpc, a.custody, "assignments(bytes32)(uint8,bytes32,uint64,uint64,uint64,uint64,bool,bool,uint64,bool,uint64,uint64,bytes32,bytes32,bytes32,uint32)", aid)
        if num(asg[2]) != a.epoch:
            continue
        for e in call(a.rpc, a.custody, "assignmentExposures(bytes32)(bytes32[])", aid)[0]:
            x = call(a.rpc, a.custody, "exposures(bytes32)(bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32,address,bool,uint32)", e)
            if h(x[5]) == want:
                lots = [num(v) for v in call(a.rpc, a.custody, "exposureLots(bytes32)(uint256[])", e)[0]]
                others = []
                for e2 in call(a.rpc, a.custody, "assignmentExposures(bytes32)(bytes32[])", aid)[0]:
                    if e2 != e:
                        others += [num(v) for v in call(a.rpc, a.custody, "exposureLots(bytes32)(uint256[])", e2)[0]]
                json.dump({"assignment": aid, "exposure": e, "entity": num(x[1]), "lots": lots, "otherLots": others, "firstRound": num(asg[5]), "rootEpoch": num(asg[2])}, open(a.out, "w"), indent=2)
                ok("the offender's exposure %s (entity %d, lots %s) is in assignment %s, root epoch %d" % (e[:12], num(x[1]), ",".join(map(str, lots)), aid[:12], a.epoch))
                return
    fail("no exposure of the offender's key among the candidate assignments for root epoch %d" % a.epoch)


# ---- calldata / refusal -------------------------------------------------------------------------------------------------------------------------------

def cmd_calldata(a):
    st = json.load(open(a.statements))
    tx = data_of(run("tx", a.tx, "--json", "--rpc-url", a.rpc))
    inp = tx["input"]
    sig = "submitEvidence((bytes32,uint8,bytes,uint64,uint64),(uint64,bytes32,uint64,bool,bytes32,uint64,uint64,uint64,bytes,bytes),(uint64,bytes32,uint64,bool,bytes32,uint64,uint64,uint64,bytes,bytes),bytes32)"
    dec = run("calldata-decode", sig, inp).splitlines()
    text = "\n".join(dec).lower()
    committing = [s for s in st["statements"] if s["committing"]][0]
    plain = [s for s in st["statements"] if not s["committing"]][0]
    for what, s in (("vote signature of the committing statement", committing["signature"]), ("seal signature of the committing statement", committing["sealSignature"]),
                    ("vote signature of the other statement", plain["signature"])):
        if s.lower() not in text.replace("0x", ""):
            fail("the submitted calldata does not carry the original %s" % what)
    for s in st["statements"]:
        if s["exec"].lower() not in text.replace("0x", ""):
            fail("the submitted calldata does not carry the executed state hash %s" % s["exec"][:16])
    if committing["commitHash"].lower() not in text.replace("0x", ""):
        fail("the committing statement's commit hash is not in the calldata")
    ok("the submitted calldata (tx %s) carries the original vote and seal signatures of the committing statement and both statements' fields, as signed" % a.tx[:12])


def cmd_refusal(a):
    want = run("sig", a.error).strip().lower()
    r = subprocess.run([CAST, "call", "--rpc-url", a.rpc, "--from", a.sender, a.to, "--data", open(a.data).read().strip()], capture_output=True, text=True)
    text = (r.stderr + r.stdout).lower()
    if r.returncode == 0:
        fail("the control call %s was accepted: wanted %s" % (os.path.basename(a.data), a.error))
    if want not in text:
        fail("the control call %s was refused, but not with %s (%s): %s" % (os.path.basename(a.data), a.error, want, text.strip()[:240]))
    ok("%s is refused with %s" % (os.path.basename(a.data).replace(".hex", ""), a.error))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("journals")
    j.add_argument("--delivery", required=True); j.add_argument("--statements", required=True)
    j.add_argument("--scan-a", required=True); j.add_argument("--scan-b", required=True); j.add_argument("--scan-both", required=True)
    j.add_argument("--stats", action="append", default=[]); j.add_argument("--offender-key", default="")
    j.set_defaults(fn=cmd_journals)
    s = sub.add_parser("snapshot")
    s.add_argument("--rpc", required=True); s.add_argument("--custody", required=True); s.add_argument("--evidence", required=True)
    s.add_argument("--exposure", required=True); s.add_argument("--reporter", required=True); s.add_argument("--other-lot", action="append", default=[])
    s.add_argument("--offence", default=""); s.add_argument("--case", default=""); s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_snapshot)
    e = sub.add_parser("effects")
    e.add_argument("--before", required=True); e.add_argument("--admitted", required=True); e.add_argument("--settled", required=True)
    e.set_defaults(fn=cmd_effects)
    rs = sub.add_parser("resolve")
    rs.add_argument("--rpc", required=True); rs.add_argument("--custody", required=True); rs.add_argument("--key", required=True)
    rs.add_argument("--epoch", type=int, required=True); rs.add_argument("--assignment", action="append", required=True); rs.add_argument("--out", required=True)
    rs.set_defaults(fn=cmd_resolve)
    c = sub.add_parser("calldata")
    c.add_argument("--rpc", required=True); c.add_argument("--tx", required=True); c.add_argument("--statements", required=True)
    c.set_defaults(fn=cmd_calldata)
    r = sub.add_parser("refusal")
    r.add_argument("--rpc", required=True); r.add_argument("--to", required=True); r.add_argument("--sender", required=True)
    r.add_argument("--data", required=True); r.add_argument("--error", required=True)
    r.set_defaults(fn=cmd_refusal)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
