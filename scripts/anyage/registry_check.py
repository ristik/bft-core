#!/usr/bin/env python3
"""Offline checks of the any-age final lane (briefs/b1-any-age-acceptance-matrix.md, checkpoint L2) on registry dumps.

A dump is the JSON written by anyage_registry_dump (scripts/lib/anyage-lib.sh) for one EVM block: the fixed B1 words and the words of every
installed entry. This file has no chain access; `--selftest` exercises it on synthetic dumps, including one negative per rule.

  registry_check.py ack BEFORE.json AFTER.json [--span N]   the acknowledgement block installed N entries atomically (default 2)
  registry_check.py shape DUMP.json                         the registry invariants of one block (format 2, g <= U = I when ready, intervals)
  registry_check.py --selftest
"""
import json
import sys

FIXED = ("format", "initialized", "genesisEpoch", "importedTipEpoch", "originReady", "originEpoch", "originRound")


class Refused(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise Refused(msg)


def entries(d):
    out = {}
    for e in d["entries"]:
        out[e["epoch"]] = e
    return out


def shape(d):
    need(d["format"] == 2 and d["initialized"] == 1, "format 2 and initialized")
    g, i = d["genesisEpoch"], d["importedTipEpoch"]
    need(i >= g, "importedTip >= genesisEpoch")
    es = entries(d)
    need(sorted(es) == list(range(g, i + 1)), "entries are exactly g..I, consecutive")
    for e in range(g, i + 1):
        x = es[e]
        need(x["present"] == 1 and 1 <= x["memberCount"] <= 16, f"epoch {e}: present with 1..16 members")
        if e < i:
            need(x["hasEnd"] == 1 and x["end"] == es[e + 1]["start"], f"epoch {e}: closed at its successor's start")
            need(x["start"] < es[e + 1]["start"], f"epoch {e}: starts strictly increase")
        else:
            need(x["hasEnd"] == 0, f"epoch {i} (the tip) is open")
    if d["originReady"] == 1:
        u, o = d["originEpoch"], d["originRound"]
        need(u == i, "ready: the usable epoch is the imported tip (no preload)")
        need(es[u]["start"] <= o, "ready: O >= start of the usable epoch")
    else:
        need(d["originEpoch"] == 0 and d["originRound"] == 0, "not ready: U = O = 0")


def ack(before, after, span):
    shape(before)
    shape(after)
    need(before["originReady"] == 1 and before["importedTipEpoch"] == before["originEpoch"], "before: ready with I = U")
    need(after["block"] == before["block"] + 1, "the Ack is the very next block after the frozen parent (no block between)")
    need(after["importedTipEpoch"] == before["importedTipEpoch"] + span, f"the one block installed exactly {span} entries")
    need(after["originEpoch"] == after["importedTipEpoch"], "after: I = U = E")
    need(after["originRound"] >= before["originRound"], "O does not move backwards")
    b, a = entries(before), entries(after)
    for e in b:
        x, y = dict(b[e]), dict(a[e])
        if e == before["importedTipEpoch"]:
            need(x["hasEnd"] == 0 and y["hasEnd"] == 1 and y["end"] == a[e + 1]["start"], "the old tip is closed once, at the first new start")
            x["hasEnd"], x["end"], y["hasEnd"], y["end"] = 0, 0, 0, 0
        need(x == y, f"epoch {e}: installed entry unchanged")
    for e in range(before["importedTipEpoch"] + 1, after["importedTipEpoch"] + 1):
        need(e not in b, f"epoch {e} was absent before")
    need(a[before["importedTipEpoch"] + 1]["start"] > before["originRound"], "the first successor starts above the old O (AppendClosesUsableOrigin)")


def entry(epoch, start, end=None, members=4):
    return {"epoch": epoch, "present": 1, "start": start, "hasEnd": 0 if end is None else 1, "end": 0 if end is None else end, "memberCount": members, "bodyID": "0x%064x" % epoch}


def dump(block, g, es, ready=1, o=0):
    i = es[-1]["epoch"]
    return {"block": block, "format": 2, "initialized": 1, "genesisEpoch": g, "importedTipEpoch": i, "originReady": ready,
            "originEpoch": i if ready else 0, "originRound": o if ready else 0, "entries": es}


def selftest():
    before = dump(10, 1, [entry(1, 7, 40), entry(2, 40, 90), entry(3, 90)], o=95)
    after = dump(11, 1, [entry(1, 7, 40), entry(2, 40, 90), entry(3, 90, 120), entry(4, 120, 150), entry(5, 150)], o=151)
    shape(before)
    ack(before, after, 2)

    def refuses(name, b, a, span=2):
        try:
            ack(b, a, span)
        except Refused:
            return
        raise SystemExit(f"selftest: {name} was not refused")

    import copy
    def mut(d, f):
        x = copy.deepcopy(d)
        f(x)
        return x
    refuses("a block between", before, mut(after, lambda x: x.update(block=12)))
    refuses("one entry only", before, dump(11, 1, [entry(1, 7, 40), entry(2, 40, 90), entry(3, 90, 120), entry(4, 120)], o=125))
    refuses("three entries", before, dump(11, 1, [entry(1, 7, 40), entry(2, 40, 90), entry(3, 90, 120), entry(4, 120, 150), entry(5, 150, 160), entry(6, 160)], o=165))
    refuses("usable epoch behind the tip", before, mut(after, lambda x: x.update(originEpoch=4)))
    refuses("O moves back", before, mut(after, lambda x: x.update(originRound=50)))
    refuses("old tip not closed", before, mut(after, lambda x: x["entries"][2].update(hasEnd=0, end=0)))
    refuses("old tip closed at the wrong round", before, mut(after, lambda x: x["entries"][2].update(end=119)))
    refuses("an installed entry changed", before, mut(after, lambda x: x["entries"][0].update(memberCount=3)))
    refuses("gap between the two new entries", before, mut(after, lambda x: x["entries"][3].update(start=121)))
    refuses("last entry closed", before, mut(after, lambda x: x["entries"][4].update(hasEnd=1, end=200)))
    refuses("successor starts at or below O", mut(before, lambda x: x.update(originRound=125)), after)
    for bad in (mut(after, lambda x: x.update(format=1)), mut(after, lambda x: x["entries"].pop(1)), mut(after, lambda x: x["entries"][1].update(memberCount=17))):
        try:
            shape(bad)
        except Refused:
            continue
        raise SystemExit("selftest: a malformed dump passed shape")
    print("registry_check selftest: ok")


def main(argv):
    if argv[:1] == ["--selftest"]:
        return selftest()
    try:
        if argv[:1] == ["shape"]:
            shape(json.load(open(argv[1])))
        elif argv[:1] == ["ack"]:
            span = int(argv[argv.index("--span") + 1]) if "--span" in argv else 2
            ack(json.load(open(argv[1])), json.load(open(argv[2])), span)
        else:
            sys.exit(__doc__)
    except Refused as e:
        print(f"FAIL: {e}")
        sys.exit(1)
    print("ok")


if __name__ == "__main__":
    main(sys.argv[1:])
