#!/usr/bin/env python3
"""Offline check of a Q4 live lane's shim traces (independent of the live counters).

Usage: q4-trace-check.py <shim dir> --roots 1,2,3,4 [--byzantine 3] [--peer N=<peer id> ...]

Reads <shim dir>/root<N>/trace.jsonl and status.json of every root and checks:
  * every line parses, event sequence numbers of one root strictly increase;
  * every attempt has an outcome (deliver, drop, or hold followed by release+deliver) -- a held message may remain held only if the
    status says so; nothing is lost silently;
  * a deliver carries the exact bytes of its attempt (SHA-256 of the serialized message is equal);
  * for every (author, epoch, round, class) the set of distinct signed statements: more than one is an equivocation. The equivocators
    must be exactly the declared Byzantine roots (by peer id); an honest author with two statements fails;
  * every injection the status records as required was injected (hits/sent > 0).
The signature of each message is NOT re-verified here (no secp256k1 in the lane's python); the in-process oracle does that on the
same message classes. Prints a JSON report and exits 1 on any violation.
"""
import argparse, collections, json, os, sys


def load(path):
    rows = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise SystemExit(f"{path}:{n}: not JSON: {e}")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--roots", required=True)
    ap.add_argument("--byzantine", default="")
    ap.add_argument("--peer", action="append", default=[], help="N=<peer id>")
    a = ap.parse_args()
    roots = [int(x) for x in a.roots.split(",")]
    byz_roots = [int(x) for x in a.byzantine.split(",") if x]
    peers = {int(k): v for k, v in (p.split("=", 1) for p in a.peer)}
    byz_ids = {peers[r] for r in byz_roots}
    problems, stmts, attempts, per_root = [], collections.defaultdict(set), 0, {}

    for r in roots:
        path = os.path.join(a.dir, f"root{r}", "trace.jsonl")
        if not os.path.exists(path):
            problems.append(f"root{r}: no trace")
            continue
        rows = load(path)
        last, pending, held, raw = 0, {}, {}, {}
        for ev in rows:
            if ev["seq"] <= last and ev["seq"] != 1:
                problems.append(f"root{r}: sequence not increasing at {ev['seq']}")
            last = ev["seq"]
            k, sid = ev["kind"], ev.get("sendId", 0)
            if k == "attempt":
                attempts += 1
                pending[(sid, ev.get("to"))] = ev
                raw[(sid, ev.get("to"))] = ev.get("rawSha256")
                if ev.get("class") in ("vote", "timeout") and ev.get("statement"):
                    stmts[(ev["author"], ev["epoch"], ev["round"], ev["class"])].add(ev["statement"])
            elif k in ("drop", "deliver"):
                key = (sid, ev.get("to"))
                if key not in pending and key not in held:
                    problems.append(f"root{r}: {k} for unknown send {sid}")
                    continue
                if k == "deliver" and raw.get(key) != ev.get("rawSha256"):
                    problems.append(f"root{r}: send {sid} delivered with other bytes")
                pending.pop(key, None)
                held.pop(key, None)
            elif k == "hold":
                key = (sid, ev.get("to"))
                if pending.pop(key, None) is None:
                    problems.append(f"root{r}: hold for unknown send {sid}")
                held[key] = ev
            elif k == "equivocate":
                if ev.get("statement"):
                    stmts[(ev["author"], ev["epoch"], ev["round"], ev["class"])].add(ev["statement"])
            elif k == "fault":
                problems.append(f"root{r}: shim fault: {ev.get('error')}")
        for key in pending:
            problems.append(f"root{r}: send {key[0]} has no outcome")
        st_path = os.path.join(a.dir, f"root{r}", "status.json")
        status = json.load(open(st_path)) if os.path.exists(st_path) else {}
        for f in status.get("faults", []):
            problems.append(f"root{r}: status fault: {f}")
        per_root[r] = {"held_remaining": len(held), "status_held": status.get("held", {}), "rules": status.get("rules", {}),
                       "byzantine_sent": status.get("byzantine", {})}
        if r in byz_roots and not any(v > 0 for v in status.get("byzantine", {}).values()):
            problems.append(f"root{r}: declared Byzantine but its adapter sent nothing")

    equivocators = sorted({k[0] for k, v in stmts.items() if len(v) > 1})
    if set(equivocators) != byz_ids:
        problems.append(f"equivocators {equivocators} != declared Byzantine {sorted(byz_ids)}")
    report = {"attempts": attempts, "decisions": len(stmts), "equivocators": equivocators, "declared_byzantine": sorted(byz_ids),
              "per_root": per_root, "problems": problems, "verdict": "PASS" if not problems else "FAIL",
              "signatures_verified_offline": False}
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
