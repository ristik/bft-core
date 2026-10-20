#!/usr/bin/env python3
"""U3b: judge the restarted aggregator's trust-base repair from its log lines (jsonl, in order). Usage: utb-repair-check.py IN OUT

The entries can arrive over two overlapping paths: a catch-up from the roots and the responses' piggybacked updates. A catch-up's "added" counts every append it
makes, including an entry a response already added, so the counts alone prove nothing about where the history came from. The repair from the roots is proved by a
catch-up that finished without error and RAISED the tip above every tip seen before it (the held tip at the start, an earlier catch-up, an earlier response)."""
import json, sys

lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
st = [i for i, l in enumerate(lines) if l["msg"] == "trust-base catch-up started"]
if not st: raise SystemExit("no catch-up started after the restart")
first = lines[st[0]]["from"]
if any(l["msg"] == "dropping an invalid trust-base update" for l in lines): raise SystemExit("the aggregator dropped an invalid trust-base update")
pages = [l for l in lines[st[0]:] if l["msg"] == "trust-base catch-up page" and l.get("status") == "OK" and l.get("entries", 0) >= 1]
if not pages: raise SystemExit("no OK catch-up page with entries from a root after the catch-up started")

seen = first - 1  # the tip held at the restart
raising, tip, by_catchup, by_response = [], 0, 0, 0
for l in lines:
    m = l["msg"]
    if m == "trust-base catch-up finished" and "error" not in l:
        by_catchup += l.get("added", 0)
        tip = max(tip, l.get("tip", 0))
        if l.get("added", 0) >= 1 and l.get("tip", 0) > seen: raising.append(l)
        seen = max(seen, l.get("tip", 0))
    elif m == "trust-base entries appended from certification response":
        by_response += l.get("added", 0)
        seen = max(seen, l.get("tip", 0))
if not raising: raise SystemExit("no successful catch-up raised the tip above what was held before it (the roots did not supply the repair)")
if tip < 3: raise SystemExit("the catch-up did not reach epoch 3 (tip %s)" % tip)
missing = tip - (first - 1)
if by_catchup + by_response < missing: raise SystemExit("epochs %s..%s were not all added: by catch-up %d, by response %d" % (first, tip, by_catchup, by_response))

r = raising[0]
out = ["peer repair: started from epoch %s, %d OK page(s), peers %s; the catch-up that raised the tip from the roots: added %s, tip %s (%s); in total by catch-up %d, by certification response %d (the counts may overlap; final tip %s)"
       % (first, len(pages), sorted({p["peer"] for p in pages}), r.get("added"), r.get("tip"), r.get("time", "?"), by_catchup, by_response, tip)]
out += [json.dumps(l) for l in lines]
open(sys.argv[2], "w").write("\n".join(out) + "\n")
