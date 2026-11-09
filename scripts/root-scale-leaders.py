#!/usr/bin/env python3
"""Where do the dead roots' leader slots fall? Reads one root-scale-lane evidence directory (a roots-N folder).

For the progress-control window (events.txt: "progress control: N roots stopped" .. the stall control) it takes root1's per-round
"next leader" lines (root1 runs at debug), marks a leader dead when its root is in the down set, and prints: rounds seen, share of dead
leaders, the longest run of consecutive dead leaders, local timeouts, and the leader sequence.
Usage: root-scale-leaders.py <evidenceDir>
"""
import csv, gzip, re, sys
from datetime import datetime

d = sys.argv[1]
short2idx = {r[2]: int(r[0]) for r in csv.reader(open(f"{d}/node-ids.csv"))}
down_order = [int(x) for x in open(f"{d}/down-set.txt").read().split(":", 1)[1].split()]
params = open(f"{d}/params.txt").read()
maxdown = int(re.search(r"progress with (\d+) down", params).group(1))
down = set(down_order[:maxdown])


def ts_ev(line):
    return datetime.strptime(line.split()[0].replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")


ev = [(ts_ev(l), l.split(" ", 1)[1].strip()) for l in open(f"{d}/events.txt") if l.strip()]
t0 = next(t for t, m in ev if m.startswith("progress control") and "stopped" in m)
t1 = next((t for t, m in ev if m.startswith("stall control")), ev[-1][0])

leaders, timeouts = [], []
pat = re.compile(r"^time=(\S+) .*next leader <peer.ID (16\*\w+)>.* round=(\d+)")
tpat = re.compile(r"^time=(\S+) .*local timeout.* round=(\d+)")
for l in gzip.open(f"{d}/root1-rounds.log.gz", "rt", errors="replace"):
    m = pat.match(l)
    if m:
        t = datetime.fromisoformat(m.group(1))
        if t0 <= t <= t1:
            leaders.append((t, int(m.group(3)) + 1, short2idx.get(m.group(2))))
        continue
    m = tpat.match(l)
    if m:
        t = datetime.fromisoformat(m.group(1))
        if t0 <= t <= t1:
            timeouts.append((t, int(m.group(2))))

print(f"window {t0:%T}..{t1:%T}Z, down roots {len(down)}: {sorted(down)}")
if not leaders:
    print("no leader lines in the window")
    sys.exit(0)
dead = [l[2] in down for l in leaders]
run = best = 0
for x in dead:
    run = run + 1 if x else 0
    best = max(best, run)
print(f"rounds with a known next leader: {len(leaders)}, dead leaders: {sum(dead)} ({100*sum(dead)/len(dead):.0f}%), longest run of consecutive dead leaders: {best}")
print(f"local timeouts of root1 in the window: {len(timeouts)}")
print("leader sequence (D = dead, . = live): " + "".join("D" if x else "." for x in dead))
