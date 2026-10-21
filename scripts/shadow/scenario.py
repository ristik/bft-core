#!/usr/bin/env python3
"""The shadow campaign's eligibility scenario (scripts/shadow/campaign.json): a deterministic schedule, from the checked-in seed, of the chain-side changes to two
spare identities that make the sampled election answer change: an unchanged committee, a valid changed candidate (spare A), a registered-and-bonded but not yet
admitted identity (still unchanged), a candidate beyond the weight bound (spare B admitted with more units than the bound allows: a refusal), and the retirements
that walk back through changed to unchanged. `plan` prints the events as JSON lines; the shell driver executes them at their offsets from the first sample.

    scenario.py plan campaign.json [--seed N]
"""
import argparse
import json
import random
import sys


def plan(campaign, seed=None):
    c = campaign["scenario"]
    rng = random.Random(campaign["seed"] if seed is None else seed)
    pick = lambda w: rng.randrange(w[0], w[1] + 1)  # noqa: E731
    a, b = c["spareA"], c["spareB"]
    a_on, a_off = pick(a["onboardWindow"]), pick(a["retireWindow"])
    b_reg, b_adm_delay, b_off = pick(b["registerWindow"]), pick(b["admitDelayWindow"]), pick(b["retireWindow"])
    units_b = rng.choice(b["unitsChoices"])
    events = [
        {"at": a_on, "op": "register-bond-admit", "spare": 1, "units": a["units"]},
        {"at": b_reg, "op": "register-bond", "spare": 2, "units": units_b},
        {"at": b_reg + b_adm_delay, "op": "admit", "spare": 2},
        {"at": b_off, "op": "retire", "spare": 2},
        {"at": a_off, "op": "retire", "spare": 1},
    ]
    events.sort(key=lambda e: e["at"])
    check(campaign, events)
    return events


def check(campaign, events):
    """The schedule's own invariants: ordered with room between events, inside the declared interval with a quiet tail, funded by the joiner account."""
    span, cadence = campaign["intervalSeconds"], campaign["cadenceSeconds"]
    ats = [e["at"] for e in events]
    assert ats == sorted(ats), "events are not ordered"
    assert all(y - x >= 2 * cadence for x, y in zip(ats, ats[1:])), "two events closer than two samples"
    assert ats[0] >= 5 * cadence and ats[-1] <= span - 8 * cadence, "no unchanged lead-in or no quiet tail"
    for s in (1, 2):
        ops = [e["op"] for e in events if e["spare"] == s]
        assert ops[0] in ("register-bond-admit", "register-bond") and ops[-1] == "retire", f"spare {s}'s lifecycle: {ops}"
    # the wei the joiner account is funded with (p85-lib.sh): 3 + 10 units; each spare costs its bond plus two units of gas
    assert sum(e.get("units", 0) + 2 for e in events if e["op"].startswith("register")) <= 13, "the spares are not covered by the joiner account's funding"


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["plan"])
    p.add_argument("campaign")
    p.add_argument("--seed", type=int)
    a = p.parse_args(argv)
    with open(a.campaign) as fh:
        campaign = json.load(fh)
    for e in plan(campaign, a.seed):
        print(json.dumps(e, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
