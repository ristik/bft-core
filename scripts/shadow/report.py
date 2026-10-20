"""The report contract (design section 5) for the shadow comparison: coverage accounting and the PASS / INCOMPLETE / FAIL rule. Pure functions over the
observation rows, so the rule itself is self-tested."""
import json
from collections import Counter

STATUS_PASS, STATUS_INCOMPLETE, STATUS_FAIL = "PASS", "INCOMPLETE", "FAIL"
REFUSAL_REASONS = ("refusal:Cardinality", "refusal:MembershipChurn", "refusal:WeightChurn", "refusal:ReferenceCapacity", "refusal:ReservationRefused")
DEFAULT_RULES = {"minDue": 24, "minEach": 2, "minDistinctInputs": 2}


def coverage(rows, scheduled, rules=None):
    """rows: observation dicts with 'verdict' in MATCH / MISMATCH / GAP, 'case', 'inputDigest'. scheduled: the number of samples the declared interval schedules."""
    rules = dict(DEFAULT_RULES, **(rules or {}))
    verdicts = Counter(r["verdict"] for r in rows)
    due = [r for r in rows if r["verdict"] in ("MATCH", "MISMATCH") and r["case"] not in ("NotDue", "Disabled")]
    cases = Counter(r["case"] for r in due)
    refusals = sum(n for c, n in cases.items() if c in REFUSAL_REASONS)
    over_bound = cases["refusal:MembershipChurn"] + cases["refusal:WeightChurn"]
    reasons = []
    mismatches = verdicts["MISMATCH"]
    if mismatches:
        reasons.append((STATUS_FAIL, f"{mismatches} observation(s) disagree"))
    accounted = len(rows)
    if accounted != scheduled:
        reasons.append((STATUS_INCOMPLETE, f"{accounted} of {scheduled} scheduled samples are accounted for"))
    if verdicts["GAP"]:
        reasons.append((STATUS_INCOMPLETE, f"{verdicts['GAP']} sample(s) are coverage gaps (certified state could not be fetched or simulated)"))
    if len(due) < rules["minDue"]:
        reasons.append((STATUS_INCOMPLETE, f"{len(due)} due comparisons, {rules['minDue']} required"))
    for label, n in (("a valid changed candidate", cases["changed"]), ("an unchanged candidate", cases["unchanged"]), ("a deliberate refusal", refusals)):
        if n < rules["minEach"]:
            reasons.append((STATUS_INCOMPLETE, f"{n} observed case(s) of {label}, {rules['minEach']} required"))
    if over_bound < 1:
        reasons.append((STATUS_INCOMPLETE, "no refusal beyond the churn bound (over-bound) was observed"))
    if len({r["inputDigest"] for r in due}) < rules["minDistinctInputs"]:
        reasons.append((STATUS_INCOMPLETE, "the due comparisons repeat one input: a vacuous answer, not coverage"))
    status = STATUS_FAIL if any(s == STATUS_FAIL for s, _ in reasons) else STATUS_INCOMPLETE if reasons else STATUS_PASS
    return {"status": status, "reasons": [m for _, m in reasons], "scheduled": scheduled, "accounted": accounted, "verdicts": dict(verdicts), "dueComparisons": len(due),
            "cases": dict(cases), "refusals": refusals, "overBound": over_bound, "idle": {"NotDue": sum(1 for r in rows if r["case"] == "NotDue"),
                                                                                       "Disabled": sum(1 for r in rows if r["case"] == "Disabled")},
            "rules": rules}


def write_markdown(path, manifest, cov, first_failure=None):
    lines = [f"# X4 shadow comparison: {cov['status']}", "",
             "The election ran on an **anvil fork** of the pinned certified state, not on ureth: no enshrined hook or precompiles. This is a comparison of the contract's "
             "output with an independent reference at identical inputs, not consensus evidence.", "",
             f"- chain id {manifest.get('chainId')}; first pinned block {manifest.get('firstBlock')}; last pinned block {manifest.get('lastBlock')}",
             f"- tools: {json.dumps(manifest.get('tools', {}))}",
             f"- scheduled {cov['scheduled']} samples, accounted {cov['accounted']}: {json.dumps(cov['verdicts'])}",
             f"- due comparisons {cov['dueComparisons']}; cases {json.dumps(cov['cases'])}; idle {json.dumps(cov['idle'])}"]
    if cov["reasons"]:
        lines += ["", "Why not PASS:"] + [f"- {m}" for m in cov["reasons"]]
    if first_failure:
        lines += ["", "First mismatch:", "```", json.dumps(first_failure, indent=1), "```"]
    open(path, "w").write("\n".join(lines) + "\n")
