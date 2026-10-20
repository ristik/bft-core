"""Field-by-field comparison of the contract's output with the independent reference's, for one observation, and its classification for the coverage rules."""

# Every compared leaf. A list-valued field compares its length and then each element's leaves; a missing field compares as None on both sides.
SCALARS = ("outcome", "reason", "resultID", "attempt", "progress", "ucTime", "origin", "predecessor", "policyID", "assignmentID", "snapshotDigest",
           "attemptCursorAfter", "openResultAfter")
FROZEN_KEYS = ("id", "generation", "weight", "raw", "bindingHash")
MEMBER_KEYS = ("id", "rootKeyHash", "evmKeyHash", "payee", "weight", "rawWeight", "lots")
PUBLICATION_KEYS = ("incumbent", "incumbentExposureDigest", "incumbentKeyDigest", "policyDigest", "contractsDigest", "kCommit", "snapshotDigest", "assignmentID",
                    "attempt")
RESERVATION_KEYS = ("state", "lineage", "rootEpoch", "evmEpoch", "policyID")


def leaves(out):
    """The ordered (path, value) pairs of an output, over exactly the compared fields."""
    rows = [(k, out.get(k)) for k in SCALARS]
    for name, keys in (("frozen", FROZEN_KEYS), ("members", MEMBER_KEYS)):
        items = out.get(name) or []
        rows.append((f"{name}.length", len(items)))
        for i, it in enumerate(items):
            rows += [(f"{name}[{i}].{k}", it.get(k)) for k in keys]
    for name, keys in (("publication", PUBLICATION_KEYS), ("reservation", RESERVATION_KEYS)):
        obj = out.get(name)
        rows.append((f"{name}.present", obj is not None))
        if obj is not None:
            rows += [(f"{name}.{k}", obj.get(k)) for k in keys]
    return rows


def paths():
    """The compared fields that do not depend on list lengths (for the injected-divergence self-test)."""
    return [k for k in SCALARS] + [f"frozen[].{k}" for k in FROZEN_KEYS] + [f"members[].{k}" for k in MEMBER_KEYS] + [f"publication.{k}" for k in PUBLICATION_KEYS] + \
           [f"reservation.{k}" for k in RESERVATION_KEYS] + ["frozen.length", "members.length", "publication.present", "reservation.present"]


def compare(contract, reference):
    """Returns the list of mismatches {field, contract, reference}; empty means the outputs agree on every compared field."""
    a, b = dict(leaves(contract)), dict(leaves(reference))
    order = [p for p, _ in leaves(contract)] + [p for p, _ in leaves(reference) if p not in a]
    return [{"field": p, "contract": a.get(p), "reference": b.get(p)} for p in order if a.get(p) != b.get(p)]


def case_of(contract, incumbent_members):
    """The coverage class of a due observation: 'changed' (a Reserved candidate that differs from the incumbent committee), 'unchanged' (a Reserved candidate equal to
    it in ids, bindings and weights), 'refusal:<reason>' (an ordered NoCandidate), or the idle outcome ('NotDue', 'Disabled')."""
    if contract["outcome"] in ("NotDue", "Disabled"):
        return contract["outcome"]
    if contract["outcome"] == "NoCandidateRecorded":
        return "refusal:" + contract["reason"]
    chosen = [(m["id"], m["rootKeyHash"], m["evmKeyHash"], m["weight"]) for m in contract["members"]]
    inc = [(m["id"], "0x" + m["rootKeyHash"].hex(), "0x" + m["evmKeyHash"].hex(), m["weight"]) for m in incumbent_members]
    return "unchanged" if chosen == inc else "changed"
