"""The independent reference of the X4 shadow comparison (T8/X4 #58, briefs/x4-shadow-campaign-design.md section 2).

It derives what ElectionPolicy.elect must produce from RAW inputs only (custody positions, lots, delegations, key registrations, the election's
parameters and cursors, the registry clock, the incumbent assignment), using its own implementation of the rules: eligibility, weights, the snapshot
digest, the ranking and greedy selection with the continuity predicates, the quantization, the reservation preconditions and every commitment word. It
calls neither the contracts nor ureth nor `cast`. It is validated against the xrepo-shared vectors continuity/testdata/{selection,continuity}-vectors.json
(the Go reference's output, replayed by the Solidity port) by test_shadow.py, with a canary that a mutated vector fails.

The selection part ports the SIMPLE form (every trial builds the whole committee), the same algorithm as the contracts' test reference NaiveSelection.
"""
from abi import encode_args
from keccak import keccak256

WEIGHT_CAP_B = 65536
U64 = (1 << 64) - 1
FAIL_MEMBERSHIP, FAIL_TURNOVER, FAIL_DISTANCE, FAIL_OVERLAP = 1, 2, 4, 8
OUTCOMES = ("Disabled", "NotDue", "Reserved", "NoCandidateRecorded")
REASONS = ("None", "InvalidProfile", "Cardinality", "MembershipChurn", "WeightChurn", "ReferenceCapacity", "ReservationRefused", "InternalFailure")

SIGNING_DOMAIN = keccak256(b"unicity.p85.signing-binding")
RESULT_DOMAIN = keccak256(b"unicity.p85.election-result")
ASSIGNMENT_DOMAIN = keccak256(b"unicity.p85.primary-assignment")
SNAPSHOT_DOMAIN = keccak256(b"unicity.p85.election-snapshot")
K_DOMAIN = keccak256(b"unicity.p85.recovery-authorization")
CONTRACTS_DOMAIN = keccak256(b"unicity.p85.contracts")

CAT_RELEASED = 4  # custody lot category: released


def h(b: bytes) -> str:
    return "0x" + b.hex()


# --- continuity and selection (a port of the Go model's rules) ---------------------------------------------------------------------------------------

def quantize(x, b=WEIGHT_CAP_B):
    n = len(x)
    if n == 0 or n >= b or any(v == 0 for v in x) or sum(x) > U64:
        raise ValueError("quantize: invalid committee")
    total = sum(x)
    if total <= b:
        return list(x)
    s = (total + (b - n) - 1) // (b - n)
    return [max(1, v // s) for v in x]


def _total(c):
    if not c:
        raise ValueError("empty committee")
    prev = -1
    t = 0
    for m in c:
        if m["weight"] == 0 or m["id"] <= prev:
            raise ValueError("invalid committee")
        prev = m["id"]
        t += m["weight"]
    if t > U64:
        raise ValueError("total above 64 bits")
    return t


def measure(o, s):
    """The merge walk over two ascending committees. Members are dicts id/binding/weight."""
    vo, vs = _total(o), _total(s)
    only_old = only_new = replaced = 0
    unchanged_old = unchanged_new = 0
    dist = 0
    i = j = 0
    while i < len(o) or j < len(s):
        if j == len(s) or (i < len(o) and o[i]["id"] < s[j]["id"]):
            only_old += 1
            dist += o[i]["weight"] * vs
            i += 1
        elif i == len(o) or s[j]["id"] < o[i]["id"]:
            only_new += 1
            dist += s[j]["weight"] * vo
            j += 1
        else:
            if o[i]["binding"] == s[j]["binding"]:
                unchanged_old += o[i]["weight"]
                unchanged_new += s[j]["weight"]
            else:
                replaced += 1
            dist += abs(s[j]["weight"] * vo - o[i]["weight"] * vs)
            i += 1
            j += 1
    removed, added = only_old + replaced, only_new + replaced
    return {"replaced": replaced, "removed": removed, "added": added, "m": removed + added, "unchangedOld": unchanged_old,
            "unchangedNew": unchanged_new, "totalOld": vo, "totalNew": vs, "distanceNumerator": dist}


def verdict(r, old_size, new_size, p):
    if p["distDen"] == 0:
        raise ValueError("invalid params")
    failed = 0
    if r["m"] > p["maxM"]:
        failed |= FAIL_MEMBERSHIP
    if 3 * max(r["removed"], r["added"]) >= min(old_size, new_size):
        failed |= FAIL_TURNOVER
    if r["distanceNumerator"] * p["distDen"] > p["distNum"] * r["totalOld"] * r["totalNew"]:
        failed |= FAIL_DISTANCE
    if 3 * r["unchangedOld"] <= 2 * r["totalOld"] or 3 * r["unchangedNew"] <= 2 * r["totalNew"]:
        failed |= FAIL_OVERLAP
    return failed


def check(o, s, p):
    r = measure(o, s)
    return verdict(r, len(o), len(s), p), r


def _better(a, b):
    return a["weight"] > b["weight"] if a["weight"] != b["weight"] else a["id"] < b["id"]


def _rank(e):
    # strict total order: descending weight, ascending identity (Python's sort is stable and the key is total)
    return sorted(range(len(e)), key=lambda i: (-e[i]["weight"], e[i]["id"]))


def _committee(e, in_s):
    members = [m for m, f in zip(e, in_s) if f]
    q = quantize([m["weight"] for m in members])
    return [{"id": m["id"], "binding": m["binding"], "weight": w} for m, w in zip(members, q)]


def select(o, e, cfg):
    """Returns (reason number, chosen committee). cfg: nMin, nTarget, nMax, maxM, distNum, distDen."""
    if cfg["nMin"] == 0 or cfg["nTarget"] < cfg["nMin"] or cfg["nMax"] < cfg["nTarget"] or cfg["nMax"] > 16 or cfg["distDen"] == 0:
        return 1, []
    n = len(e)
    for i, m in enumerate(e):
        if m["weight"] == 0 or (i > 0 and m["id"] <= e[i - 1]["id"]):
            raise ValueError("InvalidEligible")
    if n < cfg["nMin"]:
        return 2, []
    old_ids = {m["id"] for m in o}
    incumbent = [m["id"] in old_ids for m in e]
    rank = _rank(e)
    in_s = [False] * n
    count = 0
    for r in rank:
        if count >= cfg["nTarget"]:
            break
        if incumbent[r]:
            in_s[r] = True
            count += 1
    for r in rank:
        if count >= cfg["nTarget"]:
            break
        if not incumbent[r]:
            in_s[r] = True
            count += 1
    chosen = _committee(e, in_s)
    failed, _ = check(o, chosen, cfg)
    if failed:
        return _churn_reason(failed), []
    for r in rank:
        if incumbent[r] or in_s[r]:
            continue
        low = None
        for q in reversed(rank):
            if incumbent[q] and in_s[q]:
                low = q
                break
        if low is None or not _better(e[r], e[low]):
            continue
        in_s[low], in_s[r] = False, True
        trial = _committee(e, in_s)
        failed, _ = check(o, trial, cfg)
        if failed == 0:
            chosen = trial
        else:
            in_s[low], in_s[r] = True, False
    return 0, chosen


def _churn_reason(failed):
    return 3 if failed & (FAIL_MEMBERSHIP | FAIL_TURNOVER) else 4


# --- the election, derived from raw inputs ----------------------------------------------------------------------------------------------------------

def binding_of(root_key_hash: bytes, evm_key_hash: bytes) -> bytes:
    return keccak256(encode_args(SIGNING_DOMAIN, root_key_hash, evm_key_hash))


def eligible(inp, seed: bytes):
    """The eligible identities ascending, with the snapshot digest folded from `seed`. Raw inputs only (inp['identities'])."""
    unit, floor_ = inp["custody"]["bondUnit"], inp["custody"]["minBond"]
    out = []
    digest = None
    for ident in sorted(inp["identities"], key=lambda x: x["id"]):
        if not ident["indexed"]:
            continue
        pos = ident["position"]
        if pos["owner"] == 0 or pos["retirementRequested"] or ident["excluded"]:
            continue
        st = ident["staged"]
        if st is None or st["bindingHash"] == b"\0" * 32:
            continue
        rk = st["rootKeyHash"]
        if rk != pos["rootKeyHash"] and (pos["stagedRootKeyHash"] == b"\0" * 32 or rk != pos["stagedRootKeyHash"]):
            continue
        if ident["keyOwner"] != (ident["id"], 2):
            continue
        lots = [lot for lot in ident["lots"] if lot["category"] != CAT_RELEASED]
        principal = sum(lot["remaining"] for lot in lots)
        if principal < floor_:
            continue
        w = principal // unit
        if w == 0 or w > U64:
            continue
        lot_ids = [lot["id"] for lot in lots]
        digest = keccak256(encode_args(digest if digest is not None else seed, ident["id"], pos["generation"], st["bindingHash"], w,
                                       keccak256(b"".join(l.to_bytes(32, "big") for l in lot_ids))))
        out.append({"id": ident["id"], "generation": pos["generation"], "weight": w, "binding": binding_of(rk, st["evmKeyHash"]), "bindingHash": st["bindingHash"],
                    "rootKeyHash": rk, "evmKeyHash": st["evmKeyHash"], "payee": st["payee"], "lots": lot_ids})
    return out, (digest if digest is not None else seed)


def expected(inp):
    """The output ElectionPolicy.elect(origin) must produce in the state `inp` describes, as a dict of the compared fields (see compare.FIELDS)."""
    el, cu, ck = inp["election"], inp["custody"], inp["clock"]
    idle = {"reason": "None", "attemptCursorAfter": el["attemptCursor"], "openResultAfter": h(el["openResult"])}
    if not el["initialized"] or el["openResult"] != b"\0" * 32 or ck["recordCount"] != ck["custodyCursor"]:
        return dict(idle, outcome="Disabled")
    p, t = ck["progress"], ck["ucTime"]
    due_p = max(el["anchorProgress"], el["attemptProgress"]) + el["params"]["cadenceRounds"]
    due_t = max(el["anchorTime"], el["attemptTime"]) + el["params"]["cadenceSeconds"]
    if p < due_p or t < due_t:
        return dict(idle, outcome="NotDue")
    predecessor = cu["lastAckedAssignment"]
    attempt = el["attemptCursor"] + 1
    seed = keccak256(encode_args(SNAPSHOT_DOMAIN, el["network"], inp["chainId"], el["address"], inp["origin"], p, t, inp["policy"]["currentPolicyID"], predecessor, attempt))
    cands, digest = eligible(inp, seed)
    inc = inp["incumbent"]
    o = [{"id": x["id"], "binding": binding_of(x["rootKeyHash"], x["evmKeyHash"]), "weight": x["weight"]} for x in inc["exposures"]]
    entries = [{"id": c["id"], "binding": c["binding"], "weight": c["weight"]} for c in cands]
    try:
        reason, chosen = select(o, entries, el["params"])
    except ValueError:
        reason, chosen = 7, []  # InternalFailure: the election's try/catch records it
    result_id = keccak256(encode_args(RESULT_DOMAIN, el["network"], inp["chainId"], el["address"], predecessor, attempt, inp["origin"]))
    base = {"resultID": h(result_id), "attempt": attempt, "progress": p, "ucTime": t, "origin": h(inp["origin"]), "predecessor": h(predecessor),
            "snapshotDigest": h(digest), "attemptCursorAfter": attempt, "openResultAfter": h(b"\0" * 32)}
    if reason != 0:
        return dict(base, outcome="NoCandidateRecorded", reason=REASONS[reason], policyID=0, assignmentID=h(b"\0" * 32), frozen=[], members=[], publication=None,
                    reservation=None)
    by_id = {c["id"]: c for c in cands}
    # the reservation preconditions custody checks (reference capacity of the incumbent slate and of every primary lot)
    rmax = cu["limits"]["rMax"]
    lots = inp["lotTable"]
    refused = any(lots[l]["refCount"] >= rmax for x in inc["exposures"] for l in x["lots"]) or \
        any(lots[l]["refCount"] >= rmax for m in chosen for l in by_id[m["id"]]["lots"])
    if refused:
        return dict(base, outcome="NoCandidateRecorded", reason="ReferenceCapacity", policyID=0, assignmentID=h(b"\0" * 32), frozen=[], members=[], publication=None,
                    reservation=None)
    assignment_id = keccak256(encode_args(ASSIGNMENT_DOMAIN, result_id))
    frozen = [{"id": m["id"], "generation": by_id[m["id"]]["generation"], "weight": m["weight"], "raw": by_id[m["id"]]["weight"],
               "bindingHash": h(by_id[m["id"]]["bindingHash"])} for m in chosen]
    members = [{"id": m["id"], "rootKeyHash": h(by_id[m["id"]]["rootKeyHash"]), "evmKeyHash": h(by_id[m["id"]]["evmKeyHash"]), "payee": by_id[m["id"]]["payee"],
                "weight": m["weight"], "rawWeight": by_id[m["id"]]["weight"], "lots": by_id[m["id"]]["lots"]} for m in chosen]
    policy_digest = keccak256(b"".join(w.to_bytes(32, "big") for w in inc["policyTerms"]))
    contracts_digest = keccak256(encode_args(CONTRACTS_DOMAIN, inp["chainId"], *inp["moduleDigestInputs"]))
    k_commit = keccak256(encode_args(K_DOMAIN, el["network"], inp["chainId"], result_id, digest, predecessor, inc["exposureDigest"], inc["keyDigest"], policy_digest,
                                     contracts_digest))
    publication = {"incumbent": h(predecessor), "incumbentExposureDigest": h(inc["exposureDigest"]), "incumbentKeyDigest": h(inc["keyDigest"]),
                   "policyDigest": h(policy_digest), "contractsDigest": h(contracts_digest), "kCommit": h(k_commit), "snapshotDigest": h(digest),
                   "assignmentID": h(assignment_id), "attempt": attempt}
    reservation = {"state": 1, "lineage": h(inc["lineage"]), "rootEpoch": inc["rootEpoch"] + 1, "evmEpoch": inc["evmEpoch"] + 1, "policyID": inp["policy"]["currentPolicyID"]}
    return dict(base, outcome="Reserved", reason="None", policyID=inp["policy"]["currentPolicyID"], assignmentID=h(assignment_id), frozen=frozen, members=members,
                publication=publication, reservation=reservation, openResultAfter=h(result_id))
