#!/usr/bin/env python3
"""Check a wide PoS recovery against pre-recovery facts, ordered seats and SealRegistry records."""
import argparse
import json
import subprocess
from pathlib import Path

from chain_decode import assignment, words

SEAL = "0xff00000000000000000000000000000000000002"
FACTS = int("b2905100cfe7c1af5dee2b1b6726fdfd755820e0f51ef675ed653be4f1102d00", 16)


def require(condition, details):
    if not condition:
        raise ValueError(details)


def cast(*args):
    return subprocess.check_output(["cast", *map(str, args)], text=True).strip()


def word(n):
    return f"{n:064x}"


def keccak(*parts):
    return cast("keccak", "0x" + "".join(p.removeprefix("0x") for p in parts))


def record(raw):
    w = words(raw)
    require(int(w[0], 16) == 32 and int(w[7], 16) == 224, "record tuple layout")
    length = int(w[8], 16)
    require(length % 32 == 0 and length == 32 * len(w[9:]), "record data length")
    return {"index": int(w[1], 16), "id": "0x" + w[2], "kind": int(w[4], 16),
            "progress": int(w[5], 16), "data": ["0x" + v for v in w[9:]]}


def expected(snapshot, records, recovered, exposure_domain, chain_domain):
    incumbent, reserved, result = (snapshot[k] for k in ("incumbent", "reserved", "result"))
    closure = {}
    ack = None
    boundary = False
    for r in records:
        data = r["data"]
        if r["kind"] == 4 and data[0] in (incumbent, reserved):
            # An identical repeated closure does not reset its anchors.
            closure.setdefault(data[0], r)
        elif r["kind"] == 3 and data[:2] == [result, recovered]:
            require(ack is None, "duplicate RecoveryAck")
            ack = r
        elif r["kind"] == 6 and data[0] == result and int(data[5], 16) == 1:
            require(ack is not None, "Boundary preceded RecoveryAck")
            boundary = True
    require(boundary and set(closure) == {incumbent, reserved}, "missing RecoveryAck, Boundary or closures")
    require(all(r["index"] < ack["index"] for r in closure.values()), "both closures must precede RecoveryAck")
    offset, first = (int(x, 16) for x in ack["data"][2:4])
    anchor = {}
    for assigned, start in [(incumbent, snapshot["incumbent_range"]), (reserved, [offset, first])]:
        close = closure[assigned]
        h_round = int(close["data"][1], 16)
        require(h_round >= start[1], f"{assigned}: closure predates assignment")
        anchor[assigned] = max(close["progress"], start[0] + h_round - start[1])

    want = {}
    expect_overlap = expect_difference = False
    for id, before in snapshot["facts"].items():
        in_k, in_j = id in snapshot["incumbent_seats"], id in snapshot["reserved_seats"]
        expect_overlap |= in_k and in_j
        expect_difference |= in_k != in_j
        require(before["live"] == int(in_k) + int(in_j) and before["references"] == before["live"],
                f"identity {id}: unexpected obligations before RecoveryAck")
        digest = before["digest"]
        if in_k:
            eid = keccak(exposure_domain, snapshot["network"], word(snapshot["chain"]),
                         snapshot["registry"][2:].zfill(64), recovered, word(int(id)))
            digest = keccak(chain_domain, digest, eid)
        max_anchor = max(before["anchor"], anchor[incumbent] if in_k else 0, anchor[reserved] if in_j else 0)
        want[id] = {"requested": before["requested"], "live": int(in_k), "references": int(in_k), "anchor": max_anchor, "digest": digest}
    require(expect_overlap and expect_difference, "recovery must include overlapping and exclusive identities")
    return want


def check_actual(want, got, recovered_seats, incumbent_seats):
    require(list(recovered_seats.items()) == list(incumbent_seats.items()),
            "recovered seats changed order, generation or historical lot")
    require(set(got) == set(want), "recovered holder facts have missing or unexpected identities")
    for id, expect in want.items():
        actual = got[id]
        for field in ("requested", "live", "references", "anchor", "digest"):
            require(actual[field] == expect[field], f"identity {id}: {field} {actual[field]} != {expect[field]}")
        require(actual["lot_references"] == expect["references"], f"identity {id}: historical lot reference count")


class Chain:
    def __init__(self, rpc):
        self.rpc = rpc
        self.block = int(cast("block-number", "--rpc-url", rpc))

    def call(self, contract, signature, *args):
        return cast("call", contract, signature, *args, "--block", self.block, "--rpc-url", self.rpc)

    def storage(self, contract, slot):
        return cast("storage", contract, slot, "--block", self.block, "--rpc-url", self.rpc).lower()

    def seats(self, custody, assigned):
        count = int(self.call(custody, "assignmentSeatCount(bytes32)", assigned), 16)
        require(0 < count <= 16, f"{assigned}: invalid seat count {count}")
        out = {}
        for ordinal in range(count):
            w = words(self.call(custody, "assignmentSeat(bytes32,uint256)", assigned, ordinal))
            require(len(w) == 13, "assignment seat layout")
            id = str(int(w[0], 16))
            require(id not in out, f"{assigned}: duplicate identity {id}")
            out[id] = [int(w[1], 16), int(w[-1], 16)]
        return out

    def fact(self, custody, id, generation):
        key = keccak(word(int(id)), word(FACTS + 1))
        slot = int(keccak(word(generation), key), 16)
        fields = int(self.storage(custody, "0x" + word(slot)), 16)
        require((fields & 0xff) <= 1 and fields >> 136 == 0, f"identity {id}: unexpected flags")
        return {
            "requested": fields & 1,
            "live": (fields >> 8) & 0xffffffff,
            "references": (fields >> 40) & 0xffffffff,
            "anchor": (fields >> 72) & 0xffffffffffffffff,
            "digest": self.storage(custody, "0x" + word(slot + 1)),
        }


def take_snapshot(chain, custody, registry, result):
    session = words(chain.call(custody, "session(bytes32)", result))
    require(int(session[0], 16) == 1, "recovery needs an open session")
    reserved, incumbent = "0x" + session[1], "0x" + session[4]
    before = json.loads(assignment(chain.call(custody, "assignments(bytes32)", incumbent)))
    require(before["offsetSet"] == 1, "incumbent assignment has no offset")
    k, j = chain.seats(custody, incumbent), chain.seats(custody, reserved)
    require(len(k) == 16 and len(j) == 15, "expected sixteen incumbent and fifteen reserved seats")
    for id in k.keys() & j.keys():
        require(k[id] == j[id], f"identity {id}: reservation changed its generation or lot")
    facts = {id: chain.fact(custody, id, row[0]) for id, row in (k | j).items()}
    return {"block": chain.block, "result": result, "incumbent": incumbent, "reserved": reserved,
            "incumbent_range": [before["offset"], before["firstRound"]], "incumbent_seats": k, "reserved_seats": j, "facts": facts,
            "network": chain.call(custody, "network()"), "registry": registry,
            "chain": int(cast("chain-id", "--rpc-url", chain.rpc))}


def check_recovery(chain, custody, snapshot, recovered):
    vr_cursor = int(chain.call(snapshot["registry"], "recordCursor()"), 16)
    cu_cursor = int(chain.call(custody, "recordCursor()"), 16)
    facts_cursor = int(chain.storage(custody, "0x" + word(FACTS)), 16)
    require(vr_cursor == cu_cursor == facts_cursor, "VR, custody and holder cursors differ")
    records = [record(chain.call(SEAL, "recordAt(uint64)", i)) for i in range(vr_cursor)]
    require(all(r["index"] == i for i, r in enumerate(records)), "SealRegistry record index mismatch")
    want = expected(snapshot, records, recovered, keccak(b"unicity.p85.exposure".hex()),
                    keccak(b"unicity.p85.exposure-chain".hex()))
    actual = {}
    for id, (generation, lot) in (snapshot["incumbent_seats"] | snapshot["reserved_seats"]).items():
        fields = chain.fact(custody, id, generation)
        lot_words = words(chain.call(custody, "lots(uint256)", lot))
        require(len(lot_words) == 13 and [int(lot_words[i], 16) for i in (0, 1)] == [int(id), generation],
                f"identity {id}: historical lot identity mismatch")
        fields["lot_references"] = int(lot_words[7], 16)
        actual[id] = fields
    check_actual(want, actual, chain.seats(custody, recovered), snapshot["incumbent_seats"])
    return {"block": chain.block, "records": records, "assignment": recovered, "cursor": vr_cursor,
            "expected": want, "actual": actual}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("snapshot", "verify"))
    parser.add_argument("rpc")
    parser.add_argument("custody")
    parser.add_argument("registry")
    parser.add_argument("id")
    parser.add_argument("snapshot", type=Path)
    opt = parser.parse_args()
    chain = Chain(opt.rpc)
    if opt.phase == "snapshot":
        before = take_snapshot(chain, opt.custody, opt.registry, opt.id)
        opt.snapshot.write_text(json.dumps(before, indent=2) + "\n")
        print(f"captured pre-RecoveryAck facts at execution block {chain.block}")
    else:
        after = check_recovery(chain, opt.custody, json.loads(opt.snapshot.read_text()), opt.id)
        print(json.dumps(after, indent=2))


if __name__ == "__main__":
    main()
