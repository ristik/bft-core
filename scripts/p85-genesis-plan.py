#!/usr/bin/env python3
"""The proof-of-stake genesis plan of a lane: one bonded identity per root/EVM pair, in the order the trust base and the shard configuration
list their nodes (custody numbers genesis identities 1..N in that order and seeds one lot each).

    p85-genesis-plan.py <trust-base.json> <shard-conf.json> <bond-unit-wei> <bond-units-per-identity> > plan.json

The owner, withdrawal and payee addresses are derived from the root node id (sha256, first 20 bytes): lane values, not keys anyone holds.
The input of `ubft pos-relayer genesis`.
"""
import hashlib
import json
import sys


def addr(tag, node):
    return "0x" + hashlib.sha256(f"p85-lane/{tag}/{node}".encode()).digest()[:20].hex()


def main():
    tb = json.load(open(sys.argv[1]))
    conf = json.load(open(sys.argv[2]))
    unit, units = sys.argv[3], int(sys.argv[4])
    roots, evms = tb["rootNodes"], conf["validators"]
    if len(roots) != len(evms):
        sys.exit(f"{len(roots)} root nodes but {len(evms)} EVM validators: the genesis is coupled one to one")
    ids = []
    for i, (r, e) in enumerate(zip(roots, evms)):
        ids.append({
            "stakingId": i + 1,
            "owner": addr("owner", r["nodeId"]),
            "withdrawal": addr("withdrawal", r["nodeId"]),
            "payee": addr("payee", r["nodeId"]),
            "bondUnits": units,
            "rootNodeId": r["nodeId"],
            "rootKey": r["sigKey"],
            "evmNodeId": e["nodeId"],
            "evmKey": e["sigKey"],
            "lotIds": [i + 1],
        })
    json.dump({"bondUnit": unit, "identities": ids}, sys.stdout, indent=1)
    print()


main()
