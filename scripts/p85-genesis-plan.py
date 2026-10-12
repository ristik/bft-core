#!/usr/bin/env python3
"""The proof-of-stake genesis plan of a lane: one bonded identity per root/EVM pair, in the order the trust base and the shard configuration
list their nodes (custody numbers genesis identities 1..N in that order and seeds one lot each).

    p85-genesis-plan.py <trust-base.json> <shard-conf.json> <bond-unit-wei> <bond-units-per-identity> > plan.json

<bond-units-per-identity> is one number for every identity, or a comma-separated list with one number per identity in the trust base's order (the genesis weight
of each: it must equal the root member's and the EVM validator's weight, which the genesis rules fix at 1; see the testnet package's pos.genesis_weights).

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
    unit, units = sys.argv[3], [int(x) for x in sys.argv[4].split(",")]
    roots, evms = tb["rootNodes"], conf["validators"]
    if len(roots) != len(evms):
        sys.exit(f"{len(roots)} root nodes but {len(evms)} EVM validators: the genesis is coupled one to one")
    if len(units) == 1:
        units = units * len(roots)
    if len(units) != len(roots):
        sys.exit(f"{len(units)} bond-unit counts for {len(roots)} identities")
    ids = []
    for i, (r, e) in enumerate(zip(roots, evms)):
        ids.append({
            "stakingId": i + 1,
            "owner": addr("owner", r["nodeId"]),
            "withdrawal": addr("withdrawal", r["nodeId"]),
            "payee": addr("payee", r["nodeId"]),
            "bondUnits": units[i],
            "rootNodeId": r["nodeId"],
            "rootKey": r["sigKey"],
            "evmNodeId": e["nodeId"],
            "evmKey": e["sigKey"],
            "lotIds": [i + 1],
        })
    json.dump({"bondUnit": unit, "identities": ids}, sys.stdout, indent=1)
    print()


main()
