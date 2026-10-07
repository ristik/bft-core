#!/usr/bin/env python3
"""Partition `go list ./...` without dropping newly added packages.

Keep the four known slow packages apart, then greedily distribute the rest
using test-source size as a cheap, deterministic estimate of work. Actual
package timings are recorded by `go test -json` in each job.
"""

import pathlib
import sys


def select(packages, selector):
    prefix = "github.com/unicitynetwork/bft-core/"
    if selector == "race":
        # Pure Go unit tests; avoid process/devnet tests and slow discovery.
        roots = (
            "internal/quorumweight",
            "internal/weightvalidation",
            "keyvaluedb",
            "network/protocol",
            "rootchain/consensus/leader",
            "rootchain/consensus/trustbase",
            "rootchain/consensus/types",
            "rootchain/consensus/votesig",
        )
        return [p for p in packages if any(
            p == prefix + root or p.startswith(prefix + root + "/")
            for root in roots
        )]

    anchors = ("rootchain/consensus", "archivewiring", "cli/ubft/cmd", "network")
    shards = [[prefix + anchor] for anchor in anchors]
    missing = set(sum(shards, [])) - set(packages)
    if missing:
        raise ValueError(f"missing slow packages: {sorted(missing)}")

    def weight(package):
        directory = pathlib.Path(package.removeprefix(prefix))
        return max(1, sum(p.stat().st_size for p in directory.glob("*_test.go")))

    loads = [weight(shard[0]) for shard in shards]
    remaining = set(packages) - set(sum(shards, []))
    for package in sorted(remaining, key=lambda p: (-weight(p), p)):
        target = min(range(4), key=lambda i: (loads[i], i))
        shards[target].append(package)
        loads[target] += weight(package)
    return sorted(shards[int(selector) - 1])


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("1", "2", "3", "4", "race"):
        sys.exit("usage: go list ./... | scripts/ci-packages.py {1|2|3|4|race}")
    packages = sorted(set(line.strip() for line in sys.stdin if line.strip()))
    if not packages:
        sys.exit("go list returned no packages")
    selected = select(packages, sys.argv[1])
    if not selected:
        sys.exit("selected no packages")
    print("\n".join(selected))
