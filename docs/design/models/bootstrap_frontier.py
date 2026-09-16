"""Bounded design model: quorum intersection and freshness-floor counterexamples.

Run: python3 docs/design/models/bootstrap_frontier.py
No network, persistence, cryptography, runtime or timing claims.
"""

from itertools import combinations


def quorums(n, q):
    return [set(c) for c in combinations(range(n), q)]


checked = 0
for n, f, q in ((4, 1, 3), (7, 2, 5)):
    assert 2 * q > n + f
    for faulty in map(set, combinations(range(n), f)):
        for voters in quorums(n, q):
            for readers in quorums(n, q):
                # A globally sufficient commit at round 10 predates the nonce.
                # Honest contributing voters have persisted a floor >=10.
                floors = {r: (10 if r in voters - faulty else 1) for r in readers}
                assert (voters & readers) - faulty
                assert max(floors.values()) >= 10
                # A committed initial cut at round9 can never satisfy this barrier.
                assert not 9 >= max(floors.values())
                checked += 1

# Four roots: commit voters012, query responders023, Byzantine0. Honest2 intersects.
floors = {0: 1, 2: 10, 3: 1}
assert max(floors.values()) == 10
assert min(floors.values()) == 1  # wrong: accepts old bootstrap cut9
local_commits = {0: 1, 2: 1, 3: 1}
assert max(local_commits.values()) == 1  # signed stale snapshots do not replace floors
rolled_back = {0: 1, 2: 1, 3: 1}
assert max(rolled_back.values()) == 1  # safety fallback/rollback breaks the premise

# A verified high QC can increase waiting; ignoring it is not a timeout recovery rule.
assert max([10, 10, 30]) == 30
assert not 10 >= max([10, 10, 30])

# A cut before a racing commit is linearizable, but is not a future lease.
nonce_time, cut_time, ordinary_commit_time, completion_time = 5, 6, 7, 8
assert nonce_time <= cut_time <= completion_time
assert cut_time < ordinary_commit_time < completion_time

# Matching leaf content does not identify the actual LastCR seal timestamp.
leaf = ("initial IR", "TR1 hash", "configuration")
actual_pair = (leaf, "actual seal at2")
reanchored_pair = (leaf, "new cut seal at9")
assert actual_pair[0] == reanchored_pair[0]
assert actual_pair != reanchored_pair

print(f"PASS: {checked} quorum/fault combinations; 5 explicit boundary counterexamples")
