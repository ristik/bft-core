
### External companion replay and release gate

`TestExternalSealedCorpus` verifies and replays the checked-in offline cache from
an exact native-bridge-plugins commit, then compares every generated data file
with that independently imported snapshot. Refresh it with
`python3 tools/import-bridge-corpus.py CHECKOUT COMMIT SEALED_DIGEST` after the
companion import is committed. The import reads git objects at COMMIT, never
working-tree files, and verifies the complete sealed manifest before replacing
the cache. Normal tests and CI need no network for this replay.

The source commit named by seal provenance generates the corpus. A later
cache/pin-only commit can import the resulting companion snapshot without
resealing or changing that source identity. Both repositories are public;
companion CI regenerates from that source anonymously.

The current snapshot is a sealed candidate from open PR1, not a merged release.
`BRIDGEPROFILE_REQUIRE_MERGED_CORPUS=1 go test ./bridgeprofile -run TestExternalSealedCorpus`
is the explicit release gate and remains closed until the companion snapshot is
merged and its pin status is updated with merge evidence. No PR merge is implied
by successful candidate replay.

### Consolidated bundles (uc-consolidation, #526)

A wallet may consolidate its token before redeeming: the root seals every shard of the aggregation partition in one root round, and
the partition view of that round (bft-go-base `PartitionViewV1`, at most 8 shards in V1) yields an ordinary version 1 UC for every
shard (`AuthenticatedPartitionView.Certificate`). The bundle's anchors are those UCs: one per shard the leaves touch, all under one
seal. B1 and the bridge check each as any UC; the view itself never goes on chain, and no rule changes.

`AggregatorWorld.CertifyConsolidated` is the generator (one seal per sealed round, the view authenticated against the enclosing UC of
the round's master shard with one quorum check, every anchor derived from it); `NewShardedAggregator` builds partitions of 1, 2, 4 and
8 shards; `SpanningHistory` picks the first return history whose leaves touch every shard. The corpus carries
`compose-consolidated-m{1,2,4,8}-n{4,16}` with their `gate-…-exact`/`-minus-one` cases (16 leaves), the mixed bundle
`compose-consolidated-mixed` (one consolidated group of four shards plus a leaf under a later seal: five anchors, two seals) and
`compose-consolidated-altered-shard-leaf` (a derived UC with one shard-tree sibling altered: `ErrAnchorAuth`).

Measured (`TestConsolidatedGateTable`; DEV Cfg, the oracle's return histories, fixture IRs): K anchors, E epochs, S seals, Q seal
signatures (b1ref grouping), the native batch charge, the gate total of the consolidated bundle, and the gate of the same token on
the per-SID path with every leaf under its own seal (protocol 5's worst case). The gate is an estimate with no ceiling (owner §36).

| N | m | L | K | E | S | Q | batch | gate (consolidated) | gate (per SID) | envelope B | view B |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 4 | 1 | 8 | 1 | 1 | 1 | 4 | 131,208 | 2,114,314 | 3,608,136 | 6,432 | 193 |
| 4 | 1 | 16 | 1 | 1 | 1 | 4 | 131,208 | 2,805,714 | 6,007,608 | 11,296 | 193 |
| 4 | 2 | 8 | 2 | 1 | 1 | 4 | 149,940 | 2,293,470 | 3,647,064 | 7,552 | 382 |
| 4 | 2 | 16 | 2 | 1 | 1 | 4 | 149,940 | 2,954,198 | 6,085,464 | 12,160 | 382 |
| 4 | 4 | 8 | 4 | 1 | 1 | 4 | 191,992 | 2,695,186 | 3,685,992 | 10,112 | 760 |
| 4 | 4 | 16 | 4 | 1 | 1 | 4 | 191,992 | 3,325,242 | 6,163,320 | 14,464 | 760 |
| 4 | 8 | 8 | 8 | 1 | 1 | 4 | 291,272 | 3,556,920 | 3,724,920 | 15,584 | 1,516 |
| 4 | 8 | 16 | 8 | 1 | 1 | 4 | 291,272 | 4,171,640 | 6,241,176 | 19,808 | 1,516 |
| 16 | 1 | 8 | 1 | 1 | 1 | 16 | 226,632 | 2,375,050 | 5,694,024 | 7,904 | 193 |
| 16 | 1 | 16 | 1 | 1 | 1 | 16 | 226,632 | 3,066,450 | **10,179,384** | 12,768 | 193 |
| 16 | 2 | 8 | 2 | 1 | 1 | 16 | 268,788 | 2,742,942 | 5,732,952 | 10,496 | 382 |
| 16 | 2 | 16 | 2 | 1 | 1 | 16 | 268,788 | 3,403,670 | **10,257,240** | 15,104 | 382 |
| 16 | 4 | 8 | 4 | 1 | 1 | 16 | 357,688 | 3,522,130 | 5,771,880 | 16,000 | 760 |
| 16 | 4 | 16 | 4 | 1 | 1 | 16 | 357,688 | 4,152,186 | **10,335,096** | 20,352 | 760 |
| 16 | 8 | 8 | 8 | 1 | 1 | 16 | 550,664 | 5,138,808 | 5,810,808 | 27,360 | 1,516 |
| 16 | 8 | 16 | 8 | 1 | 1 | 16 | 550,664 | 5,753,528 | **10,412,952** | 31,584 | 1,516 |

Read: consolidation is always the cheaper bundle, and the per-SID path costs about 10.4M at 16 members and 16 leaves (bold, over
the former 7M ceiling). Each additional shard under the shared seal costs about 0.15–0.2M at 4 members and 0.3–0.4M at 16 (UC bytes
and items of the repeated seal copy). The leaf and history-byte terms grow with L.

### The resource policy (owner §36, B7 direct path)

There is no gas ceiling and no bridge-specific history cap (`limits.go`, briefs/b7-direct-uncapped-design.md §1). The gas formula is
an estimate that wallets set their gas limit from; a call with too little gas runs out of gas and reverts. The aggregate bounds are
the native kernels' own until the native composition streams them: MaxTransfers 64 and MaxLeaves 65 (B2), MaxSemanticBytes 128 KiB
(B2 history), MaxAnchors 16 (B1 claims). MaxEnvelopeBytes is 512 KiB, an ingress bound above every envelope those admit. The
cumulative path-step budget (2,048) and the shared Solidity item budget (4,096) are gone: path steps and items are charged; each
certificate, path and CBOR object keeps its own shape bound, and the envelope's declared siblings never exceed its bytes.

### Measurements (#526 step 5)

`step5_limits_test.go` keeps the measurements: the oracle's return history is 548 + 272·L bytes (up to 23 transfers, a one-byte
array head); RSMT membership paths have about log2(n) siblings for n state IDs (mean 20, p99 23 at 10^6, behind
`STEP5_RSMT_LARGE=1`); and `TestEstimateHasNoCeiling` prices a 16-member committee over 8 shards at 65 leaves and 24 siblings far
above the former 7M, unrefused. A token whose leaves each carry their own certificate can still need more than MaxAnchors anchors,
which the parser refuses (`compose-anchors-over-max`); consolidation removes that need.
