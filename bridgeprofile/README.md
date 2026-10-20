
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
the per-SID path with every leaf under its own seal (protocol 5's worst case). The gate is 7,000,000.

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

Read: every consolidated bundle up to the 16-leaf profile bound fits the gate at both committee sizes; on the per-SID path a 16-leaf
history whose leaves all carry distinct seals fits at 4 members but not at 16 (bold). Each additional shard under the shared seal
costs about 0.15–0.2M at 4 members and 0.3–0.4M at 16 (UC bytes and items of the repeated seal copy). The leaf and history-byte terms
still grow with L, so longer histories (a later profile step) and the B7 fallback are unaffected by this table.

### Profile limits after #526 step 5 (MaxLeaves 24, MaxTransfers 23)

`step5_limits_test.go` holds the measurements behind the raise:
- the oracle's return history is 548 + 272·L bytes;
- RSMT membership paths have about log2(n) siblings for n state IDs: a mean of 20 and a p99 of 23 at 10^6 (the 10^6 run is behind
  `STEP5_RSMT_LARGE=1`);
- at 24 leaves with 24 siblings per path, a consolidated bundle stays below 6M gas for a 4-member committee over up to 4 shards
  (5.91M) and for a 16-member committee over up to 2 shards (5.93M).

A 16-member committee over 8 shards is over the 7M budget already at 16 leaves. The gate prices every bundle, and what does not fit
redeems via the B7 fallback. MaxAnchors stays 16: with 24 leaves a token can need more anchors than that, which the parser refuses
(`compose-anchors-over-max`). New corpus cases `return-transfers-max` and `-over-max` pin the transfer bound. `return-valid-16` (17
transactions) is now accepted.
