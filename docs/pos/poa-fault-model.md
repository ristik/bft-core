# PoA fault model: what the fleet tolerates

Written for the X1 matrix row X-42 ([#42](https://github.com/ristik/bft-core/issues/42)). It states the assumptions the M2 evidence is chosen against; it is not a new design decision. The governing decisions are [ADR 0012](../adr/0012-validator-entity-model.md) (validator entity, coupled changes, co-hosted trust, aggregator disclosure) and the owner's acceptance of M2a with limits on [#43](https://github.com/ristik/bft-core/issues/43). Code references are to bft-core `integration/enshrined-evm` at the revision of the matrix; the one dependency reference names its pinned module version.

## Setting

Proof of Authority, equal weights. One validator is one organizational entity: a BFT Core node plus its co-hosted EVM node (ADR 0012, decision 1). Validator-set changes are coupled: one root handoff changes the root committee and the EVM assignment together (decision 2). The M2 evidence lanes use four validators and a four-member root committee (`scripts/reth-paired-devnet.sh:61-64` requires four validators for the profile-2 handoff lane; `devnet-runs/m2a-final-merged-20260930T071819Z/start-evm.log:14` records "started 4 root nodes"). Each lane handoff replaces one root by a new one (`scripts/m2-profile2-handoffs.sh:338-350`), so that run has six root directories but four committee members in every epoch.

## Quorum rules, by layer

`n` is the number of configured members, `q` the quorum, `f` the number of members whose fault the layer survives. Values for n = 4 in the last column.

| Layer | Quorum rule | Where set | Safety against Byzantine members | Liveness | n = 4 |
|---|---|---|---|---|---|
| Root chain (BFT Core consensus) | q = ⌊2W/3⌋ + 1 over the total stake W by default; a lower threshold is refused. PoA roots have unit stake (refused otherwise at `rootchain/consensus/handoff_operator.go:376` and `rootchain/consensus/frontier_sampler.go:111`), so W = n and q = ⌊2n/3⌋ + 1 | `bft-go-base@v1.1.1-0.20260421100318-01ab63a83bf5` (`go.mod:24`) `types/root_trust_base.go:84-97`; the handoff body recomputes it as `evmroot.RootQuorumThreshold` at `evmroot/d3weights.go:136` and `rootchain/consensus/handoff_operator.go:401`; vote weights at `rootchain/consensus/vote_register.go:131` (one per vote unless the profile uses stake weighting) | f < n/3, that is f ≤ n − q | n − q members may be down | q = 3, f = 1 |
| EVM shard certification requests | q = ⌊n/2⌋ + 1 of the configured shard keys, one vote per key | `rootchain/consensus/storage/sharding.go:681`; checked when the root admits the request at `rootchain/request_buffer.go:221` and `rootchain/consensus/types/ir_change_request.go:123` | two conflicting quorums overlap in at least 2q − n signers, so n = 4 needs two double-signers | q members must be up | q = 3; tolerates 1 down or 1 Byzantine, not both |
| Aggregator shards | the same unweighted majority rule, over that shard's configured keys | `rootchain/partitions/partition_trust_base.go:22`, `rootchain/consensus/storage/sharding.go:681` | see below: the keys are held by one operator | q members must be up | q = 1, 2, 2, 3 for n = 1 to 4 |

Notes.

- **Root consensus** also requires `2N/3 < q ≤ N` wherever a root quorum is verified from a trust base outside the voting path (`rootchain/consensus/frontier_sampler.go:121`). Handoff approval needs endorsements of weight q from the old committee (`rootchain/consensus/handoff_operator.go:981-983`), and so does a handoff abort (`:1146`): with four roots, three live members. This is the accepted "needs a live old quorum" limit.
- **Faulty bound.** The running root takes n − q (or W − q under stake weighting) as the weight that may be Byzantine while a root quorum is still safe (`rootchain/consensus/vote_register.go:162`, from `GetMaxFaultyNodes` in the pinned bft-go-base); the pacemaker jumps to the timeout state once timeout votes exceed it (`rootchain/consensus/pacemaker.go:198`). The D3 specification helper `FaultyWeightBound` (`evmroot/d3weights.go:147`) states the same W − q but is used only by the vector generator. For n = 4 it is 1.
- **EVM shard threshold in code versus design.** The design defines `ShardAttestationThreshold = ⌊W/2⌋ + 1` over root-assignment weights (`evmroot/d3weights.go:141`), but that function is used only by the D3 vector generator (`evmroot/d3vectors.go:153`); the running EVM shard uses the unweighted count rule above. Under PoA's equal weights the two coincide; they diverge only when weights differ (PoS), which is outside this model.
- **Root round timeouts and shard no-quorum.** When a shard cannot form a quorum, the root issues a repeat certificate (on a proven no-quorum or after the T2 timeout), never a different state (ADR 0012, "What the root checks"; `rootchain/consensus/types/ir_change_request.go:129-141` refuses to certify "no quorum" unless a quorum is truly impossible).

## What the four-validator fleet tolerates

| Fault | Root chain (4 roots) | EVM shard (4 validators) | Evidence in the matrix |
|---|---|---|---|
| One validator crashed or isolated | continues (3 of 4) | continues (3 of 4) | X-20 (D2C and chaos), X-29 |
| One validator Byzantine | safe | safe: one signer cannot form or conflict a quorum | X-12, X-13, X-17 |
| One validator's disks lost, key authority alive | unaffected | restore from the archive (replaced node signs above its high-water) | X-29, X-21 |
| Two validators down | no commits; no handoff can complete (needs 3 live old members) | no quorum: repeat certificates only; the certified chain does not fork | not exercised; outside the assumption |
| Two validators Byzantine | root safety lost | conflicting shard quorums possible | outside the assumption |
| Signing key lost with its state | rotate the key through a certified coupled handoff while the old quorum lives; no same-key restore (D-M2-2) | same | X-17 limit |

Precisely: with four roots and q = 3, `f = 1` is one faulty validator in total, of any kind (crashed, isolated or Byzantine), not one of each. With one Byzantine root, safety holds; liveness then needs the other three roots up and connected, because they are exactly a quorum. One crash plus one Byzantine member is two faults and is outside the assumption. The matrix does not claim behaviour for two simultaneous faults; the lanes inject one fault at a time.

## Co-hosted trust

A BFT Core node fully trusts its co-hosted EVM node (ADR 0012, decision 3), so a validator entity is one fault domain in both layers: a Byzantine or crashed co-hosted reth counts as that validator's fault in the root set and in the EVM set at the same time. The budget is therefore `f = 1` entities across both layers, not one per layer. Defences run between validators: every follower verifies the proposed block independently and refuses invalid ones before certification (matrix X-06 to X-08), and the BFT and EVM processes must not share private keys, with EVM and signing-authority keys delegated and procedural (decision 4). The reverse direction is not defended: a node does not distrust its own reth.

## Aggregator shards: `proof_type` none

Aggregator shards run centrally at launch without consistency proofs (ADR 0012, decision 7 and its "Trust-assumption disclosure"). The root checks signatures from the configured keys, a count majority on one record, chain continuity and the installed configuration hash, and orders certified states in one chain. It does **not** check that the transition is valid (`NoOpVerifier`; `verifyZKProof` returns before reading any proof), data availability, independence of the signers, or stake. Because one operator holds the configured keys, the quorum attests only that the operator signed: a majority rule over keys the operator holds adds no fault tolerance against the operator. Clients of an aggregator shard trust its operator for the correctness and availability of transitions, and the root for quorum, continuity, order and configuration binding. The matrix covers only the root-side behaviour (X-35, X-36); changing this needs a separate owner decision.

## Why four, and what this does not justify

Four is the smallest size with f = 1 for a ⌊2n/3⌋ + 1 rule, so it is the cheapest fleet that tests one-fault tolerance for both layers; it is chosen for that fault model and is not a substitute for coverage of the faults above (the matrix rows are). It gives no tolerance of two faults, and PoS weights, a different fleet size or non-equal weights need this document revisited.
