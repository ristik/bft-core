# F6f: automatic root-quorum bootstrap freshness

Refs [#176](https://github.com/ristik/bft-core/issues/176), [#167](https://github.com/ristik/bft-core/issues/167)
and [#14](https://github.com/ristik/bft-core/issues/14). Design prerequisite based on integration
`6a60a878`; no implementation, protocol registration or activation is included.

The owner selected automatic fresh root-quorum confirmation. This supersedes F6e's pending provider
choice and removes an operator assertion as a default/fallback. [F4f](f4f-standard-genesis-json-bootstrap.md)
still makes trusted finalized standard genesis JSON the sole execution configuration. This protocol
neither distributes allocations nor makes a root echo certify their correctness.

## 1. Guarantee and boundary

An accepted receipt proves that the **genuine initial shard UC/TR assignment** was current at some
linearization point between generating this acquisition's unpredictable nonce and completing verification.
It does not prove the shard remains initial when the receipt is later used. A receipt is a process-local
starting point for F6e's authenticated assignment continuity, executor-B0 check and finality-coordinated
readiness checks. Known ordinary evidence defeats it immediately, including failed-persistence cases.

The initial profile is one fixed root committee/epoch and one unchanged shard deployment at epoch zero.
Deletion/re-addition of the same shard/configuration, round wrap, epoch transition and committee transition
are refused. Roots and the client use independently configured trust. The proof assumes ordinary root BFT
finality and durable honest safety state; restoring a quorum of root signing keys with rolled-back safety
databases is outside that fault bound, not repaired by a nonce. Replacement **shard** disks need no special
operator assertion: they run this acquisition again, or remain unready.

No synthetic UC, rewritten signed nil state or second genesis manifest is introduced. Ordinary responses
select normal authenticated recovery even if their execution state equals S0. No response means unavailable,
not initial. This service grants no signing authority and does not clear the restored-local-key gate.

## 2. What the implementation actually provides

At this base:

| Source | Consequence for freshness |
| --- | --- |
| [`Node.onHandshake`](../../rootchain/node.go) | Returns `ShardInfo.LastCR`; membership/subscription and a signed old UC do not establish a current read. |
| [`SafetyModule.MakeVote`](../../rootchain/consensus/safety_module.go) | Persists `SetHighestQcRound(parentQC.round, votingRound)` before releasing a vote signature. `isCommitCandidate` commits the parent QC's round when consecutive. |
| [`BoltDB.SetHighestQcRound`](../../rootchain/consensus/storage/db_bolt.go) | Atomically preserves the maximum QC/voted rounds. Its **getter currently substitutes genesis on read failure**; that getter is forbidden for this protocol. |
| [`ProcessQc`](../../rootchain/consensus/storage/block_store.go), [`BlockTree.Commit`](../../rootchain/consensus/storage/block_tree.go), [`processQC`](../../rootchain/consensus/consensus_manager.go) | Commit QC drives block/state persistence and then certificate publication. A voter can already have signed a globally sufficient commit while its local committed snapshot/LastCR is behind. |
| [`ShardStates.UnicityTree`](../../rootchain/consensus/storage/sharding.go) | Commits IR, TR hash and shard configuration, **not the LastCR seal/its timestamp**. |
| [`GenerateCertificates`](../../rootchain/consensus/storage/block_executor.go), `nextRound` and `ValidRequest` in [`sharding.go`](../../rootchain/consensus/storage/sharding.go) | Unchanged shards retain LastCR. Each shard update advances TR.Round. BCR timestamp must equal the actual LastCR seal timestamp. A newer root seal cannot silently replace it. |

This motivates a two-part proof: nonce-bound quorum **safety frontiers**, followed by a committed state cut
at or beyond those frontiers. Neither a local snapshot lock nor quorum signatures over old LastCR alone suffice.

## 3. Query and root response

The proposed additive protocol/domain is `root-bootstrap-admission/v1`; no existing handshake, vote,
UnicitySeal, QC, RootInput or configured-progress encoding changes. Exact transport registration and
independent encoding vectors belong to implementation review. Messages use deterministic CBOR definite
arrays, shortest unsigned integers, canonical byte strings, no extra fields and bounded decoding.

`Context` is `[network, partition, canonicalShardBytes, fullShardConfHash, rootEpoch,
GenesisOriginIdentity]`. Hashes and nonce are exactly 32 bytes. The client derives the context from its
trusted JSON origin and local root trust, not the reply. Roots validate network/epoch and active shard/config
membership; origin identity is echoed request binding, not a root endorsement of execution settings.

1. Client creates fresh random nonce N after beginning a new process-bound acquisition. Request is
   `[1, Context, N]`. No receipt, nonce or acquisition completion is restored from disk.
2. A root enters a serialized consensus/safety read boundary. It obtains an **error-returning** coherent
   durable safety snapshot H (highest QC round), its committed deployment state and actual LastCR pair P.
   It must not sign during incomplete initialization, failed persistence, unknown safety state or recovery
   that has not reconciled these values. If P is absent, it refuses; it does not construct a genesis UC.
3. Root supplies a real quorum-certified frontier QC Q with `Q.VoteInfo.RoundNumber >= H` and at least its
   sampled committed root round. To avoid network-less non-commit/genesis shortcuts, this profile requires
   a non-genesis **commit-capable** QC: normal quorum signatures, matching network and pinned epoch in both
   vote and commit information, a nonzero committed round equal to VoteInfo.ParentRoundNumber, and
   `VoteInfo.RoundNumber = committedRound + 1` without overflow. Root waits/refuses if only a newer non-commit
   QC is available and no eligible QC covers H. It never lowers H to the QC it happens to retain.
4. Root signs a distinct query domain over
   `["root-bootstrap-admission/frontier", 1, Context, N, author, PairIdentity(P), SHA256(canonicalQC(Q))]`.
   Reply carries `[1, author, canonicalPair(P), canonicalQC(Q), signature]`. A root copies P from the sampled
   committed state's LastCR, not from the request or an arbitrary proof supplied by the client.
   Root signs only after the safety read; no slow network wait is inside the serialized boundary.

`PairIdentity` hashes a domain-separated canonical tuple of the **complete** signed IR, complete seal signing
bytes, full TR and deployment identity. Equivalent valid seal signature subsets do not change identity.
The actual UC and TR remain owned canonical evidence and undergo complete normal authentication.
Do not use only root/partition rounds, only the state hash or an index. Q's digest binds its full canonical
encoding; normal QC verification binds VoteInfo to the signed LedgerCommitInfo through PreviousHash.

The concrete v1 tuple is CBOR `["root-bootstrap-admission/pair", 1, inputRecordBytes,
sealSigBytes, technicalRecordBytes, Context]`, where the three record encodings are byte strings.
`inputRecordBytes` is the complete canonical `InputRecord.Bytes()`, `sealSigBytes` is the complete
canonical `UnicitySeal.SigBytes()` (and therefore excludes only the seal signature map), and
`technicalRecordBytes` is the canonical full TR. In the reply, `canonicalPair(P)` and
`canonicalQC(Q)` are byte strings containing canonical `[UC,TR]` and the complete QC including its
signature map. `canonicalShardBytes` is `ShardID.Bytes()` including its sentinel encoding. The
request origin identity remains caller binding that the root echoes; it is not root endorsement.
Independent encoding vectors and their standard-library generator are in
[`vectors/frontier_signing_vectors.json`](vectors/frontier_signing_vectors.json) and
[`vectors/generate_frontier_signing_vectors.py`](vectors/generate_frontier_signing_vectors.py).
Those vectors test encoding and hashes only: their opaque IR, seal, TR and QC bytes are synthetic,
while genuine signed loop fixtures separately test certificate and response authentication.

The response signature is an attestation about a durable safety floor and actual LastCR. It is **not** an
assertion that the root's local snapshot is globally latest. Subsequent votes need not be blocked: a root
may vote immediately after signing the response. The proof below explicitly permits that race.

Root implementation requires a new error-returning safety-read API, serialization with every vote/timeout
signing and recovery path, and copied committed-state access. A separate uncoordinated mutex around the query
handler is insufficient. The existing getter's genesis fallback must not be reused. A missing historical QC
at or above H is an availability refusal; recovery must authenticate a suitable QC before responding.

## 4. Client completion and genuine assignment

Authenticate every reply under the pinned committee and exact context/N/domain/author. Validate every QC
and every UC/TR independently; reject unknown/duplicate signers and invalid proofs. Collect a quorum R
agreeing on `PairIdentity(P)`, then set F to the **maximum QC vote round in that quorum**. Respondents may
have different QCs. Do not use a minimum, median, signed local committed height or unsigned claimed floor.
Any independently authenticated ordinary UC/TR encountered selects ordinary observation/recovery, even
without a complete query quorum; do not discard it to assemble a convenient bootstrap quorum.

That negative handoff precedes cancellation, timeout, budget-exhaustion and receipt-return decisions. Once
ordinary evidence authenticates, synchronously latch process bootstrap invalidation and retain the owned
observation in the bounded admission first/latest slots before returning from acquisition. The handoff must
not depend on a canceled network context, a successful store write or a further finality-gate wait. It grants
no target adoption before normal durable admission. Do not call a canceled `Submit` and assume evidence
was retained: the provider/admission integration needs an explicit acknowledged retention boundary for an
already authenticated observation, with the same local context checks. This boundary remains an implementation
prerequisite. Before releasing a constructed receipt, recheck its generation and drain/account for every
authentication already completed in the acquisition; a late ordinary result defeats that receipt even when
its signer was not in R. Deterministic tests must pause between receipt construction and release, inject such
an ordinary result, then cancel/exhaust the budget and verify sticky invalidation plus retained retry evidence.

Obtain a separate proof at a genuinely committed root cut C with `C.round >= F`:

- a normal, non-genesis, quorum-verified commit QC establishing C's network, epoch, round, timestamp and root;
- shard-tree and unicity-tree membership of exactly P's full IR, TR hash and configuration under C's root;
- the original genuine pair P, fully authenticated under the local shard/config/root pins.

The cut may come from any untrusted provider. Only proof verification grants it meaning. No arbitrary root
snapshot or `StateMsg` alone substitutes for the commit QC and membership path. Verify the cut's round as
the **committed** round, not the QC's later voting round. An old LastCR seal is permitted because membership
at C proves its shard state, not because receipt time makes that old seal fresh.

Do **not** repackage the cut membership as a replacement UC and feed it to BFTClient/Round. P's genuine seal
timestamp, signed nil fields and TR assignment are retained byte-for-byte, apart from normal equivalent
signature-subset handling. The query quorum additionally attests the actual LastCR identity: a provider
cannot take the unchanged leaf proof at C, attach C's newer seal and thereby change the timestamp expected
by `ValidRequest`.

The fixed-deployment profile depends on this explicit root invariant: LastCR is replaced only by a committed
shard update, and every such update strictly advances TR.Round (initial insertion occurs once). No reset,
overflow, epoch crossing or delete/re-add is permitted. Thus an honest response's actual LastCR P remains
the same actual assignment at any later committed cut with the same full IR/TR/config. This invariant must
be covered by implementation tests; if it cannot be enforced, the protocol needs a separately reviewed
quorum attestation binding actual LastCR directly to the selected cut. Leaf membership alone cannot repair it.

For bootstrap issuance, P must be the exact genuine initial `InputRecord{Version:1}`, with all F6e initial
shape checks; TR is epoch zero and authorizes a positive round. Root epoch/context must match. Ordinary,
unsupported, conflicting or unavailable evidence never produces a bootstrap receipt. A result whose
acquisition deadline has elapsed is discarded even if all signatures verify.

## 5. Safety argument

Let the fixed root committee have total voting power W, quorum threshold q, and Byzantine power at most b,
with `2q > W+b`. Signatures are counted once per authorized identity with checked arithmetic. The same
committee and threshold authenticate frontier responses and root commit QCs. In the current unit-vote PoA
profile this is the familiar N=3f+1, q=2f+1, b=f case. The pinned base's QC verifier sums stake, whereas
`VoteRegister.InsertVote` currently counts authors; **this design does not claim general weighted runtime
support**. Initial activation requires unit-weight roots, `2N/3 < q <= N`, fault assumption `b <= N-q`, and
matching configured quorum semantics; weighted
activation needs the root aggregation path reviewed/corrected separately.

Let t0 be generation of N, and let K be the latest root block whose commit-capable quorum existed before
t0. A globally formed quorum counts even if some roots have not assembled/processed its QC locally.
If no real commit exists, bootstrap acquisition must wait for one; unsigned genesis is not a receipt.

1. K's commit voters V and accepted response quorum R intersect in power at least `2q-W > b`; at least
   one intersection signer h is honest.
2. Before releasing its signature that can commit K, h persisted highest-QC round at least K.round:
   current `isCommitCandidate` commits the proposal's parent QC, and `MakeVote` persists that QC's round
   before signing. Monotonic durable safety state survives ordinary root restart.
3. h responds to unpredictable N after t0. Its error-checked H therefore remains at least K.round, and its
   attached authenticated QC has vote round at least H. Hence `F >= K.round`.
4. C is genuinely committed and `C.round >= F`. Root finality places C at or after K on the one committed
   history. If C committed before t0, it must be K; if it commits later, that occurs during acquisition.
   Consequently P's proven shard state at C is current at some point within the request interval.
5. The response quorum agreeing on P contains an honest signer that copied the actual LastCR. Strict
   assignment advancement plus identical IR/TR/config at C preserves that actual assignment (section 4).

This establishes a **linearizable read**, not a lease. A commit that races after t0 may be before or after
the chosen cut. If it is after C, a bootstrap receipt may still legitimately finish: its linearization point
is before that commit. A root that already processed ordinary state will return ordinary evidence; the client
must preserve it. Delayed later delivery cannot turn ordinary state back into bootstrap.

After C, root `ValidRequest` still checks the actual predecessor, assigned TR round/epoch and seal timestamp.
An obsolete bootstrap assignment cannot certify a competing successor to already advanced root state.
Local Build/sign additionally require current authenticated held-pair continuity, unchanged progress token,
exact executor B0, live receipt and independent signing authority; the receipt itself permits none of them.
Learning ordinary progress invalidates bootstrap before persistence succeeds. No expiry setting replaces
these checks, and this design does not repair the separately tracked first-BCR proof-composition boundary.

## 6. Races, faults and limits

| Case | Required result |
| --- | --- |
| Ordinary commit before N, local committed snapshots lag | Honest quorum intersection forces F beyond that transition; an initial cut below it is refused. |
| Commit during gathering | Either the cut includes it (ordinary response) or the read linearizes before it; subsequently known ordinary evidence wins. |
| Ordinary commit after C | Receipt is not a future-state promise. Old assignment cannot pass root current-state checks; local readiness/authority checks remain mandatory. |
| Old signed receipt/reply delayed | New N/session rejects old replies. Current-N replies arriving after overall deadline cannot issue a receipt. Expiry is measured from t0, not delayed arrival. |
| Valid but high Byzantine QC | QC must really satisfy the fixed trust/epoch/network and commit-capable checks. It may force waiting for a higher cut; timeout is unavailable, never lower-F acceptance. Peer cannot inflate a floor with just its own vote/signature. |
| Valid QC from an abandoned certified branch | A later committed cut at or above its round is sufficient under root finality; the client must not claim that QC's branch was committed. |
| Shard database/whole backup rollback or empty store | New N and query required. JSON identity, local marker, stored receipt and old UC cannot establish freshness. Known ordinary history still cannot regress. |
| Root crash between safety persistence and vote/publication | H may be ahead; recover a covering QC or refuse. Never default to genesis or lower H because the vote/QC body is absent. |
| Root safety read/persistence error, incomplete recovery | No response signature. Recovery copying state cannot erase durable safety floors. |
| Too many restored/equivocating root signers | Outside the root BFT fault assumption; no quorum-read protocol can make those same keys a fresh trusted authority. |
| Different actual LastCR identities among responses | Do not splice assignments. Obtain a quorum for one identity within budget or retry a new acquisition later. |

Receipt is opaque and process-only: context/origin instance, N, P identity, root barrier/cut proof identity,
issuance generation and a monotonic deadline. Verification owns all evidence. No durable permission bit is
added to configuredprogress. Receipt generation and cancellation are rechecked before release; replacement
or renewal cannot resurrect an invalidated generation.

Proposed local implementation ceilings (not consensus timing or deployment activation): one acquisition,
30 seconds overall, 5 seconds per exchange, four concurrent exchanges, at most 64 configured root identities,
at most two bounded query passes in that episode with 5-second backoff, and 1 MiB aggregate canonical proof
material including deduplicated QCs/pairs/membership paths. A single encoded pair or QC is at most 256 KiB;
no partial/truncated evidence. Every refusal, timeout and retry consumes budget. Per-peer bookkeeping is
bounded by that configured set. Requests cannot trigger unbounded recovery, historic scans or new queues.
Implementation must demonstrate the selected committee's proofs fit or propose a reviewed cap amendment.
The 1-MiB limit is also a running acquisition-wide received-byte/accumulation ceiling, checked before reads,
copies and decoding, not merely the size of a final deduplicated proof. Malformed/failed replies and repeated
copies count toward it; deduplication never refunds consumed budget. Concurrent exchanges reserve from the
same cap rather than each receiving an independent allowance. Partial/oversized responses terminate their
attempt without permitting another unbudgeted body or a new acquisition triggered by that peer.

Proposed receipt lifetime is at most five minutes from t0 in monotonic process time, further limited by
cancellation, epoch/context change and known ordinary progress. It is not renewed by UC receipt. Initial
timeout repeats require F6e's genuine assignment-chain verification, bounded to its 512-pair/1-MiB history
limit; missing history or expiry requires another acquisition. These local values need implementation review;
owner approval selected the automatic mechanism, not a public availability/retention promise.

## 7. Implementation and evidence units

[F6g](f6g-root-frontier-boundary.md) maps these units to the consensus loop, owned storage reads,
covering-QC selection and failure/recovery admission boundaries at the current implementation.

The inactive storage prerequisite exposes `BoltDB.ReadSafetySnapshot`, which reads the persisted highest
QC and highest-voted rounds coherently in one bbolt view and returns an error for unavailable or malformed
state. This value is a storage snapshot only; it is not globally fresh or a certified authority, and it does
not change existing getters, callers, schemas or write behavior. Vote and recovery serialization remain
separate implementation work.

1. **Root frontier read/sign API:** error-returning durable safety read; actual LastCR copy; covering-QC
   selection/validation; serialized vote/timeout/recovery ordering; bounded signing domain and refusal.
   Fault-test every persist/sign/recover cut and missing QC. No protocol registration in this unit.
2. **Cut proof and codec:** independently generated canonical vectors for request/frontier/cut proof,
   context/nonce/domain/signature rejection, actual assignment identity, quorum and byte limits. Read a
   consistent committed snapshot without generating a replacement UC or altering LastCR.
3. **Inactive client provider:** bounded gathering/grouping, maximum floor, membership/cut verification,
   ordinary handoff and opaque session receipt. Test arbitrary stale signatures, high QC, delayed responses,
   quorum intersection, rollback and expiry. No operator fallback.
4. **Reviewed runtime integration:** finite peer admission, root feature compatibility, Node startup,
   actual v2 readiness and signing interlocks. Requires F4f/F6e executor/first-BCR prerequisites and independent
   consensus review. The existing inactive admission bridge does not activate this provider.

No old root speaks this new protocol; mixed deployments fail unavailable rather than downgrade to handshake
freshness. No migration/cleanup of consensus safety state is permitted. Existing default root/shard behavior
is unchanged by this design PR. Full #14/#167 remain incomplete; public activation remains a separate decision.

The small [intersection model](models/bootstrap_frontier.py) enumerates unit-vote quorum/fault sets and
checks the floor argument plus counterexamples for local-status/minimum-floor/rollback substitutions.
It models assumptions, not real cryptography, consensus, weighted activation or execution. Required later
tests must exercise the concrete APIs, current commit rules and assignment-preservation invariant above.
