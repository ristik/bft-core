# F6g: root frontier sampling boundary

Refs [#176](https://github.com/ristik/bft-core/issues/176), [F6f](f6f-automatic-bootstrap-freshness.md),
and #180. Source audit at `a9007e758e06ddbf448db20ccae47437940a2bf1`. This records the implemented
inactive unsigned sampler boundary; it is not evidence that bootstrap activation is safe. F6f's quorum/cut proof and
fixed-deployment restrictions remain unchanged. Standard finalized genesis JSON remains the sole
execution configuration.

## 1. Use the consensus loop, not the public getters

The concrete serialization boundary is `ConsensusManager.loop`. Its handlers run synchronously:

| Entry | Safety/state operations inside that handler |
| --- | --- |
| `onProposalMsg` | Process parent QC/TC, execute/Add, `MakeVote`, persist last vote, send, replay buffered votes. |
| `handlePacemakerEvent` / `onLocalTimeout` | Process round QC or call `SignTimeout`; store/reuse the timeout vote and send it. |
| `onVoteMsg` / `onTimeoutMsg` | Verify incoming votes, update round state, process QC/TC or enter recovery. |
| `onStateResponse` | Verify recovery, construct/persist a replacement block store, apply pending blocks, replace manager fields, clear recovery, and possibly call `MakeVote` for the triggering proposal. |
| `processNewRoundEvent` / `onPartitionIRChangeReq` | Sign proposals/change messages with `SafetyModule.Sign`; these are not commit-vote safety writes but share the signer and loop. |

Sources: [loop and dispatch](../../rootchain/consensus/consensus_manager.go#L344),
[normal vote](../../rootchain/consensus/consensus_manager.go#L710),
[timeout](../../rootchain/consensus/consensus_manager.go#L443),
[recovery](../../rootchain/consensus/consensus_manager.go#L999),
[safety module](../../rootchain/consensus/safety_module.go#L96).
The pacemaker's clock goroutine emits events; it does not sign votes. The separate
`sendCertificates` goroutine delivers already produced certificates; it is not the sampling boundary.

The optional sampler submits a bounded request to this loop and receives one buffered reply.
It must not invoke consensus handlers itself or sample from a network callback. There is no separate
query mutex: that would serialize queries with each other, not with `MakeVote` or recovery.
Enqueue/wait respects request and manager cancellation; unavailable capacity refuses immediately.
Bound both queued requests and callers waiting for replies. No external RPC, peer fetch, retry sleep,
or response delivery runs inside the loop. A canceled caller cannot leave the loop blocked on reply.
Input and queue limits bound admitted work; they do not make a bbolt read or a local signer forcibly
cancellable. A delayed operation may hold the loop, but an expired request must never publish a response.
No request is admitted before startup initialization completes or after shutdown begins. The enabled
sampler must enforce one active `Run` owner for this manager and exclusive ownership of its safety/store
mutation paths; two loops on the same manager would invalidate this serialization argument. The current
`Run` method is not itself a single-run admission guard.

`ShardInfo`, `GetState`, `GetCertificate`, `Root` and `HighQc` return pointers or structures containing
pointers after their local lock is released. Their locks do not cover the safety database and replacement
of `ConsensusManager.blockStore`. They are not an immutable combined frontier API. In particular,
`BlockStore.lock` used by several getters is not acquired by `ProcessQc`.
Sources: [getters](../../rootchain/consensus/storage/block_store.go#L187),
[tree root](../../rootchain/consensus/storage/block_tree.go#L221),
[state construction](../../rootchain/consensus/storage/block_tree.go#L386).

## 2. Owned sample and bounded QC selection

Inside one loop turn, obtain the checked `ReadSafetySnapshot` and an owned, size-bounded copy of:

- the sampled committed root round and its commit QC;
- the requested shard's actual committed LastCR certificate and technical record, plus the local
  configuration identity needed to check it;
- the tree's current high QC, as an optional second candidate;
- the fixed locally provisioned root trust/configuration identity and the sampler generation.

A new narrow storage copy API must select only the requested shard and these two QCs while holding
`BlockTree.m`. It must not copy the entire recovery state or enumerate pending blocks. Check collection,
field and total encoding limits before cloning/marshalling; an oversized local object is a refusal too.
Missing shard, LastCR, commit QC or required safety field produces no partial authoritative result.
The returned representation owns all bytes, slices and signature maps. A storage copy is unsigned data,
not proof or a freshness capability.

Use only those two retained QC candidates in the first implementation. Each candidate must independently
satisfy F6f's full signature, network/epoch, non-genesis, commit-capable and non-overflow checks, and its
vote round must cover both persisted highest-QC round H and the sampled committed round. Select a valid
covering candidate; a newer non-commit high QC must not hide an eligible committed-root QC. If neither
covers H, return `covering-qc-unavailable`: never lower H, fabricate a QC, use an unsigned genesis QC,
scan unbounded history, or block the loop waiting for a peer. This deliberately permits an availability
refusal even if some other historical candidate could exist.

`QuorumCert.Verify` is necessary but insufficient: it skips signatures at the genesis round and does not
itself enforce all the F6f profile conditions. The sampler validates its copied pair and QC under its
fixed local trust, not trust chosen by a claimed epoch. `HighestVotedRound` remains diagnostic/checking
input; it is not substituted for H and does not imply a QC exists for that round.
Sources: [QC verification](../../rootchain/consensus/types/quorum_certificate.go#L83),
[checked read](../../rootchain/consensus/storage/db_bolt.go#L314).

The genuine LastCR seal is retained, not rewritten to the commit QC's round or timestamp. The response
frontier and the later committed-cut membership proof have different jobs. No unsigned sample becomes a
client receipt. Authentication, quorum intersection and the separate cut proof remain mandatory.

## 3. Failure and recovery are explicit admission states

The loop alone prevents interleaving; it does not prove all earlier operations completed durably.
Current code has partial-mutation failure paths:

- `BlockTree.Add` links the node before `WriteBlock` returns.
- `InsertQc` changes a block's QC before its write, and updates `highQc` only after success.
- `Commit` updates LastCR/changed state and prunes in-memory nodes before the committed-root write;
  `root` is advanced only after that write succeeds.
- Recovery `NewFromState` writes its new root to the same database before the manager swaps its
  `blockStore`; subsequent pending-block failure can leave the old manager view and new disk state.

Sources: [Add/InsertQc](../../rootchain/consensus/storage/block_tree.go#L146),
[Commit](../../rootchain/consensus/storage/block_tree.go#L338),
[recovery root write](../../rootchain/consensus/storage/block_tree.go#L59),
[manager recovery sequence](../../rootchain/consensus/consensus_manager.go#L1017).
These are reasons to gate the new response path, not a claim that this document reproduces a consensus fault.

The sampler therefore needs its own fail-closed admission state, maintained in the consensus loop:
`not-started`, `eligible`, `recovering`, `persistence-uncertain`, `stopped`. Initially it is not-started.
Any safety/block/last-vote/timeout persistence error makes it persistence-uncertain before another query
can be processed, including errors currently logged and swallowed. Do not infer success from a handler's
nil return: `processQC`, `processTC`, `onLocalTimeout` and normal last-vote storage have such paths.
This extra state governs only frontier responses; it does not silently change existing consensus behavior.
Once a recovery attempt invokes `NewFromState`, any failure before installing and fully checking the new
manager state also latches persistence-uncertain, even when the immediate error is not an I/O error: the
replacement root may already be on disk. Rejecting an unauthenticated response before that point does not
by itself claim that local persistence failed.

For the first sampler implementation, persistence-uncertain is sticky for that process lifetime. A normal
successful proposal or clearing `recoveryState` does not clear it. Recovering without a persistence fault
may become eligible only after the complete recovery handler, including trigger replay, has finished and
an owned sample passes all checks. Epoch/profile mismatch remains ineligible even after recovery.

A new process must reconstruct and validate its committed view, actual LastCR and covering QC against the
checked safety state before admitting a response. Merely opening the database or resetting the pacemaker
is insufficient. A missing covering QC after a crash is unavailable, even when the safety counters are
readable. No safety counter is lowered or inferred from the recovered committed state. Reboot durability
and rollback of a quorum of root signing keys remain F6f's assumptions, not proved by an API read.

Startup reconstructs the high QC from retained root/pending data and need not retain every QC body that
once justified a safety write. The constant two-candidate policy above is intentionally conservative.
Source: [tree reload](../../rootchain/consensus/storage/block_tree.go#L91).

## 4. Sampling and signing stages

The smallest next coding unit is the **unsigned owned storage view** described in §2: one bounded requested
shard lookup, root metadata and at most two QC copies, with real-store ownership/bounds tests. No manager
query channel, signer or registration is needed for that unit, and it must not claim freshness.

`BlockStore.ReadFrontierStorageView` now implements that unsigned copy boundary. It copies only the
selected LastCR, shard/configuration identity, committed round/epoch and the two QC candidates under the
tree lock. The QC's network ID is copied data, not independently configured trust. Collection cardinality
is capped at 1,024, shard IDs at 4,096 bits, traversal at 10,000 values/depth 32, each pair/QC at 256 KiB
and cumulative data at 1 MiB. A conservative encoding-size preflight runs before each clone; actual
encodings are checked too. These local availability limits do not validate a committee or a certificate.
Private copies protect stored objects from CBOR marshalers that normalize version fields. The real bbolt
fixtures check ownership and unchanged files, not cryptographic authentication or crash freshness.
Existing pointer-returning getters still expose aliases; callers must serialize with the manager loop and
must not mutate those aliases concurrently. No safety read, fault latch or runtime sampler is added here.

The optional manager sampler implements the bounded query path and admission state in §3. It combines the
checked safety read with the owned storage view in one loop turn and authenticates the complete LastCR/QC
pair against a locally pinned, unit-weight root profile. Its store proxy makes persistence uncertainty
sticky for that process, including recovery after replacement-root persistence begins. Real-loop tests
cover ordinary vote/commit ordering, timeout and write failures, queue saturation, cancellation, shutdown,
and recovery refusal through completed trigger replay. Validation tables cover the fixed QC candidates and
profile limits. This remains unsigned diagnostic output; no caller, transport, signer, bootstrap path or
activation default consumes it.

Only after those units are reviewed should a domain-separated frontier signer be added. For the initial
implementation, bounded local validation and response signing stay within the admitted loop turn, with
cancellation rechecked before signing and before reply publication. Signature work must have fixed input
and committee bounds; there is no external signer or unbounded operation inside that turn. A later off-loop
signer would need separately reviewed generation/ownership/fault semantics. Transport admission/rate limits,
cut-proof serving/client verification and bootstrap activation remain later units.

## 5. Required deterministic evidence

| Boundary | Required assertion |
| --- | --- |
| Normal/recovered `MakeVote` before and after the safety write | A queued sample occurs wholly before or after the handler; the later sample cannot report a lower persisted floor. Include the second MakeVote call in recovery. |
| Safety write fails; last-vote write fails after signing | No frontier reply thereafter in that process, even if consensus continues or a later write succeeds. |
| QC insertion/Add/Commit fails after in-memory mutation | No response built from the partially updated tree; no successful subsequent query clears the fault latch. |
| Recovery fails after writing a replacement root | No old-memory/new-disk sample; ordinary recovery Clear does not bypass the fault latch. |
| Clean recovery and startup | Only complete revalidation opens admission; absent QC, missing/corrupt safety state, unsupported epoch and genesis-only QC refuse. |
| Newer non-commit high QC | An eligible committed-root QC can be selected; if both are below H, refuse without reducing H. |
| Ownership and bounds | Mutating source/returned slices cannot change retained evidence; oversized pair/QC fails before unbounded copy; no shard/history scan. |
| Cancellation/saturation/shutdown | No signature after pre-sign cancellation; no publication after cancellation; bounded queue and pending waiters; an abandoned reply never stalls consensus. |
| LastCR and cut differ in root round | Keep genuine UC/TR byte identity and timestamp; never construct a replacement UC from the cut. |

Fault-injection fixtures establish process ordering and refusal only. They do not establish filesystem
power-loss behavior, weighted-root support, or the full quorum freshness theorem. Those limits and F6f's
strict assignment/no-wrap invariant remain activation prerequisites.
