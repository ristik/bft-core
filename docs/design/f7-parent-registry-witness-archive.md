# F7 prerequisite: retained parent-registry witness retrieval

Refs [#15](https://github.com/ristik/bft-core/issues/15). **Proposed design only**, based on
`integration/enshrined-evm` at `5e74dd9c30072efbbf4ec4d69ac60bcb63110860` (accepted F6d W2).
[Claim](https://github.com/ristik/bft-core/issues/15#issuecomment-5688779806).
The owner chose shard-internal libp2p first for this bounded slice; a broader HTTP archive API is separate.
No code, protocol registration, storage migration, activation or readiness change is included.

## 1. Boundary and sources

The consumer already knows the authenticated exact EVM block B and checked deployment context, but its
execution client's proof window no longer covers B. This slice retrieves the retained RLP header and
SealRegistry proofs for B. It neither authenticates a new parent nor chooses a replacement one.

- [F4a §7–8](f4a-seal-registry-contract.md) defines verification and witness(B), including archive
  reacquisition; [F4c](f4c-registry-proof-reader.md) implements the 22-slot verifier and bounds.
- [F4e](f4e-proof-acquisition-witness.md) and
  [`registrywitness.Acquire`](../../registrywitness/registrywitness.go) acquire by exact hash and separate
  unavailable from invalid evidence. Its in-memory store is bounded and re-verifies on use.
- [F6b](f6b-certified-record-store.md), [`certifiedstore.Load` and `verifyHead`](../../certifiedstore/store.go),
  and [`verify` and `Loaded.Witness`](../../certifiedstore/record.go) define durable record verification.
- [F6d W1/W2](f6d-node-record-wiring.md) separates reload, executor application, capture and publication.
  W3 is a separately reviewed implementation under #14; this document does not prescribe its internals.
- [D6 §2–3](d6-historical-trust-proof-custody.md) and the specification's
  [Execution Proof Export](../pos/specification/appendix-evm.tex) require independently authenticated
  history, explicit archive responsibility and typed unavailable results. D6 was accepted in
  [#82](https://github.com/ristik/bft-core/pull/82) at `28459b85b4bfb0dafad34a5334bdd0e16a06ac68`.

F6 remains open, and **broader F7 remains blocked on F6**. This is a prerequisite design, not acceptance
of F7 or a complete offline proof bundle. Receipts/events, transactions, canonical root-input companions,
checkpoint distribution/ancestry, epoch transitions, bridges and replacement-disk recovery remain outside
this slice. In particular, proof-window expiry is not certificate-age admission: an old certificate supplied
by a provider cannot replace the consumer's D6 trust initialization or historical authentication.

## 2. Proposed request and response contract

The proposed logical version is `parent-registry-witness/v1`, restricted to the accepted single shard epoch
and single root epoch `sealRegistry/v1` deployment. Version denotes this retrieval schema, independently of
`certifiedstore.RecordVersion = 1` and registry layout version 1. Unsupported versions are refused; no
silent downgrade or reinterpretation. A later implementation freezes the exact protocol ID and canonical
CBOR array layout with independently generated vectors before registration.

One request names one subject; no batches, ranges, block numbers, latest tags, redirects or arbitrary keys.

| Request member | Meaning and source |
| --- | --- |
| Version | Exact retrieval schema version |
| NetworkID, PartitionID, ShardID | Checked deployment identity; shard uses its canonical `types.ShardID` byte encoding |
| FullShardConfHash | Full 32-byte configuration hash, not an abbreviation |
| RegistryAddress, RegistryCodeHash | Fixed v1 address and configured 32-byte runtime hash |
| GenesisCommitment, EVMGenesisHash | Configured 32-byte genesis pins |
| ShardEpoch, RootEpoch | Configured unsigned epochs |
| BlockHash | Exact, nonzero 32-byte B, authenticated independently by the consumer |

These fields cover the identities in `certifiedstore.Context` and `registryproof.Context`; the full
configuration hash binds additional configuration. Configuration consistency is checked locally before
requesting, including agreement between the store and registry configuration hashes. A digest may index
this tuple locally, but no abbreviated digest substitutes for the full context at verification.

Every response echoes the version, full context and B and has exactly one tagged outcome:

| Outcome | Payload and meaning |
| --- | --- |
| `found` | Raw canonical RLP header, account proof nodes, exactly 22 ordered storage-proof node lists; no partial success |
| `unavailable` | No witness can be served; optional bounded diagnostic reason such as absent, evicted, storage-unreadable or verification-refused |
| `busy` | Admission capacity exhausted; no queued work or availability promise |
| `unsupported-version`, `wrong-context`, `invalid-request` | Named protocol refusals |

Only `found` carries evidence. Empty/partial evidence with `found`, malformed envelopes, a wrong echo or
extra payload on a refusal are invalid responses. Diagnostic text is never machine authority; reasons are
claims of this provider, not proofs of global absence, eviction or finality. No certificate, trust base,
parsed registry snapshot or claimed state-root summary is needed on this wire: the consumer brings authority
for B and derives the state root and fields from the witness. This explicitly is not the specification's
self-contained offline bundle.

## 3. Verification and state boundaries

1. Pin an immutable local acquisition target: full checked context, authenticated B, and the local attempt
   generation. Preserve the certificate/continuity evidence that justifies B outside the archive response.
2. Apply transport and structural caps before decoding or allocating proof arrays; require exact request
   echo and supported schema. Decode evidence into owned bytes.
3. Run [`registryproof.Verify`](../../registryproof/registryproof.go) with the **local** context and B.
   It checks header hash/shape, account/code hash, each fixed storage path, canonical values, configuration,
   epochs, genesis and finalized-registry conditions. No provider-supplied field changes a trusted pin.
4. Only the verified snapshot/evidence may reach a consumer. The capture consumer still binds state root
   and executed round to its certificate; genesis retains its explicit configuration-bound exception.
   Re-verify retained evidence when used under current context, as existing store/witness paths do.
5. Publication and child readiness remain the existing F6 responsibilities: revalidate the active target
   and executor identity, use the existing finality coordination and store publication boundary, and prove
   continuity to the held certificate. Network acquisition and expensive verification stay outside those
   locks. If B/context changes, the old result cannot satisfy the new attempt merely because state matches.

Transport success, verified witness, durable record and child readiness are separate states. A provider's
record need not be its current execution head. Provider availability is a further independent property:
one verified response says nothing about future retention. A failure neither deletes the prior local record,
changes finality/signing authority, nor installs a zero cursor. A witness cannot reconstruct signing state or
supply a replacement disk's missing trust anchor. Peer identity authenticates the connection, not the proof.

## 4. Safe serving and storage

The provider serves only locally retained material for a configured deployment. Requests cause no executor
RPC, recursive fetch, arbitrary disk path access or unauthenticated insertion. Admission to archive storage
requires verification under checked local context and a locally authenticated subject. Duplicate identities
are idempotent; differing proof encodings that verify the same subject need not create extra records.

At this base `certifiedstore.Load` reads **only the head**. `Keys` is inspection, and its strings are unsigned
metadata. There is no existing safe arbitrary-block export API. A head-only provider can use `Load`, require
its verified identity to equal the request, and export the copied `Loaded.Witness`; it must report unavailable
for another block. Changing the head to export an older record is forbidden.

Historical retained records need a separately reviewed exact-subject read operation before they can be
served. It must copy the indexed key and value in a consistent read transaction, enforce the existing record
size/version/digest checks, run the same complete verification as `Load` (context, certificate/trust base,
technical record, epochs, block/state/round and witness), bind the canonical key to that verified record, then
compare verified full context and B to the request. Only the resulting verified value's witness is exported.
A key or secondary index may locate a candidate; it cannot establish round, identity, certification or
availability. Missing/damaged/aliased entries refuse without raw-byte export or fallback to the head.

The implemented inactive v2 locator uses key `record-hash/v1/<64 lowercase block-hash hex>` in the
`configured-progress/v2` bucket and canonical value `[1, canonicalRecordKeyBytes]`. It is written and
removed atomically with ordinary record publication and retention. The locator is never authority:
`ReadByHash` consistently copies and re-verifies descriptor, control, published head, locator and candidate,
then requires the candidate at or behind both authenticated observed progress and head. Missing locators in
old unindexed databases are unavailable; there is no scan, backfill, head fallback or peer-supplied round.

Forward use of old unindexed v2 databases is supported. Backward write compatibility is not: an old v2
binary ignores these additive keys and may prune records without their locators, leaving dangling/orphan
entries beyond `Retain` after downgrade and re-upgrade. Reads fail closed. Cleanup would require separately
reviewed bounded verified maintenance; startup and peer requests never repair or scan implicitly.

Any separate witness-only archive similarly re-verifies its bounded evidence under checked local context
and exact B on read. Its local admission and indexed identity must be reviewed; it cannot be labelled a
certified-record store or bypass verification when populated from one. No new archive schema is implemented
here. Index rebuilding, if later added, derives entries from verified records, is bounded maintenance work,
and is not performed by a peer request. Serving from a copied verified read is valid if concurrent eviction
later removes the entry; eviction changes subsequent availability, not the already verified response.

## 5. Retention and availability contract

Local `certifiedstore.Settings.Retain` counts non-genesis records (bounded by `MaxRetain`); genesis is retained.
It is **not an archive duration, completeness guarantee or replication policy**. W2 coalesces pending captures,
and acquisition/publication can fail: an archive populated from these records can have holes. A claimed
height interval cannot assert every witness exists merely because its endpoints do.

Before operating a promised archive service, the operator must publish the supported contexts, coverage
with gaps, retention/eviction rule, capacity limits, restart/durability guarantee and responsible providers.
The horizon, redundancy target and deployment values remain owner decisions: none is set by this document.
A storage-capacity ceiling and a promised minimum retention period are different constraints. Admission must
refuse when fulfilling the promise would exceed capacity, or responsibility must already be durably handed
off under a separately reviewed policy; silent early eviction is not success. Provider read requests never
extend retention implicitly. Pure best-effort retained-record serving must advertise that status.

Data and index insertion/deletion must have crash-consistent ordering; no acknowledgement of durable archive
admission before its promised persistence boundary. Startup/maintenance revalidation is bounded; every served read verifies its candidate, so no unbounded
startup scan or unverified export is required. An evicted, missing or
unreadable witness yields typed `unavailable`; inability to remember why does not justify guessing `evicted`.
Unavailable is not a permanent negative cache and does not authorize another block. Execution-state pruning
cannot silently erase a separately promised witness service: captured proof bytes are retained independently.
No archive can recover a witness that no provider captured before proof availability expired.

## 6. Bounded libp2p acquisition and admission

Use a distinct, additive shard-internal request/response protocol following the bounded framing approach in
[`evidencetransport.go`](../../shardnode/evidencetransport.go), not its anchor-evidence message schema or
unbounded shared deserializer. One length-prefixed request and response per stream; reject oversize declared
frames before reading bodies. No Engine API, header, registry contract or existing protocol semantic changes.

The exact encoded caps require schema vectors in the implementation review. Proposed ceiling: 4 KiB request,
272 KiB response (256 KiB binary evidence plus CBOR framing/context allowance), diagnostic text at most 200
bytes. Decoder limits must also bound nesting, array cardinalities and individual byte strings; reject
trailing items and noncanonical/ambiguous encodings before verification. Evidence limits remain unchanged:
header 1,024 bytes, 65 nodes per proof, 1,024 bytes per node, total 256 KiB, exactly 22 storage proofs.
The response allowance must be checked against worst-case schema encoding, not a single happy-path fixture.

Require explicit positive finite configuration for global and per-peer pending-stream caps, concurrent
serve/verification caps, per-peer request rate/burst, end-to-end stream deadline and archive record/byte
capacity. Acquire a stream slot before reading its first byte and a verification slot before storage/proof
work; refuse/reset immediately on saturation, with no unbounded queue. Cap disk reads to a bounded indexed
candidate (no record scans); size-check before copying. Use libp2p resource limits as an additional bound.
Admission and verification accounting must include refusals and repeated duplicate requests. For this
shard-internal slice, check a finite configured set of eligible peer identities before allocating per-peer
rate/admission state; peer-ID churn must not grow a bookkeeping table. Bound pre-admission work globally
as well. Membership refresh must retire accounting entries within that same finite bound. This is serving
eligibility, not a redesign of historical key authentication; the deployment supplies the eligible count.

A consumer's acquisition episode has one shared finite budget: `MaxAttempts`, `MaxProviders`, `Overall`,
`PerAttempt` and maximum downloaded bytes, plus explicit failure `Backoff`. Count every attempted provider,
including busy, malformed/invalid, unavailable and timed-out responses. Each attempt deadline is the lesser
of `PerAttempt` and remaining `Overall`; each response is additionally bounded as above. Local execution
acquisition and archive fallback, if composed, share the total acquisition budget rather than multiplying it.
Configured eligible shard peers supply providers; never follow a provider-supplied redirect. Sequential
attempts suffice; any later parallelism needs a total concurrent-work bound.

Coalesce repeated triggers for the same context/B, permit one active episode and bounded pending state per
consumer, and rate-limit new episodes after failure. Cancellation or changed context/subject invalidates the
attempt generation. Restarting for a moving target consumes an explicit bounded restart allowance and the
same overall budget; certificate arrival must not restart deadlines indefinitely. Same B with a newer held
certificate still requires the consuming readiness/continuity check. W3 may trigger a later episode after
backoff without a new transaction, but this design does not add a second competing retry loop.

Preserve outcomes `verified`, `unavailable`, `invalid`, `budget-exhausted`, `stopped` and `superseded` in local
diagnostics. Invalid evidence costs an attempt and may be followed by another provider; it does not poison
B or contradict authenticated local history. Budget exhaustion leaves the consumer unready, records the
failed attempts, and permits a later bounded retry. Neither positive liveness nor archive completeness follows
from this contract without the operator's capture, retention and provider-availability assumptions.

## 7. Follow-on review evidence and decisions

Implementation is separate and requires review of the exact protocol ID/schema/caps, storage lookup/export
API and fault boundary, and composition with accepted W3 budgets. Operator horizons, redundancy and concrete
admission/retry values require explicit deployment decisions. They are not defaults inherited from existing
anchor recovery or the execution proof window.

Required evidence for that later implementation:

- Independently encoded wire vectors; exact frame and nested-decoder bounds; unknown version, wrong full
  context/B, truncated/partial evidence and each registryproof refusal; no acceptance before verification.
- Signed real-store records served only after Load-equivalent verification, including an intact authentic
  record aliased under another key, corrupt index/value, missing entry, concurrent eviction and restart.
- Proof-window expiry with a retained provider succeeds for exact B; absent/evicted proofs remain unavailable;
  same height/state with another block fails. No executor call is made by serving.
- Busy/stalled/invalid providers and repeated triggers cannot exceed stream, memory, disk, verification,
  provider, attempt, elapsed-time or byte budgets. A later provider becoming available succeeds after backoff.
- Context/head/certificate movement during fetch never bypasses consumer revalidation; receipt of valid
  evidence alone changes no vote, executor head, signing state, durable head or child-readiness result.

This documentation change is validated by reference/symbol inspection and `git diff --check`. No runtime tests,
devnet, hosted CI or real-reth evidence is claimed. It closes none of #10, #11, #12, #14 or #15.


## 8. Inactive requester implementation

`parentwitness.Requester` adds one sequential acquisition episode over a copied, finite, unique provider
list. `Request(ctx, target)` coalesces concurrent calls for the same complete context and exact block hash.
The first caller owns cancellation of that episode; another caller may cancel only its own wait. Changing
the target cancels and joins the current episode and imposes the configured positive backoff. There is no
queued target or automatic restart allowance: a later attempt needs an explicit call after backoff.

Attempts, providers, elapsed time and downloaded bytes share the episode budget. Download accounting includes
length prefixes, partial bodies and malformed/refusal responses; consuming the exact byte limit cannot
select the single-exchange helper's unmetered mode. Each response still passes the existing independent
proof verifier, and a successful result is checked against cancellation and the active generation before
publication. Results contain the existing opaque, owned `VerifiedResponse`; returning evidence gives copies.

An optional inactive local execution RPC source is attempted before peers. It is one source attempt and
performs at most the two exact-hash calls already defined by `registrywitness.Acquire`; peer identity counts
remain peer-only. Both raw HTTP response bodies (including JSON-RPC envelopes and refusal or malformed
bodies) and peer frame prefixes/bodies consume the same episode download budget. The local call context uses
the same per-attempt/overall deadline, redirects are refused for metered calls, and exact byte exhaustion
cannot enter the transport's legacy unmetered mode. Unavailable or invalid local evidence may fall back only
within the remaining attempt, time and byte budgets. Missing local configuration preserves peer-only use.

`Close` cancels the active episode and all callers of `Close` join that same completion. As with the transport,
shutdown requires a cooperative opener honoring its context and a stream whose reset/deadline interrupts I/O.
No custom implementation that ignores those contracts can be forcibly stopped by this API.

This unit does not register a protocol, choose deployment budgets, perform peer discovery, retain a durable
record, or activate node acquisition/readiness/signing. Node wiring must use this shared coordinator rather
than independent local and archive retry loops. Rechecking current certificate continuity and readiness
before use remains unwired.
