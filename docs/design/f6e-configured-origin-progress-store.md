# F6e: configured-origin progress, admission and crash contract

Refs [#167](https://github.com/ristik/bft-core/issues/167) / #14. **Proposed design-only prerequisite** for
unit 3b, based on `b759b1eaec55f7dd21765d74e998284e7ee068ba` (merged #169).
Claims: [#167](https://github.com/ristik/bft-core/issues/167#issuecomment-5690384440),
[#14](https://github.com/ristik/bft-core/issues/14#issuecomment-5690384596).
This implements no gate, storage format, root protocol or activation. It specializes
[F4f §§3–5](f4f-standard-genesis-json-bootstrap.md); standard finalized JSON remains the sole execution
configuration and ordinary certification permanently supersedes bootstrap once authenticated progress is known.

## 1. Actual boundary and coordinated interfaces

At the base revision:

- [`registrygenesis.GenesisOrigin`](../../registrygenesis/genesisjson.go) is an immutable result of pure
  finalized-JSON validation. Its `Identity`, `ExecutionConfigIdentity`, `BlockHash`, `StateRoot`,
  `FullShardConfHash`, `ProofContext` and owned `Evidence` supply this design's descriptor. It grants no readiness.
- [`certifiedstore.LoadWithToken`](../../certifiedstore/store.go) re-verifies the head and its canonical key;
  `HeadToken` covers the head bytes, not independently observed ordinary progress. `Prepare/Commit` protects
  head publication with byte comparison. This design extends the transaction boundary, not its trust assumptions.
- [`recordwiring.Readiness`](../../recordwiring/readiness.go) requires an S0-valued genesis UC and process-local
  observations. Its `PublishGenesis` cannot publish the genuine root initial `InputRecord{Version:1}`.
- [`BFTClient.handleCertificationResponse`](../../shardnode/bftclient.go) updates `luc` **before** driving Round.
  A persistence hook only inside Round/CommitObserver is therefore too late for the required admission boundary.
  `SeedLUC` alone neither authenticates a seed nor supplies TR/history/freshness.
- [`Round.HandleCertificate`](../../shardnode/round.go) observes before executor application; `commitPrevious`
  depends on a local pending proposal. Its first-round commit decision currently compares state changes, so
  a distinct B1 with S1=S0 can be certified but not committed/captured. Recovery must not depend on that pending slot.
- [`VerifyGenesisContinuity`](../../shardnode/anchorevidence.go) expects S0-valued genesis history. Its existing
  ordinary assigned-round/repeat rules are reusable, but calling it with repaired fields is forbidden.
- The [root handshake](../../network/protocol/handshake/handhake.go) has partition, shard and node ID, no
  challenge or freshness attestation. A signed UC, its receipt time, an encrypted connection, `ClassifyUC(nil,uc)`
  and a signing authority's high-watermark each establish less than current bootstrap eligibility.

Unit 3a provides the shared **two-stage** boundary: `AuthenticateObservationV2` authenticates and owns UC/TR
under independent configured context and derives `OriginClassV2`; `DeriveV2` later adds checked origin,
chosen-parent proof/ancestry and execution input derivation. The first stage must not require B1's header or
witness. Persist ordinary supersession immediately after authentication even if later derivation is unavailable.
The three classes are F4f's bootstrap, first-certified and ordinary; class is derived from actual signed IR,
never accepted as a caller/peer boolean. These are coordinated proposed APIs; exact names may follow 3a's
reviewed implementation without changing this ordering. No second origin-identity algorithm is introduced.

## 2. Fresh admission is separate from storage

**Owner-selected direction (subsequent #176 amendment):** automatic fresh root-quorum confirmation.
[F6f](f6f-automatic-bootstrap-freshness.md) specifies the proposed safety-frontier/cut-proof prerequisite;
it adds no implementation or activation. An operator assertion is not the default or a fallback. The current
handshake supplies neither mechanism. Storage APIs may remain inert while the provider is absent. No
production bootstrap gate may be enabled with a test provider or an unsigned `fresh=true` flag.

The gate accepts an opaque `FreshBootstrapAdmission` returned by a separately reviewed provider. It binds:

- checked `GenesisOrigin.Identity`, full network/partition/shard/configuration and pinned root epoch;
- a fresh cryptographically random 32-byte process-session nonce and exact authenticated bootstrap UC/TR;
- an authenticated root-history floor/read barrier at which that shard still has the exact initial nil-state IR;
- a local monotonic expiration and provider provenance, with no execution-setting overrides.

The receipt is process-only, not a serialized permission restored on restart. The provider authenticates the
bootstrap-state assertion; the importer independently authenticates JSON configuration. Root echo of an
origin identity is request binding, not a root certification of JSON allocations.

### 2.1 Automatic provider prerequisite

A new nonce-bound quorum read must establish a cut at which the returned shard state is current, not just
collect signatures over possibly stale local views. It needs the configured active root quorum threshold
(with distinct authorized signers and the applicable weighted policy), full context/nonce binding, and a
reviewed finality interlock: a respondent cannot attest bootstrap after contributing to an already finalized
ordinary transition while serving an older local committed snapshot. The proof must cover the actual vote,
commit, persistence and certificate-publication ordering. If local snapshot locking cannot provide that
property, a consensus-confirmed read barrier is required. Plain quorum local-status polling is insufficient.

The root protocol, signing domain, wire schema and interlock proof are a **separate prerequisite**, proposed
in F6f and not implemented by this document. A valid admission is a linearization point during the request, not a
promise that no block can ever finalize afterward. Subsequently received ordinary progress immediately
supersedes it; ordinary certification and signing checks still govern each request. A single untrusted
provider's reply or a signed old UC can never mint the receipt.

Proposed local budget for acquiring a receipt: one episode in flight; 30 s overall; 5 s per exchange;
at most 2 quorum-query rounds within that same overall budget, with 5 s backoff; at most the configured finite root set;
4 simultaneous exchanges; at most 512 authenticated certificate/TR pairs and 1 MiB total proof material
including those pairs per episode.
Use the smaller remaining deadline and existing context cancellation; no unlimited queue/retries. These are
provisional provider-review choices, not an owner-selected or frozen admission policy. They are proposed
local defaults/ceilings, reducible by configuration, not root protocol parameters.
The provider review must demonstrate its chosen proof fits these bounds or explicitly revise them.

Provisional provider-review lifetime: an issued receipt is valid at most 5 minutes of monotonic process time. Its verified initial pair may be
advanced by a bounded chain of genuine initial timeout repeats; it is not renewed by receipt of a certificate.
Renewal uses another bounded provider episode. Expiry pauses bootstrap Build/sign readiness, not receive or
verification. This bounds replay opportunity; expiration alone does not establish freshness.

### 2.2 Usable start/restart cases

| Situation | Admission |
| --- | --- |
| Fresh standard-JSON deployment, empty v2 store, exact executor B0 | create descriptor/control as data; acquire fresh admission for genuine initial UC/TR; bootstrap readiness then possible |
| Restart with intact bootstrap-only v2 store and executor B0 | verify store and current initial history; acquire a new process-bound admission; persisted bootstrap data is not a renewed permit |
| Restart with ordinary evidence, including no durable block record yet | ordinary mode immediately; recover the authenticated target and its witness; no bootstrap admission is attempted |
| Empty/replaced/rolled-back local store with executor B0 | no automatic inference; the fresh-admission provider must establish current initial state. If ordinary state is returned, retain it and recover; if unavailable, remain unready |
| Non-genesis executor or authenticated ordinary evidence conflicts with a bootstrap response | reject bootstrap; preserve known ordinary mode and investigate/recover; a receipt cannot erase known progress |

This is usable without a second long-lived allocation/identity manifest. With the selected automatic provider,
normal fresh starts and bootstrap restarts will obtain admission without an operator assertion once the protocol
and runtime prerequisites are implemented and reviewed. No manual fallback is specified. Signing authority
and restored-local-key restrictions are untouched.

## 3. Exact v2 persistence format

The configured profile uses a **new database format**, not a legacy file with an optional marker. One bbolt
bucket is named `configured-progress/v2`; the database contains this bucket only for this bounded store.
`OpenConfiguredV2` refuses a legacy `certified-record/v1` bucket or unknown top-level bucket; it never migrates,
resets or overwrites one. Legacy/default Open and behavior remain unchanged. Parent-directory durability,
regular-file checks, file lock and `NoSync=false` requirements remain F6b's.

All outer v2 structures use deterministic CBOR with definite arrays, shortest unsigned integers, byte strings and null;
no maps, tags, floats, indefinite arrays, unknown trailing fields or alternate empty/null spellings. An envelope
is `[2, kind, payloadBytes, SHA256(payloadBytes)]`, with kind 0 descriptor, 1 control, 2 ordinary record.
The digest detects damage, not authenticity. Unknown version/kind is a typed refusal.

### 3.1 Descriptor (key ASCII `descriptor`, kind 0)

```
[2, originIdentity, executionConfigIdentity,
 [networkID, partitionID, shardIDBytes, fullShardConfHash,
  registryAddress, registryCodeHash, registryGenesisCommitment,
  shardEpoch, rootEpoch],
 B0, S0, 2, 1]
```

The final integers are root-input profile version 2 and registry layout version 1. Hashes are exactly 32
bytes, address 20 bytes, shard ID its canonical existing encoding, numeric IDs/epochs unsigned. Shard epoch
is 0 for this profile. Every field is compared with the freshly checked local GenesisOrigin/configuration;
none is loaded as trusted configuration. `descriptorDigest = SHA256(exact descriptor payloadBytes)`.
Do not persist JSON allocations again. Recompute genesis evidence from the trusted finalized JSON on reload,
or retain it only as untrusted bounded cache re-verified against that origin.

### 3.2 Control (key ASCII `control`, kind 1)

```
[2, descriptorDigest, revision, firstOrdinaryPairOrNull, observedPairOrNull, headKeyOrNull]
Pair = [canonicalUCBytes, canonicalTRBytes]
```

`revision` starts at 0 and strictly increases for every mutating transaction; uint64 overflow refuses.
Initial control has all three optional fields null. A pair carries actual full certificates, including
signatures, and the bound TR, encoded with existing canonical `types.Cbor`. Pair authenticity, context,
epoch and TR hash are verified on every load. Comparisons of signed statement identity/classification use
3a's canonical identity, not signature-subset bytes; byte comparison still protects transaction CAS.

`firstOrdinaryPair` is the **first non-bootstrap observation this store accepted**, not a claim that it is B1
or that all earlier history was received. Once non-null, its exact bytes are immutable and never pruned.
It must authenticate and be non-bootstrap. `observedPair` is the latest durably accepted current target;
it can advance while executor/head remains behind. Bootstrap observedPair with non-null firstOrdinary is
invalid. A non-bootstrap observedPair with null firstOrdinary is invalid. Null observedPair is allowed only
in revision-0 empty initialization. A head implies firstOrdinary and observedPair are non-null.

The control contains no authoritative mode bit. `uninitialized`, `bootstrap-data` and `ordinary` are derived
from verified evidence. A peer/index/unsigned key cannot manufacture these states. On load, verify descriptor,
control, first pair, latest pair, their non-equivocation/relative ordering, and referenced head together.
The head certificate must not be newer than observedPair; same-round conflicting statements are refused.
An older head with a later observed target is durable data, not ready state. Satisfying this ordering alone
does not establish the complete continuity path to the held assignment.
A gap does not prove readiness continuity; it can be a valid ordinary recovery target.

### 3.3 Ordinary record (kind 2)

Key: ASCII `record/` followed by the certified partition round as exactly 20 decimal digits, `/`, and the
32-byte block hash as exactly 64 lowercase hexadecimal characters. No `record/genesis` exists.

Payload is `[2, descriptorDigest, legacyOrdinaryRecordBytes]`. The nested bytes use the existing
`certifiedstore.RecordVersion=1` envelope/payload encoding and verification **only for block number >0**;
there is no reinterpretation of its block-0 exception. Verify all its context, UC/TR, epochs, block/state/round
and witness bindings, then bind the v2 outer descriptor and canonical key. This reuses an ordinary record
representation without pretending the v1 store is v2. First-certified B1 additionally requires decoded header
number 1 and predecessor B0; Snapshot.ParentHash is the verified subject, not that predecessor.

`headKey` names the verified ordinary head, never an observed-but-unapplied target. Retain the existing
configured 1..65,536 ordinary-record count; never evict head or firstOrdinary evidence. No fallback to an
older retained record on a damaged/missing head. Index rebuild/repair is not implicit startup behavior.

### 3.4 Fixed bounds and token

Descriptor envelope <=4 KiB; each encoded Pair <=1 MiB; control envelope <=(2 MiB + 4 KiB); nested ordinary
record <=1 MiB; outer ordinary envelope <=(1 MiB + 4 KiB). Apply byte limits before copying/decoding and
bound nesting to 16, pair array count to 2, control/descriptor arities exactly, and witness limits unchanged. Nested legacy UC/TR decoders additionally cap array/map cardinality at
65,536 and nesting at 16 before allocation; allowing existing signature maps inside opaque canonical UC
bytes does not permit maps in the outer v2 schema.
The readiness history bundle remains <=512 UC/TR pairs and <=1 MiB including its full encoding. Metadata
work is constant-size; no full-database scan is needed for reload. Retention pruning remains bounded by the
configured record count, not peer-supplied ranges.

`ProgressToken` is opaque and process-owned: store instance, descriptor/control byte digests, exact head key
and head-envelope digest (or null), observed canonical identity and revision. A fast check compares all these
inside one read transaction; it proves only unchanged bytes previously verified. It neither verifies a new
record nor supplies freshness. A readiness token additionally binds GenesisOrigin instance, exact held UC/TR,
observation generation, executor identity, and any current FreshBootstrapAdmission session/expiry.

## 4. Atomic boundaries and current-target adoption

### 4.1 Initialize

Given a checked GenesisOrigin and a new v2 database, create descriptor and revision-0 control in one syncing
transaction. No UC, readiness or signing permission is fabricated. Existing nonempty state must load/verify;
initialization cannot be used to clear it. This operation needs no freshness receipt because it creates data
only. The configured genesis must not be published as a synthetic certified record.

### 4.2 Admit an observation before adopting it

1. Bound/copy UC/TR and authenticate via stage 1 under local configured trust; classify relative to the verified
   durable observation using existing UC ordering/non-equivocation rules. Stale/duplicate deliveries do not
   regress/rewrite the target. A non-bootstrap result immediately invalidates in-memory bootstrap readiness
   while persistence is pending. Invalid/foreign messages grant no authority.
2. `PrepareObservation` verifies the current descriptor/control/head, captures a ProgressToken and constructs
   the next control. Set firstOrdinary if this is the first non-bootstrap pair; keep it byte-identical thereafter.
   This needs no executor RPC, B1 witness or DeriveV2 success. An authentic statement unsupported by the v2
   shape/epoch profile stops readiness; it is not an excuse to fall back to initial history.
3. Under the existing finality coordination, `CommitObservation` compares exact expected descriptor/control/
   head bytes and writes the next control in **one** syncing transaction. It changes no executor state and no
   ordinary head. CAS failure retries only within the caller's bounded admission budget.
4. Only after success may BFTClient install `luc`, Round/continuity/recovery install the current target, and
   consumers derive/build/sign from it. Feed the owned verified pair, not mutable network pointers. A crash
   after commit but before delivery reloads that pair and retries delivery; it is not lost to duplicate filtering.

Implement this as an opt-in admission boundary **before** BFTClient's current `c.luc = &cr.UC`, not only a
RoundDriver wrapper. Delivery/application failure remains separate from durable observation. A store failure
keeps prior durable state but makes the process unready; it must not keep building from the prior bootstrap
permit after learning ordinary progress. The unapplied retry path must include persist-before-adopt failures;
failed persistence cannot be converted into a successful duplicate/no-op. The admission coordinator has
one in-flight write preparation and one bounded newest-pair slot, retaining the first ordinary evidence
separately until durably latched. A retry episode has at most 3 CAS/write attempts, a 5 s overall deadline
and 1 s spacing; after exhaustion wait at least 10 s before another episode. Repeated delivery cannot reset
these budgets. Newer observations may replace the pending latest pair, never the pending first-ordinary
proof. Cancellation stops the episode and leaves readiness false. Ordinary supersession is never forgotten merely because execution is behind; intermediate history outside
the bounded retained set may need reacquisition before readiness.

All slow authentication is off Round/finality locks. Serialize admission by one coordinator and take no
Round mutex while holding the finality gate; release the gate before driver invocation. Current Round holds
its mutex before taking the gate, so reversing that order would deadlock. An old readiness token fails against
the changed persisted control even in the short interval before in-memory target adoption. Any operation
already holding the gate linearizes before the observation commit. Implementation must show this ordering
with a deterministic race test, not introduce an uncoordinated second head check.

### 4.3 Apply and publish a certified block

The verified observed certificate/continuity yields an exact certified block target. Resolve block/header and
witness outside locks. Authenticate B1's actual predecessor B0 for first-certified input; do not infer it from
state equality or Snapshot.ParentHash. Commit by block identity under the finality gate, whether sourced from
local pending work, repeat/re-delivery or recovery after restart. A new B1 must be canonicalized even when
S1=S0; the first root transition is still null->S0. Never treat an echo of B0 as the first executed child.

A `StatusValid` commit followed by exact Head number/hash/state confirms executor application; it does not
publish durability. Capture/re-verify witness and ordinary record, bind source UC/TR, prepare against current
control/head outside locks, then under the gate reconfirm executor target and CAS-publish outer record,
head pointer, incremented control revision and retention deletions in **one** transaction. firstOrdinary never
clears. A failed acquisition/publication leaves ordinary observation durable and readiness false; a later
bounded retry can succeed without a new transaction or local pending proposal. Existing W2 capture and
recovery notifications must share one retry coordinator, not create multiplying retry loops.

A later observed quiet UC may authorize readiness from this source only through authenticated continuity.
Publishing an older target must not erase a newer observation; preserve control's observedPair and reject a
stale preparation if it changed. Re-prepare against the newer control and prove continuity if appropriate.
Capturing does not manufacture missing certificate history or repair an unavailable executor by guessing.

## 5. Genuine bootstrap continuity and readiness

Bootstrap continuity begins at the exact UC/TR bound by the live admission receipt, not a fabricated S0 record.
Authenticate every pair and compare the full canonical initial IR with `InputRecord{Version:1}`: all state/block
fields are nil, round/epoch/timestamp and other numeric fields are zero. TR is genuine, hash-bound, epoch 0,
positive assigned round; root epoch equals the pinned one. An initial repeat retains that exact IR and advances
root round/assignment according to the existing repeat-normalization rule. No new genesis-state quiet record
is invented. A pair that certifies non-bootstrap work takes the ordinary admission path immediately.

Use the accepted assigned-round continuity rule, not consecutive integers: next new certificate must certify
the preceding TR's assignment, while repeats preserve the signed input and replace the assignment under the
root-order rule. Terminal UC/TR must match the actual held statement and assignment. Limit history as §3.4;
if a bootstrap tail exceeds the bound, obtain a new fresh admission at the genuine current initial pair rather
than assume the missing history. No protocol age policy is weakened by a new receipt.

For ordinary readiness, load a verified ordinary head record, prove continuity from its certificate/TR to
held, and match executor to that source by number/hash/state. Stage-2 DeriveV2 performs the v2 parent/origin
checks; it is not a substitute for storage continuity. Before Build and before release to signing, revalidate
under finality coordination the progress/head token, held observation, origin instance and executor. Bootstrap
also requires the live receipt and exact B0. Ordinary mode never requires or consumes a bootstrap receipt.
No signed v2 result leaves the node unless its separate authority/P-sign protection permits it. Followers
continue receiving/validating while readiness is unavailable.

## 6. Reload, rollback and recovery

Reload is bounded read/verification first: revalidate configured JSON origin, descriptor/control/evidence/head,
then executor identity. Never seed the configured client from the legacy certificate file. Validated durable
observedPair is the classification/retry seed, with its bound TR. firstOrdinary preserves the no-bootstrap
restriction when a target/record is unavailable; it is never a fallback target for corrupt or missing latest
observation/head bytes. Those cases retain the refusal below. Corrupt or inconsistent bytes are a refusal, not a reason to clear
metadata. A missing control in a nonempty store is corruption, not fresh initialization.

| Verified store / executor situation | Outcome and next step |
| --- | --- |
| Revision 0 or bootstrap-data; executor B0 | `bootstrap-admission-required`; fetch a fresh receipt, never restore one from disk |
| Bootstrap-data; executor non-genesis | `executor-ahead-of-bootstrap`; ordinary recovery/authentication required; no genesis fallback |
| Ordinary; head null | `ordinary-record-missing`; retain observed evidence, recover/apply its block source and capture |
| Ordinary head present; executor behind | `executor-behind`; certificate authorizes bounded reconciliation to that exact target |
| Ordinary head present; executor ahead | `executor-ahead`; authenticate its certified association/recover target, do not relabel it durable |
| Same height, different hash or state | `executor-diverged`; not ready; no automatic rollback to old/genesis state |
| Exact ordinary head | `ordinary-durable`; still require held continuity and normal admission/authority before child readiness |
| Missing/corrupt/foreign/version-mismatched descriptor/control/head | typed unavailable/untrusted/version refusal; no older-head fallback |

Same-disk monotonicity cannot detect a whole valid backup rollback. The receipt provider addresses fresh
bootstrap admission only, not general historical trust. Ordinary replacement recovery still obeys D6's trusted
checkpoint/history policy; old signatures alone are not a current trust initializer. If an older authentic
bootstrap database is restored, the new session must obtain current admission: a current ordinary response
selects ordinary recovery, and no response means unready. This is an explicit external evidence requirement,
not an assumed durable boolean. Known ordinary evidence from any authenticated source always defeats a
bootstrap receipt; failed persistence also defeats bootstrap in the current process. No new signing state is
stored here, and this store never overrides an independent signing-authority high-watermark.

## 7. Crash cuts and implementation handoff

| Cut/failure | Durable outcome; permitted continuation |
| --- | --- |
| Before initial transaction / after it | no initialized store / revision-0 data; both need fresh admission for bootstrap |
| Ordinary authenticates, observation write fails | prior disk state; current process unready, bounded retry; restart needs fresh current evidence |
| Observation transaction commits, before `luc`/driver adoption | ordinary supersession and exact observed pair survive; reload/retry delivery without needing pending proposal |
| B1 executor commit fails or returns syncing | ordinary observation retained; bounded application retry, never bootstrap |
| B1 committed, before capture/publish | executor-applied but ordinary record missing/behind; reacquire exact witness and publish |
| Record/head/control transaction fails before commit | all prior keys/control retained, no partial retention deletion |
| Transaction succeeds, process dies before reporting | reload exact record/control; duplicate publication/application is idempotent |
| Later quiet UC observed while capture in flight | observed target survives; stale capture CAS cannot overwrite it; re-prepare with continuity |
| Old bootstrap permit or backup replayed | permit fails session binding; disk data alone grants no admission; independent freshness required |

Implement/review separately: (a) inactive v2 storage/verification API with exact encoding and fault vectors;
(b) root freshness provider contract and implementation, if the automatic option is chosen; (c) configured
BFTClient admission, genesis/ordinary readiness, recovery and capture composition against reviewed 3a APIs.
No production bootstrap gate before its provider, no v2 execution activation before matching Go/client/
projection/companion evidence. Proven-profile first-BCR nil-state bypass remains prohibited and outside this
attested slice. Legacy/default path is unchanged.

Required implementation evidence includes exact byte vectors, malformed/foreign/aliased state, every crash
cut above, genuine initial-root timeout repeats, first B1 at S0 without pending proposal, corrupted/missing
witness, certificate movement under the gate, bounded acquisition failures, and old-session/whole-backup cases.
Run appropriate storage fault/race and integrated tests then; this PR has only source/reference inspection and
diff checks, no runtime tests, models, root-quorum exchange, devnet or activation evidence.
