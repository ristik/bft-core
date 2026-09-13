# F6c: signing authority across shard-process restart

Status: **accepted** (design) by the owner on 2026-09-11, first deliverable of #105;
Q1–Q3 approved as recorded in §9. Each implementation step still needs independent review.
Base: `fbc4d08b1a2bf7b3e8b58b5632d02053d6789535`. This document and its
executable model enable nothing. #92 is complete; #14 and #105 remain open.

## 1. Decision for the first private profile

Use one independent, fenced signing authority per validator signing key. The
authority owns the key and the signing journal; the shard process owns neither.
It admits structured certification requests, never arbitrary `SignBytes` calls.
The journal reserves the complete unsigned request before any signature can be
released. A shard process may restart or restore an older UC store, reconnect to
the same authority, reconcile P-id, and request signing without lowering the
authority's history. The old process is fenced on replacement.

The first profile deliberately supports **shard-process restart while the signing
authority remains alive**, not recovery of that authority's private key after its
own crash. The authority generates a fresh, non-exported signing key in memory;
it has no key-import, key-backup, seed-replay or generic signing endpoint. Loss of
that process loses signing availability for this identity. The signing record and
key have the same in-memory lifetime; no disk journal is required. Every new authority lifetime generates a
different public key: neither an empty directory nor an old journal recreates the
old identity. This is a private-deployment simplification, not the final operator
availability target. Generating or deploying such keys is not authorized by this PR.

**Operational cost:** every authority restart, including planned upgrades, host
maintenance or a crash, permanently removes that voter from the current assignment.
There is no implemented key-replacement procedure today. Until H-series/#10 supplies
one, a disposable private deployment needs a separately authorized fresh genesis to
recover that capacity. This profile is unsuitable for an always-available service.
It is not a suggestion to treat maintenance as a harmless restart.

This selects a concrete way to avoid making a false disk-freshness promise. It
costs a separate trusted process/host and loses a voter on *authority* failure,
instead of on every shard restart. A later recoverable authority/HSM profile needs
its own independently reviewed freshness and key-custody contract. It must not
silently replace this failure behavior with `load key + load journal`.

For an existing validator whose signing key has ever been exported, this profile
does **not** offer in-place migration. Its prior signatures and surviving key
copies cannot be reconstructed or revoked by scanning UCs. Keep that validator
non-voting after restart. A private fresh-genesis rehearsal with fresh authority
keys, or an independently authorized assignment/key replacement with the old key
retired, is the migration boundary. The latter belongs to the H-series/#10, not
an ad-hoc root protocol in #105.

## 2. Evidence from the actual boundary

| Location at the base | Consequence |
|---|---|
| `shardnode/round.go`, `completedRound`, `HandleCertificate` | In-memory replay retains one signed request by assigned round, authorizing partition round and root round; restart loses it. Persistence failure can re-deliver an already answered authorization. |
| `network/protocol/certification/block_certification_request.go`, `Bytes` | CBOR encodes the entire request with `Signature=nil`: partition, shard, node ID, IR, ZkProof, BlockSize and StateSize. Comparing only IR omits signed fields. Nil and empty byte strings must remain distinct. |
| `shardnode/inputrecord.go`, `ExpectationFromCertificate`, `ValidateLocal` | Assigned round/epoch, prior certified state and seal timestamp constrain the request. |
| `rootchain/consensus/storage/sharding.go`, `ValidRequest`, `nextRound` | Root admission checks those fields. Timeout/repeat advances the assigned round; use authenticated TechnicalRecord.Round, not UC round+1. |
| `cli/ubft/cmd/key_conf.go` | Signing and libp2p authentication keys are separate. Moving certification signing does not require exporting the signer key back for peer identity. |
| `shardnode/node.go`, `resumeFrom`, `persistingDriver` | Restored UC precedes any new signing action. SaveLUC follows handling; it cannot be the signing watermark. |

The legacy request preimage has no explicit network identifier, configuration hash,
root epoch, authorizing root round or new D5 domain prefix. This design does not
pretend otherwise or change the bytes signed. Scope metadata is an **authority
policy binding**, not a cryptographic addition to the legacy wire message. One key
is enrolled for exactly one immutable network/partition/shard/config/epoch/profile.
Reusing that key on another network would undermine this restriction and is
forbidden. D5 root-vote slashing domains are a different protocol and are not
implemented by this journal.

## 3. Trust model and alternatives

The adversary may replay/delete/corrupt all shard-node files, replay certificates
and RPC responses, delay or duplicate messages, race two old/new shard processes,
and crash the shard at any instruction. It may exhaust resources and cause loss of
availability. It cannot forge root certificates or compromise the enrolled key's
signing authority, its host, or its authenticated operator control plane.

The authority host is outside shard backup/restore, snapshot, key-export and
process-cloning domains. Restoring a VM snapshot of the authority, duplicating its
memory/key, arbitrary authority journal rollback during its lifetime, malicious
authority code and compromise of the key are **outside** this initial profile.
No checksum or file lock can detect those attacks. Operators unable to enforce
that isolation cannot enable this profile. A same-directory sidecar does not
satisfy it merely by having a different PID. Network failure means non-voting;
there is no fallback local signer.

| Mechanism | What it buys | Why selected / deferred |
|---|---|---|
| Local WAL + fsync + exclusive lock | Ordinary crash safety on an honest unreplayed filesystem | Cannot distinguish a complete old snapshot or a second host with the key. Insufficient for #105's node-store replay threat. |
| Local MAC/checksum or second watermark | Corruption detection, not freshness | A complete older valid pair replays. Rejected as anti-rollback authority. |
| Independent journal while the node retains its key | Fresh admission decisions | A key-holding clone bypasses the journal. Requires a different trusted-client threat model; not selected. |
| Independent key-owning authority, fail-stop on authority loss | Node-store replay cannot reset signing history; serial admission survives node restart | Selected private profile. Availability cost and host-isolation assumptions explicit. |
| Recoverable remote signer/HSM or monotonic service | Potential authority restart/host recovery | Backend-specific durability, fencing, key import and whole-store freshness require evidence. No such primitive is assumed shipped here. |
| Root-certified signing recovery/epoch replacement | Potential recovery independent of local storage | Changes root/operator protocol and history assumptions. Existing handoff may eventually provide it; no new consensus path justified for this first unit. |

An arbitrary malicious shard can request a wrong execution result. Anti-equivocation
does not prove execution: existing honest-node P-id/verification and validator
assumptions still apply. The authority independently authenticates *authorization*
and binds the request; it is not another EVM.

## 4. Scope, conflicts and authenticated input

Enrollment fixes an opaque authority ID, signing public key fingerprint, NodeID,
network/genesis identity, partition, canonical shard bytes, shard epoch,
configuration hash, and signing profile `legacy-bcr-v1`. Root trust/configuration
comes from the authority's own provisioned context, never from the requester's
claimed verifier result. Root-epoch transitions and configuration/key changes are
unsupported in this profile: freeze, not a fresh empty journal namespace.

The production structured request must carry the UC and bound TechnicalRecord.
Before reservation the authority verifies signatures/quorum, inclusion paths,
partition/shard/config, root trust epoch, TR hash and assigned epoch against local
trust, then derives `ExpectationFromCertificate` and validates the proposed BCR.
It also checks enrolled NodeID, request PartitionID/ShardID, supported version and
all bounds. Authenticity is not freshness; the journal supplies the latter.
No `authenticated=true` field received over the network is authority.

Record the signature-free authorization identity as canonical CBOR of a versioned
array containing UC.InputRecord.Bytes(), UC.UnicitySeal.SigBytes(), and canonical
TR bytes after verifying their bindings. Valid seal signer subsets then identify
the same authorization. This metadata explains a decision; it never partitions
the conflict lock. A different root round cannot reopen an already signed round.

The conflict key is `(enrolled key, immutable profile, assigned partition round)`.
Epoch/config/network are immutable enrollment guards, not map keys a caller can
change to escape a previous decision. For one conflict key there is at most one
complete unsigned BCR byte string. Even different valid authorizations for that
same assigned round cannot authorize different bytes. If the root legitimately
assigns a higher round after a repeat, that is new work. A gap is permitted only
when an authenticated TR assigns that round; do not manufacture consecutive rounds.

On the highest reserved round:

- identical complete bytes return the retained signed response;
- differing bytes are `signing-conflict`, never a rebuild or a retry override.

Below the highest reserved round, refuse `signing-stale`, even for identical bytes.
Keeping just the highest request is thus bounded and safe; the availability cost is
that old delivery retries stop once new signing work has superseded them. The
application can still accept/reconcile old evidence under its separate rules.

## 5. State and linearization

Authority state: immutable enrollment; current fenced client generation; highest
reserved round; full unsigned bytes; completed signed response (if any); and
health `active / faulted / lost`. The record is process memory, owned by the same
authority lifetime as the key. Proposed initial cap: 1 MiB
per complete unsigned request and 2 MiB per active journal record including
response/metadata; reject oversize before decoding or allocation on the wire.
Future larger proof profiles need an explicit version/config review, not truncation.

The current process gate in Round remains until all implementation steps below
land. Its eventual replacement requires **both** current P-id and live authority
admission. It must run for fresh starts too: deleting the UC file is not a way to
select a local signing path. Observe, applied, durable UC and signed cursors remain
separate; an unchanged executor head cannot advance or rewind the signing cursor.

| Transition | In-memory authority state / response |
|---|---|
| Enroll fresh authority lifetime | Generate non-exported key; fix enrollment in memory before returning its public key, except the shard configuration hash. That hash commits to the validators' signing keys, including this one, so it is stated once afterwards from a configuration the authority checks names its own key, and no session exists before then (amended 2026-09-13; see "Deployment wiring, before step 4" in §8). No existing-key import or bootstrap from UC history. |
| Replace shard client | Operator-authenticated control operation increments generation atomically; old tokens cannot reserve/sign/release new work. Client cannot mint a generation. |
| Validate request | Check enrollment, client generation, authenticated context and size; no journal mutation on refusal. |
| Reserve new higher round | Serialize compare-and-reserve; retain the full preimage, new round and metadata atomically before invoking signing. Lower rounds become refused even if no signature was ever produced. |
| Sign reservation | Sign only that owned immutable preimage. A failure leaves the reservation; never reclaim its round for different bytes. |
| Store signed response | Retain exact signed BCR bytes before release. A shard disconnect does not clear them. A failed private signing attempt may retry the same bytes; authority death loses the key as well. |
| Release/replay | Recheck active generation and journal consistency. Release only the retained response; identical retries after lost responses get identical wire bytes. |
| Detected internal state inconsistency | Latch non-voting for the authority; no reset while retaining the key. Memory corruption is not universally detectable and is outside the honest-authority assumption. |
| Shard restart | New fenced session against the same live authority; stale UC affects evidence availability, not the signing cursor. |
| Authority process/host loss | Key and signing record are lost together; any optional diagnostic export grants no authority. Never infer fresh enrollment for the old identity from missing files. |

Admission and release share one serialization domain with fencing. If fencing wins
before release, the old client gets no new response. A response already released
may arrive after fencing; messages/signatures in flight cannot be recalled. Its
content is still the one permitted for that round. New client retries cannot
obtain a conflicting response. No time lease is used as a proof that an old process
has stopped; monotonic generations are checked by the key owner at every operation.

Bound concurrency and queue length before parsing. One signing operation per key;
no unbounded waiter queue. A request timeout cancels waiting, not an admitted
reservation. The next client queries/retries the same reservation. An unavailable
authority cannot block the Round lock or observation feed; return a distinct
non-voting status and retry with bounded backoff. Rate limits protect availability,
not safety. An old client may cause denial of service if it retains operator
credentials; it cannot reset the conflict journal. Separate operator and client
credentials in deployment.

Generation and round arithmetic must never wrap. Generation exhaustion disables
admission; a root assignment that cannot be represented is refused, not coerced.

The client connection authenticates both endpoints and pins the authority's
enrolled signing public key as well as its transport identity. A replacement
authority returning a fresh key is not accepted for the configured validator.
Client credentials permit signing requests only; session takeover requires the
separate operator role. Enforce this at the authority, not in a caller's config.
RPC authentication, operation correlation and wire-size admission have their own
implementation tests; the executable design does not claim to test a transport.

Each operation/response also names its reserved round and full preimage digest.
A delayed call for an older reservation must receive `signing-stale`, not the
response of the newer reservation now occupying the bounded slot. The client
validates the returned signed BCR against its requested bytes before sending it.
The model stages signing on the current reservation, and tests that release
cannot answer a caller for another round or request digest; production asynchronous signing work
must additionally carry its reservation identity through completion.

## 6. Crash and operational outcomes

| Boundary or input | Required result |
|---|---|
| Before reservation is recorded | No released signature; retry against the live authority. Shard cancellation cannot erase an already admitted reservation. |
| After reservation, before signing | Same bytes may finish; altered candidate at that round refused. |
| After signing, before response retention | No response released; same reserved bytes may be signed again, regardless of deterministic-signature assumptions. |
| After response retention, before/after network delivery | Replay exact stored response. Losing the caller or a UC-store write cannot alter it. |
| Whole older shard backup, including old session token | New session required; authority history unchanged. Old token fenced, lower rounds refused. |
| Missing/corrupt shard UC store | May diagnose/recover evidence as supported by #14; cannot bootstrap a signing key or bypass authority checks. |
| Missing or inconsistent active authority record | If an invariant fails, `signing-state-untrusted`; never clear the record and continue with the same key. No journal import or restore path exists. |
| Restored backup/replacement host for authority | Old identity cannot start: no private key import exists. Require separately authorized fresh assignment, not a reset counter. |
| Two shard instances | Only current generation can newly release; same-round changed bytes refused across generations. |
| Key/domain/epoch/config substitution | `signing-context-mismatch`; no state reset, no signing. |
| Authority unavailable or key lost | `signing-authority-unavailable` or `signing-key-lost`; keep observing/reconciling, never vote locally. |

**No safety-critical disk writes in this profile.** When the key cannot survive
process death, making its signing record survive death adds no safety: nothing can
sign with that identity afterwards. A required disk write would add an avoidable
availability failure. Optional diagnostic logging must not gate signing or supply
recovery authority. Therefore step 2 does not require WAL/fsync fault injection.
A later profile that retains or restores the key must revisit durable-before-release,
whole-store freshness and atomicity together; none is discharged by this model.
Full block/UC/TR persistence and its storage-failure tests remain #14's work.

## 7. Executable design evidence and its limits

`docs/design/models/f6csigning/contract_test.go` is test-only and imported nowhere.
It models a trusted atomic in-memory authority record, generation fencing, staged reservation,
signature production, response retention and release. It enumerates shard crashes at
each boundary and adversarial request ordering. It also uses the real BCR Bytes and
secp256k1 signing/verification APIs to pin complete-message and nil/empty semantics.

It does not implement RPC, real UC verification, a filesystem journal, key isolation
or the production Round gate. The input-authentication premise is explicit; no model
verdict is a network format. Its crash model discards client state while retaining
the independent authority. Authority loss is tested as permanent key unavailability.

Run `go test -race ./docs/design/models/f6csigning -count=5`.

| Design obligation | Fixture |
|---|---|
| Retain-before-release and all client crash cuts | `TestCrashBoundariesKeepOnePreimage` |
| Entire signed message, size fields, timestamp and nil/empty proof | `TestFullRequestAndCanonicalBytesAreTheLock` |
| Historical node state and quiet executor cannot reset watermark; assigned-round gaps | `TestHistoricalCheckpointQuietHeadAndRepeatCannotResetSigning` |
| Immutable enrollment, including epoch/config/domain | `TestScopeIsEnrollmentNotAResetNamespace` |
| Authority loss or untrusted storage cannot bootstrap old identity | `TestAuthorityLossAndDetectedStateFaultNeverBootstrap` |
| Conflicting concurrent candidates, fenced release, owned response bytes | `TestConcurrentCandidatesAndFencedRelease` |
| 256 adversarial request/fence schedules | `TestAdversarialOrdersNeverReleaseTwoStatements` |
| Negative control: replayable key-holding authority can equivocate | `TestReplayableLocalJournalIsNotFreshness` |
| Delayed caller cannot receive a different reservation's response | `TestLaterReservationCannotAnswerAnEarlierCall` |
| Release binds the full request digest as well as its round | `TestReleaseBindsRoundAndRequestDigest` |
| Authority replacement generates a different key, requiring fresh enrollment | `TestLostAuthorityCannotRecreateEnrolledKey` |
| Exhausted generations cannot revive an old token | `TestGenerationCannotWrapIntoAnOldSession` |

## 8. Implementation handoff after independent design acceptance

1. **Authority boundary and protocol fixtures.** Build the narrow structured signer
   interface and real UC/TR/BCR authentication fixtures. Pin enrollment scope and
   existing signed bytes; reject all generic signing/key-import paths. Test network,
   epoch/config substitution, missing proof, signer-subset canonicalization and
   repeated authenticated assignments. No runtime re-enablement.
2. **In-memory record, custody and fencing.** Implement bounds, compare/reserve,
   retain-before-release, exact response replay and operator-controlled session
   replacement. Inject client cancellation and authority death at each boundary. Demonstrate
   node-backup replay cannot reset a live authority; authority restart cannot recover
   its old key. Review deployment isolation and lack of local signing bypass.
3. **Round integration.** Route every BCR through the authority; retain P-id before
   Build/vote, keep the root-feed renewal independent of signing, and fence old
   instances. A rebuilt candidate conflicting with a reserved request must use the
   recorded request only when the current authenticated authorization permits it,
   otherwise abstain; never overwrite the reservation to regain liveness. Preserve
   runtime replay and persistence-failure regressions. Keep key-generation/activation
   explicit; do not auto-convert existing KeyConf files.
4. **Private acceptance.** Fresh approved authority keys, actual reth, shard-only
   restarts and old shard-backup restoration: recover first, then sign/follow new
   work with no conflicting message. Kill the authority: demonstrate non-voting and
   no automatic new-key substitution. Race old/new shard processes and interrupted
   sends. This is the step that may replace the unconditional restored gate under
   the accepted profile; no earlier PR may do so.

### Step 1 as implemented

`signingauthority/` is the boundary and nothing more. `New` enrolls one immutable scope and
generates the key for that authority lifetime; an enrollment that names a key is refused, because
there is no import path to honour it. `Authenticate` takes a structured request (certificate, bound
technical record, proposed certification request), checks it against the authority's own provisioned
trust and its enrollment, and returns the authorization: assigned round and epoch from the
authenticated technical record, the canonical authorization identity, and the complete
signature-free preimage with its digest.

The package has four exported methods, pinned by a test: `Authenticate`, `Close`, `Enrollment` and
`SigningPublicKey`. There is no `SignBytes`, no key import or export, and no journal load.

Repairs after the first review of step 1 (PR #137, head `818add57`):

- **One owned snapshot before any check.** `Authenticate` encodes the proposal once, bounds that
  encoding, decodes it back into a structure the authority owns, and copies the certificate and
  technical record. Every check, the authorization identity and the returned preimage come from that
  snapshot. Previously the proposal was encoded first and the caller's structure validated
  afterwards, so a change during the trust lookup could separate validated content from returned
  bytes in either direction.
- **The root epoch is enrollment context.** §4 makes root-epoch transitions unsupported, but
  enrollment pinned only the shard epoch, so the next genuine root epoch was accepted in the same
  authority lifetime. `Enrollment.RootEpoch` now states the permitted epoch, is never inferred or
  reset per request, and a certificate from another epoch is refused as `signing-context-mismatch`
  rather than as an authentication failure, because such a certificate verifies perfectly. It is a
  pointer so that "not stated" and "pinned to epoch 0" stay distinct: nothing rejects epoch 0 in a
  seal, and an enrollment that never named one is refused.

  The freeze is checked **before** the trust lookup, so that an epoch chosen by whoever sent the
  request cannot select which trust base the authority fetches. One consequence is worth stating,
  because §4 asks for the freeze to stay separate from authentication failures: a certificate that is
  forged *and* names another root epoch is refused by the freeze, at a point where nothing about it
  has been authenticated. The refusal therefore reports what the certificate **claims** and says so,
  rather than asserting that it is genuinely from that epoch. A certificate naming the enrolled epoch
  reaches verification, where a forgery is reported as `signing-unauthenticated-input`.

Refusal names raised by this step: `signing-context-mismatch` for enrollment substitution (node,
partition, shard, network, configuration, shard epoch or profile), `signing-unauthenticated-input`
for a certificate, quorum, inclusion path or technical-record binding that does not verify,
`signing-proposal-mismatch` for an authentic authorization whose proposal is not the one it assigns,
`signing-request-too-large` for a request over the 1 MiB bound, `signing-unsupported-version`, and
`signing-key-lost` for a closed authority. `signing-unauthenticated-input` and
`signing-proposal-mismatch` are new here: §6 named the outcomes, not these two codes.

What step 1 does not do, and what therefore cannot be claimed from it: there is no signing record, so
a replayed but genuine authorization passes `Authenticate` every time. Nothing is reserved, signed,
retained or released, no round is wired to the authority, and the restored non-voting gate is
untouched. Authenticity is checked here; freshness is step 2.

The authority restates `shardnode.ExpectationFromCertificate` and `shardnode.ValidateLocal` rather
than importing them, because step 3 wires `shardnode.Round` to this package and importing `shardnode`
here would be a cycle. `TestExpectationMatchesTheShardNodeRule`, in the external test package, holds
the two rules against each other so the copy cannot drift silently.

### Step 2 as implemented

The signing record lives in `signingauthority/record.go` and the operations on it in `authority.go`.

**Sessions and fencing.** `ReplaceSession` is the operator control plane: it advances the generation,
so every token issued earlier stops being admitted, and it changes nothing else. A client cannot mint
a session, and that is enforced by the type rather than by convention: `Session` has no exported
field, so outside this package only its zero value can be constructed, and the zero value is never
admitted. Fencing does not clear the record; the replacement client inherits the same history, which
is the point of fencing rather than restarting.

**The record.** One reservation, for the highest assigned partition round admitted so far, holding
the complete unsigned request, its digest, the authorization identity that admitted it, the private
signature and the retained response. The conflict key is the assigned round with the enrolled key and
profile, so a different root round produces no second record.

`Reserve` authenticates first (step 1) and then compares: the same bytes at the reserved round are
admitted again and answer identically, different bytes at that round are `signing-conflict`, a lower
round is `signing-stale` even for identical bytes, and a higher round replaces the record including
any response for the older one. Gaps are permitted, because an authenticated technical record assigns
the round and assigned rounds are not consecutive integers. A cancelled caller stops waiting and does
not return a round it already holds.

`Sign` signs the bytes the authority owns and takes no bytes from the caller. `RetainResponse` makes
the response replayable before any of it can leave. `Release` requires the caller to name both the
round and the request digest, so a delayed call for an older reservation is refused rather than
answered from the newer one now occupying the slot.

**Faults and death.** A detected inconsistency between the record's own parts latches the authority
faulted: the record is kept, the key is kept, nothing further is signed, and there is no reset.
Generation exhaustion latches the same way rather than wrapping into an old session. `Close` discards
key and record together, because a record outliving its key would describe signing that nothing can
perform, and a key outliving its record could sign a round again.

**Bounds.** 1 MiB per complete request, 2 MiB per record including the retained response. Bounding
concurrency and queue length is the transport's job (§5) and is not implemented here; a mutex
serialises operations and callers wait.

Repairs after the first review of step 2 (PR #140, head `17be3393`):

- **A session names the authority that issued it.** `Session` carried only a generation, and every
  authority starts counting at the same place, so a token issued by one authority was admitted by
  another that happened to be at the same generation. Each authority now draws a private 128-bit
  identity for its lifetime, and a token carries it; a foreign token is refused on every client
  operation. The identity is not in `Status`, not in `Enrollment` and not derived from anything an
  operator can name, because a published identifier would not be a capability.
- **The caps compose.** The record kept the request, the signed response and a second copy of that
  response, so a 750 KB proof was admitted and signed and then could never be retained, leaving a
  round locked and answerable by nothing. Retention is now a flag on the one response copy rather
  than a second copy, and `MaxRecordBytes` is derived from `MaxUnsignedRequestBytes` plus the
  authorization identity and a signing allowance rather than being an independent number. `Reserve`
  also projects the completed record before locking the round, so anything admitted can be
  completed.

**What step 2 does not establish.** No round is wired to the authority and the restored non-voting
gate is untouched, so this changes no runtime behaviour. There is no transport, so nothing here tests
RPC authentication, wire-size admission or operation correlation. There is no durable journal, by
§6: with a key that cannot survive process death, making the record survive it adds no safety.

### Step 3 as implemented

Step 3 wires the round to a signer. `shardnode.CertificationSigner` is the single funnel every
certification request goes through, `LocalKeySigner` is the default and preserves exactly today's
behaviour, and `NewAuthoritySigner` routes the request through a signing authority instead. A round
is switched over by an explicit `SetCertificationSigner` call at wiring time; nothing about
constructing a round enables it.

**Where the signer sits in a round.** After the certificate has been observed, classified, committed
and reconciled, and after the P-id identity gate; before anything is retained as the completed round
and before the send. So:

- P-id is still retained before Build and before any signature is requested: a node that cannot prove
  its executor is on the certified block never reaches the signer at all.
- The restored non-voting gate (P-sign) is unchanged and still earlier, so a restored process does not
  request a signature. Step 3 does not re-enable restored voting.
- The root feed is untouched by signing outcomes. A refusal returns nil from `HandleCertificate`, not
  an error: the certificate was already applied, and a refusal must not present itself as a delivery
  failure that re-drives the round or drops the subscription.
- A re-delivered round replays the retained signed request through `completed`, without asking the
  signer again.

**A refusal is an abstention.** When the signer refuses, for any reason, the round records an IR
divergence, sets the node non-voting with a reason naming the refusal, logs it, and sends nothing.
It does not rebuild the candidate, retry with other bytes, or sign locally. `signing-conflict`,
`signing-stale`, `signing-session-fenced`, `signing-state-untrusted`, `signing-key-lost` and an
unreachable authority are distinguishable in the health reason, because they are different situations
for an operator, and none of them is a reason to find another way to sign.

**What the wiring narrows, and what it does not.** The round is given `SigningAuthorityClient`,
which declares `Reserve`, `Sign`, `RetainResponse` and `Release` and nothing else. Omitting
`ReplaceSession` narrows what this code can call, and the type carries no constructor and no key, so
there is no path here that mints a session or rebuilds an authority after a restart. That is API
narrowing, not process isolation and not a capability boundary: a value whose dynamic type is
`*Authority` can be asserted to an interface that does have `ReplaceSession`, and in this
unactivated profile the round still holds the legacy key. An authority in a separate process, with
operator credentials separate from the shard's and a lifetime independent of it, remains a
prerequisite for activation (§6, §8.3) rather than something the interface provides.

**The client checks every answer against its own work.** The signer takes its own copy of the
proposal before it calls the client, and that copy's preimage, digest and assigned round are the
expectation. The reservation must name them; the release is asked for by them; the released bytes
must re-encode to that same preimage and must verify under the enrolled authority's signing key,
provisioned with this node's configuration and never read from the response being checked. Two
remote answers agreeing with each other establishes nothing, so a consistently substituted exchange
is refused, and a present-but-invalid signature is refused rather than cached as a completed round.
Verifying the response does not stop an authority from signing two different requests, which is what
the record inside the authority is for; it stops a corrupt or misrouted answer from becoming this
node's vote.

**A refusal is retained.** The candidate taken to the signer is recorded before the call, with the
refusal recorded on it. A re-delivery of the same authorization, which the delivery layer produces
whenever applying a certificate fails after the round ran (a failed checkpoint write, for example),
abstains again with the reason first recorded, without building a second candidate and without
asking again. This matters most where the answer was lost rather than refused: the authority may
already hold a reservation for the first candidate, and a rebuild against a mempool that has moved
on would strand it behind a conflict. A genuinely new authorization is a different key and builds
normally.

**What step 3 does not establish.** There is still no transport, no durable journal, no production
activation and no key replacement: nothing in a deployed configuration selects the authority signer,
and no existing KeyConf file is converted. Restored voting remains disabled. Step 4 (private
acceptance) is separate and gated.

### The authority process boundary, before step 4

Step 4 exercises an authority an operator can kill, race and re-provision. Steps 1 to 3 left the
authority a library, so its lifetime was the shard process's lifetime and both sides drew on one
credential space. §3 asks for the opposite: a host outside the shard's backup, snapshot and
process-cloning domains, where a same-directory sidecar does not qualify merely by having a
different PID. `signingauthority/service` is that boundary, and it comes before step 4 rather than
inside it.

**What crosses.** A length-prefixed CBOR message naming one of four operations: reserve, sign,
retain, release. There is no message that carries bytes to sign, none that reads or writes a key,
and none on the client endpoint that replaces a session. A frame larger than the derived maximum is
refused on its header, before its body is read or allocated, and the connection ends there because
it is no longer at a known boundary. A frame of another protocol version is refused rather than
coerced. Connections are bounded per endpoint, one request is served at a time on each, and a
connection that does not produce a complete message within the idle deadline is closed.

**One authority per path.** A socket path is claimed with an exclusive lock on a file beside it, held
for as long as the listener is open. A second authority started on a path that a running one serves
is refused (`ErrPathHeld`) rather than removing the socket and listening in its place: the shard node
dialling that path could not tell the two apart, since the operations and refusals are identical, and
two keys for one enrolled node is what §3 exists to prevent. The kernel releases the lock when its
process dies, and that is the only condition under which an existing socket file is removed.

**Two credentials, two endpoints.** The client endpoint admits the current client credential only.
Anything else (an old credential, an operator credential, no credential) is
`signing-session-fenced`, the same answer an old generation gets in one process. The operator
endpoint has its own credential and is the only place session replacement, status and enrollment
live. Neither endpoint falls back to the other, and the endpoint refusal is decided before any
credential is compared, so a misconfiguration is diagnosable without one being involved in the
answer.

**Where the session lives.** The shard process holds no `signingauthority.Session`. Replacement
mints the session inside the authority process and returns a bearer credential the server maps to
it; the unmintable type stays where the key is. Replacing fences the old credential in the same step
that advances the generation, so the two cannot disagree about who is admitted, and a fenced shard
process cannot unfence itself because what it holds is the thing that was invalidated. The whole
replacement (advancing the generation, drawing the credential, installing both) is one critical
section. The authority orders concurrent replacements, and the server must install them in that
order; otherwise a replacement that won inside the authority can lose the race to install its
credential, and the server ends up admitting a credential the authority has already fenced, leaving
no returned credential usable. With the section held, concurrent replacements leave exactly one.

**Unavailability is not a refusal.** No process listening, a connection that died mid-exchange, a
deadline, a caller that cancelled: all of these are `signing-authority-unavailable`, distinct from
every decision the authority makes. The round abstains either way, and an operator can tell "the
authority said no" from "the authority said nothing". A connection that was already cached and turns
out to be dead is retried once on a fresh one, which is safe because every operation here replays
rather than repeats. There is no fallback local signer at any point.

**One deadline per operation, and cancellation reaches the socket.** The client's timeout bounds the
whole operation: waiting behind another operation for the connection, connecting, sending, reading
the answer and the single retry share one deadline, the earlier of the caller's and the configured
one, and the retry is not attempted once it has passed. A cancelled context wakes a call blocked in a read or write by moving the connection's
deadline into the past, because a `net.Conn` takes no context; waiting for the next operation slot is
interruptible for the same reason. A cancelled caller stops waiting. As §6 already states, that does
not undo a reservation the authority has admitted.

**Server operations are bounded and end with the server.** Socket deadlines bound reading and
writing, but a reserve can wait on something other than the connection, such as the trust lookup
that authenticates its certificate. Each dispatched operation therefore runs under a context derived
from the server's own lifetime, bounded by `OperationTimeout` and cancelled by `Close`, so a lookup
that never returns can neither hold a connection's handler indefinitely nor keep shutdown waiting.
That context is not tied to the connection: a client that goes away mid-request withdraws nothing,
and cancellation stops waiting without undoing anything the authority has already admitted. A
lookup that runs out of time is refused as `signing-unauthenticated-input`, because the input was not
authenticated, and the connection and server continue serving.

**What the tests establish.** A real second operating-system process holds the key: killing it makes
every client operation unavailable and nothing else; restarting it produces a DIFFERENT key for the
same enrollment, the old client credential is refused, and returning to service is a fresh operator
assignment rather than a reset. A shard-side client going away leaves the authority holding its
reservation.

**What it does not do.** It does not authenticate hosts or encrypt the wire: it is a local transport
for a private profile, and a socket in a directory only the two parties may enter is the isolation
it assumes, on top of the host separation §3 already requires of the operator. It activates nothing:
no command runs a server, no deployment flag selects an authority for a shard node, no KeyConf file
is converted, and the restored non-voting gate is untouched. The shard node's own interface lost its
session argument in this change, because a shard process that talks to an authority holds a
credential rather than a token, and binding a session is the local adapter's job
(`signingauthority.NewLocalClient`).

### Deployment wiring, before step 4

Step 4 needs an authority an operator can start and a shard node that can be pointed at it. This
section is that wiring. It changes one enrollment rule, by owner decision on 2026-09-13, because the
rule as first written could not be deployed.

**Enrollment is completed after the key exists.** The shard configuration hash that every
certificate commits to covers each validator's `SigKey`, and the root chain verifies a validator's
certification requests under that key. The authority generates its key in `New`, and §5 fixed the
enrollment, hash included, before the public key was returned. So no configuration naming an
authority's key could exist when that authority was enrolled, and an authority enrolled for any
existing configuration signed under a key that configuration does not name. The two-phase rule
resolves this without taking a hash from the operator:

- An enrollment without a `ShardConfHash` is pending. The authority generates its key, publishes the
  public half through the operator endpoint, and admits nothing: `ReplaceSession` and `Authenticate`
  refuse with `signing-enrollment-incomplete`, so no client credential exists yet.
- `CompleteEnrollment`, on the operator endpoint only, carries the whole configuration. The authority
  checks that it is valid, that it is for the enrolled network, partition, shard and shard epoch,
  and that it names the enrolled node with this authority's own public key. Only then does it compute
  the hash and fix it. A refused completion changes nothing, and the reason is logged by the
  authority process, since the operator's client receives only the refusal name.
- A second completion is refused (`signing-context-mismatch`), including one with the same
  configuration, so the enrollment cannot be moved to another configuration within a lifetime.
- An enrollment given a hash at `New` is complete from the start. That hash was computed before the
  key existed, so a configuration with that hash cannot name the key, and anything signed under it
  fails the root chain's check. It remains for in-process use and fixtures; the command below never
  uses it.

**The authority command.** `ubft signing-authority run` generates the key and serves the client and
operator sockets, each claimed as before. Every enrollment field is a required flag, including the
shard epoch and root epoch, whose zero values are meaningful and therefore not defaults. No flag names
a key, a key file or a seed. The trust base must be for the enrolled network and root epoch. The
operator commands reach the authority only through the operator socket with the operator credential:

- `credential` creates an operator credential file and does not overwrite an existing one.
- `node-info` writes the enrolled node ID with the authority's public key, which is what
  `shard-conf generate --node-info` takes. The node info `shard-node init` writes names the key
  configuration's own signing key, which the authority does not hold, and a configuration generated
  from it is refused by both sides. An existing node-info file is not overwritten, because a file
  from an earlier authority lifetime names a key that no longer exists.
- `complete-enrollment` sends the configuration; `replace-session` writes the client credential by
  renaming a new file over the old one, and the previous credential is fenced in the same step;
  `status` prints the enrollment and the record's state, without request bytes or credentials.

Credential files are hex text of `CredentialBytes`, created readable by the owner only, and refused
when other users can read them.

**The shard node.** `shard-node run --signing-authority-socket ... --signing-authority-credential ...`
selects the authority signer at startup, before anything else is built. What the shard side trusts
comes from its own configuration:

- The key responses must verify under is the one the shard configuration names for this node's ID,
  the same key the root chain uses. It is never read from the authority.
- A configuration naming the key configuration's own signing key is refused, as is a configuration
  that does not name this node.
- No local signer is retained or passed to the round. `shardnode.New` receives none, and
  `LocalKeySigner` refuses to sign without a key rather than panicking, so there is no local key for
  the round to fall back to. (Correction, 2026-09-13: this bullet first said no local signer is
  constructed. `localSigningKey` does construct a temporary signer from the key configuration, only
  to derive its public key for the comparison above, and does not keep it.)
- The node holds the client credential only. The operator credential is not a flag of this command.
- An authority flag without the socket is refused, so a mistyped deployment does not start signing
  with the local key.
- One authority operation is bounded by the shard's T2 unless `--signing-authority-timeout` says
  otherwise, because a signature arriving after T2 is of no use to that round.

The key configuration is not converted. Its authentication key remains the node's libp2p identity
and node ID, and its signing key stays in the file, unused while an authority is configured.

**What this does not change.** Without the new flags a shard node signs with its local key exactly as
before, so no existing deployment changes behaviour. The restored non-voting gate is untouched: a
node resumed from a persisted certificate still requests no signature, with or without an authority,
and step 4 remains the only step that may replace it. The transport is still a local Unix socket, so
§3's host separation remains the operator's to provide; nothing here carries the socket between
hosts. Stopping the authority loses its key, as §1 states. An authority's key reaches a validator set
only through a newly generated shard configuration, which needs the separately authorized fresh
genesis or assignment of §1 and Q3; this wiring authorizes neither, and replaces no existing
validator's key.

**What the tests establish.** In `signingauthority`: a pending authority issues no session and
authenticates nothing; completion checks node, key, network, partition, shard epoch and validity, a
refusal leaves it completable, and completion does not reopen; a request under the completed
configuration is reserved, signed and released, and the response verifies under the key that
configuration names. Across the service boundary: the refusal name crosses the wire, the client
endpoint does not serve completion, and the same exchange completes. In the CLI, the deployment order
runs with the real commands: an authority started by `run` in its own goroutine, a second `run` on
its sockets refused, `replace-session` refused while pending, `node-info` feeding `shard-conf
generate`, a configuration from the local node info refused, completion, a client credential, and a
shard-side signer built by the same function `shard-node run` uses. Its response verifies under the
configured key and not under the key configuration's key; replacing the session fences it; stopping
the authority makes it unavailable. The selection rules have their own cases. The tests do not run
the `shard-node run` binary against an authority, so the two lines in `shardNodeRun` that pass no
local signer and install the authority signer are checked by review rather than by a test. The
process acceptance below exercises both with the real binary.

### Process acceptance, before step 4

The deployment tests above run the authority's `run` command in a goroutine of the test binary and
build the shard-side signer by calling `buildCertificationSigning` directly. The acceptance lane
`scripts/f6c-authority-acceptance.sh` runs the same sequence with separate operating-system
processes: one `root-node run`, one `signing-authority run` and one `shard-node run` with the fake
executor, each a `build/ubft` process started from the checkout, and the operator commands as
separate invocations. Each scenario uses a fresh cluster in which this node is the shard's only
validator, because fencing, authority loss and a restart each end the node's voting for the life of
its process.

**Setup in every scenario.**

- The authority process starts pending. `replace-session` is refused with
  `signing-enrollment-incomplete`, and no client credential file exists.
- A configuration generated from the node info `shard-node init` wrote is refused by
  `complete-enrollment` with `signing-context-mismatch`.
- The configuration generated from `signing-authority node-info` names the node with the authority's
  key. Its fingerprint equals the one the authority process logged and differs from the key
  configuration's key. Completion and `replace-session` then succeed at session generation 1.
- A control against the root verifier: the same node started without the authority flags, signing
  with its local key and using a separate checkpoint file, has its request rejected by the root chain
  with `signature verification: verification failed`, and the root reaches no consensus. Every
  consensus the root reaches afterwards is on a request from this node that passed the same check
  under the key the configuration names.
- `shard-node run` with the authority flags logs the authority signer pinned to that fingerprint.

**Positive control** (fencing, authority loss and restart). The node submits three requests through
the authority, the root reaches consensus three times after the control and rejects no request, and
the node accepts three valid certificates. The authority's record holds a round for which the node
logged a submission, and health reports `voting=true`.

**Fencing.** `replace-session` moves the authority to generation 2 while the node still holds the
credential it loaded. The node abstains on every following round with `signing-session-fenced`,
submits nothing after its first abstention, and keeps accepting certificates. The root reaches no
consensus after that point and rejects no request. The authority process logs the refused operations
and stays unfaulted.

**Authority loss.** The authority process is killed with SIGKILL. The operator `status` command and
the node both report `signing-authority-unavailable`. The node abstains on every following round,
submits nothing and keeps following the shard, and the root certifies nothing and rejects nothing.

In both cases no request signed under any other key reached the root chain, which is how the absence
of a local fallback is observed from outside the node.

**Restart from a retained checkpoint.** There are two scenarios, because which check stops a
restarted node depends on what the restarted process observes.

- `restart`: after the positive control the node is stopped with SIGTERM and started again with the
  same flags and credential. It resumes from its checkpoint, follows the shard, submits nothing and
  never calls the signer. The check that refuses first is P-id, with `no-anchor`: the fake executor
  produces no non-quiet round after genesis, so the restarted process observes no certificate that
  names a block. The restored gate is not reached in this scenario, although the health reason names
  the restored state first.
- `restart-at-anchor`: the node is frozen with SIGSTOP once its first authority-signed request has
  been sent and its checkpoint written, and then killed with SIGKILL. The root certifies that round
  (round 2) while the checkpoint still holds the round-0 certificate. The restarted process resumes
  from round 0, installs an anchor from the non-quiet round-2 certificate, passes P-id, and is stopped
  by the restored gate itself (`restoredFromRound=0`). Health gives the restored reason alone. The
  freeze has to reach the process before it accepts the certificate for its own request, and the
  script fails the scenario when it did not. The freeze was in time in the recorded run and in three
  repeats. An earlier trial, which started watching only after a two-second startup wait, was late
  and failed as intended.

In both scenarios the authority status is identical before and after the restart (enrollment,
configuration hash, session generation 1, reserved round and retained response), the same authority
process runs throughout, and it refuses no operation. The shard restart changed nothing in the
authority's record or session. The restored non-voting gate is unchanged.

**Recorded run.** Revision `cfb132b4` with a clean worktree passed all four scenarios: fencing with 25
assertions, authority loss with 24, restart with 27 and restart-at-anchor with 25. The evidence
directory holds a manifest (revision, binary digest, Go version, host, ports and T2), every command as
run, process start and stop records with PIDs, the logs, the status and health snapshots, and a digest
list. Credential and key files are removed after every process has stopped. Cleanup signals only the
PIDs the run recorded, after `owned_pid` confirms each command and working directory. The run is
repeated with `scripts/f6c-authority-acceptance.sh` and writes under `evidence-runs/`.

**What this does not show.** The lane has one validator and the fake executor, and no reth. The
authority and the shard node run on one host and reach each other over a local Unix socket, so it says
nothing about §3's host, backup and snapshot isolation, which the private test deployment must state
and supply. It does not exercise a concurrent second shard instance, an identical retry, a conflicting
request for the same round, or an old checkpoint against the authority's record. Those cases belong to
step 4, which must connect restored signing to P-id and to the authority's record and session
guarantees, and which remains gated.

#105 closes only after all four steps and independent review. #14 still owns
atomic block/UC/TR persistence; changing that format requires rechecking the R2/R3
cold-start equivalences in #92's ledger. No new Engine methods, reth changes, root
quorums, currency issuance or production activation are included.

## 9. Owner decisions on the three review questions (2026-09-11)

All three were approved by the owner as answered below.

1. **Q1 approved for a disposable private profile only.** Its availability cost is
   permanent voter loss on any authority restart until an authorized replacement
   mechanism exists. Planned maintenance has the same consequence as a crash.
   An operationally recoverable service requires the later key-custody/freshness
   design; do not promote this profile to that role. Remove disk durability from
   this profile because key and record die together.
2. **Q2 approved: the conservative assigned-round lock.** The root's
   `block_executor.go` certification flow calls `ShardInfo.nextRound`, which
   increments `TR.Round` even when the request is nil for a timeout. The same
   assigned round never needs a new conflict namespace under a later root
   authorization. The journal rule is stricter than the in-memory replay cache
   without restricting that valid progression.
3. **Q3 approved: the migration restriction.** Old exported keys have no trustworthy
   reconstructed signing history; neither importing them nor replaying a UC is
   migration authority. Fresh genesis or an authorized key/assignment replacement
   remains a separate action.

With these decisions ADR 0009 is Accepted as a design, and implementation step 1
(§8) may start. The acceptance does not approve key generation, deployment,
activation or restored voting. #105 stays open until all four steps pass
independent review. The model now verifies the actual released BCR before comparing its canonical
bytes in the 256 schedules. The rollback negative control explicitly requires two
valid, different statements at the same round under the same key.
