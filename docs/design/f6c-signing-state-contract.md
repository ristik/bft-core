# F6c: signing authority across shard-process restart

Status: **proposed**, first deliverable of #105; independent review required.
Base: `fbc4d08b1a2bf7b3e8b58b5632d02053d6789535`. This document and its
executable model enable nothing. #92 is complete; #14 and #105 remain open.

## 1. Decision proposed for the first private profile

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
| Enroll fresh authority lifetime | Generate non-exported key; fix enrollment in memory before returning its public key. No existing-key import or bootstrap from UC history. |
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

#105 closes only after all four steps and independent review. #14 still owns
atomic block/UC/TR persistence; changing that format requires rechecking the R2/R3
cold-start equivalences in #92's ledger. No new Engine methods, reth changes, root
quorums, currency issuance or production activation are included.

## 9. Answers to the three review questions

1. **Recommend Q1 only for a disposable private profile.** Its availability cost is
   permanent voter loss on any authority restart until an authorized replacement
   mechanism exists. Planned maintenance has the same consequence as a crash.
   An operationally recoverable service requires the later key-custody/freshness
   design; do not promote this profile to that role. Remove disk durability from
   this profile because key and record die together.
2. **Accept Q2's conservative assigned-round lock.** The root's
   `block_executor.go` certification flow calls `ShardInfo.nextRound`, which
   increments `TR.Round` even when the request is nil for a timeout. The same
   assigned round never needs a new conflict namespace under a later root
   authorization. The journal rule is stricter than the in-memory replay cache
   without restricting that valid progression.
3. **Accept Q3's migration restriction.** Old exported keys have no trustworthy
   reconstructed signing history; neither importing them nor replaying a UC is
   migration authority. Fresh genesis or an authorized key/assignment replacement
   remains a separate action.

ADR 0009 remains Proposed pending review of this revised profile. These answers
select the author's recommended design, not deployment or restored-voting approval.
The model now verifies the actual released BCR before comparing its canonical
bytes in the 256 schedules. The rollback negative control explicitly requires two
valid, different statements at the same round under the same key.
