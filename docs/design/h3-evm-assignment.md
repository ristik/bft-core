# H3: changing the EVM validator assignment through the existing root handoff

Status: implemented in the bft-core half of H3 (this branch). The contracts half is
`ristik/unicity-pos-contracts#5` (`sealRegistry/v2`, 8b30801) and the Ureth half is
`ristik/ureth#47` (5f3bb7e4). No lane was run for this change; the locked acceptance lane is a
separate step. Amended 2026-10-01: validator-set changes are always coupled (section 1). No migration
of an already initialized chain is claimed.

## 1. Protocol

An EVM assignment change reuses `prepare → freeze/endorse → commit H → root activate → EVM
acknowledge`, the existing old-root-quorum authority, Abort and attempt+1. The committed
candidate gains an optional EVM assignment. There is no separate shard-handoff protocol.

- Every handoff advances the root epoch `e → e+1`, **including a configuration-only boundary with identical
  root keys**. The new epoch's root trust base is published with every rotation.
- A root-only handoff keeps the shard epoch. An EVM assignment handoff advances the installed
  assignment `s → s+1`.
- **Coupled-only (candidate version 3).** The candidate carries `Bindings`: one `(rootNodeId, evmNodeId)` pair per
  successor root member, sorted and one-to-one with the successor EVM validators, equal weights, and no shared signing
  key (co-hosted processes never share keys). Root members and the assignment change together in one handoff
  (`evmassign.ErrCombined` is removed). An EVM validator change with an unchanged committee is refused
  (`ErrEVMOnly`); an identical committee and identical EVM validators (a configuration-only boundary) is allowed.
  Where the EVM shard configuration carries `validator_coupling=true` (set at genesis, hashed with the configuration),
  the legacy root-only freeze companion may not change the committee either: block validation in every root
  validator refuses it (`ErrCoupling`), so no path adds a root entity without its EVM binding. The binding is
  authorized by the old root quorum's endorsement of the candidate digest plus the EVM key's possession proof; a
  signature by the successor root key over its binding is not required under PoA.
- One designated EVM shard (`PartitionTypeID 8`), unit effective weights (`Stake == 1`), at most 64
  validators. Chain, fork, fee and execution settings are fixed: the successor PDR must equal the
  installed one in every field except validators, epoch (+1) and activation round
  (`evmassign.ConfigHash`).
- Another handoff of any kind needs a certified acknowledgement first, except a **supersession**
  (§4).

## 2. Candidate binding, authorization, possession

Package `evmassign` defines the canonical successor assignment, the proof of possession (PoP) and the
version-2 candidate.

- The **assignment hash** covers network/partition/shard, the new shard epoch, the sorted unique
  validators (identity, key, unit weight) and the non-membership configuration hash (which includes
  the immutable `seal_registry_genesis` commitment of G). The activation round is not part of it: it is
  fixed by the commit, and the derived PDR hash that certificates carry includes it.
- Every successor key, retained keys included, signs a domain-separated message over
  `(network, partition, shard, assignment hash, predecessor root BodyID, attempt, frozen parent P,
  node id)`. Signatures must be exactly 65 bytes and the recovery byte must recover the validator
  key, so a signature has one accepted encoding.
- The **candidate** (`evmassign.Candidate`, one encoding) binds the successor root members, the
  replaced assignment's epoch and full hash, the successor PDR, the ordered PoPs and, for a
  supersession, the superseded committed H and chain. Its SHA-256 digest is the 32-byte candidate hash
  that `D4CandidateContextHash` binds into `TrustBaseBodyV2.ChangeRecordHash`. Hash order: assignment
  hash → PoPs → candidate digest → change-record hash / next BodyID → FrozenID. No preimage contains its
  enclosing BodyID, FrozenID or a regenerated genesis identity.
- The preimage travels **once**: in the version-2 freeze companion
  (`storage.FreezeAssignmentAuthorization`, retained under the successor BodyID) and in the retained
  handoff bundle (`handoffdelivery.Bundle.Candidate`). It is verified again at endorsement
  (`ConsensusManager.validateHandoffApproval`) and at block admission
  (`v1HandoffAuthority.VerifyFreeze` + `verifyFreezeAssignment`), not only in the CLI. The root-input
  `D[]` stays at most 16 KiB: it carries hashes and scalar epochs, never validator lists.
- Old **root** quorum authorizes H. Old EVM signatures never authorize the successor; the successor
  EVM quorum signs the acknowledgement. Local configuration and peer-supplied keys confer no authority.
- Possession is not availability: successor restoration/readiness at P is the operator's check before
  every attempt; an attempt+1 recollects PoPs for its own attempt (a replayed attempt-n PoP fails).

## 3. The EVM configuration is derived from committed history

Committed root storage is the only source: the genesis PDR plus the committed handoff records, their
verified candidate preimages and activation boundaries. Orchestration holds a **derived index**.

- At the first new-root block the executor installs, once, the derived PDR
  (`activateEVMAssignment`): the committed successor technical record (TR) must equal the one H
  committed (`SuccessorTRHash`), then the shard state is switched with the same `nextEpoch` the shard's
  ordinary progress would use. The TR installed is the next monotone shard round, the successor epoch,
  the new set's leader and the rolled fee/stat commitments; IR stays P's original IR.
- `nextBlock` decides the epoch switch against the installed configuration hash, **not** `TR.Epoch !=
  IR.Epoch`: that inequality is true throughout a delayed acknowledgement and previously re-ran
  `nextEpoch` every root round, which reset the fee list repeatedly. The test
  `TestEVMAssignmentActivatesOnceFromCommittedHistoryAndSurvivesRestart` fails if the old condition is
  restored.
- `Orchestration.InstallDerivedShardConfig` is idempotent and keyed by activation round with
  provenance (`evmassign.Provenance`: H record id, candidate digest, root epoch). An identical entry is
  a no-op; a different entry at the same key, or a gap in the epoch chain, is corruption
  (`ErrDerivedConflict`) and refuses startup. After genesis (`Epoch != 0`) `AddShardConfig` and
  `PUT /api/v1/configurations` refuse the designated EVM shard (`ErrDerivedOnly`); aggregator PDRs keep
  using ordinary orchestration, including independent updates while an EVM acknowledgement is pending.
- Order of operations: `InstallEpochAnchor` derives and installs the configuration **before** it writes
  the anchor root. On startup `storage.New` runs `repairCommittedAssignment` (anchor root's committed H
  + retained candidate + body) and `NewConsensusManager` runs `reconcileAssignmentHistory` (every
  archived handoff bundle that carries a candidate), both before `initBlock` rebuilds trust bases,
  before the frontier service and before any vote. A crash between committed storage and the derived
  write is repaired from committed data. Missing candidate, body or bundle refuses activation; there is
  no fallback to the genesis or retired PDR. `initBlock` also refuses a stored EVM shard whose
  configuration hash is not the derived one.
- Readers: `initBlock`, `block_store` readers, `nextBlock/nextRound/nextEpoch`, request/leader
  verification and the frontier sampler all read `ShardConfigs(round)`, i.e. the derived view. Old
  suffix blocks (committed phase) read the configuration at the **ordered** round, which is how the
  overlap with the successor's first rounds is resolved.

## 4. Freeze, supersession and the acknowledgement boundary

- Branch-local freeze rejects EVM certification from the Freeze block through H. The old builder's
  cancellation is optional responsiveness work and is not included; root validation supplies safety.
- **Supersession.** If the installed assignment `s+k` has no certified acknowledgement, a new
  EVM-only handoff may replace it on the **same frozen parent P**: the shard's IR is still P (a block
  certified after P would have been the acknowledgement and ended the pending state) and the candidate
  carries `Supersession{SupersededH, BaseRootEpoch, BaseShardEpoch, BaseActiveHash, ChainLen,
  ChainCommitment}`. Block execution recomputes the chain from this validator's own derived history
  (`storage.CommittedChain`) and requires the candidate to equal it. Every replacement advances the
  installed shard and root epochs once. Only the newest installed set is in the shard trust base, so a
  superseded set's late acknowledgement fails membership verification.
- Abort before H discards the pending assignment only; attempt+1 recollects fresh P/PoPs. After a
  superseding attempt aborts the previously installed assignment stays current. After H a replacement is
  another committed supersession, never an Abort.
- **Folded acknowledgement.** Transition encoding v3 (`handoff.EVMTransition`, shared vector
  `handoff/testdata/evm-transition-v3.json` with Ureth) names old/new root epoch, old/new shard epoch,
  old/new active configuration hash, a supersession span and commitment. A root-only step moves the root
  epoch by 1 and keeps the shard epoch and hash. An assignment step moves both by 1. A supersession folds
  `n` consecutive committed steps: root and shard deltas both equal `n ≤ 64`, the hash changes, the
  commitment is non-zero. `handoff.FoldTransitions` builds it from per-step transitions and
  `evmassign.ChainCommit` is the commitment; BFT verifies every intermediate step (the per-step
  transition of each handoff is built from its own verified bundle), the contract and Ureth check only the
  monotone jump and the commitment. Incomplete history is a typed
  `engineapi.ErrAssignmentSpanUnavailable`, never a bare epoch-jump error.
- The latest set builds one acknowledgement-only block on P; after it is certified, ordinary
  transactions resume.

## 5. Guard inventory

The shard-epoch-zero rejection sites at the surveyed pins, all changed with tests:

| Site | Change |
| --- | --- |
| `evmroot/rootorigin_v2.go` `RootInputV2.Validate` | certified epoch = origin IR epoch, authorized epoch = TE epoch, authorized ≥ certified, and authorized ahead only with a transition |
| `rootinput/v2.go` `authenticateObservationV2` | authorized epoch ≥ certified epoch; `ConfForEpoch`: the certificate's shard epoch selects exactly one installed configuration (no scan of installed assignments) |
| `rootchain/consensus/frontier_sampler.go` | IR epoch ≤ TR epoch; TR epoch equals the derived PDR's |
| `rootchain/consensus/frontierclient/collector.go` | IR epoch ≤ TR epoch under the collector's configuration binding |
| Ureth `crates/unicity/execution/src/lib.rs` | `ristik/ureth#47` |

`RootOriginV2.Class`'s actual genesis check (epoch zero / null IR for the bootstrap class) and the
root-epoch sentinels are different invariants and are kept. Also changed: `DeriveV2` (nonzero epochs,
registry assignment, transition v3), `certifiedstore` (per-record PDR), `registryproof` (layout 2),
`recordwiring`, `parentwitness`, `registrywitness`, `configuredprogress` descriptor layout, bundle codecs.

## 6. F7 and immutable genesis versus active configuration

- `SealRegistry` v2 keeps `config.shardConfHash` (the genesis full hash) immutable and adds
  `assignment.activeConfHash` (initialized to it) and `assignment.spanCommitment`. `registryproof`
  reads layout 1 exactly as before and layout 2 as the 30-word list the artifact pins; a v2 snapshot is
  checked for internal consistency and, when the caller supplies it, against the authenticated active
  assignment (`Context.Active`).
- `mintproof` bundle **schema version 2** carries the full canonical PDR of its subject UC's
  configuration. The verifier requires `H(PDR) == bundle configuration == UC.ShardConfHash`, verifies the
  UC under the caller's trust base for the UC's root epoch (an EVM-only rotation advances the root epoch
  with identical keys; publish that body), requires the PDR's non-membership configuration to equal the
  immutable genesis pin, validates the validator set, and requires `UC.InputRecord.Epoch == PDR.Epoch`.
  No H-proof chain is needed offline. Version 1 bundles stay valid only under their explicit original
  configuration pin: a missing PDR is never read as the latest assignment.
- `certifiedstore` record **version 2** carries the record's own PDR; version 1 bytes never change.
  Each record is validated against its own PDR, not a deployment-wide hash. A recertification of P under
  a successor assignment (certified epoch `s`, authorized `s+1`) is an authorization for the next
  acknowledgement and fails as P's resulting evidence; the archive keeps P's original resulting UC.

## 7. Durability and compatibility

- Persisted shapes change with explicit decoders and refusals: freeze companion version 2; handoff
  bundle with an optional `Candidate` (legacy shape written when empty, both decoded, nothing
  reinterpreted); `certifiedstore` record v2; mint bundle v2; transition v3. The delivery protocol id
  becomes `/unicity/root-handoff-bundle/2.0.0`: a peer that does not speak it cannot fetch an
  assignment-bearing bundle and is refused before activation. `HandoffApprovalMsg` gains the candidate
  preimage; peers must be upgraded together (the root network is one deployment).
- Aggregator behavior is unchanged: after root activation they keep certifying while the EVM
  acknowledgement is pending, and the EVM transition never resets aggregator PDRs, IRs, leaders or
  counters.
- `parentwitness` carries the registry layout in its context; its version-1 wire cannot name layout 2, so
  a layout-2 context is refused rather than dropped.

## 8. M3 genesis

The assignment-capable registry must be in the **M3 launch genesis**: a hash repin cannot replace live
contract code and migration of an initialized chain is separately specified. `ubft engine-api genesis
--registry-layout 2` and `ubft shard-node run --registry-layout 2` select the pinned v2 artifact (code
hash `0x7787f316…caf38`, also pinned independently of the embedded file); the default stays 1 so existing
deployments are unchanged. Regenerating the final T1 export, gate hashes, storage/proof fixtures,
T4 reconciliation and T5/T6 evidence for the M3 genesis is **not** done by this change and needs the
external toolchain.

## 9. Not claimed here

The locked acceptance lane; the shard-node core's multi-assignment anchor-evidence and the H4 frontier
restore *across* an assignment change beyond the guards above; the wire v2 of `parentwitness`; the final
M3 genesis hashes. See the PR description for the exact test coverage.

## Amendment: aggregator node-key replacement (candidate version 4)

The candidate gains `Changes[]` (kind 1 = `ReplaceShardValidators`: partition, shard, expected installed PDR hash, successor PDR,
possession proofs; kinds 2 and 3 are reserved tag numbers only and refused as unsupported) and `SourceRef` (must be empty).
`ConfigHash` equality makes a change validators-only. All derived configurations of one H (the EVM assignment and each
replacement) install in one transaction; restart re-derives them from the retained candidate. The first new-root block
activates every replacement like the EVM assignment: immediate technical-record advance and trust-base install, so the retired
key's first request is refused. There is no aggregator freeze. Under the handoff profile PUT and any local epoch>0 or edited
epoch-0 configuration are refused.

## Amendment: #85 lifecycle (candidate version 5, PR 1a)

Design: `briefs/p85-design-v5.md` sections 5 and 10 item 1 (docs/design/pos-architecture.md on PR #415). Inactive: nothing builds these candidates
in production, and there is no migration (greenroom, one format).

- **One candidate format, two kinds.** `Candidate.Kind` is `KindPrimary` (J) or `KindRecovery` (K). Both carry the full recovery
  `Authorization` (K, the exact last acknowledged committee, with its base root body and assignment hash), so a primary whose K is not the
  incumbent is refused at admission, not when recovery is needed. A primary carries a fresh possession proof from every successor key
  (retained keys included); a recovery carries none and names the assignment hash of the committed primary it replaces
  (`ReplacedAssignment`). `Encode` refuses a mismatched shape (`ErrKind`).
- **Identity records.** `Candidate.Identities` is the one authenticated description of the coupled set, sorted by StakingID: StakingID,
  generation, root and EVM NodeIDs and keys, weight, **operatorPayee** and exposure digest. Root members, bindings and the successor
  validators are matched to it by identifier (their orders differ), never positionally (`ValidateIdentities`). `IdentitiesDigest` enters
  `PoPContext` and therefore the assignment hash every possession message signs, so a proof authenticates the payee; `ExposureCommit`
  binds payee, generation and exposure per identity into the authorization. A payee-only nomination is not a binding replacement.
- **Continuity** (`continuity.Check`, exact integers): `r` shared identities with any changed binding field counted once,
  `removed=|O\S|+r`, `added=|S\O|+r`, `M=removed+added` within the budget, `3*max(removed,added) < min(|O|,|S|)`, normalized weight
  distance `D` within its bound, and unchanged-binding weight strictly above two thirds of both committees. It runs at O to J (primary,
  O = the acknowledged committee) and J to K (recovery, O = the committed J). The budget is read from the committed EVM configuration
  (`continuity_max_m`, `continuity_max_distance`, DEV-DEFAULT M<=4, D<=1/4).
- **Recovery is derived, never chosen** (`DeriveRecovery`): exactly K, successor epoch +1, the primary's non-membership configuration.
  Root admission (`VerifyLifecycle`, run by `verifyFreezeAssignment` after the supersession evidence and by the operator) requires the
  authorization digest to be the committed primary's, K equal to the acknowledged committee, the replaced assignment to be that primary's,
  and the J to K continuity predicates. A recovery-kind candidate whose committee differs from K in any member, key, weight, payee or
  exposure is `ErrNotIncumbent`.
- **Session count from committed history.** The orchestration retains each committed candidate with its kind (`Provenance`), and the
  acknowledged committee (`SetGenesisIdentities` at genesis, the retained candidate afterwards). `storage.LifecycleFor` derives the pending
  chain, its head and the committed recovery count from that, so a restart, a new attempt or an abort cannot reset the allowance and an
  uncommitted retry consumes none. One committed recovery per frozen parent (`ErrRecoveryUsed`); no primary may replace a committed primary
  (`ErrPendingPrimary`); the unacknowledged chain is at most two (`ErrSpan`, `handoff.MaxSupersessionSpan = 2`).
- **NodeID encoding for custody.** Root chain NodeIDs stay libp2p peer-ID strings here. The custody contracts treat them as opaque
  `bytes32`, so the one canonical image is `evmassign.NodeIDWord(id) = keccak256(utf8(id))`: derived at the boundary, never carried or
  signed in place of the string, injective up to collisions, and tied to the key by the key hash that sits beside it in every signed
  binding. Keys stay 33-byte compressed secp256k1.
- **Root records, progress, closure and UC time (`rootrecords`).** The projection custody imports (`IRootRecords`): a linked log of
  SessionClosed, Ack, RecoveryAck, Closure and Retirement records, each with the canonical progress p and UC time of the moment it was
  ordered. The record identifier is `keccak256(abi.encode(index, predecessor, kind, progress, ucTime, data))`, payloads are the static
  words of `P85Types.sol`. Progress is `offset_e + (r - firstRound_e)` over ordinary committed rounds of the current epoch; ordering H at
  round h fixes the endpoint `p(e,h)`, the successor offset `p(e,h)+1` is derived (never supplied), and progress stays at the endpoint
  until the successor has an ordinary round, so seal rounds, arrival time and old-epoch suffix rounds cannot move it. A closure is keyed by
  `(closed epoch, H record, H round)` with the terminal root and digests as its immutable value, and carries no proof. An epoch closes
  once: the first closure fixes p_close and its UC time, an identical repeat is a no-op, any other closure of the epoch (another value,
  H record or H round) is `ErrClosureConflict`, and none can anchor before some H was ordered and its successor has ordinary progress
  (`ErrClosureEarly`). Custody applies the same rule; `closureCases` in the shared vectors are run against both. UC time is the seal
  timestamp of the verified root certificate's `RootOrigin` (`ReferenceTime`), imported on one lineage (network, then epoch and round) and
  never backwards; a record cannot be ordered before a time was imported. `rootrecords/testdata/records-vectors.json` is produced by this
  projection and replayed verbatim by the custody contracts' tests.
- **UC time is an authenticated physical-time annotation.** An honest proposer uses the later of its clock and the authenticated
  parent time; equal seconds are valid. Root consensus enforces non-decrease and a 30 s live voter future bound (#479). The
  bound relative to UTC depends on honest-clock accuracy; it supplies no past-time bound. Custody consumes UC time, not EVM time.
  A UC-time delay alone does not prove a real-time hold after retirement without an anchor-freshness premise (see Root UC time below).
  The importer also enforces non-decrease on one lineage; this is defence in depth and does not replace the root rule.
- **Root payload and P85 controls (`rootchain/consensus/types`).** The profile-2 root payload is exactly the definite four-element tuple
  `[2, Requests, HandoffRecords, PosControls]`; every collection is a definite array (empty is `80`, never null), so the empty payload is
  `8402808080`. The retired three-element form, a null or indefinite collection, other arities or tags and any non-canonical encoding
  are refused. A `PosControl` is `["UNICITY_P85_CONTROL", network, chainID, custody, orderingEpoch, orderingRound, op, context, data,
  witnessHash]` for op 1 CloseLiability (context `[closedEpoch, bundleSemanticID]`, 192-byte ClosureData), op 2 Retirement (context
  `[evmBlockHash, evmStateRoot]`, 96 bytes) or op 3 RejectResult (context `[predecessorBodyID, attempt, evmBlockHash, evmStateRoot]`,
  32 bytes); `data` is the exact ABI payload, uint64 words within range. Within a block closures come first in strictly ascending closed
  epoch, then at most one RejectResult, then retirements in strictly ascending `(id, generation)`; at most 32 controls. A control-bearing
  payload is never empty, so a post-H old-epoch suffix with a control is `ErrHandoffSuffix`. The legacy profile keeps its one-element
  payload. Proof checks and lifecycle rules belong to the executor (next slice).
- **Root source of the record log (`rootrecords.State`, `ControlState.Pos`).** The root keeps one canonical, copyable source state in the
  control state, committed by the control digest (so a checkpoint and a handoff bundle carry it verifiably): the progress tracker
  (current epoch, offset, first round, and while H's successor has not started, the frozen endpoint and the successor's offset/first
  round), the committed assignment handoffs awaiting their EVM acknowledgement (at most a primary and its recovery, each with the body
  that names its retained candidate), and the cursor of the log (count, tip, last anchors). It changes only at events: a committed H
  (`Commit` fixes p(e,h), the successor's offset p(e,h)+1 on its activation round), the first successor block at or after the
  activation (ends the freeze), and a projected record. An ordinary or empty block leaves the digest alone, and an old-epoch suffix
  block moves nothing. The designated EVM shard's certified acknowledgement (its IR epoch catching up with the installed TR epoch while
  a handoff is pending) projects `Ack` (one pending handoff) or `RecoveryAck` (a primary and its recovery) from the offsets fixed at
  commit, never derived again, with the election result and assignment id read from the retained candidates, anchored at the
  acknowledging block's progress and committed timestamp. The genesis epoch's ordinary rounds start after the genesis round. The
  records of a block are kept in `ShardStates.Records` (omitted from the encoding when empty, so a chain that projects none keeps
  byte-identical blocks) and are retained durably, oldest block first, when the block commits (`BoltDB.AppendRecords`, idempotent and
  linked); `Records`/`RecordCount` read them back. A control state without a source state projects nothing (fixtures that predate it).
  A checkpoint taken from a snapshot does not carry the log's earlier records.
- **P85 control executor (`storage.posStep.controls`).** PosControls run after the block's certifications, in payload order, each
  naming this deployment and this block's epoch and round. Witness bytes are fetched by their SHA-256 (unavailable is not false). The
  verifiers (`ClosureAuthority`, `EVMStateAuthority`) are injected; the executor checks what they return against the control and the
  root's own state. CloseLiability: the epoch must await its closure (`State.Awaiting`: entered when an assignment handoff's freeze ends,
  left by the closure), bundle facts must match the control, and the exposure and key-history digests are derived from the closed
  assignment's frozen identity records (`evmassign` custody formulas, shared fixture generated by custody). Retirement: P must be the EVM
  block certified in the parent, its state root the retained block's; custody's facts at P must show a request, no live exposure or
  lot reference, records caught up and the chain digest verbatim; the carrying block's progress must reach the maximum liability anchor;
  it is refused while any handoff is in flight (a conservative stand-in for "no prepared/session obligation for the generation"); a
  repeat with the same digest emits nothing, another digest conflicts (`State.Retired`). RejectResult: only at a quiet control state
  (idle or aborted) with no pending primary, the next attempt of the root's own authority; the unresolved result with no competing
  session is proven at P; it emits SessionClosed and sets the control state to aborted at that attempt, so the next Prepare is the next
  attempt. A committed D4 Abort closes the Election result only when its Freeze retained a primary candidate; the abort of a recovery
  attempt closes nothing. A result resolves once (`State.Resolved`): a repeat Abort projects nothing, and a primary Freeze whose result
  is already resolved is refused, because custody refuses a second SessionClosed or an Ack of a session that is no longer open and its
  record cursor is strict. At most 32 records per block.
  **Open (architecture):** a Prepare carries no candidate, so a Prepare-only Abort names no result, and the result stays open on custody.
  RejectResult cannot end it under this attempt rule: after Prepare(N) and Abort the control state is `aborted` at attempt N, the open
  result is bound to attempt N, and RejectResult requires attempt N+1. Either bind the result in the Prepare record, or allow
  RejectResult at `aborted` for the aborted attempt when no candidate was frozen. Not implemented until decided.
- **Not implemented here:** the on-chain `IRootRecords` implementation in the SealRegistry and its feed from Ureth; the reference model
  above and the vectors are what it must match. The Closure and Retirement digest words (exposure, key history, reference digest) are
  contract-derived and opaque labels in the vectors.

## Root UC time (#445, corrected by #479)

The protocol provides a strictly ordered committed history with an authenticated, non-decreasing physical-time annotation.
Consensus position determines ordering; timestamps support time-based predicates. Timestamp advancement is independent of block
production rate. Certified timestamps have a bounded future offset under explicit honest-clock assumptions, while freshness and
eventual time advancement depend on consensus progress.

[ADR 0013](../adr/0013-root-time-semantics.md) records the decision. The semi-formal specification and proof arguments are in
[UC seal timestamps](../pos/specification/bft.tex) (`sec:root-time-semantics`).

For a block `B`, let `P(B)` be its authenticated parent, `R(B)` its consensus position under epoch/round ordering, and `T(B)` its
nonzero Unix timestamp in whole seconds. `C_v(t)` is voter `v`'s clock reading at real time `t`; `Delta = 30 seconds` in DEV.

- Positions strictly advance on the selected committed lineage. Round gaps can include timeouts; they measure neither elapsed
  seconds nor a count of committed blocks. Hashes and ancestry still identify the particular block.
- In addition to ordinary consensus checks, a live voter requires `T(B) >= T(P(B))` and `T(B) <= C_v(t_vote) + Delta`.
  Implement the future check by comparing before subtracting, without overflowing unsigned arithmetic.
- An honest proposer uses `T(B) = max(C_p(t_propose), T(P(B)))`. Several rounds may share a second.
- `P(B)` is the locally executed QC parent, not the block committed by its ledger commit info. A timeout certificate does not
  reset that floor. Epoch anchors retain the authenticated old committed checkpoint time. Restart, recovery and clock rollback
  do not authorize lowering it; missing parent state prevents voting.

The guarantees are conditional and distinct:

1. **Order and non-decrease:** underlying consensus safety orders the committed lineage; induction over validated parent edges
   gives `T(A) <= T(B)` for every ancestor `A` of `B`. Handoffs preserve the checkpoint floor. Legacy history needs its own
   monotonicity premise; authenticating a timestamp alone does not prove how it was chosen.
2. **Future bound:** assume a certificate includes an honest signer enforcing this live rule and honest clocks satisfy
   `C_v(t) <= t + eps`, including clock error and second quantization. At certificate formation time `t_cert`, that signer voted
   at `t_v <= t_cert`, so `T(B) <= C_v(t_v) + Delta <= t_cert + eps + Delta`. This also bounds time at later commitment or
   observation, but supplies no unconditional UTC claim and no past-time/freshness bound. Genesis, synthetic anchors and
   differently certified legacy history do not acquire a fresh live-time guarantee merely through import.
3. **No rate-induced inflation:** along an honestly proposed parent chain,
   `T(B_n) = max(T(B_0), C_p1(t_1), ..., C_pn(t_n))`. No term grows with block count. An inherited future floor may persist;
   honest proposers do not amplify it. Byzantine proposals are still constrained by honest voters' future bound.
4. **Conditional timestamp liveness:** if enough honest voting weight to form a quorum has both
   `T(P(B)) <= C_v(t_vote) + Delta` and `C_p(t_propose) <= C_v(t_vote) + Delta`, both arguments of the maximum are admissible.
   Timestamp checks then impose no minimum block interval. Full liveness still needs the underlying network, leader and state
   availability assumptions. A too-future floor or clock rollback can pause voting until clocks catch up; never lower the floor
   to force progress.

**Deadline semantics.** `T(B) >= D` implies only `t_cert >= D - (Delta + eps)` under the future-bound premises. An absolute
wall-time gate must account for that tolerance. `T(B) < D` does not prove real-time certification before `D`. A relative gate
`T(B) >= T(A) + d` does not alone establish `d` real seconds since anchor certification: with a separate anchor-freshness
premise `T(A) >= t_A - sigma`, it establishes only `t_cert - t_A >= d - sigma - (Delta + eps)`. Without that premise no positive
relative real-time hold follows. Do not derive withdrawal or checkpoint-protection guarantees by converting rounds into seconds,
or by substituting the strictly increasing EVM header timestamp. No per-block time advance, bounded staleness, or time advance
during a consensus stall is promised. Quantitative freshness requires additional progress and clock assumptions.

**Authentication and recovery.** New scheme 2 votes and QCs authenticate time in an appended VoteInfo field. Recovery compares
executed times against verified QCs and the committed head against its signed native seal before installing a floor. Historical
four-field wire/six-field signing encodings remain valid with their original bytes; new five-field wire/seven-field signing
encodings bind a nonzero timestamp. A timestamp-less uncommitted QC cannot authenticate a live floor; a historical committed
block needs a separately verified native commit seal. UC sealing uses the committed block time. Current-clock checks apply to
live voting, including recovery-triggered votes and restart retries, never certified-history verification or catch-up replay.
A live timestamp refusal after completed replay leaves frontier serving unfaulted; it is not a recovery persistence fault.

#479 changed validity, not units or encoding. Validators enforcing the former strict-increase rule reject equal timestamps;
DEV validators must activate the rule together. The timestamp-bound wire extension also requires compatible readers.

## Amendment: PoA genesis identities and the first coupled handoff

The #85 lifecycle (above) needs the genesis committee's identity records as the incumbent baseline (`SetGenesisIdentities`), but nothing in
production recorded them, so no coupled handoff could be admitted. Under proof of authority there is no staking contract to read them
from: the operator provisions them.

- `root-node run --genesis-identities <file>` records the file's identity records, once, for the one genesis shard that has
  `validator_coupling=true`. They are verified exactly as a candidate's records are (`ValidateCoupling`, `ValidateIdentities`) against the
  genesis trust base and that shard's genesis validators: one record per root member and per EVM validator, keys and weights equal, bound
  one to one. The same set again (a restart) is a no-op; a different set is `ErrGenesisIdentitiesConflict`, never an overwrite. A proof-of-stake
  genesis takes the same records from its manifest and does not use the flag.
- `ubft genesis-identities generate` writes the file. The staking id, operator payee and exposure digest of an entity are operator-assigned DEV
  values, deterministic from its root node id (the weight lives in the record, so a reweighting leaves the entity's identity and payee alone).
- `root handoff evm-authorization` writes the recovery `Authorization` of a primary candidate: K is the incumbent committee's records (the
  genesis file before any rotation, the previous assignment's afterwards); the base root body and assignment hash come from the context
  `handoff evm-context` printed; the election inputs (contracts, result, snapshot, policies) are operator-assigned DEV digests.
- A weighted rotation must fit the continuity budget the genesis configuration commits (`continuity_max_m`, `continuity_max_distance`); the
  DEV default (D <= 1/4) admits no reweighting of a four-member committee, so a deployment that rotates weights sets its own bound.
