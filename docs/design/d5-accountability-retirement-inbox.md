# D5 — Accountability, retirement and forced-inbox model

Issue: [#7 D5](https://github.com/ristik/bft-core/issues/7) · Milestone: M0 ·
Prereqs: [#3 D1](https://github.com/ristik/bft-core/issues/3),
[#6 D4](https://github.com/ristik/bft-core/issues/6) · Status: **proposed for freeze**

> **Forced-inbox part deferred 2026-10-01 ([ADR 0012](../adr/0012-validator-entity-model.md)).** The I-track (roadmap I1-I5)
> is deferred by the owner decisions; this design stays as the reference. The slashable vote domain and the retirement
> protection are unaffected.

D5 fixes three things the initial PoS needs and the prototype does not have:

1. the exact **slashable vote domain** and the `VoteInfo → LedgerCommitInfo`
   hash binding, including a signed preimage that binds network/domain **even for
   a non-committing vote**;
2. the **collateral reservation and retirement lifecycle**, with inherited
   protection, the evidence-timeliness rule and the inbox-watermark gate on
   withdrawal;
3. the **paid forced-inbox admission** model — prepaid UCT credits, exactly-once
   charging, refund reconciliation, FIFO progress past poisoned entries, and the
   published inclusion bound `K`.

Model: [`evmroot/d5vote.go`](../../evmroot/d5vote.go),
[`evmroot/d5retire.go`](../../evmroot/d5retire.go),
[`evmroot/d5inbox.go`](../../evmroot/d5inbox.go). Vectors:
[`evmroot/testdata/d5-vectors.json`](../../evmroot/testdata/d5-vectors.json).
Decision record: [ADR 0007](../adr/0007-accountability-retirement-inbox.md).

Specification basis: `docs/pos/specification/appendix-evm.tex` §§ Evidence, Forced
Inclusion; `governance.tex` §§ Slashing, Economic Invariants.

---

## 2. Slashable vote domain and hash binding

- **`VoteInfo`** is the consensus round data. Its canonical form is
  `CBOR([network, messageDomain, votingEpoch, votingRound, parentRound, execStateHash])`
  and `VoteInfo.Hash() = SHA-256(CBOR(VoteInfo))`.
- **`LedgerCommitInfo`** binds a vote iff `VoteInfoHash == VoteInfo.Hash()`.
  Verification authenticates the canonical `VoteInfo` hash *inside* the signed
  `LedgerCommitInfo`, then reads the **voting** epoch and round from `VoteInfo` —
  never the seal's older committed round. A non-committing vote has empty
  `CommitStateHash` / `CommitRound == 0` and still binds its `VoteInfo`.
- **`SigningPreimage`** is the exact signed byte string:
  `CBOR([ "UNICITY_POS_VOTE", network, messageDomain, VoteInfo.Hash, commitStateHash|null, commitRound ])`.
  It opens with the domain tag and network and binds `messageDomain` **even when
  the commit fields are empty**. A domain value passed as an argument to a
  verification builtin is **not** part of this preimage and authenticates
  nothing.
- **`SlashableConflict(a, b)`** is the objective double-signing offense: same
  `(accountableKey, network, messageDomain, votingEpoch, votingRound)` with
  **different** signed statements. It is **false** for: an identical preimage
  (duplicate delivery / re-encoding / malleable signature), a different message
  domain, a different voting round, or a legacy vote (legacy votes keep their
  explicit legacy rules and are never reinterpreted as domain-bound PoS votes).

## 3. Reservation and retirement lifecycle

Phases: `Bonded → RetirementRequested → Draining → Released`.

- Requesting retirement does **not** start the protection clock.
  `AcknowledgeRetirement` records `R_ret` — an authenticated acknowledgement that
  the stake no longer backs any **active or prepared successor** assignment. An
  acknowledgement while a prepared successor still relies on the stake is
  rejected.
- **Timing parameters** (`ProtectionParams`), ordering mandatory:
  `W_cert ≤ Δ_ev < Δ_hold` and `Δ_hold > Δ_ev + Δ_incl + Δ_exec`.
- **`CanWithdraw(now, p, positionCutoffSatisfied, timelyEvidencePending)`** requires, in order:
  1. phase `Draining`;
  2. `now ≥ max(R_ret + Δ_hold, inheritedProtectionUntil)` — inherited protection
     from key rotation / delegation changes dominates a nearer boundary;
  3. **position cutoff** satisfied — see below;
  4. no timely-queued evidence case against the key is unprocessed.
  Exceeding `Δ_incl` / `Δ_exec` never unlocks an unresolved liability.
- **Position cutoff (fixing the unit mismatch).** The reservation carries
  `LiabilityDeadlineRound` (a **root round**). The linkage to the inbox is
  `ForcedInbox.PositionCutoffSatisfied(deadlineRound)`: **every** entry whose
  `AdmissionRound ≤ deadlineRound` must be **certified-consumed**. It never
  compares a sequence number to a root round. An **empty interval** (nothing
  admitted through the deadline) is trivially satisfied; many entries admitted in
  one root round, or long empty intervals, or a partial acknowledgement, are all
  covered (`withdrawal_gates.cutoff_*` vectors;
  `TestD5_PositionCutoffNotAWatermarkComparison`).
- **`EvidenceTimely`** — timely iff executed within `Δ_ev` root rounds of the
  offense, **or** its complete payload was committed to the forced inbox within
  that window. A bare local submission or an unavailable payload hash does not
  preserve timeliness. A timely queued case blocks the related withdrawal until
  processed — even after a late execution.

## 4. Paid forced-inbox admission

### Authenticated credits

- `ApplyDeposit(CertifiedDeposit{DepositID, Owner, Amount, Certified})` requires
  `Certified` and dedups on the **certified `DepositID`** — the root-certified
  deposit identity, *not* a hash of a proof serialization. A re-encoded proof for
  the same deposit is the same `DepositID` and adds nothing; an uncertified
  deposit is rejected.
- `Admit` **mints one credit** for `sender` from its available balance and binds
  the credit to the queue `seq`. Each credit records its `owner` and originating
  deposit.
- Queue sequences remain `uint64` end to end. A credit stores its bound
  `consumedBy uint64` together with a separate `consumed` flag; no signed
  sentinel represents an absent sequence. `MaxUint64` may be assigned once,
  after which admission reports `sequence_exhausted` rather than wrapping and
  reusing sequence zero. Refund reconciliation consults the bound sequence
  only when `consumed` is true. For the matching D2 rejection-digest encoding
  of signed `ValueDelta`, see the [D2 design note](d2-reth-system-call-fee-profile.md).
- A second `Admit` with the same `creditID` is rejected
  (`credit_already_consumed`, or `credit_already_reconciled` if it was refunded).
  An `Admit` from a sender with no available credit is `no_credit`.

### Admission checks (root, ordered)

`wrong_network → bad_signature_syntax → unsupported_tx_type → too_large →
declared_gas_over_g_fi → payload_not_disseminated → per_sender_queue_full →
global_queue_full → credit charge`. No application logic runs; no future balance
is predicted. Every admitted entry's `declaredGas ≤ g_fi`.

### Enqueue certificate vs HTTP ack

Only a successful `Admit` yields an `*EnqueueCertificate` (`seq`, payload digest,
admission round). **A local HTTP response or a shard-statistics field is never an
enqueue certificate.**

### Entry lifecycle: pending → tentatively executed → certified-consumed

Each entry has three states.
`ProcessDuePrefix` **tentatively executes** the pending prefix whose combined
`declaredGas` fits `g_fi`, marking each `entryTentativelyExecuted`. A poisoned
entry (`nonce_already_used`, `insufficient_balance`, `fee_cap_below_base_fee`,
`incompatible_activated_rules`, `higher_nonce_not_ready`) is consumed with its
authenticated reason and does **not** stall the queue.

**D2 gas accounting (reconciled).** When the produced EVM block is imported, D2
§3 charges *each executed prefix entry's* gas — the actual gas an entry valid at
its turn consumed, whether it succeeded or EVM-reverted (`ExecGas ≤ declaredGas`)
— to `g_forced_actual` against the **same reserved `g_fi`**, plus
`RejectedConsumptionGas` for each entry invalid at its turn. It is **never**
charged to ordinary block capacity, so the reservation this section relies on is
real: a discretionary-transaction backlog can never make an admitted prefix
unincludable. See [ADR 0004](../adr/0004-reth-system-call-fee-profile.md) §3 and
`evmroot/d2import.go` `reconcileWork`.
`AcknowledgeConsumption(throughSeq)` moves every live entry with `seq ≤ throughSeq`
to `entryCertifiedConsumed`, **removes it from the executable queue, releases its
per-sender / global slot, and archives it** (retained for proof export, never
re-executed). It advances the watermark **exactly once**; a repeat / lower call
is a no-op.

**Crash / replay.** `ProcessDuePrefix` skips certified-consumed entries
(`EntryOutcome.AlreadyFinal`) — a re-run after a restart never re-executes an
acknowledged entry, and the freed capacity lets a previously `per_sender_queue_full`
sender admit (`TestD5_QueueLifecycleReleasesCapacityAndNoReExecution`).

### Refund provenance — one bound rollback-and-return transition

The first-review model let `ReconcileUnusedCredit` restore the balance and mark
the credit reconciled **without touching the credit's live queue entry**. That
allowed credit reuse: deposit one credit, admit `c1` (seq 0), refund `c1`, admit
`c2` (seq 1) from the restored balance — `ProcessDuePrefix` then executes seq 0
*and* seq 1, so one paid credit backs two entries. Passing `nil` for the queue
skipped the consumed-entry guard entirely.

`ReconcileUnusedCredit(RefundStatement{CreditID, Owner, RootCertifiedUnused}, q)`
is now the certified admission rollback **and** the credit return as one
transition. It applies **only** when:

- the statement is root-certified (`RootCertifiedUnused`);
- the forced inbox `q` it rolls back is supplied — `q == nil` is rejected
  (`reconciliation must be applied against the forced inbox it rolls back`);
- **`q` is the inbox this escrow backs** — `q.escrow == e`. `seq` and `creditID`
  are only unique *within* a queue, so a queue from another escrow/admission
  domain (with its own owner-`a`, credit-`c1`, seq-0 entry) cannot stand in: a
  refund on escrow 1 handed escrow 2's queue would refund escrow 1 while revoking
  escrow 2's entry, leaving escrow 1's original entry executable. In a deployment
  this binding is the authenticated network/partition/queue domain; the model's
  `q.escrow == e` is its stand-in. Rejected **before any mutation**;
- the statement's `Owner` equals the credit's **recorded** owner (a refund can
  only return value to the original owner — not a caller-selected address);
- it has not already been reconciled;
- if the credit was consumed into a queue entry, that entry is still
  `entryPending` — a `entryTentativelyExecuted` or `entryCertifiedConsumed`
  entry cannot be rolled back and its credit is not refundable.

A pending entry is **permanently revoked** here — `q.RevokeEntry(seq, creditID)`
matches on both `seq` and `creditID`, drops it from the live queue and releases
its per-sender / global slot. A revoked entry is neither live nor archived, so it
no longer blocks `PositionCutoffSatisfied`: its admission was resolved by the
certified rollback. `consumedBy` is cleared and the credit id is marked
reconciled, so the same paid credit can never also back an executed entry.

Applied **at most once** regardless of racing requests. Re-admitting a reconciled
`creditID` fails (`credit_already_reconciled`); the restored balance is usable
only through a fresh credit id, and it backs exactly one fresh admission. A
conflicting `Admit` / reconciliation interleaving can neither create nor redirect
credit.

### Inclusion bound `K` — entry-count / fragmentation aware

FIFO entries are **indivisible**, so the adversary makes every entry as large as
the declared limit allows:

```
entriesPerBlock  = max(1, g_fi / declaredGasLimit)
blocksForBacklog = ceil( (maxBacklogEntries + 1) / entriesPerBlock )
K = blocksForBacklog + originObservationLagBlocks + rootRoundAllowanceBlocks
```

All three added terms are in **produced EVM blocks**. `maxBacklogEntries` is the
admission-bounded global-queue size; `declaredGasLimit` is the per-entry cap; the
`+1` counts the entry itself. Vector `inclusion_bound_k`:
`adversarial_indivisible_packing` — **3 entries of 60 gas, `g_fi` 100 ⇒ one per
block ⇒ K = 3** (the case the earlier fluid-gas formula got wrong, returning 2);
`half_target_two_per_block` ⇒ K = 10; `empty_backlog` ⇒ K = 2.

### Sponsor path — executable

`GrantSponsoredCredit(SponsorGrant{GrantID, Sponsor, Recipient, Amount, Certified})`
debits a sponsor's certified credits and credits a first-time `Recipient`, so a
credit-less newcomer can then `Admit` (`TestD5_SponsorPathIsExecutable`;
`SponsorPathAvailable()`). It dedups on `GrantID`. This replaces the former
`SponsorPathDocumented = true` constant with a real path. Local receipt of a
request is not a liveness promise; bounded inclusion assumes root enqueue
progress and enough honest execution weight. A root quorum failure cannot be
repaired by this queue.

## 5. Acceptance mapping

| D5 acceptance clause | Evidence |
|---|---|
| no unbacked admission | certified-deposit dedup + `no_credit`; `forced_inbox.duplicate_certified_deposit_rejected`, `admit_without_credit_rejected`; `TestD5_InboxNoUnbackedAdmissionNoDoubleSpend` |
| no double spend | `forced_inbox.double_spend_of_credit_rejected` |
| no refund of reserved credits; refund provenance; a refund cannot leave the admitted entry executable; a refund cannot target a foreign queue | §4 "Refund provenance — one bound rollback-and-return transition" — owner-bound, queue-required, **queue-identity-bound** (`q.escrow == e`), pending-only, revokes the entry, once; `forced_inbox.refund_to_wrong_owner_rejected`, `refund_of_certified_consumed_entry_rejected`, `refund_without_root_certification_rejected`, `refund_race_applied_at_most_once`, `admit_reusing_a_reconciled_credit_rejected`, `refund_permanently_revokes_the_pending_queue_entry`, `refunded_balance_backs_exactly_one_fresh_admission`, `refund_with_no_queue_rejected`, `refund_with_a_foreign_escrow_queue_rejected`; `TestD5_RefundProvenance`, `TestD5_RefundedCreditCannotBackTwoEntries`, `TestD5_RefundRejectsForeignQueue` |
| no poisoned entry stalls the queue; **acknowledged entries leave the executable queue with no re-execution and released capacity** | §4 "Entry lifecycle"; `forced_inbox.poisoned_entry_does_not_stall_queue`, `acknowledgement_releases_per_sender_capacity`, `reprocess_after_ack_does_not_re_execute`; `TestD5_PoisonedEntryDoesNotStallQueue`, `TestD5_QueueLifecycleReleasesCapacityAndNoReExecution` |
| timely evidence survives delayed execution without premature withdrawal; **withdrawal linkage in compatible units** | §3 position cutoff (root-round deadline → certified-consumed positions, not a watermark comparison); `withdrawal_gates.cutoff_*`; `TestD5_PositionCutoffNotAWatermarkComparison`, `TestD5_WithdrawalGates` |
| published K derivation is entry-count / fragmentation aware; observation lag has explicit units | §4 `K` (indivisible entries, `entriesPerBlock`, terms in produced EVM blocks); `inclusion_bound_k.adversarial_indivisible_packing` (K=3); `TestD5_InclusionBoundK_EntryCountAware` |
| an HTTP acknowledgement is never an enqueue certificate | §4; `forced_inbox.http_ack_is_not_an_enqueue_certificate` |
| an executable permissionless newcomer path | §4 "Sponsor path"; `forced_inbox.certified_sponsor_grant_lets_a_newcomer_admit`; `TestD5_SponsorPathIsExecutable` |
| exact slashable vote domains + VoteInfo↔LedgerCommitInfo binding | §2; `vote_binding`, `slashable_conflicts`; `TestD5_VoteInfoLedgerCommitBinding`, `TestD5_SlashableConflictDomain` |
| PoS signing preimage binds network/domain even for non-committing votes; builtin argument is not a binding | §2; `vote_binding.non_committing_vote_still_binds_domain`; `TestD5_SigningPreimageBindsDomainEvenForNonCommittingVote` |

## 6. Reproduce

```
go test ./evmroot/... -run TestD5
go run ./evmroot/cmd/d5vectors            # print the vector set
go run ./evmroot/cmd/d5vectors -update    # regenerate testdata/d5-vectors.json
```
