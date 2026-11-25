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
- **Signature rule (both offences, P85 reset release).** Evidence accepts a
  signature only in the strict native form: exactly 65 bytes `r‖s‖v`,
  `1 ≤ r < n`, `1 ≤ s ≤ n/2`, `v ∈ {0,1}`, and one recovery with that parity
  (`ecrecover` with `v+27`) that yields the member's installed historical key. A
  64-byte compact signature, a high `s`, the opposite parity, `v` of 27/28 and
  `v ∈ {2,3}` are refused. Recovery ids 2 and 3 are native-valid (the
  bft-go-base verifier accepts `v ≤ 3`) but **ineligible for P85 evidence**:
  the native signer only emits 0 and 1, and 2/3 occur only when the ephemeral
  point's x-coordinate is `≥ n` (probability ≈ 2⁻¹²⁸). The equivocation path
  moved to this rule as well (it previously accepted 64 bytes and tried both
  parities).

### 2.1 Post-term seal offence (#1297)

The equivocation offence cannot catch a retired committee that keeps signing:
every old-committee seal after the handoff is a *new* round, so there is no
second statement for the same slot. D4 lets the old committee keep certifying
empty suffix blocks past `A*` (D4 §1, §4), so "signed after its term" alone is
not an offence either. The post-term offence ([#1297](https://github.com/ristik/bft-core/issues/1297)) is:

> A quorum of epoch `e`'s installed committee signed a native scheme 2 seal
> (tag 39005 v1) with `commitEpoch = e`, **`commitRound ≥ start[e+1]`** and
> **`Hash ≠ R_H`**, the terminal root of epoch `e`'s applied Closure.

- **Round.** `commitRound` is the seal's `RootChainRoundNumber`, the round B1
  compares with the epoch's exclusive end. Equality is an offence. The VoteInfo
  voting round is *never* compared with `A* = start[e+1]`: a seal committing
  `A*−1` is in term even when its vote is at `votingRound ≥ A*`.
- **Frozen root exemption.** Every seal with `Hash = R_H` is exempt — H's own
  commit at `c ≥ A*` and arbitrarily late honest empty-suffix repeats alike. No
  test on `VoteInfo.exec` turns such a seal into a charge. The signature bytes
  cannot tell an honest late repeat from a backdated one; distinguishing intent
  among signatures on the frozen root would need a protocol change.
- **Statement (astra's option (a)).** The reporter supplies the native seal
  fields: `commitRound`, `commitEpoch = e`, `commitTimestamp`, `PreviousHash`
  and `Hash`. `PreviousHash` is an opaque signed word, and no VoteInfo opening
  is required. Wallets and B1 accept a quorum seal without that opening. If
  evidence needed it, a reporter holding a whole accepted seal could charge
  nobody. Evidence rebuilds the tag-39005 seal bytes with null signatures under
  its installed `N` and verifies over `SHA-256` of those bytes. The statement
  conditions are `commitEpoch = e` and `commitRound > 0`. A wrong opening, an
  altered field or another `N` changes the signed bytes and fails the
  signatures. No PV signature, QC envelope or shard inclusion proof is needed.
- **Installed lineage.** Evidence reads epochs `e` and `e+1` (presence, start,
  end, signing scheme, member keys and weights, `activationCommitID`) from a
  bounded read-only view of the genesis-pinned SealRegistry and requires both
  installed and consecutive with `end[e] = start[e+1]`. The authenticated system
  writer fixes that lineage; a reporter never supplies a UTB. The ordinary B1
  verifier and 0x0100 keep refusing the out-of-term seal.
- **Quorum.** One strictly increasing subset of at most 16 distinct predecessor
  member indices, one signature each. Every supplied signature must verify under
  the rule of §2 — an invalid, unknown or repeated extra refuses the whole
  submission (a reporter can leave bad extras out). The checked weight sum must
  reach `⌊2W/3⌋+1`, and the charged member must be in the subset. A lone
  signature never proves the offence.
- **Attribution (v1).** Only a P85 custody assignment with `rootEpoch = e`,
  closed by its applied Closure: custody keeps the closure's `terminalRoot`
  (`R_H`) and binds the Closure to `e+1`'s `activationCommitID` through its H
  RecordID, with `o = hRound < start[e+1]`. Compact mode charges the exact seat
  and its lot, legacy mode the exposure's lots; the key is the historical
  exposure key. One submission opens one case for one signer.
- **Root-only terms are a residual.** A term with no custody assignment for `e`
  (a root-only handoff, an operator-derived committee) fails closed with a typed
  error: its post-term seals carry **no v1 penalty**. Charging them would need an
  authenticated epoch terminal record and an epoch→exposure binding that v1 does
  not have.
- **Offence identity.** A versioned domain and an offence-kind tag (so a
  post-term case never collides with an equivocation of the same voting round),
  the deployment domain, chain id, Evidence address, `N`, `G`, then for this
  offence `e`, the native seal digest and the charged key hash. Reporter,
  signatures, subset and ordinal are excluded, so another valid subset or another
  reporter of the same seal and signer is the same case and debits once. Holds,
  exclusion, the capped historical debit, bounded settlement and the incremental
  bounty are the equivocation path's.
- **Admission deadline.** The deadline does not start from the Closure
  record's own `pClose`/`tClose`. Those date the source record, and custody may
  apply it much later. The anchors come from the first permissionless
  `custody.anchorTerm(assignmentID, hRecordID, terminalRoot)` call at or after
  the moment the evidence context is jointly usable on chain: the applied
  Closure (the call opens its closure key with the H RecordID and `R_H` from
  the Closure record), its attribution and the installed successor
  (`SuccessorNotInstalled` before that). The call captures the current
  authenticated `p0 = progress()` and `t0 = ucTime()` once. Waiting before the
  call cannot consume the report window, because both clocks start at the call.
  Until the call, the term stays fail-safe: its lots cannot mature
  (`TermAnchorPending`) and no post-term report against it is admitted. There
  is no keeper or relay, so the parties that need the call make it. The exit
  tooling makes it: `ubft validator claim`, the package's
  `remote_entity.py claim` and the lanes' exit step all anchor every closed,
  unanchored term of the exiting lots first. Any reporter can make it too. A
  report is the two-call path: `anchorTerm` once, then the evidence submission.
  A report is admitted while
  `p ≤ p0 + suffixEvidenceWindow` **or** `t ≤ t0 + reportWindow`; only the
  expiry of both closes admission. The progress clock can run out in minutes when
  rounds are fast; the UC-seconds clock keeps the report window open for real
  time. Each historical lot's floors rise from the same anchors
  (`timeUntil ≥ t0 + timeFloor`, progress floors likewise). Equivocation keeps
  its existing deadline.
- **Key isolation across root histories.** `N` is signed, but the root genesis
  `G` is not: it appears only inside a VoteInfo opening, and an opaque
  `PreviousHash` hides it. `G`, the chain id and the Evidence address in the
  offence ID name this deployment, not the history that produced a signature.
  Consider a seal signed by an honest key in another root history that shares
  `N`, such as an earlier reset generation. This deployment would charge it.
  Every validator must therefore sign each independent root history with a
  fresh, genesis-specific consensus key, including when it enrolls later and
  when it rotates. The reset tooling enforces this:
  - `generate.py` records the generation's genesis root signing keys in its
    manifest.
  - Its retired inventory is cumulative. It holds every root key of the prior
    generation's verified UTB history (`ubft trust-base utb-verify --keys-out`),
    which covers keys that joined or rotated after genesis, and the prior
    generation's own inherited list. It refuses to run without that history,
    unless `--first-generation` says there is none.
  - It publishes the union as `network/retired-root-keys.json`.
  - The joiner, enrollment and rotation tooling refuse any key on that list:
    `joiner.py`, `pos_join.py`, `remote_joiner.py`, and
    `ubft validator --retired-root-keys`.

  The key hash is keccak256 of the compressed key, which is custody's root key
  hash. If this isolation cannot be guaranteed for a deployment, opaque evidence
  must stay disabled there until the native signed statement binds the root
  genesis.
- **Corpus.** Go-signed vectors through the native paths (votesig,
  `types.UnicitySeal`, `types.RootTrustBaseV2`, the secp256k1 signer):
  [`s1ref/s1gen/testdata/post-term-corpus-go-v1.json`](../../s1ref/s1gen/testdata/post-term-corpus-go-v1.json).
  It covers:
  - the `A*`/`A*−1` boundary, the exempt H commit and the suffix repeats;
  - opaque-`PreviousHash` seals that b1ref accepts with `e` as the open tip,
    charged from the seal alone, and a genuine frozen-root repeat that stays
    exempt;
  - a seal from another root history, charged when presented with its own word;
  - quorum and subset cases;
  - every signature edge case, with what `ecrecover` and the native verifier
    make of it.

## 3. Reservation and retirement lifecycle

Phases: `Bonded → RetirementRequested → Draining → Released`.

- Requesting retirement does **not** start the protection clock.
  `AcknowledgeRetirement` records `R_ret` — an authenticated acknowledgement that
  the stake no longer backs any **active or prepared successor** assignment. An
  acknowledgement while a prepared successor still relies on the stake is
  rejected.
- **Timing parameters** (`ProtectionParams`), ordering mandatory:
  `Δ_ev < Δ_hold` and `Δ_hold > Δ_ev + Δ_incl + Δ_exec` (checked arithmetic). Certificate age is not a parameter: certificates do not expire (owner decision §25, ADR 0007 note).
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
- **Deployed form (P85, option A).** The contracts use ordinary EVM inclusion
  for timeliness (no forced inbox) and count `Δ` in authenticated *progress*
  (root rounds of ordinary blocks), plus one elapsed-time floor in **UC
  seconds** — the root quorum's certified timestamps, monotonic on import, with
  the voter clock skew (30 s). Progress alone measures no time: fast rounds
  advance it quickly.

### 3.1 Retirement report window and time floor (#1298)

A lot can leave custody only through `mature`, which needs the strict progress
gates **and** `t ≥ max(tRet + lot.timeFloor, timeUntil)` (inclusive). Request and
key rotation start no clock; a lot that returns to Free keeps its floors across
reuse. The floor must outlast the window in which a timely post-term report can
still land and settle ([#1298](https://github.com/ristik/bft-core/issues/1298)):

- `reportWindow` = W (the wallet's trust-base staleness window: within W a
  wallet accepts a known historical seal without a refresh; 7 days in
  production) plus a
  reporting/inclusion margin; `settlementMargin` covers settling a timely case.
  Both are deployment immutables.
- Policy validation (genesis and governance updates) requires
  **`timeFloor ≥ reportWindow + settlementMargin`**, so a lot's captured floor
  always covers a report admitted at the last second of the window plus its
  settlement. `MAX_FLOOR = 691,200 s`.

| Profile | reportWindow | settlementMargin | timeFloor |
|---|---|---|---|
| production | 648,000 s (7 d W + 12 h) | 43,200 s (12 h) | 691,200 s (8 d) |
| resettable testnet | 1,800 s (900 W + 900) | 1,800 s | 3,600 s |

The floors are captured per lot when it is bonded and per assignment policy, so
the policy is set before any reset-genesis lot exists; changing it on a running
chain cannot repair old captured floors. A pending hold stays decisive beyond
either margin. Both features ship in one reset-genesis release: no toggle, no
migration of old lots.

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
| post-term seal offence: `A*` boundary on the seal round, frozen-root exemption, quorum subset, strict signatures | §2.1; `s1ref/s1gen/testdata/post-term-corpus-go-v1.json`; `TestPostTermCorpusIndependentReplay`, `TestPostTermSignatureEdgeCases`; contracts corpus replay |
| retirement time floor covers the report window and settlement | §3.1; contracts genesis and governance policy tests |

## 6. Reproduce

```
go test ./evmroot/... -run TestD5
go run ./evmroot/cmd/d5vectors            # print the vector set
go run ./evmroot/cmd/d5vectors -update    # regenerate testdata/d5-vectors.json
go test ./s1ref/s1gen -run PostTerm       # post-term seal corpus (-update regenerates it)
```
