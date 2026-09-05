# D5 — Accountability, retirement and forced-inbox model

Issue: [#7 D5](https://github.com/ristik/bft-core/issues/7) · Milestone: M0 ·
Prereqs: [#3 D1](https://github.com/ristik/bft-core/issues/3),
[#6 D4](https://github.com/ristik/bft-core/issues/6) · Status: **proposed for freeze**

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
- **`CanWithdraw(now)`** requires, in order:
  1. phase `Draining`;
  2. `now ≥ max(R_ret + Δ_hold, inheritedProtectionUntil)` — inherited protection
     from key rotation / delegation changes dominates a nearer boundary; key
     rotation and queued withdrawals cannot remove liability for an earlier
     offense;
  3. `inboxWatermark ≥ LastLiabilityRound` — the forced-inbox consumption
     watermark has passed this reservation's last liability;
  4. no timely-queued evidence case against the key is unprocessed.
  Exceeding `Δ_incl` / `Δ_exec` never unlocks an unresolved liability.
- **`EvidenceTimely`** — timely iff executed within `Δ_ev` root rounds of the
  offense, **or** its complete payload was committed to the forced inbox within
  that window. A bare local submission or an unavailable payload hash does not
  preserve timeliness. A timely queued case blocks the related withdrawal until
  processed — even after a late execution.

## 4. Paid forced-inbox admission

### Credits

- `CreditEscrow` is an immutable EVM escrow. `ApplyDeposit(proofID, owner, amount)`
  credits against a **certified** deposit; replaying the same `proofID` is a
  **no-op** — never a second credit, so a duplicated deposit proof produces no
  unbacked admission.
- Admission consumes **exactly one unique, unconsumed** credit in root consensus.
  A second `Admit` with the same `creditID` is rejected (`credit_already_consumed`
  / `credit_already_reserved`) — no double spend. An `Admit` from a sender with
  no credit is rejected (`no_credit`) — no unbacked admission.

### Admission checks (root, ordered)

`wrong_network → bad_signature_syntax → unsupported_tx_type → too_large →
declared_gas_over_g_fi → payload_not_disseminated → per_sender_queue_full →
global_queue_full → credit charge`. No application logic runs; no future balance
is predicted. Every admitted entry's `declaredGas ≤ g_fi`.

### Enqueue certificate vs HTTP ack

Only a successful `Admit` yields an `*EnqueueCertificate` (`seq`, payload digest,
admission round). **A local HTTP response or a shard-statistics field is never an
enqueue certificate.**

### FIFO progress and poisoned entries

`ProcessDuePrefix` processes the FIFO prefix whose combined `declaredGas` fits
`g_fi`. An entry invalid at its deterministic turn (`nonce_already_used`,
`insufficient_balance`, `fee_cap_below_base_fee`, `incompatible_activated_rules`,
`higher_nonce_not_ready`) is **consumed with an authenticated rejection reason**
and does **not** stall the queue; the entries after it still execute. An
executable transaction that reverts consumes gas and has a normal failed receipt.

### Consumption watermark

`AcknowledgeConsumption(throughSeq)` advances the watermark **exactly once**; a
repeat call with the same or a lower value is a no-op — a repeat UC does not
double-advance the watermark or create a second claim.

### Refund reconciliation

`ReconcileUnusedCredit` refunds a credit **only** when the root has certified the
entry was never consumed, and **at most once** regardless of how many refund
requests race. A credit backing a consumed entry is never refunded.

### Inclusion bound `K`

```
K = ceil( (maxBacklogGas + declaredGasLimit) / g_fi )
    + originObservationLagBlocks
    + rootRoundAllowanceBlocks
```

published in produced EVM blocks, folding in the maximum admitted backlog, the
declared per-entry gas limit, the reserved per-block budget `g_fi`, and the
input-observation lag. The root-round allowance additionally assumes bounded EVM
progress. Vector `inclusion_bound_k` shows `K = 16` for a 3M-gas backlog with
`g_fi = 300k`, lag 2, allowance 3.

### Sponsor path

A first-time user without credits has a **documented permissionless sponsor
path**; the inclusion guarantee is explicitly conditional on it
(`SponsorPathDocumented`). Local receipt of a request is not a liveness promise;
bounded inclusion assumes root enqueue progress and enough honest execution
weight producing blocks. A root quorum failure cannot be repaired by this queue.

## 5. Acceptance mapping

| D5 acceptance clause | Evidence |
|---|---|
| no unbacked admission | `forced_inbox.duplicate_deposit_rejected`, `admit_without_credit_rejected`; `TestD5_InboxNoUnbackedAdmissionNoDoubleSpend` |
| no double spend | `forced_inbox.double_spend_of_credit_rejected` |
| no refund of reserved credits | `forced_inbox.refund_of_reserved_credit_rejected`, `refund_race_applied_at_most_once`; `TestD5_RefundOnlyViaReconciliationAndAtMostOnce` |
| no poisoned nonce/fee/balance entry stalls the queue | `forced_inbox.poisoned_entry_does_not_stall_queue`; `TestD5_PoisonedEntryDoesNotStallQueue` |
| timely evidence survives delayed execution without premature withdrawal | `evidence_timeliness.inbox_committed_in_window_then_late_exec` + `withdrawal_gates.timely_evidence_pending`; `TestD5_WithdrawalGates` |
| published K derivation includes max backlog, declared gas limits, origin-observation lag | §4 `K`; `inclusion_bound_k`; `TestD5_InclusionBoundK` |
| an HTTP acknowledgement is never an enqueue certificate | §4; `forced_inbox.http_ack_is_not_an_enqueue_certificate` |
| exact slashable vote domains + VoteInfo↔LedgerCommitInfo binding | §2; `vote_binding`, `slashable_conflicts`; `TestD5_VoteInfoLedgerCommitBinding`, `TestD5_SlashableConflictDomain` |
| PoS signing preimage binds network/domain even for non-committing votes; builtin argument is not a binding | §2; `vote_binding.non_committing_vote_still_binds_domain`; `TestD5_SigningPreimageBindsDomainEvenForNonCommittingVote` |

## 6. Reproduce

```
go test ./evmroot/... -run TestD5
go run ./evmroot/cmd/d5vectors            # print the vector set
go run ./evmroot/cmd/d5vectors -update    # regenerate testdata/d5-vectors.json
```
