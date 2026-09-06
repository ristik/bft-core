# ADR 0007: Accountability, retirement and forced-inbox model (D5)

## Status

Proposed (D5, issue #7). Revised after the first review (#81): a three-state
entry lifecycle (pending → tentatively executed → certified-consumed + archived)
that releases queue capacity and never re-executes on replay; the withdrawal
gate uses a **root-round liability deadline → certified-consumed positions**
cutoff, not a watermark-vs-round comparison; `K` is **entry-count /
fragmentation aware** (indivisible entries); credits and refunds are bound to a
**certified deposit identity** and the **recorded owner**, with an **executable
sponsor path**.

Revised again after the second review (#81): a refund is the certified admission
rollback and the credit return as **one bound transition**. `ReconcileUnusedCredit`
now requires the forced inbox it rolls back (rejects `nil`), applies only to a
still-`pending` entry, and **permanently revokes** that entry
(`RevokeEntry(seq, creditID)` — matched on both fields, drops it from the live
queue, releases the slot) before returning the credit. This closes the credit-reuse
gap where a refunded credit's admitted entry stayed executable (refund `c1`, admit
`c2` from the restored balance, both execute). Freeze once re-reviewed by a
consensus reviewer and a custody-accounting reviewer, neither the author. Depends
on ADR 0003/0005/0006.

## Context

The initial PoS needs objective double-signing accountability, a safe retirement
path, and a gas-safe forced-inclusion queue. `appendix-evm.tex` §§ Evidence and
Forced Inclusion and `governance.tex` §"Economic Invariants" specify the rules;
the prototype implements none of them, and the spec explicitly leaves the
admission-credit mechanism to be pinned before the endpoint is enabled.

## Decision

Adopt the model in
[`docs/design/d5-accountability-retirement-inbox.md`](../design/d5-accountability-retirement-inbox.md):

1. **Slashable vote domain.** `VoteInfo.Hash = SHA-256(CBOR(VoteInfo))`;
   `LedgerCommitInfo` binds a vote iff `VoteInfoHash == VoteInfo.Hash`; the
   voting epoch/round come from the authenticated `VoteInfo`, not the seal's
   committed round. The signed preimage opens with `"UNICITY_POS_VOTE"` + network
   and binds `messageDomain` even for a non-committing vote. The offense is a
   different signed statement for the same `(key, network, domain, votingEpoch,
   votingRound)`; duplicate delivery, different domain/round, and legacy votes
   are not the offense.

2. **Retirement lifecycle.** `Bonded → RetirementRequested → Draining →
   Released`. `R_ret` is recorded only on an authenticated acknowledgement that
   the stake backs no active or prepared successor. Withdrawal requires
   `now ≥ max(R_ret + Δ_hold, inheritedProtection)`, the inbox watermark past the
   last liability, and no pending timely evidence. `Δ_hold > Δ_ev + Δ_incl +
   Δ_exec`, `W_cert ≤ Δ_ev < Δ_hold`. Evidence is timely by in-window execution
   **or** in-window forced-inbox commitment of its complete payload.

3. **Paid forced inbox.** Prepaid UCT credits in an immutable escrow; a certified
   deposit credits once (duplicate proof is a no-op); admission consumes exactly
   one unique credit in root consensus; a refund of an unused credit requires a
   root-certified reconciliation against the queue, permanently revokes the
   still-pending entry, and applies at most once. FIFO progresses past a
   poisoned entry (consumed with an authenticated reason). The consumption
   watermark advances exactly once. Only a successful admission yields an
   `EnqueueCertificate`; an HTTP ack is not one. `K` is published as
   `ceil((maxBacklog + declaredLimit)/g_fi) + observationLag + rootRoundAllowance`.
   A first-time user without credits has a documented permissionless sponsor path,
   and the inclusion guarantee states that condition.

## Deliverables

- `evmroot/d5vote.go`, `d5retire.go`, `d5inbox.go` — the three models.
  `d5inbox.go` adds `ForcedInbox.RevokeEntry` and the bound
  rollback-and-return in `ReconcileUnusedCredit`.
- `evmroot/testdata/d5-vectors.json` — vote binding, slashable-conflict domain,
  protection-param ordering, withdrawal gates, evidence timeliness, forced-inbox
  accounting (no unbacked admission / no double spend / no reserved-credit
  refund / poison does not stall / watermark once), and `K` derivation.
- `evmroot/cmd/d5vectors` + `TestD5_VectorsMatchGolden`.

## Consequences

- `S1`–`S4` (consensus-signature primitive, objective slashing, evidence
  retention, end-to-end slashing) implement against the vote domain and evidence
  rules; `P2`–`P4` (stake custody, key binding, retirement queue) against the
  reservation lifecycle; `I1`–`I5` (admission queue, FIFO execution, root
  acknowledgements, evidence watermark, censorship gate) against the forced-inbox
  model.
- The admission-credit endpoint stays disabled until the anti-spam cost and
  sponsor path are pinned (this ADR pins the mechanism; the parameter values are
  a release decision).
- Downtime slashing / absence-based jailing remain disabled.

## Alternatives considered

- **Bind the domain as a builtin argument.** Rejected: a caller-supplied domain
  is not authentication; it must be inside the signed preimage.
- **Refund on entry rejection.** Rejected: a poisoned entry is still consumed
  (it occupied a queue slot and admission work); refunds are only for credits
  whose entry was never consumed, via root-certified reconciliation.
- **Refund by restoring balance alone, leaving the queue entry in place.**
  Rejected on re-review: the refunded credit's admitted entry stayed executable,
  so one paid credit could back both a refund and an executed entry. The refund
  now revokes the entry in the same transition and requires the queue to do so.
- **Treat an HTTP 200 from the intake as an enqueue receipt.** Rejected
  explicitly by the spec; only a consensus enqueue certificate counts.
