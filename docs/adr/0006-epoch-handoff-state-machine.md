# ADR 0006: Epoch handoff state machine (D4)

## Status

Proposed (D4, issue #6). Revised after the first review (#80): the endorsement
signs a `FrozenID` that binds the whole frozen state (not the bare body id); the
trust-base body records `EarliestActivation = A_min` and `A*` lives only in the
`ActivatedTrustBase` commit record (removes the D3-`EpochStart` circularity — a
joint D3/D4 change); `FinalizeCommit` / `CommitFinalized` gates activation on the
root 2-chain rule, not a round count (the check is tightened in the third review,
below).

Revised again after the second review (#80): the multi-replica model's **global
signer lock** — which prevented *every* signer, honest or Byzantine, from
equivocating — assumed away the fault. It is replaced by an **adversarial
model**: honest signers hold durable local state and sign at most one of two
conflicting statements; an explicit Byzantine set of weight `≤ f_W` equivocates
freely (signs both); every quorum is the weight of the actual distinct
authenticated signer set (`WeightSet.SignerWeight`). The model enumerates every
honest assignment and shows **at most one** of two conflicting `FrozenID`s /
`CommitRecordID`s (conflicting `A*`) / a commit-vs-abort pair reaches a quorum
(G2). Per-replica commit tuples are kept un-deduplicated and required to agree
(G3), with a conflicting-`A*` counterexample the tuple check must flag. `G1`
("no signer equivocates") is explicitly dropped.

Revised again after the third review (#80):

- **`FinalizeCommit` no longer takes a round number.** It takes a descendant
  `CommitQC` — the executable stand-in for the root `SafetyModule.isCommitCandidate`
  relation plus the signed `LedgerCommitInfo` — and checks the real relation:
  `ParentCommitID == this CommitRecordID` (rejects an unrelated higher-round QC),
  `Round == CommitRound + 1` (rejects a timeout gap), `QuorumWeight ≥ ⌊2Wₒₗd/3⌋+1`,
  and a 32-byte committed root hash. `Commit` records the handoff's own
  `SelfCommitQC`.
- **The bootstrap step is explicit.** `FirstSuccessorProposal()` (only from a
  finalised commit) returns the successor-TR leader, the finalised committed root
  it builds on (not a new-set round — none exists yet), the finalised commit
  chain as authorisation, and `A*` as the proposed round; its certification is
  the first certified round `≥ A*`.
- **A handoff progress/abort model** (`d4progress.go`) supplements the static
  quorum enumeration. *(Superseded — see the fourth review.)*

Revised again after the fourth review (#80):

- **Finality evidence is a checked mapping, not a fabricated hash.** The
  descendant `CommitQC` is produced by `DeriveFinalityEvidence(RootCommitChain,
  commitRecordID, oldThreshold)` — a checked walk of the verifier's authenticated
  view of the root `LedgerCommitInfo` commit stream (a **verified external
  precondition**). It succeeds only for a hash-linked, consecutive-round, quorate
  chain that contains the commit **and a descendant** that extends it; the
  returned `CommittedRootHash` comes from the chain. `FinalizeCommit` still
  re-checks the relation directly, so a hand-built QC is also rejected.
  `FinalizeFromRootChain` is the positive helper. Negatives: 1-chain, gap,
  under-quorum, commit-not-in-chain.
- **The progress model no longer invents a handoff consensus.** The third-review
  "view-change + lock" model did not hold — a Byzantine handoff leader could send
  `X` to one signer and `Y` to another. `d4progress.go` rev 2: the **freeze
  record is committed by the existing root BFT consensus** before endorsement
  (`FrozenOrdered` — the verifier's authenticated view of that root commit), and
  root consensus commits at most one freeze per `(attempt, predecessor)`. An
  honest signer endorses only a `FrozenID` carrying a `FrozenOrdered` proof, so a
  Byzantine leader cannot split honest weight; durable per-signer state is
  checked **unconditionally** (restart-safe); two quorate `FrozenOrdered` proofs
  for one slot are flagged as a root-consensus violation, not resolved by the
  handoff.

Freeze once re-reviewed by a Go consensus / protocol reviewer other than the
author. Depends on ADR 0003 (D1) and ADR 0005 (D3).

## Context

`governance.tex` §"root handoff" specifies an ordered root transition but flags
that "a production version needs an explicit handoff state machine and
safety/liveness validation, including crash points; these requirements do not
assume the current REST intake already implements it." `appendix-evm.tex`
§"Trust Base Record Derivation" adds: "The wire version must reconcile root
pipelining, old-quorum endorsement and actual activation without requiring a
signature over unknown future state. Until that state machine is implemented and
validated, automatic PoS handoff is disabled."

D4 is that state machine and its validation.

## Decision

Adopt the state machine in
[`docs/design/d4-epoch-handoff-state-machine.md`](../design/d4-epoch-handoff-state-machine.md):

1. **Six phases + committed-abort**, strictly ordered, no phase skippable.
   Prepare/Freeze commit under the old root quorum; Endorse needs old-epoch
   unique signer weight ≥ `⌊2Wₒₗd/3⌋+1`; Commit binds the actual activation
   boundary `A*` and successor TR under old consensus rules; Activate is gated on
   the committed `A*`; Acknowledge closes old liabilities from the first
   new-assignment block's system operation.

2. **`A*` is fixed only at Commit**, with `A* ≥ A_min` and
   `A* ≥ commitRound + PipelineDepth`. The endorsement signature binds
   `bodyIdentity` and `A_min` but never `A*` or the successor TR — so no
   signature commits to state unknown when signed.

3. **`Authorized(round)`** returns the old set for rounds `< A*` and the new set
   for rounds `≥ A*` once committed; the old set for every round before commit or
   after abort. One `≥` comparison against one `A*` — no overlap, no gap.

4. **Activate requires a committed record that is final under the root
   2-chain.** From any pre-Commit phase it fails (`errNoCommit`); with a commit
   but no descendant commit it fails (`errCommitNotFinal`); clock passage and
   local trust-base insertion cannot activate. Safety of two conflicting commits
   / a commit and an abort rests on quorum intersection under Byzantine
   equivocation, not on a no-equivocation assumption (see the design §4
   adversarial model).

5. **Abort is pre-Commit and old-quorum only.** After it, the attempt `j` is
   dead; a replacement is attempt `j+1` with the same predecessor. A committed
   handoff cannot be aborted. Conflicting prepare/abort/activate records cannot
   all become effective.

## Deliverables

- `evmroot/d4handoff.go` — `Handoff` state, the phase transitions, `Authorized`,
  `FieldsAreKnown`, `PipelineDepth`, `CommitRecordID`, `ActivationRecord`,
  `CommitQC`, `RootCommit` / `RootCommitChain` / `DeriveFinalityEvidence`,
  `FinalizeCommit(descendant CommitQC, oldThreshold)` /
  `FinalizeFromRootChain`, `FrozenOrdered`, `FirstSuccessorProposal`.
- `evmroot/d4explore.go` — `checkInvariants` and 12 fault scenarios (delayed
  signatures, asymmetric delivery, missed earliest activation, crash at every
  phase, old quorum loss, committed abort vs late activate, incomplete-prepare
  via clock / REST insertion).
- `evmroot/d4multireplica.go` — the adversarial model: honest per-signer locks,
  a bounded Byzantine equivocating set, exhaustive honest-assignment
  quorum-intersection search (G2), per-replica commit tuples (G3), the
  conflicting-`A*` counterexample, the descendant-`CommitQC` finality negatives.
- `evmroot/d4progress.go` — the handoff progress/abort model (rev 2): the
  root-ordered freeze (`FrozenOrdered`), unconditional durable per-signer state,
  Byzantine-leader-cannot-split, commit-vs-abort exclusion, combined
  delay/restart/equivocation schedule.
- `evmroot/d4vectors.go` — scenario results plus the exhaustive 24-permutation
  phase-order check.
- `evmroot/testdata/d4-vectors.json` + `TestD4_VectorsMatchGolden`.

## Consequences

- `H1`–`H5` (trust-base storage, prepare/commit handoff, EVM assignment handoff
  and acknowledgement, joining readiness) implement against these phases and the
  `Authorized` boundary rule.
- `P5`/`P6` (deterministic snapshot, certified candidate transport) produce the
  `Candidate` this machine consumes; `D5` consumes the `f_W` bound and the
  endorsement domain.
- Automatic PoS handoff stays **disabled** until this machine is implemented in
  `rootchain/consensus` and re-validated against these scenarios with a real
  consensus harness — the model is necessary evidence, not sufficient.

## Alternatives considered

- **Endorse the exact `A*`.** Rejected: `A*` is not known until the old-quorum
  commit; endorsing it would be a signature over unknown future state, exactly
  what the spec forbids.
- **Activate on `A_min` (the proposed start).** Rejected: a locally submitted
  trust base could then activate on clock passage; activation must follow a
  committed record.
- **Allow abort after commit for liveness.** Rejected: a committed handoff and a
  later abort could both look effective to different replicas; abort is
  pre-Commit only.
- **A global signer non-equivocation lock as the safety model** (first-review
  version). Rejected on re-review: it forbids the Byzantine equivocation the
  protocol has to survive, so it proves nothing about the adversarial case.
  Replaced by the honest-lock + bounded-Byzantine-equivocation +
  quorum-intersection model.
- **Deduplicate committed handoffs by `FrozenID` in the exploration.** Rejected:
  it hides a disagreement on `A*` between replicas that committed the same
  `FrozenID`. Per-replica tuples are compared field-by-field instead.
- **Treat a larger descendant round as finality evidence** (`FinalizeCommit(uint64)`,
  second-review version). Rejected on the third review: any value `> CommitRound`
  toggled the flag with no linked block/QC/parent. Replaced by a descendant
  `CommitQC` with a checked parent link, consecutive round, quorum weight and
  committed root hash.
- **Rely on the static quorum-intersection enumeration as the whole handoff
  model.** Rejected: it assumes a fixed honest partition and cannot explain how
  ordering prevents an honest split before endorsement.
- **Model a bespoke handoff "view-change + lock" protocol** (third-review
  version). Rejected on the fourth review: a Byzantine handoff leader can send
  different `FrozenID`s to different signers within one view, and "following a
  leader is not agreement". Replaced by consuming the **existing root
  consensus's** commitment of the freeze record (`FrozenOrdered`) — no second
  consensus.
- **Fabricate the descendant `CommitQC` in a helper.** Rejected on the fourth
  review: `CommittedRootHash` was an unrelated SHA-256 and the weight was
  caller-supplied. `DeriveFinalityEvidence` derives it from an authenticated
  `RootCommitChain` and takes the root hash from the chain.
