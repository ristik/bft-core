# ADR 0006: Epoch handoff state machine (D4)

## Status

Proposed (D4, issue #6). Revised after the first review (#80): the endorsement
signs a `FrozenID` that binds the whole frozen state (not the bare body id); the
trust-base body records `EpochStart = A_min` and `A*` lives only in the commit
record (removes the D3-`EpochStart` circularity); `FinalizeCommit` /
`CommitFinalized` gates activation on the root ordering rule, not a round count;
a **multi-replica exploration** with a global signer lock replaces the
4-method-permutation check as the safety evidence. Freeze once re-reviewed by a
Go consensus / protocol reviewer other than the author. Depends on ADR 0003 (D1)
and ADR 0005 (D3).

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

4. **Activate requires a committed record.** From any pre-Commit phase it fails
   (`errNoCommit`); clock passage and local trust-base insertion cannot activate.

5. **Abort is pre-Commit and old-quorum only.** After it, the attempt `j` is
   dead; a replacement is attempt `j+1` with the same predecessor. A committed
   handoff cannot be aborted. Conflicting prepare/abort/activate records cannot
   all become effective.

## Deliverables

- `evmroot/d4handoff.go` — `Handoff` state, the phase transitions, `Authorized`,
  `FieldsAreKnown`, `PipelineDepth`.
- `evmroot/d4explore.go` — `checkInvariants` and 12 fault scenarios (delayed
  signatures, asymmetric delivery, missed earliest activation, crash at every
  phase, old quorum loss, committed abort vs late activate, incomplete-prepare
  via clock / REST insertion).
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
