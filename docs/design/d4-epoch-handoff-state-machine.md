# D4 — Epoch handoff state machine

Issue: [#6 D4](https://github.com/ristik/bft-core/issues/6) · Milestone: M0 ·
Prereqs: [#3 D1](https://github.com/ristik/bft-core/issues/3),
[#5 D3](https://github.com/ristik/bft-core/issues/5) · Status: **proposed for freeze**

D4 is the executable state machine for the root epoch handoff:
`prepare → freeze → endorse → commit → activate → acknowledge`, plus
`committed-abort`. It fixes the exact consensus rounds and message domains that
determine actual activation and the frozen state summary — including root
pipelining — such that **no signature depends on state unknown when it is
signed**, and it makes the two headline safety properties checkable by
exploration:

- there are never **two effective successors** for one epoch;
- there is **no root round at which both the old and the new assignment** may
  authorise a governance block — no overlap, no gap.

Model: [`evmroot/d4handoff.go`](../../evmroot/d4handoff.go),
[`evmroot/d4explore.go`](../../evmroot/d4explore.go). Vectors:
[`evmroot/testdata/d4-vectors.json`](../../evmroot/testdata/d4-vectors.json).
Decision record: [ADR 0006](../adr/0006-epoch-handoff-state-machine.md).

Specification basis: `docs/pos/specification/governance.tex` §"root handoff"
(the ordered transition), §"Election", §"Extension"; `evm-partition.tex`
§"Validator Set"; `appendix-evm.tex` §§ Candidate Record, Trust Base Record
Derivation.

---

## 1. Phases

| Phase | What is committed | Under whose quorum | New durable fields |
|---|---|---|---|
| **Prepare** | prepare record; admission of new old-assignment governance proposals closed; in-flight work drained or cancelled | old root quorum | — |
| **Freeze** | last certified EVM block/state; frozen root state summary; next trust-base body constructed (D3 v2 identity) | old root quorum (same record as Prepare) | `FrozenSummary`, `LastEVMParent`, `BodyIdentity` |
| **Endorse** | old validators endorse **only the agreed body**, domain-separated signature, durable non-equivocation | old-epoch **unique signer weight ≥ ⌊2Wₒₗd/3⌋+1** | `EndorsementWeight`, `EndorsementDomain` |
| **Commit** | the endorsed handoff: new body + **actual activation boundary A\*** + successor technical record | old consensus rules | `CommitRound`, `ActivationRound (A*)`, `SuccessorTRHash` |
| **Activate** | the new root set resumes from the certified handoff state | new set, gated on the **committed** A* | phase only |
| **Acknowledge** | first new-assignment governance block's system op acknowledges the handoff, closing the old assignment's liabilities | new assignment | `AckEVMRound` |
| **Committed-abort** | old-quorum committed abort of an **incomplete** prepare (pre-Commit only) | old root quorum | `AbortReason` |

Progress is strictly `Prepared → Frozen → Endorsed → Committed → Activated →
Acknowledged`. `Aborted` is reachable only from `Prepared`/`Frozen`/`Endorsed`.
No phase can be skipped — the exhaustive interleaving check (§4) confirms that of
all 24 orderings of the four core phases, only the canonical order reaches
`committed`.

## 2. Rounds, pipelining, and "no signature over unknown future state"

The candidate carries `A_min` (earliest activation bound) — **not** a prediction
of the actual round (`appendix-evm.tex` §"Candidate Record").

### The endorsement binds the whole frozen state (`FrozenID`)

`Freeze` does not store `frozenSummary` / `lastEVMParent` loosely next to the
body. It computes

```
FrozenID = SHA-256( CBOR([ "UNICITY_HANDOFF_FROZEN",
                            bodyIdentity, frozenSummary, lastEVMParent,
                            candidateHash, attempt, predecessorHash ]) )
```

and the endorsement signs **`FrozenID`**, not the bare body identity. Two
handoffs that freeze the *same* body with different frozen summaries or EVM
parents get **different** `FrozenID`s, so a single endorsement can never be
counted toward divergent handoff states
(`TestD4_FreezeBindsFrozenStateIntoEndorsedIdentity`). `Freeze` also rejects a
body whose `EarliestActivation != A_min` or whose predecessor ≠ the candidate's,
and a missing frozen summary / parent.

### The trust-base body records `A_min`, not `A*`

D3's v2 body hashes `EarliestActivation` (renamed from `EpochStart` in the joint
D3/D4 revision). To keep the body identity stable from Freeze,
`EarliestActivation == A_min` (known at Freeze). The **actual** boundary `A*` is
fixed only at Commit and lives **only in the `ActivatedTrustBase` commit
record** — it is never in the body, so fixing it later cannot change any
endorsed identity. This removes the circularity the review flagged.

| Signed message | Fields it binds | All known at signing? |
|---|---|---|
| endorsement | `network, protocolVersion, predecessorHash, attempt, FrozenID, A_min` (= body `EarliestActivation`) | yes. **No `A*`, no successor TR.** |
| commit | `… + A*, successorTRHash` | yes — `A*` is fixed now, `A* ≥ A_min` and `A* ≥ commitRound + PipelineDepth`; the successor TR is constructed now |

### Finality is the root rule, not a round count

`PipelineDepth` is only the minimum gap `A*` must leave after the commit round so
`A*` is not scheduled inside the reorg window. It does **not** establish
finality. Finality of the commit is the root's own 2-chain rule, modelled by
`FinalizeCommit(descendantCommitRound)` / `CommitFinalized`, which requires a
descendant commit at a root round strictly greater than this commit's round.
**`Activate` requires `CommitFinalized` and `observedRootRound ≥ A*`** — a round
counter reaching `A*` on its own is `errCommitNotFinal`
(`TestD4_ActivationRequiresFinalizedCommit`). From any pre-Commit phase,
`Activate` returns `errNoCommit`.

### First successor proposal, old-quorum proof, timeout gaps

- The **first governance proposal under the new assignment** is produced by the
  leader named in the committed **successor technical record**
  (`FirstSuccessorProposalLeader` → `SuccessorTRHash`).
- Its **authorisation witness** is the commit record: an old-quorum QC over
  `CommitDomainFor` (`FrozenID`, `A*`, `successorTRHash`, predecessor, attempt).
  The new set does not need the old set online — it carries the proof.
- **Timeout gaps**: if no block is certified at exactly `A*`, the certified root
  round clock (D1) crosses `A*` and the **first certified round `≥ A*` under the
  new assignment** is the activation. A repeat/timeout certificate between the
  commit and `A*` installs nobody (`Authorized` still returns `old` for rounds
  `< A*`, `new` for `≥ A*`, on a committed+finalised replica only).

## 3. Authorisation function (the safety core)

`Authorized(observedRootRound)` returns which assignment may authorise a
governance block whose imported root round is `observedRootRound`:

```
phase ∈ {Committed, Activated, Acknowledged}:
    observedRootRound  <  A*  ->  old
    observedRootRound  >= A*  ->  new
otherwise (pre-Commit, or Aborted):    old
```

- **No overlap**: the boundary is a single `≥` comparison against one `A*`.
- **No gap**: every round maps to exactly one side.
- **Abort ⇒ old for all rounds**: an aborted attempt names no successor, so it can
  never authorise a new block.
- **Extension does not install a successor**: until a handoff is committed the
  incumbent set remains authoritative; a timeout never installs a successor
  (`governance.tex` §"Extension").

## 4. Exploration and the fault scenarios

`checkInvariants` evaluates, after every step of every scenario, over a window of
probe rounds:

| Invariant | Statement |
|---|---|
| `single_successor` | an aborted handoff carries no successor technical record |
| `no_overlap_no_gap` | `Authorized(r)` matches the §3 table for every probe round `r` |
| `no_future_signature` | once set, the endorsement domain binds no post-commit field |
| `activation_gap` | `A* ≥ commitRound + PipelineDepth` (reorg-window gap, not finality) |
| `activation_requires_final_commit` | `Activated`/`Acknowledged` implies `CommitFinalized` |

### Adversarial multi-replica exploration (`multi_replica_exploration`)

The single-`Handoff` scenarios exercise **one** replica's phase API. The
adversarial model (`d4multireplica.go`) states the fault the handoff must
survive and checks that safety holds under it. The first-review version used a
**global signer lock** — no signer, honest or Byzantine, could ever be counted
for two conflicting statements. The re-review (#80) rejected that: it assumes
away Byzantine equivocation. The model now:

- gives **honest** signers durable local state — each signs **at most one** of
  two conflicting statements (a per-honest-signer lock, not a global one);
- names an explicit **Byzantine** set whose authenticated weight is `≤ f_W =
  W − ⌊2W/3⌋ − 1` and lets it **equivocate freely** — sign *both* statements;
- derives every quorum from the **actual distinct authenticated signer set**
  via `WeightSet.SignerWeight`, never a supplied cumulative number;
- enumerates **every** assignment of the honest signers to `{X, Y, abstain}`
  (`3^|honest|`) and records the largest number of the two statements that
  simultaneously reach `⌊2W/3⌋+1`.

| Property | Statement | Result |
|---|---|---|
| G2 | over every honest assignment, with the Byzantine set on both sides, **at most one** of two conflicting statements reaches a quorum — applied to two `FrozenID`s, two `CommitRecordID`s (conflicting `A*`), and commit-vs-abort of one attempt | `max_simultaneous_quorums = 1` in every run; at the `f_W` bound the closest split is one side at 17, the other at 14 |
| G3 | per-replica commit tuples `(replica, FrozenID, A*, commitRound, CommitRecordID)` are kept **un-deduplicated** and must all agree | holds for `replica_commit_tuples_agree`; the counterexample is **flagged**, not silently merged |
| G4 | activation requires `FinalizeCommit(descendantRound > commitRound)` — the root 2-chain, not a round count | holds (`activation_requires_finalized_commit`) |
| G5 | (conditional) every record delivered, no abort ⇒ every replica reaches `acknowledged` | `reached` (`conditional_liveness_all_delivered`) |

`G1` ("no signer ever equivocates") is **deliberately not a property**:
Byzantine signers do equivocate, and safety must not depend on their not doing
so — the reason the global lock was wrong.

Runs: `endorsement_quorum_honest_only`, `endorsement_quorum_byzantine_below_bound`
(weight 6), `endorsement_quorum_byzantine_at_bound` (weight 7 = `f_W`),
`commit_quorum_conflicting_activation_rounds` (two `CommitRecordID`s for one
`FrozenID` with `A*` = 12 and 15 — the mechanism that makes finding 1's
scenario unreachable), `commit_versus_abort_exclusion`,
`replica_commit_tuples_agree`, `conflicting_activation_round_counterexample`
(`is_counterexample: true` — replica A committed `A*`=12, replica B `A*`=15;
the tuple check must flag the disagreement), `activation_requires_finalized_commit`,
`conditional_liveness_all_delivered`.

### Scenarios (all in `d4-vectors.json`, `phase_ok` and `invariants_ok` true for each):

| Scenario | What it exercises | Terminal phase |
|---|---|---|
| `delayed_signatures` | endorsement crosses the threshold in a later batch, before commit | acknowledged |
| `asymmetric_delivery` | a replica never receives the commit record → cannot self-activate, keeps old set authoritative | endorsed |
| `missed_earliest_activation` | observed round passes `A_min` before commit; activation waits for committed `A*` | acknowledged |
| `crash_at_prepared` / `crash_at_frozen` / `crash_at_endorsed` / `crash_at_committed` | resume from the durable phase; the next phase cannot be skipped (last one resumes and activates) | prepared / frozen / endorsed / activated |
| `old_quorum_loss_after_prepare` | endorsement can never reach the threshold → stall; safety over progress; no path to Activated | frozen |
| `committed_abort_vs_late_activate` | a committed handoff cannot be aborted | committed |
| `aborted_then_activate_rejected` | a pre-commit abort kills attempt `j`; `Activate` impossible after | aborted |
| `incomplete_prepare_then_clock` | round counter reaches the proposed start with only a prepare → no activation | prepared |
| `incomplete_prepare_then_rest_insertion` | a locally submitted trust base (Activate with no committed record) is rejected | prepared |

Plus the exhaustive check: all 24 phase-order permutations; `only_canonical_commits`
and `no_early_new_authorization` both true.

Under the declared synchrony/availability assumptions (all messages eventually
delivered, no permanent crash, old quorum available through Commit) the machine
reaches `acknowledged` — `delayed_signatures` and `missed_earliest_activation`
are the witnesses. Outside them (`asymmetric_delivery`, `old_quorum_loss_after_prepare`)
it stalls with the old set authoritative rather than proceeding — safety
preserved, recovery not claimed.

## 5. Candidate binding, cancellation, disposition

- **Attempt binding**: `Candidate.Attempt = j`, `PredecessorHash = h_e` (the
  current trust-base body identity). A replacement after an abort is a new
  candidate with `Attempt = j+1` and the same predecessor. "An agent cannot
  choose whichever historical candidate it prefers" — the predecessor + attempt
  pin it.
- **Cancellation** requires a root-certified abort of any prepared handoff plus
  an EVM acknowledgement that releases its reservations. Only one candidate is
  pending per epoch.
- **Outstanding-proposal disposition**: at Prepare, in-flight old-assignment
  governance work is drained or cancelled; a cancelled proposal is never revived
  under the new assignment.
- **Last certified EVM parent**: recorded at Freeze; the first new-assignment
  governance proposal builds on it.
- **Successor technical record**: bound at Commit; the new set resumes under the
  leader it names.
- **Joining-node readiness**: a joining node must synchronise the certified root
  and EVM states before its votes count (`governance.tex` §"root handoff").

## 6. Acceptance mapping

| D4 acceptance clause | Evidence |
|---|---|
| model exploration (not a phase-API test) shows two effective successors / old+new authorisation of the same extension cannot occur, across competing replicas with quorum intersection under Byzantine equivocation / attempts / delayed commit vs abort | §4 adversarial model — G2 (at most one of two conflicting `FrozenID`s / `CommitRecordID`s / commit-vs-abort reaches a quorum, honest signers split every way, Byzantine set ≤ `f_W` on both sides), G3 (per-replica commit tuples kept un-deduplicated and required to agree; conflicting-`A*` counterexample flagged); `TestD4_MultiReplicaGlobalInvariants` |
| delayed signatures, asymmetric delivery, missed earliest activation, crash at every phase, old quorum loss, committed abort vs late activate | scenario table §4 (`asymmetric_delivery`, `old_quorum_loss_after_prepare`, `crash_at_*`, `committed_abort_vs_late_activate`) |
| freeze authenticates the state it endorses — one endorsement cannot authorise divergent handoff states | §2 `FrozenID` (binds body + frozen summary + parent + candidate + attempt); `TestD4_FreezeBindsFrozenStateIntoEndorsedIdentity` |
| pipeline/activation is not circular; who produces the first successor proposal and which old-quorum proof authorises it; behaviour under timeout gaps; `EpochStart` reconciled with D3 | §2 "The trust-base body records `A_min`, not `A*`" (D3's `EpochStart` renamed to `EarliestActivation`; `A*` in the `ActivatedTrustBase` record) + "First successor proposal…" + "Finality is the root rule"; `FinalizeCommit(descendantRound)`/`CommitFinalized` gate; `TestD4_ActivationRequiresFinalizedCommit` |
| an incomplete prepare cannot activate through local REST insertion or clock passage | `incomplete_prepare_then_clock`, `incomplete_prepare_then_rest_insertion`; `TestD4_NoActivationWithoutCommit` |
| under declared assumptions the model completes a handoff; outside them it preserves safety without claiming recovery | §4 G5 (`reached` vs `held-safe`); scenario `old_quorum_loss_after_prepare` |
| no signature depends on unknown future state | §2; `FieldsAreKnown` (endorsement binds `FrozenID`, not `A*`); `TestD4_EndorsementBindsNoFutureState` |

## 7. Reproduce

```
go test ./evmroot/... -run TestD4
go run ./evmroot/cmd/d4vectors            # print the scenario set
go run ./evmroot/cmd/d4vectors -update    # regenerate testdata/d4-vectors.json
```
