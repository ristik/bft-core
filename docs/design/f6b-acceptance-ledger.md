# F6b (#92) acceptance ledger

What this is: a line-by-line reconciliation of #92's acceptance list against the work merged for it,
naming the exact pull requests and the exact evidence — deterministic fixture, real-client run, or
both — and saying plainly which lines are met, which are met in part, and what is missing from the
ones that are not.

What it is not: a closure of #92. A ledger written by the party that did the work is a proposal for
somebody else to check, and the issue says so itself: it stays open through implementation and final
real-client recovery acceptance. Nothing here closes it.

Two habits are deliberate throughout. **Evidence is named, not summarised** — every claim below
points at a test function or a retained run, so a reader can disagree with the mapping rather than
with an adjective. And **a measurement is attributed to what it measured**: a deterministic fixture
proves a property of the code, a real-client run proves that a real client and a real root chain
behaved a particular way once, and neither is the other.

---

## 1. The acceptance list, line by line

### 1.1 "Fresh deterministic signed-certificate/adapter fixture proves the empty-target failure and passes after repair without relaxing certificate equality."

**Met.**

| what | evidence | merged in |
|---|---|---|
| the failure, reproduced | `TestRound_QuietUCAfterMissedBlock_RecoveryTargetIsEmpty` | #94 |
| it passes after the repair | `TestRound_QuietUCRecoversViaLiveAnchor` (payload present, payload absent, payload invalid, and the anchor surviving a failed attempt) | #106 |
| certificate equality not relaxed | `sameInputRecord` is untouched by this work (last changed in `a0730c1b`, merged by PR #102 under issue #93, before stage 3 — the issue and the PR are different numbers and the distinction matters when chasing the commit); `TestAnchorEvidence_SameStateDifferentBlockIsNotHistory` refuses a chain that returns to a state by another block; `TestCheckHeadIdentity` keeps the block-hash comparison | #112, #106 |

The repair does not substitute a state root for a block hash and does not call `Commit(nil)`:
`recoveryTarget` refuses with a named reason rather than returning an empty hash.

### 1.2 "Quiet and non-quiet UC recovery cases; local payload present/absent; invalid payload/anchor/config/epoch; retry and process restart at each relevant boundary."

**Met.** Every case up to and including retry is met. The final clause — "process restart at each
relevant boundary" — is met for five boundaries by fixture and for two by a reviewed equivalence
argument; §1.2.1 enumerates them rather than leaving the clause to be read as a whole.

Two earlier verdicts on this clause are worth keeping straight, because only one of them was an
error. The first recorded the clause as met on the strength of three fixtures that prove different
properties: that was wrong when it was written. The second marked R4, R5 and R6 unestablished: that
was **correct at its revision**, and it did not become wrong when later fixtures supplied the
evidence — a boundary with no fixture is unestablished, and saying so is the ledger working.

| case | evidence | merged in |
|---|---|---|
| quiet UC | `TestRound_QuietUCRecoversViaLiveAnchor`; `TestAnchorEvidence_QuietTailRecoversWithoutNewTransactions`; real client `f6b-quiet-tail-recovery.sh` | #106, #112, #118 |
| non-quiet UC | `TestTargetApplier_CommitsTheCertifiedBlock`; real client `f6b-missed-block-recovery.sh`, where P-id is satisfied by an exact block-hash match and row 13 cannot apply | #116, #119 |
| payload present locally | `TestRound_QuietUCRecoversViaLiveAnchor` / "payload present: recovers via the anchor across the quiet round" — the executor head is rewound while payload state is retained, and a recovery `Commit` is asserted; complementary to it, `TestTargetApplier_AdoptsWithoutCommittingWhenTheExecutorIsAlreadyThere` starts from `recoveredHead()` and asserts *no* `Commit`, which is recognising an already-canonical block rather than making a retained payload canonical | #106, #118 |
| payload absent | `TestAnchorEvidence_VerifiedTargetSurvivesAnUnavailablePayload`; `TestTargetApplier_TheThreeExecutorSituationsStayApart`; real client `f6b-execution-peer-isolation.sh` and `f6b-unhelpful-peers.sh` | #112, #116, #120, #121 |
| invalid payload | `TestTargetApplier_TheThreeExecutorSituationsStayApart` — invalid is a fault, unavailable is retryable, and the two never merge | #116 |
| invalid anchor | `TestAnchorEvidence_MiddleEvidenceMissingOrAltered`; `TestAnchorEvidence_ReplayOfAnOlderCompleteBundle`; `TestContinuityState_InstallVerifiedRefusesAnAnchorWithNoBlock` | #112, #117 |
| invalid config / epoch | `TestAnchorEvidence_WrongPartitionShardConfigOrEpoch`; `TestEvidenceRequester_ConfigurationAndEpochAreThisNodesOwn`; `TestTargetApplier_RefusesAnUnusableConfiguration`; `TestRecoveryStack_RefusesConfigurationsThatCannotDoWhatTheySay` | #112, #115, #116, #117 |
| retry | `TestTargetApplier_AttemptsAreBoundedAndSpaced`; `TestAnchorRecovery_ASyncingExecutorKeepsGettingAttempts`; `TestAnchorEvidence_RetryClassification` | #116, #112 |
| process restart at each relevant boundary | enumerated in §1.2.1 — partly met | #106, #77 |

#### 1.2.1 The restart boundaries, enumerated

A restart is "relevant" at a point where this node holds recovery state that a restart would destroy,
or where the executor and this node can disagree about what happened. The recovery lifecycle has
seven such points. What makes most of them answerable without a fixture apiece is a single reviewed
fact about what survives a restart: **the recovery checkpoint persists one certificate, not the requester/applier state.**
`FileStore.SaveLUC` keeps one certificate (`store.go`, and the note in `evidencebuffer.go`), and
`resumeFrom` installs no execution anchor from it — `TestAnchorIsNotRestoredFromDisk` drives the
production seeding path and asserts both that the certificate cursor is restored and that
`continuity.anchor` stays nil. The requester's witness entry and retained bundle, the verified
target, the applier's attempt budget, and the round's continuity anchor are all process memory.

| # | boundary | status | basis |
|---|---|---|---|
| R1 | start with no recovery state at all | met | `TestAnchorIsNotRestoredFromDisk`; every real-client lane restarts here (#118–#121) |
| R2 | evidence received or buffered, verification not finished | met by equivalence | nothing of the bundle is persisted, so the restart discards it and the process re-enters at R1; no executor call has been made, so there is nothing to reconcile that a cold start does not already do |
| R3 | a verified target is held, `Commit` not yet called | met by equivalence | same: the verified target is memory-only, and the executor has not moved. The target must be re-derived from authenticated incoming evidence (a quiet certificate alone does not name it), as in R1 |
| R4 | `Commit` in flight when the process dies | met | `TestRestart_InFlightCommitIsDecidedByTheLiveExecutorHead` covers the two resolved outcomes — the call did not apply (the returning process redoes it) and it applied while the answer was lost (no second execution, because the applier asks the executor before commanding it) — plus a fresh attempt the executor cannot satisfy yet. `TestRestart_AnAdmittedCommitCompletesAfterTheProcessIsGone` covers the third, genuinely delayed outcome: the executor admits one operation, the caller dies, the operation keeps running across the restart, answers every later request SYNCING without starting a second one, and applies the block on its own — so the head moves with **no new request behind it**, which is asserted by counting | #123 |
| R5 | `Commit` succeeded, the anchor not yet adopted | met, with R6 | `TestRestart_ResumingOlderThanTheExecutor`. That R5 and R6 are one state is no longer assumed: the fixture kills a process in each and requires the resumed process's observations to be *equal*, so the claim that the adoption difference is memory-only is measured rather than asserted | #123 |
| R6 | adopted, certificate not yet persisted | met | adoption happens inside `HandleCertificate`; `persistingDriver` calls `SaveLUC` only after it returns (`node.go`), so the restart resumes from an *older* certificate with the executor ahead of it. `TestRestart_ResumingOlderThanTheExecutor` runs the production `LoadLUC` → `verifyRestoredLUC` → `resumeFrom` from exactly that checkpoint: the target is re-derived from authenticated evidence, no Commit is issued at all, the head does not move in either direction, and nothing is signed — against a control, over the same certificates and the same executor, that does sign. `TestRound_CrashAfterSubmitBeforeUC_…` remains adjacent and is not cited here: it constructs a bare `NewRound` and submits after its simulated restart | #123 |
| R7 | restarted from a persisted certificate | met | `TestRestoredNodeIsNonVoting` drives the production sequence and asserts the node follows, reconciles and does not vote, against a control that does vote |

The cold-start equivalence argument is the load-bearing claim in R2 and R3, so it is stated as a claim
to disagree with rather than as a result: *if* something later persists verified evidence or an applied
cursor — which is #14's work — those two equivalences must be re-reviewed. They are the only rows in
the table that rest on an argument rather than on a fixture.

One thing the B2 fixtures deliberately do not model, so it is not over-read: power loss, an
interrupted write or any fsync guarantee. The executor is a live process that keeps its state across
the shard node's restart, which is the deployment #92 is about; storage durability is #14's. What
they *do* model, after review found the first attempt insufficient, is an executor-side operation
that outlives the process that asked for it and completes on its own — bounded and joined, so a
failure cannot hang the suite. The rollback
the fixtures assert against is one their executor can actually perform, and that capability is
asserted too — otherwise "it did not roll back" would be a property of the stub.

**One boundary is deliberately out of scope rather than missing.** Recovery *across a legitimate
epoch transition* is refused by design (§3.1 of the design record: a chain crossing an epoch change
returns `ErrEvidenceEpochChange`, because saying "unsupported" is safe while a wrong answer chooses a
block hash). This acceptance line asks for the *invalid* epoch case, which is covered above. Support
for crossing one belongs to #10 and is listed in §3 below.

### 1.3 "No signing of new work from an unreconciled executor, no unverified forkchoice target, no duplicate execution effects."

**Met.**

| clause | evidence | merged in |
|---|---|---|
| no signing from an unreconciled executor | `TestRound_IdentityGate`; `TestRestoredNodeIsNonVoting`; every real-client lane asserts the node declares itself NON-VOTING and logs zero `submitting block certification request` | #106, #118–#121 |
| no unverified forkchoice target | one comparison, `anchorHeadIdentity`, used by both the live and the recovery path; `TestCheckHeadIdentity`; `TestTargetApplier_EnforcesHeadIdentityAfterAValidCommit`; the evidence predicate refuses anything it cannot authenticate against locally configured trust | #117, #106, #116, #112 |
| no duplicate execution effects | *serialisation*: `TestTargetApplier_OneAttemptIsInsideTheExecutorAtATime`, and the finality gate over every finality-changing executor call (`TestFinalityGate`, `TestRound_TakesTheFinalityGateForItsOwnCommits`). *Replay and idempotency*, which a one-at-a-time gate does not prove: `TestDeliverySeparatesApplicationFromSending` — a send failure leaves the certificate applied so its duplicate is not re-driven, and a persistence failure after a successful send is an application failure whose retry commits nothing uncertified — with `TestFailedDeliveryIsRetriedByDuplicate` and `TestRound_RepeatUC_DoesNotCommitButAdvancesRound` | #116, #117, #77 |

The signing gate withholds the **signed certification request** and nothing else: a restored node
still observes, reconciles, and — *once P-id is satisfied* — builds and disseminates. That is a
measured decision, not an oversight: an earlier revision that withheld block production
unconditionally stalled every round a restored node led.

**P-id restricts building independently, and that is not a consequence of P-sign.** The two answer
different questions — P-sign decides whether this node may SIGN, P-id whether it may make its
execution client FINALIZE — and `round.go` evaluates identity for *every* process, declining
leadership before `Build` when it fails, because `Build` itself changes forkchoice and finality:
`TestRound_DoesNotBuildOnAnIdentityRejectedParent` (including its restored-process half) and
`TestRound_TakesTheFinalityGateForBuild`. So a restored node may lead after satisfying P-id while
remaining non-voting under P-sign, and a node that has not satisfied P-id does not build at all. The
earlier interpretation — withhold only the signature, even on an unverified parent — let exactly the
node with no anchor reach `Build` and finalize an unproven parent; it must not be revived by reading
this row as unconditional permission to build.

### 1.4 "Real-reth isolated restart scenario demonstrates positive work before/after and agreement on certified target, canonical block, state and receipts."

**Met in part.** One clause of it is not demonstrated, and with B2 delivered it is now the only unmet
clause in the acceptance list.

| clause | status | evidence |
|---|---|---|
| isolated restart against a real reth | met | four lanes, pinned reth `189c0df3`, sealed artifacts (#118–#121) |
| positive work **before** | met | #119, #120, #121 each execute real transactions before the outage; the recovered anchor is an ordinary certified block, not the genesis-round exception |
| agreement on the certified target | met | the recovered block hash is compared against the value the surviving validators agree on, read from *them*, and re-read at the end of the run so a head that moved underneath could not have been the claim (#119) |
| agreement on canonical block and state | met | exact head hash and state root (#119, #120, #121) |
| agreement on receipts | met | receipts for every missed transaction name the same block number and hash on the recovered node as on a survivor (#120, #121) |
| a clean fail-closed result as an intermediate milestone | met | #120 with no execution peers, #121 with peers that provably do not hold the block: anchor verified over BFT, `payload-unavailable` and never `payload-invalid`, target retained, executor unmoved, nothing signed |
| positive work **after** | **not met** | no lane demonstrates it — see below |

**What is missing, precisely.** Every lane deliberately stops all transaction injection at the moment
the recovering node returns, and asserts by counting that nothing new executed in either arm. That
is what makes recovery attributable to the authenticated evidence rather than to new activity, and it
is the whole reason the F1 baseline's "recovery" was not recovery. The cost is that no run shows the
recovered node taking part in work produced *after* it recovered.

**And what "after" can mean here, which is not obvious.** P-sign (#105) keeps a restored process
non-voting for its whole lifetime, so the recovered node cannot contribute a signature to new work
no matter how well it recovered. "Positive work after" therefore means: the shard certifies a new
block after the node has recovered, and the recovered node follows it, executes it, and agrees with
the survivors on the resulting block, state and receipts. It does not, and under #105 cannot, mean
that the recovered node votes for it. Stating that distinction is part of satisfying the line, not a
way around it.

### 1.5 "Explicit distinction between process-restart evidence and crash durability/fsync; full durability remains parent #14. Preserve logs and no-secret artifacts."

**Met**, as a distinction correctly drawn. The durability work itself is #14 and is not claimed here.

| clause | status | evidence |
|---|---|---|
| process-restart evidence | met | all four lanes restart the shard-node process with its executor left running; `TestAnchorIsNotRestoredFromDisk` pins that the anchor is *not* restored from disk, so what the process loses it must re-derive. Which restart *boundaries* that evidence covers is the separate question answered in §1.2.1 |
| crash durability / fsync | not claimed, and not required here | no lane simulates power loss or an interrupted write. `TestRound_CrashAfterSubmitBeforeUC_…` is about a crash *boundary* and not the storage guarantee — and, as §1.2.1 records, it constructs a bare `NewRound` rather than running the production restoration sequence, so it is weaker evidence than its name suggests |
| full durability remains #14 | recorded | the design record says a restored checkpoint proves historical continuity and not authorisation to sign, and that persistence of verified evidence is out of scope |
| logs and no-secret artifacts preserved | met | every run writes `artifacts/<lane>/<utc>-<pid>/` outside `test-nodes/`, with revision, worktree cleanliness, `ubft` and reth hashes, and SHA-256 digests of **copied** logs; JWT secrets are never among the copied files |

---

## 2. The four distinctions, held apart

These are the ways this work could be over-read, and each is a separate contract with a separate
owner.

**Executor recovery is not restored signing eligibility (#105).** Everything above is about putting
the executor back on the certified block and proving the node knows which block that is. None of it
is authorisation to sign. A restored process is non-voting for its lifetime because the persisted
certificate proves the node was once at a round, not that it has not signed a later one; the
monotonic signing record that would lift the gate is #105's, and no path here may be read as
supplying it. Every real-client lane asserts the gate still holds *after* a successful recovery,
which is the only way to show that recovering did not quietly re-authorise anything.

**Durable verified/applied state is not in scope (#14).** The four cursors — observed, verified
anchor, applied, signed — are kept apart in process memory, and the anchor is deliberately not
restored from disk. Persisting the verified-evidence cursor, and the fsync guarantees that would make
it trustworthy across a crash, are #14's.

**Epoch and configuration boundaries are refused, not handled (#10).** A chain crossing a shard
epoch change is refused with its own outcome rather than decided. That is safe and deliberate;
supporting recovery across one requires the configuration and migration review #10 owns.

**The stall and "Too deep reorg" investigation is independent (#16).** Nothing in this work explains
either, and no result here should be cited as evidence about them. The one reth refusal of that shape
seen in this programme remains unexplained and is recorded as such.

---

## 3. Remaining gaps, separated

### 3.1 Required acceptance work for #92 — B1 remains, B2 delivered

**B1. Positive work after recovery, measured once against a real client.** The unmet clause of §1.4. A bounded run: recover as #119 does, then submit one transaction *after* the recovered
node has adopted its anchor, and assert that the recovered node reaches the new certified block and
agrees with the survivors on block hash, state root and receipts — while still not voting. It reuses
the existing lane's machinery; what it must not do is let the new transaction be what recovers the
node, so the assertion order matters: adoption first, injection second, agreement third.

**B2. The two restart states (R4 and shared R5/R6). Delivered in #123.** Two deterministic
fixtures in `shardnode/restart_boundaries_test.go`, in the shape the review specified:

- Restart across an in-flight `Commit`. Exercise both resolved executor outcomes — the request did
  not apply, and it applied despite the caller losing the response — and, separately, the delayed
  completion: one bounded executor-side operation admitted by the dead process, still pending when
  its successor starts, released independently of any new `Commit`. Recover from authenticated
  evidence and the live executor head, not an assumed RPC result; preserve unavailable versus invalid
  and the non-voting gate.

  Review found the first attempt at the delayed case short of this: a scripted SYNCING answer to a
  *new* request looks like an old operation still in flight and is not one, because the head then
  moves on a later request rather than on the admitted operation. The distinction is the whole
  boundary, and the fixture now asserts it by counting requests across the completion.
- Use production `LoadLUC` → `verifyRestoredLUC` → `resumeFrom` with a checkpoint older than the
  executor's state. This covers both R5 and R6 because their only difference is lost memory.
  Re-derive the authenticated target before adoption, reconcile without rolling back to the stale
  checkpoint, and assert exact head/state, no duplicate execution effects and zero signed requests.
  An idempotent retry of a certified `Commit` is not itself a duplicate execution effect.

These are process-boundary fixtures, not power-loss/fsync tests or a runtime redesign. They exposed no
implementation defect: every assertion passed against the code as merged, which is itself a result
worth naming rather than assuming. The one defect the work did surface was in the fixtures, and
review found it. Each load-bearing assertion was checked against a deliberate
mutation of the production code — removing the signing gate on restore, committing without first
asking whether the executor is already there, discarding the verified target after one use, and
installing an execution anchor from the restored checkpoint — and every one of those mutations is
caught. The mutations were reverted; they are recorded here as the reason to believe the fixtures
can fail.

### 3.2 Not blockers — named follow-up scope

| item | why it is not a blocker | owner |
|---|---|---|
| recovery across a legitimate epoch/config transition | refused by design today, which is a safe answer, and the acceptance line asks for the invalid case | #10 |
| crash durability and fsync | explicitly excluded by acceptance line 1.5 | #14 |
| restored signing eligibility | explicitly excluded; the fail-closed gate is the accepted intermediate state | #105 |
| partial ancestry — peers holding *some* of the missing blocks | bounds the acquisition mechanism further; §8.2 identifies and bounds it enough to justify adding no fetch protocol | follow-up, needs a named acceptance requirement first |
| long outage, and how long a node stays fail-closed before anything else degrades | same | follow-up, needs a named acceptance requirement first |
| the execution-mesh setup intermittency | a harness defect in run setup, detected and refused rather than measured through | its own harness repair |
| stall / "Too deep reorg" | independent investigation | #16 |

The last two rows are held deliberately. Further partial-ancestry or long-outage experiments should
follow a named acceptance requirement rather than accumulating on their own momentum, and the mesh
intermittency is a repair to the harness rather than a measurement.

---

## 4. Proposal

1. Deliver **B1** as one bounded run, in the shape described in §3.1. It is the last outstanding item.
2. **B2** is delivered in #123 and is no longer outstanding.
3. On the acceptance of B1, #92's five acceptance lines are met, and the issue can be **proposed**
   for closure — by review, not by the measurement PR that finishes it.
4. Carry §3.2 on the issues named there. Nothing in §3.2 blocks #92, and #92 closing does not
   discharge any of them.

## 5. What this ledger does not do

It does not re-verify the evidence it cites. Every row points at a test that runs in CI or a retained
artifact whose digests are in its manifest; the mapping is the claim, and the mapping is what a
reviewer should disagree with. It also does not weigh the deterministic fixtures against the
real-client runs: a fixture that passes says the code has a property, and a run that passed says a
real client behaved that way on a particular revision at a particular hour, and the acceptance list
asks for both because neither substitutes for the other.
