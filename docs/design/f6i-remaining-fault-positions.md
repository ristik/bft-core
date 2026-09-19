# F6i (#14): the remaining fault positions

Issue: #14. Base: `integration/enshrined-evm` at `bd7a5041` (#199). Ledger:
`f6-acceptance-ledger.md` §2.2 and §2.4.

The ledger tabulated the eight fault positions #14's acceptance list names and found two unmet, plus
one crash window between the two stores that nothing exercises. This unit closes all three. It adds
tests and fixtures only. No production behaviour changes.

## 1. Position 1: a fault before proposal submission

**What is missing.** Nothing injects a fault between the candidate existing and the certification
request reaching the root chain. `TestDeliverySeparatesApplicationFromSending` fails the send itself,
which is the transport rather than a crash, and
`TestARefusedAuthorizationIsNotRebuiltAfterAPersistenceFailure` fails the checkpoint write after the
signer already refused, so nothing was pending.

**The case that matters** is not the one `TestARebuiltCandidateNeverOverwritesAReservation` covers.
That test synthesizes an earlier reservation for a *different* candidate and establishes that a
rebuilt one is refused. The untested case is the ordinary crash: a process built a candidate, the
authority signed it, and the process died before the request reached the root chain. A second process
re-derives the round deterministically and arrives at the **identical** candidate. #14 requires it to
recover "without a second conflicting vote", and the authority's retained response is what makes that
possible: an identical re-request returns the retained bytes rather than producing a second signature
or a conflict.

**The fixture.** One authority across both processes, because the authority outlives the shard
process by design (F6c). Process A is a `Round` from `wiringFixture` signing through a real
`signingauthority.Authority`, whose send fails, standing for a request that never reached the root
chain. Process A is then discarded. Process B is a fresh `Round` over the same executor and the same
authority session, and the same certificate is delivered again.

**What must hold.** The candidate B builds is byte-identical to A's; the authority releases exactly
one statement for that assigned round; B's submitted request equals A's signed bytes; and the
authority's reserved round is unchanged. A second, different signature for the round is the failure
this asserts against.

## 2. Position 5: a fault before the execution commit

**What is missing.** No test over production code injects a crash between observing a certificate and
issuing `executor.Commit`. `TestRestart_InFlightCommitIsDecidedByTheLiveExecutorHead` is a Commit that
was issued and whose answer was lost, which is position 6's other branch, and
`TestTargetApplier_RechecksTheCertificateBeforeCommitting` checks a precondition rather than injecting
a fault. The only coverage is the F6a model's "after observing, before executor commit".

**The fixture.** An executor wrapper whose `Commit` returns an error on its first call, so the round
fails with the executor unchanged and nothing certified locally. That is the state a crash at this
point leaves behind: the certificate was seen, the executor never moved. The process is discarded and
a second `Round` is built over the same, still-unmoved executor and driven with the next certificate.

**What must hold.** The second process does not sign a candidate that claims the uncommitted state.
It reconciles forward, through the ordinary commit path when the certificate in hand names the block
and through #92 recovery when it does not, and the executor reaches the certified block before any
vote is cast. The distinction from position 6 is stated in the test: there the executor moved and the
answer was lost, here the executor never moved.

## 3. The crash window between the record and the checkpoint

**What is missing.** `persistingDriver` calls `SaveLUC` only after the round's `HandleCertificate`
returns, and the certified-record capturer publishes from inside the round. A crash between those two
writes leaves the record naming a block whose certificate is newer than the checkpoint cursor. The
ledger's §2.2 called this out and nothing exercises it.

**Why it is not an atomicity defect.** The two artifacts are not, and need not be, in one transaction.
Each is independently authenticated on restart: the checkpoint by `verifyRestoredLUC` against the
configured trust base, partition, shard and configuration hash, and the record by W1 `Reload` under
the deployment's store context, compared with the executor by exact identity. Neither is treated as
evidence of freshness, which `f6a-certified-record-crash-contract.md` states as a property of the
whole contract. What the acceptance line needs is therefore not a shared transaction but a defined
outcome for each crash window, and the windows are:

- **Record published, checkpoint not yet written.** On restart the cursor is older than the record.
  This is the window this unit tests.
- **Checkpoint written, record not yet published.** This is the routine state, not only a crash
  outcome, because capture is asynchronous. The readiness gate abstains until capture catches up,
  which is `f6d-node-record-wiring.md` §9 and already covered.

**What must hold.** A record ahead of the cursor is not an error: `Reload` reports its ordinary
outcome for the recorded block, the node resumes from the older cursor under the restored-signing
restriction, and it moves forward on the live feed. Nothing falls back to the record as a cursor, and
nothing treats the newer record as authority to vote.

## 4. The canonical input

The same acceptance line names "canonical inputs". The canonical root input is a deterministic
function of the certificate and technical record, which the record already holds atomically, plus the
node's pinned configuration context, whose hash is enforced on every certificate. It is derived on
use and not stored, and that is the correct answer rather than a gap: persisting it would create a
second source of truth that can disagree with the inputs it was derived from, and no reader would know
which to believe. This section records the reasoning; it adds no test, because there is no stored
artifact whose association could be asserted.

## 5. Not in this unit

- Any production behaviour change. The two executor and submitter wrappers are test fixtures.
- Sweeping orphaned `.luc-*.tmp` files (F6h §5).
- Position 6's existing coverage, which is not revisited.

## 6. Tests

| Test | Covers |
| --- | --- |
| `TestCrashBeforeSubmissionRecoversTheRetainedSignature` | §1: identical candidate after the crash, one released statement, byte-identical request, reserved round unchanged |
| `TestCrashBeforeSubmissionStillRefusesADifferentCandidate` | §1's boundary: a second process whose candidate differs is refused, so §1's test cannot pass by the authority being permissive |
| `TestCrashBeforeExecutionCommitReconcilesWithoutVoting` | §2: executor unmoved, second process reconciles forward and casts no vote on the uncommitted state |
| `TestRecordAheadOfTheCheckpointIsNotAnError` | §3: reload outcome, restricted resumption, no fallback to the record as a cursor |
