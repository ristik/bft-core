# F6 (#14) acceptance ledger

What this is: a reconciliation of #14's acceptance list against the work merged under F6a to F6g,
naming the sub-unit, the pull request and the exact test or design record behind each claim, and what
each one does not show.

What it is not: a closure of #14. The ledger is written by the party that did the work, so it is a
proposal for review. §4 states why #14 cannot close yet and names what would have to change.

Base for every citation: `integration/enshrined-evm` at `bd7a5041` (the #199 merge), plus the F6i tests
added in the same pull request as this revision.

This is a parent ledger. F6b and F6c already have their own line-by-line ledgers
(`f6b-acceptance-ledger.md`, `f6c-acceptance-ledger.md`) and are cited rather than re-derived.

## 1. The units and where their evidence lives

| Unit | Design record | Merged as | Delivers |
| --- | --- | --- | --- |
| F6a | `f6a-certified-record-crash-contract.md` | #159 | the crash contract and its executable model under `docs/design/models/f6arecord/` |
| F6b | `f6b-certified-record-store.md`, ledger `f6b-acceptance-ledger.md` | #160 and predecessors | the transactional record store, its durability and its retention |
| F6c | `f6c-signing-state-contract.md`, ledger `f6c-acceptance-ledger.md` | #142 to #150 (#105) | the independent signing authority and the non-equivocation record |
| F6d | `f6d-node-record-wiring.md` | #161 (W1), #162 (W2), #165 (W3a), #196 (W3b-1), #197 (W3b-2) | node lifecycle wiring: reload, capture, publication, the readiness gate, recovery capture |
| F6h | `f6h-filestore-durability.md` | #199 | durable checkpoint writes and their fault injection |
| F6i | `f6i-remaining-fault-positions.md` | this pull request | the two remaining fault positions and the record/checkpoint crash window |
| F6e | `f6e-configured-origin-progress-store.md` | #170 | configured-origin progress |
| F6f | `f6f-automatic-bootstrap-freshness.md` | #177 | bootstrap freshness (#176 remains open) |
| F6g | `f6g-root-frontier-boundary.md` | #182 to #191 | the root-frontier sampling and failure boundary |

## 2. The acceptance list, line by line

### 2.1 "Define transactional schema and persist non-equivocation state before outbound signatures"

The transactional schema is F6b's, and `f6b-acceptance-ledger.md` reconciles it. The non-equivocation
half was answered by F6c, not by a schema: the owner accepted a disposable private profile (ADR 0009,
`f6c-signing-state-contract.md` §1 and §9) in which the authority is a separate process holding a
fresh key and an in-memory record, and nothing about it is written to disk.

**What it does not show.** Under that profile the property is non-rollback while the authority lives,
plus a tested end to signing when it dies. It is not disk durability, and `f6c-acceptance-ledger.md`
§0 says so in terms. It also rests on a deployment premise, that the authority runs outside the
shard's backup and cloning domains, which no test in this repository establishes.

### 2.2 "Atomically associate certified head, UC, technical record, canonical inputs and replay cursors"

`certifiedstore` holds the certified head, the certificate, the technical record and the witness in one
verified record, published in one transaction under the finality gate (F6b; F6d W2, #162). F6d W1
(#161) reloads and re-verifies it against the executor by exact identity, and W3a/W3b (#165, #196,
#197) add the continuity predicate and the gate that consumes it.

**Met**, with the two remaining names resolved in `f6i-remaining-fault-positions.md` §3 and §4.

The canonical root input is derived, not stored, and that is the answer rather than a gap: it is a
deterministic function of the certificate and technical record the record already holds atomically,
plus the node's pinned configuration context whose hash is enforced on every certificate. Persisting
it would create a second source of truth that can disagree with its own inputs.

The replay cursor is the checkpoint in `shardnode.FileStore`, and it does not share a transaction
with the record. It does not need to: each is independently authenticated on restart, the checkpoint
by `verifyRestoredLUC` and the record by W1 `Reload` against the executor by exact identity, and
neither is treated as evidence of freshness. What the line needs is a defined outcome per crash
window. Both are defined, and the previously untested one, a record published before the checkpoint
was written, is now `TestRecordAheadOfTheCheckpointIsNotAnError` (`recordwiring/crash_window_test.go`).

### 2.3 "Inject crashes around every write/certification boundary and document migration and replacement-disk behavior"

Crash and restart evidence exists on two axes, and they are not the same axis.

*Process restart with the executor retained.* `shardnode/restart_boundaries_test.go` covers a Commit
interrupted in flight and a process resumed from a certificate older than its executor's state
(`TestRestart_InFlightCommitIsDecidedByTheLiveExecutorHead`,
`TestRestart_ResumingOlderThanTheExecutor`, `TestRestart_AnAdmittedCommitCompletesAfterTheProcessIsGone`),
and `TestRound_CrashAfterSubmitBeforeUC_RecoversWithoutEquivocatingOrDoubleBuilding`
(`round_recovery_test.go`) covers the submit-to-UC window. F6d adds `TestCaptureAcrossRestart`
(#162), stopped before and after publication.

*Storage durability and lost writes.* The record store syncs its file and its parent directory, with
`F_FULLFSYNC` on macOS, and a failed sync is an open failure (`certifiedstore.ErrDirectorySync`, F6b
and F6d §3). `certifiedstore/fault_test.go` injects a failure at each publish checkpoint and
`certifiedstore/kill_test.go` SIGKILLs a real child process at each one, reopening the bbolt file to
assert the prior or new state byte for byte. The F6a model exercises whole-store rollback and an empty
replacement disk (`TestWholeStoreRollbackCannotTestifyToCurrency`, `TestReplacementDiskAndMigration`,
rows 12 and 13). §2.4 tabulates all eight positions.

**Discharged by F6h (#199).** The restart fixtures state that "power loss, an interrupted write, or
any fsync guarantee" are not modelled by them and assign storage durability to #14, and
`shardnode/store.go` carried the matching deferral: "Durable write ordering and fault injection
remain F6 (#14) — a rename is not an fsync." `SaveLUC` now syncs the temporary file before the rename
and the parent directory after it, and the path has the fault injection it never had: six
checkpoints, exercised both by injected failure and by SIGKILL of a real child process that the
parent then reopens (`shardnode/store_durability_test.go`). Design:
`f6h-filestore-durability.md`.

The replacement-disk case is covered for the record store at the model level (row 13) and is **not**
covered for `FileStore`. The migration case is discussed in §3.

### 2.4 "Faults before/after proposal submission, UC receipt, execution commit and database write recover without a second conflicting vote, loss of certified block association or falsely finalized pending payload"

The list names four boundaries, so eight positions. "P" is a test over production code, "M" a test
over an executable model under `docs/design/models/`, which is imported by nothing.

| # | Position | Evidence | Class |
| --- | --- | --- | --- |
| 1 | before proposal submission | `TestCrashBeforeSubmissionRecoversTheRetainedSignature` and `TestCrashBeforeSubmissionStillRefusesADifferentCandidate` (`shardnode/crash_before_submission_test.go`) | P |
| 2 | after proposal submission | `TestRound_CrashAfterSubmitBeforeUC_RecoversWithoutEquivocatingOrDoubleBuilding` (`shardnode/round_recovery_test.go`) | P |
| 3 | before UC receipt | the same test: the confirming certificate is never processed by the dead process | P |
| 4 | after UC receipt | `TestFailedDeliveryIsRetriedByDuplicate`, `TestDeliverySeparatesApplicationFromSending` (`shardnode/delivery_retry_test.go`), `TestRestart_ResumingOlderThanTheExecutor` (`shardnode/restart_boundaries_test.go`), `TestConfiguredAdmissionPersistsBeforeLUCAndOwnsDriverEvidence` (`shardnode/bftclient_admission_test.go`) | P |
| 5 | before execution commit | `TestCrashBeforeExecutionCommitReconcilesWithoutVoting` (`shardnode/crash_before_commit_test.go`); model `TestCrashBetweenPipelineSteps`, "after observing, before executor commit" | P, M |
| 6 | after execution commit | `TestRestart_InFlightCommitIsDecidedByTheLiveExecutorHead`, `TestRestart_AnAdmittedCommitCompletesAfterTheProcessIsGone`, `TestRestart_ResumingOlderThanTheExecutor` (`shardnode/restart_boundaries_test.go`); model `TestCrashBetweenPipelineSteps` | P, M |
| 7 | before database write | `TestInjectedFailuresLeavePriorOrNewState` (`certifiedstore/fault_test.go`, checkpoints `before-publish` and `before-commit`), `TestProcessKilledAtEachCheckpoint` (`certifiedstore/kill_test.go`), `TestRecordCASAndAtomicFailure` and `TestRetentionDeletionFailureRollsBackWholeTransactionAcrossReopen` (`configuredprogress/`) | P, M |
| 8 | after database write | the same two `certifiedstore` tests at checkpoint `after-commit`, `TestCaptureAcrossRestart` (`recordwiring/capture_test.go`), model `TestCrashBetweenPipelineSteps` | P, M |

Positions 7 and 8 are the strongest evidence in F6 and are worth naming precisely:
`TestProcessKilledAtEachCheckpoint` runs a child process that publishes, SIGKILLs it at each
checkpoint, and reopens the real bbolt file to assert the prior or the new state byte for byte. That
is a lost write, not a restarted process.

**All eight positions are now covered over production code.** F6i closed the two that were not.
Position 1's case is the one #14's wording names: a process built a candidate, the authority signed
it, and the process died before the request reached the root chain. A second process re-derives the
identical candidate and is answered with the authority's retained response, byte for byte, with the
reserved round unchanged, so there is no second conflicting vote. A companion test establishes that a
differing candidate is still refused, so the first cannot pass by the authority being permissive.
Position 5 is a Commit that was never issued over an executor that never moved, which is distinct
from position 6, where the Commit was issued and its answer was lost.

**What it does not show.** Positions 7 and 8 exercise the stores that carry the F6b and F6h
durability treatment. No store in the node is now without it, but the executor's own durability is
the execution client's and is outside this contract.

### 2.5 "Both retained-executor-data and replacement-host recovery paths have explicit behavior"

**Met.** Retained executor data is the modelled deployment throughout #92 and F6d, and the W1 reload
outcomes enumerate it (`f6d-node-record-wiring.md` §4; `TestReloadOutcomes`,
`TestReloadRefusesUntrustedRecordsWithoutFallback`).

Replacement is explicit on both sides. For the signing authority the answer is deliberately negative:
the key and record are lost together and returning to service needs a separately authorized
assignment (`f6c-acceptance-ledger.md` §0). For the store and executor,
`f6a-certified-record-crash-contract.md` §"Limitations, stated explicitly" defines three cases:

- **Replacement disk, retained executor.** With no record the node is not ready for any non-genesis
  child, and must obtain the certificate and `witness(B)` for the executor's certified head from the
  network, the certificate from the live feed or #92 anchor evidence and the witness within the
  client's proof window or through #15.
- **Replacement host, fresh executor.** The executor must first reach a certified block by
  execution-client sync, which the contract does not define. Until then it is behind or empty and the
  node is not ready.
- **Genesis.** With a wiped store and the executor at genesis the genesis record is rebuilt from
  configuration, and readiness for the child still requires continuity and #153 E1 to E4.

Whole-store rollback is called out as undetectable by the store, with the executor's head and
continuity as the only exposure (`f6a` §"Whole-store rollback", `f6b-certified-record-store.md`).

**What it does not show.** The replacement cases are design statements with model-level coverage
(`TestReplacementDiskAndMigration`, `TestWholeStoreRollbackCannotTestifyToCurrency`, rows 12 and 13),
not production tests, and the f6e v2 reload table is design for an inactive path. The criterion asks
for explicit behaviour and that exists; it does not ask for a production fixture per case.

### 2.6 "Old file-store migration is documented before any public state exists"

**Met.** The production behaviour is a deliberate refusal rather than a migration: a legacy JSON
checkpoint fails startup, the file is left in place, and the error names two recovery routes (copy a
current store from a healthy validator, or, on a discardable devnet, move the file aside and
re-register). A file that starts with `{` but does not parse as a certificate is reported as damaged
rather than as a migration, and an absent file remains a clean fresh start
(`shardnode/store.go`, tested by `TestCheckpointLegacyJSONFailsClosed`,
`TestCheckpointDamagedVersusLegacy` and `TestCheckpointRejectsUnusableStores` in
`shardnode/store_roundtrip_test.go`).

That decision is written down in `docs/`, and in the place this criterion asks for:

- `f6a-certified-record-crash-contract.md` §"Migration from `FileStore`": the legacy file holds only
  the latest certificate, a migration may treat it as an observed certificate after
  re-authentication, it carries no witness so it creates no readiness, the file is left in place, and
  "No public state exists yet, so no in-place conversion is defined." That last clause answers the
  criterion's own condition directly.
- `f1-baseline.md` §6.3.1: legacy JSON stores fail startup with a migration message and are left on
  disk; a damaged file is reported as damaged rather than as a migration; neither is ever treated as
  a fresh store.
- `f6b-certified-record-store.md` and `f6d-node-record-wiring.md` §6 both scope migration out of
  their units explicitly rather than silently.

**What it does not show.** There is no operator-facing procedure in the operations documentation
(`docs/troubleshooting.md`, `docs/shard-node.md`); the decision lives in design records and in the
error message an operator actually hits. That is a documentation-placement gap, not an unmet
criterion, and it does not block closure on this line.

## 3. What `FileStore` is for

`shardnode/store.go` justified the fatal legacy refusal partly on the grounds that "the stored
certificate is this node's non-equivocation authority". Under the accepted F6c profile that is not
true: the authority is the separate signing-authority process and its in-memory record, and the
shard's own files are explicitly untrusted, replayable or restorable from an older backup
(`f6c-acceptance-ledger.md` §0). The sentence has been removed and replaced with what the checkpoint
actually is, the restoration cursor; the refusal stands on its other two grounds, that the legacy
encoding cannot be converted losslessly and that continuing would mean voting from genesis or
resuming from a certificate that does not match what was signed.

The durability work was never contingent on that question. `f6c-signing-state-contract.md` assigns it
here by name: "Full block/UC/TR persistence and its storage-failure tests remain #14's work." F6h did
it, and §2.3 records the result.

## 4. Proposal

1. Every line of #14's acceptance list now maps to evidence over production code, with the two
   interpretive questions in §2.2 answered rather than left open.
2. On that basis #14 can be **proposed** for closure, by the review of this ledger and not by this
   document. Per `docs/pos/PROCESS.md` that needs a named maintainer decision and a closing comment
   linking the final PRs, exact commits and residual limits; neither is this document, and no PR
   closes it automatically.
3. Closing #14 would discharge none of these:
   - the deployment premise F6c rests on, that the signing authority runs outside the shard's backup
     and cloning domains, which no test here establishes;
   - whole-store rollback detection, which `f6a` states the store cannot do and which only the
     executor's head and continuity expose;
   - the execution client's own durability, which is outside this contract;
   - #176, the bootstrap freshness contract, and anything else still open under F6g.
4. Residual limits worth carrying into the closing comment: one orphaned `.luc-*.tmp` file survives
   each process kill before the rename (`f6h` §5); the replacement-disk and replacement-host cases of
   §2.5 have model-level rather than production coverage; and the §2.6 decision lives in design
   records rather than operator-facing documentation.

## 5. What this ledger does not do

It does not review the accounting of F6g's frontier work against #176, which is open. It does not
re-verify F6b's or F6c's line-by-line evidence; it takes their ledgers as given. It records no
maintainer decision: per `docs/pos/PROCESS.md`, closing a ticket needs a named decision and a closing
comment linking final PRs and evidence, and neither is this document.
