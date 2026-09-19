# F6 (#14) acceptance ledger

What this is: a reconciliation of #14's acceptance list against the work merged under F6a to F6g,
naming the sub-unit, the pull request and the exact test or design record behind each claim, and what
each one does not show.

What it is not: a closure of #14. The ledger is written by the party that did the work, so it is a
proposal for review. §4 states why #14 cannot close yet and names what would have to change.

Base for every citation: `integration/enshrined-evm` at `61d7f8d4` (the #197 merge).

This is a parent ledger. F6b and F6c already have their own line-by-line ledgers
(`f6b-acceptance-ledger.md`, `f6c-acceptance-ledger.md`) and are cited rather than re-derived.

## 1. The units and where their evidence lives

| Unit | Design record | Merged as | Delivers |
| --- | --- | --- | --- |
| F6a | `f6a-certified-record-crash-contract.md` | #159 | the crash contract and its executable model under `docs/design/models/f6arecord/` |
| F6b | `f6b-certified-record-store.md`, ledger `f6b-acceptance-ledger.md` | #160 and predecessors | the transactional record store, its durability and its retention |
| F6c | `f6c-signing-state-contract.md`, ledger `f6c-acceptance-ledger.md` | #142 to #150 (#105) | the independent signing authority and the non-equivocation record |
| F6d | `f6d-node-record-wiring.md` | #161 (W1), #162 (W2), #165 (W3a), #196 (W3b-1), #197 (W3b-2) | node lifecycle wiring: reload, capture, publication, the readiness gate, recovery capture |
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

**What it does not show.** The replay cursor is not part of that record. `certifiedstore` holds the
certified block and its authority; the shard's own replay position is still the single certificate in
`shardnode.FileStore`, written separately. Nothing establishes that the two are consistent after a
crash between the two writes, and no test asserts an ordering between them.

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

**What it does not show, and this is the important line.** The restart fixtures say so themselves:
"power loss, an interrupted write, or any fsync guarantee" are not modelled, and
`restart_boundaries_test.go` explicitly assigns storage durability to #14. The durability work landed
for `certifiedstore` and not for `shardnode.FileStore`, whose `SaveLUC` writes a temporary file,
closes it and renames it with no `Sync` of either the file or its directory. `shardnode/store.go:35`
records that deferral in the code: "Durable write ordering and fault injection remain F6 (#14) — a
rename is not an fsync." It is still open.

The replacement-disk case is covered for the record store at the model level (row 13) and is **not**
covered for `FileStore`. The migration case is discussed in §3.

### 2.4 "Faults before/after proposal submission, UC receipt, execution commit and database write recover without a second conflicting vote, loss of certified block association or falsely finalized pending payload"

The list names four boundaries, so eight positions. "P" is a test over production code, "M" a test
over an executable model under `docs/design/models/`, which is imported by nothing.

| # | Position | Evidence | Class |
| --- | --- | --- | --- |
| 1 | before proposal submission | **none** | |
| 2 | after proposal submission | `TestRound_CrashAfterSubmitBeforeUC_RecoversWithoutEquivocatingOrDoubleBuilding` (`shardnode/round_recovery_test.go`) | P |
| 3 | before UC receipt | the same test: the confirming certificate is never processed by the dead process | P |
| 4 | after UC receipt | `TestFailedDeliveryIsRetriedByDuplicate`, `TestDeliverySeparatesApplicationFromSending` (`shardnode/delivery_retry_test.go`), `TestRestart_ResumingOlderThanTheExecutor` (`shardnode/restart_boundaries_test.go`), `TestConfiguredAdmissionPersistsBeforeLUCAndOwnsDriverEvidence` (`shardnode/bftclient_admission_test.go`) | P |
| 5 | before execution commit | `TestCrashBetweenPipelineSteps`, "after observing, before executor commit" (`docs/design/models/f6arecord/contract_test.go`) | M only |
| 6 | after execution commit | `TestRestart_InFlightCommitIsDecidedByTheLiveExecutorHead`, `TestRestart_AnAdmittedCommitCompletesAfterTheProcessIsGone`, `TestRestart_ResumingOlderThanTheExecutor` (`shardnode/restart_boundaries_test.go`); model `TestCrashBetweenPipelineSteps` | P, M |
| 7 | before database write | `TestInjectedFailuresLeavePriorOrNewState` (`certifiedstore/fault_test.go`, checkpoints `before-publish` and `before-commit`), `TestProcessKilledAtEachCheckpoint` (`certifiedstore/kill_test.go`), `TestRecordCASAndAtomicFailure` and `TestRetentionDeletionFailureRollsBackWholeTransactionAcrossReopen` (`configuredprogress/`) | P, M |
| 8 | after database write | the same two `certifiedstore` tests at checkpoint `after-commit`, `TestCaptureAcrossRestart` (`recordwiring/capture_test.go`), model `TestCrashBetweenPipelineSteps` | P, M |

Positions 7 and 8 are the strongest evidence in F6 and are worth naming precisely:
`TestProcessKilledAtEachCheckpoint` runs a child process that publishes, SIGKILLs it at each
checkpoint, and reopens the real bbolt file to assert the prior or the new state byte for byte. That
is a lost write, not a restarted process.

**What it does not show.** Two positions are unmet.

- **Position 1 has no test.** Nothing injects a fault between sealing the block and sending the
  certification request. The nearest fixtures cut elsewhere:
  `TestDeliverySeparatesApplicationFromSending` fails the send itself rather than crashing before it,
  and `TestARefusedAuthorizationIsNotRebuiltAfterAPersistenceFailure`
  (`shardnode/round_authority_test.go`) fails the certificate-file write after the signer already
  refused, so no submission was pending.
- **Position 5 is model-only.** No test over production code injects a crash before
  `executor.Commit`. `TestRestart_InFlightCommitIsDecidedByTheLiveExecutorHead` is a Commit that was
  issued and did not apply, which is position 6's other branch, and
  `TestTargetApplier_RechecksTheCertificateBeforeCommitting` checks a precondition rather than
  injecting a fault.

Positions 7 and 8 also cover only the stores that got the F6b treatment, `certifiedstore` and
`configuredprogress`. The `shardnode.FileStore` path has no fault injection at any position, for the
reason in §2.3: it takes no step a fault could be injected into between `os.Rename` returning and the
data reaching stable storage, because it never syncs.

### 2.5 "Both retained-executor-data and replacement-host recovery paths have explicit behavior"

Retained executor data is the modelled deployment throughout #92 and F6d. Replacement host is explicit
for the signing authority, and the answer there is deliberate and negative: the key and record are
lost together, the validator cannot sign under that identity again, and returning it to service needs a
separately authorized assignment (`f6c-acceptance-ledger.md` §0).

**What it does not show.** For the store and executor side, "empty replacement disk yields no record,
therefore not ready" (F6a row 13) is a refusal, not a recovery path. Nothing states how an operator
brings a replacement host back into service with its state intact, which is what this line asks for.

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

## 3. A contradiction worth settling before this closes

Two parts of the tree disagree about what `shardnode.FileStore` is for.

`shardnode/store.go:53-61` says "the stored certificate is this node's non-equivocation authority" and
justifies the fatal legacy refusal on that basis. The accepted F6c profile says the opposite: the
authority is the separate signing-authority process and its in-memory record, and "the shard side is
untrusted. Its files may be replayed, restored from an older backup, or run twice"
(`f6c-acceptance-ledger.md` §0).

Both cannot be current. Which one is decides whether §2.3's missing fsync is a defect or a
non-requirement:

- If the file is the non-equivocation authority, then a rename without an fsync is a live safety gap
  on the path #14 exists to close, and the deferral at `store.go:35` must be discharged.
- If the F6c authority is, then `store.go:53-61`'s justification is stale, the file is a
  liveness-and-convenience cursor, and the durability line should be restated as such rather than left
  reading as a safety claim.

This ledger does not decide it. It is a design question for the owner, and it is the one thing that
changes what still has to be built.

## 4. Proposal

1. #14 **cannot close** on this evidence. Unmet: the `FileStore` durability deferral recorded at
   `store.go:35`, which leaves that path with no fault injection at any position (§2.3, §2.4); fault
   position 1, before proposal submission, which has no test at all; fault position 5, before
   execution commit, which exists only over the model; the replacement-host recovery path for the
   store and executor side (§2.5). The replay-cursor association in §2.2 is a smaller fifth.
   The migration line (§2.6) is **met**; only its placement in operator-facing documentation is
   open, and that does not block.
2. §3 is settled first, because it decides whether the largest of those is a defect or a
   non-requirement. Everything else is scoped from that answer.
3. Moving §2.6's decision into the operations documentation is independent of §3 and can be done at
   any time. It restates an accepted decision rather than making one.
4. Nothing here reopens F6b, F6c or F6d. Their ledgers and merges stand; what is missing was never
   claimed by them, and two of the three gaps are recorded in the code as deferrals to #14 rather than
   discovered here.

## 5. What this ledger does not do

It does not review the accounting of F6g's frontier work against #176, which is open. It does not
re-verify F6b's or F6c's line-by-line evidence; it takes their ledgers as given. It records no
maintainer decision: per `docs/pos/PROCESS.md`, closing a ticket needs a named decision and a closing
comment linking final PRs and evidence, and neither is this document.
