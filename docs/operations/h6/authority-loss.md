# Authority loss, clones, freshness and storage faults

The H6 checklist transferred from the M1 gate ([issue 23](https://github.com/ristik/bft-core/issues/23), "Define and rehearse
recovery after signing-authority loss and stale bootstrap state"). For each item this page states the contract the code follows,
the in-process evidence, and what is a **supported limit or refusal**. A limit is not a defect to work around in operations: it is
what the operator must not do, or what an independent rehearsal on real hosts still has to show.

There are two signing roles with different contracts:

- **Shard validators** sign through an external, fenced **signing authority** whose key exists only in its memory
  ([F6c](../../design/f6c-signing-state-contract.md), [ADR 0009](../../adr/0009-restart-signing-authority.md)). The shard
  process and its disks never hold signing permission.
- **Root validators** sign with a key on their own host. Their non-equivocation memory is the root's safety store (bbolt, sync
  on): the recorded decisions and the highest voted round, written before a vote or timeout is released.

## 1. Kill, restart or replace an authority; crashes around publication and outbound signatures

**Contract.** Never two conflicting statements. A shard process restart opens a new fenced session against the same live authority.
An authority that dies is gone for good: no key import, backup or seed replay exists, and the validator's signing permission ends
until a certified key rotation or replacement assignment admits a new key. A root restart reopens its own safety store and either
replays the recorded message byte for byte or refuses a different statement for the same round.

**Evidence (in-process).**
- **Shard authority:** `signingauthority/record_test.go` (`TestCrashBoundariesKeepOneStatement`,
  `TestAnOlderNodeBackupCannotResetTheAuthority`); `signingauthority/service/process_test.go` (`TestKillingTheAuthority…`,
  `TestARestartedAuthorityIsANewOneAndNotARecoveredOne`); the model `docs/design/models/f6csigning` (256 adversarial fence schedules,
  `TestLostAuthorityCannotRecreateEnrolledKey`); `shardnode/restore_voting_test.go` (`TestRestoredNodeIsNonVoting`) and
  `shardnode/restore_authority_process_test.go` (`TestRestoredVotingThroughAnIndependentAuthority`).
- **Shard execution journal:** crash cuts around submission, UC receipt and commit (`shardnode/crash_before_submission_test.go`,
  `crash_before_commit_test.go`, `restart_boundaries_test.go`), and `configuredprogress/journal_test.go`
  (`TestJournalFaultBoundariesLeaveNoSignatureAuthorityOrPartialCertification`).
- **Root votes and timeouts:**
  - `rootchain/consensus/safety_decision_test.go`: crash before the record, after the record before the round, and replay after
    a restart;
  - `vote_store_before_send_test.go`: a vote that cannot be stored is not sent;
  - `q4b_crash_test.go` (`TestQ4BCrash`): a cluster with crash cuts before signing, between the paired signatures, before the
    record and after the save; no honest double sign.
- **Certified rotation after loss:** the retired key is refused:
  - `network/protocol/abdrc/domainbound_test.go` (`TestDomainBoundRetiredKeyFailsForTheCurrentEpochOnly`);
  - `rootchain/consensus/storage/handoff_changes_test.go` (`TestRotationKeepingTheNodeIDRefusesTheRetiredKey`,
    `TestRetiredKeyRequestIsNotCertifiedInTheActivationBlockOrTheNext`);
  - `archivewiring/restore_retired_key_test.go` (`TestRestoreRefusesAContinuationSignedOnlyByRetiredKeys`).
  The live rotation is the H3 lane ([scenarios.md](scenarios.md) section 1).

**Refusals the operator sees.** `signing-key-lost`, `signing-authority-unavailable`, `signing-state-untrusted`, `keyLost`, `faulted`:
preserve logs, fence the validator, escalate ([evidence.md](evidence.md)). No restart or import restores the old permission.

## 2. Cloned or restored disks; concurrent old and new hosts

**Contract.** A plain backup must not manufacture signing permission.
- **Shard side:** this holds by construction. A restored shard home has no key and is non-voting until it opens a session with the
  live authority, which fences every older session. An authority cannot be restored at all.
- **Root side:** the key and the safety store live on one host, and nothing in the store can tell a restored or cloned copy from the
  live one ([F6a](../../design/f6a-certified-record-crash-contract.md) section on whole-store rollback;
  `docs/design/models/f6arecord` `TestWholeStoreRollbackCannotTestifyToCurrency`).

**Evidence.** `rootchain/consensus/authority_restore_limit_test.go`
(`TestARestoredOrWipedRootSafetyStoreWithTheSameKeySignsASecondStatement`) is a negative control:
- the live store refuses a second statement for a round it voted in (`ErrDecisionConflict`);
- a store restored from an older backup, or deleted (a fresh store is created at genesis), signs a second, valid, conflicting vote
  for that round under the same key.

**Supported limits.**
- **A root host must never be restored, cloned or run twice with its key.** Root disk backups are for evidence and history
  (archives, UC/TR), never for signing.
- **A lost root host is replaced by a certified key rotation**, not by restoring it. The H3 coupled rotation retires the old key, and
  the retired key is refused (item 1).
- **Fencing a root host is the operator's job.** Power it off, revoke its network identity, or destroy its key before any
  replacement starts. The code does not fence a duplicate root.
- **Too many such roots exceed the BFT bound.** At most f equivocating roots are tolerated by root BFT. A quorum of restored root
  keys with rolled-back safety stores is outside the fault bound, and no protocol step repairs it
  ([F6f](../../design/f6f-automatic-bootstrap-freshness.md) section 1).
- **Concurrent old and new shard processes:** only the current session generation can release a signature
  (`cli/ubft/cmd/signing_authority_process_test.go`, the fencing and replace-session cases).

## 3. Bootstrap and the fresh-authority gate

**Contract.** A shard may sign from an initial (bootstrap) state only with a live, process-local receipt from a root-quorum
frontier acquisition ([F6f](../../design/f6f-automatic-bootstrap-freshness.md)). Known ordinary progress ends bootstrap eligibility
at once, even before it is persisted. A stored journal, receipt, marker or old UC never grants freshness.

**Evidence (in-process).**
- **The gate:** `configuredadmission/freshness_test.go`:
  - no receipt, no bootstrap (`TestFreshnessStartsAcquiringAndRefusesBootstrapWithoutReceipt`);
  - receipt expiry, replacement and cancellation (`TestRequireFollowsTheReceiptLifetime`);
  - ordinary progress supersedes bootstrap before it is written (`TestOrdinaryAdmissionSupersedesBootstrapBeforeItIsPersisted`);
  - a persisted bootstrap certificate is data, not freshness (`TestBootstrapAdmissionDoesNotSupersedeBootstrap`);
  - a restart, restored or empty store needs a new acquisition and never restores a receipt
    (`TestRestartNeedsNoReceiptForOrdinaryProgressAndNeverRestoresOne`);
  - execution recovery is gated (`TestExecutionRecoveryReadinessIsGatedOnFreshness`).
- **The requester:** `rootchain/consensus/frontierrequester`:
  - concurrent owner, expired context, and expiry or replacement invalidating copies (`requester_test.go`);
  - renewal after expiry, and no root query once bootstrap is refused (`maintain_test.go`);
  - the policy deadline (`review_policy_test.go`).
- **Cancellation and a new target:** `configuredadmission/recovery_test.go` (`TestExecutionRecoveryCancellationAndNewTarget`).

**Supported limits.**
- **Single profile:** one fixed root committee and epoch, one unchanged shard deployment at epoch zero (F6f section 1).
  Re-adding a shard, a round wrap, and epoch or committee transitions refuse bootstrap.
- **Expiry is the only renewal:** a receipt lives at most five minutes from its start and is not renewed by a UC. An initial timeout
  repeat after expiry needs a new acquisition.

## 4. Filesystem and power-loss durability

**Contract.** Safety-critical root writes happen in one bbolt transaction with sync on (`storage.NewBoltStorage`;
`TestNewBoltStorage_Sync`), and the vote or timeout leaves the process only after they returned. The shard authority keeps no
safety-critical disk state at all: its key and record die together (F6c section 6).

**Evidence, by kind.**

| Kind | Evidence |
| --- | --- |
| Simulated ordering (in-process cuts) | `safety_decision_test.go`, `q4b_crash_test.go` (close and reopen at each cut), `configuredprogress/journal_test.go`. |
| Process kill (SIGKILL) | Root safety store: `rootchain/consensus/storage/decision_kill_test.go` (`TestRootDecisionsSurviveSIGKILL`). A child records decisions through the production write path and is killed at eight points; on reopen every released decision is exact, the floor is not below it, and an unreleased round is complete or absent. A child that releases before recording fails it. Shard stores: `certifiedstore/kill_test.go`, `configuredprogress/journal_process_test.go`, `configuredprogress/journal_frontier_test.go`, `shardnode/store_durability_test.go`. |
| Failed fsync / directory sync | `shardnode/store_durability_test.go` (the shard FileStore). |
| Actual storage failure (power loss, lost device cache, a filesystem that does not honour fsync) | **None.** Not exercised anywhere. |

**Supported limits.**
- **Hardware is assumed honest about fsync.** The guarantees assume a filesystem and device that honour fsync and bbolt's write
  ordering. Run root validators only on storage with that property (no volatile write cache without power protection, no
  network filesystems).
- **No power-loss evidence exists.** A process kill keeps written pages, so it is not power-loss evidence ([F6b](../../design/f6b-certified-record-store.md)).
  Power-loss durability is an operator-host property to be shown on the Linux host with real power interruption, or accepted as an
  assumption by the OWNER.
- **After a suspected storage fault, treat the root's safety store as untrusted.** Stop that validator and rotate its key
  (item 2); do not resume signing from the store.
- **Safety and liveness are recorded separately.** Every case above is a safety claim (no conflicting statement). Liveness after a
  loss (time to an authorized replacement) is an interruption objective in [evidence.md](evidence.md), measured on real hosts.

## What remains for the independent rehearsal

These need real hosts, not in-process tests:
- the second operator's execution;
- an actual authority-host loss followed by the certified replacement;
- the root host fencing procedure performed by hand;
- power-loss behaviour on the chosen storage.

They stay on the Linux host rehearsal ([README.md](README.md)).
