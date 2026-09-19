# F6d (#14): node wiring of the certified-block record, W1 and W2

> **Later genesis amendment (#167, proposed):** [F4f](f4f-standard-genesis-json-bootstrap.md). The amendment replaces W3a’s unavailable S0-valued genesis UC premise and specifies a future v2 readiness/persistence unit; the implementation evidence below remains W3a evidence. This note does not activate v2 or alter historical test results.

Issue: #14, node lifecycle wiring (claim issuecomment-5685890196). Base: `integration/enshrined-evm` at `3ad216a3`
(#160). Contract: `f6a-certified-record-crash-contract.md`. Store: `f6b-certified-record-store.md`.

Node wiring is delivered in three reviewed units:

| Unit | Scope |
| --- | --- |
| **W1** (#161, merged `30084e5f`) | deployment context built once; store opened with its directory entry durable; restart reload with the executor compared by exact identity; reported, no effect on voting |
| **W2** (§7) | witness capture off the round lock; verification outside the finality gate, final head check and atomic publication inside it |
| **W3a** (§8) | inactive readiness/continuity preparation and bounded capture retry machinery |
| W3b | Round/Node gating alongside P-id, recovery-source capture and composed lifecycle tests after W3a review |

## 1. Default path

`ubft shard-node run` without `--certified-record-store` constructs nothing from this unit and runs as before:
- `startCertifiedRecord` is not called;
- `recordwiring` and `certifiedstore` are imported only by the shard-node command
  (`TestOnlyTheShardNodeCommandImportsTheWiring`, `TestNoProductionPackageImportsTheStore`), and the round,
  client, recovery and executor adapters import neither.

The signing record and the signing authority are untouched. Nothing here activates SealRegistry execution or
removes `v0`.

## 2. The deployment context

`recordwiring.NewDeployment` checks configuration once and builds the store context and the proof context from
one result. Every input is the node's own configuration; nothing comes from the store, a certificate or a peer.

1. The running shard configuration must carry `seal_registry_genesis` (`ErrNotSealRegistryDeployment`).
2. G is regenerated with `registrygenesis.Generate` from:
   - the base configuration, which is the running configuration with that parameter removed;
   - the pins: the root epoch of the configured trust base, the pinned registry artifact and its code hash,
     and the v1 system and registry addresses;
   - the EVM genesis parameters (`--registry-evm-gas-limit`, `--registry-evm-coinbase`,
     `--registry-evm-extra-data`, base fee 1 gwei as `ubft engine-api genesis` writes).
3. `registrygenesis.VerifyContext(running, pins, G)` must accept (`ErrDeploymentConfig`, with the registrygenesis
   refusal in the chain). It binds the running configuration's base hash and commitment to G, so the running
   configuration is the generated full configuration.
4. Its hash must equal the configuration hash the node already enforces on every certificate (#134)
   (`ErrDeploymentConfig`).
5. The trust base store must serve the pinned root epoch (`ErrTrustBase`).
6. The executor's block 0 must be the generated EVM genesis by number, hash and state root
   (`ErrExecutorGenesis`; `ErrExecutorUnavailable` if it does not answer), and `--expected-genesis-hash`, when
   set, must agree (`ErrExecutorGenesis`).

A stock `ubft engine-api genesis` chain has no registry, so its block 0 differs and startup with the record store
fails at step 6. That is the intended refusal: the record holds SealRegistry witnesses.

## 3. Directory-entry durability

`certifiedstore.Open` syncs the store file's parent directory on every open, after the file and its bucket exist,
and a failed sync is an open failure (`ErrDirectorySync`) that closes the handle and returns no store. This closes
the gap `f6b-certified-record-store.md` §5 recorded: bbolt syncs a new file's pages but never the directory entry
naming it. On macOS the directory sync is `F_FULLFSYNC` on the directory descriptor, measured to succeed on APFS.

The directory synced must be the one holding the database entry. bbolt follows a symbolic link in the final
path component, so `links/db -> actual/db` would create `actual/db` while `filepath.Dir` names `links` (review
5214761349). `Open` therefore refuses a path whose final component is a symbolic link, dangling or not, before
anything is created through it, and after opening requires the entry at the path to be a regular file, which
catches a link substituted between the two checks (`ErrStorePath`). A symbolic link in an earlier component is
allowed: opening the parent directory for the sync resolves it to the directory that holds the entry. The
checks cover a misconfigured or changed path, not a party racing them with write access to the directory, who
could delete the store anyway.
`Open` does not create directories; the directory holding the store and those above it must already exist
durably, which the deployment provides.

## 4. Restart reload

`recordwiring.Reload` is the F6a §6 sequence. It loads and re-verifies the head record under the deployment's
store context, then reads the executor's head and compares by exact identity.

| Outcome | When | Error in the chain |
| --- | --- | --- |
| `no-record` | the store has no head | `certifiedstore.ErrNoRecord` |
| `record-untrusted` | the head record is damaged, foreign, of an unknown version or does not verify | the store's named refusal |
| `executor-unavailable` | the record verified; the executor's head could not be read | `ErrExecutorUnavailable` |
| `executor-behind` | head number below the record's | `ErrExecutorBehind` |
| `executor-ahead` | head number above the record's | `ErrExecutorAhead` |
| `executor-diverged` | same number, another hash or another state root | `ErrExecutorDiverged` |
| `durable-ready` | same number, hash and state root | none |

Reload reads and decides only:
- it never falls back to an older retained record, the legacy certificate file, the executor's head or a zero
  cursor;
- it issues no executor call that changes finality;
- it writes nothing to the store.

`durable-ready` is readiness for the recorded block, not for its child: that needs continuity to the held
certificate, which is W3. `executor-behind` is not repaired here, although the record's certificate would
authorize committing the recorded block.

The shard-node command reports the outcome in health (`certifiedRecord`, `certifiedRecordDetail`) and the log. A
configuration that fails §2, or a store that cannot be opened, stops startup: the operator asked for a record
store, and a node silently running without one looks the same from outside. A reload outcome other than
`durable-ready` does not stop startup and changes no vote.

## 5. Tests

| Test | Covers |
| --- | --- |
| `TestDeploymentIsBuiltFromCheckedConfiguration` | the contexts equal the generated deployment's; the store context is a copy; an agreeing expected genesis hash |
| `TestDeploymentRefusals` | one condition each: no `seal_registry_genesis`; a commitment for another root epoch; another setting under the same commitment; another enforced configuration hash; no trust base for the root epoch; executor unreachable; block 0 with another hash, state root or number; other EVM genesis parameters; a disagreeing expected genesis hash; missing configuration, trust base store or executor |
| `TestReloadOutcomes` | every outcome, each on a store published through one handle, closed and reopened in a fresh handle as a restarted process does, with the store's contents unchanged by the reload |
| `TestReloadRefusesUntrustedRecordsWithoutFallback` | a damaged head record while an older record exists and the executor is at that older block; a record published under another deployment |
| `TestOpenSyncsTheParentDirectory`, `TestOpenFailsWhenTheDirectoryCannotBeSynced` | the directory sync on create and reopen; an injected failure refuses the open and releases the file lock |
| `TestOpenRefusesSymbolicLinkStorePaths` | review 5214761349: a dangling final-component link and a link to an existing store are refused before anything is created or opened through them; a path that cannot be examined is refused; a link substituted after the first check is refused after opening and the backend handle is released; nothing is synced in any case |
| `TestHealthReportsTheCertifiedRecordOutcomeWithoutChangingVoting` | the health field, with voting unchanged |
| reach guards | only the shard-node command imports `recordwiring`; the proof, genesis and store guards admit `recordwiring` and the test fixture package |

The stub executor embeds a nil `Executor`, so any call other than `Head` and `GenesisBlock` panics the test:
nothing in W1 commits or builds. Certificates are really signed and verified; the chain is
`internal/testutils/certifiedchain`, a registrygenesis deployment whose blocks carry finalized registry storage in
real state tries.

**Mutations.** An uncommitted script disabled each rule in turn against its package's tests, with a 300 s timeout,
and restored and compared the sources after each. All 20 were caught:
- the deployment's ten checks: `seal_registry_genesis` presence, `VerifyContext`, the enforced configuration
  hash, the trust base for the root epoch, block 0's number, hash and state root, the expected genesis hash, the
  executor error, and the copied store context;
- the reload's seven rules: no record, an untrusted record, the executor head error, behind and ahead swapped,
  ahead not distinguished, and the hash and state root compared at the recorded height;
- the directory sync: not synced, the handle left open on failure, and a store returned despite failure.

The path policy added after review 5214761349 had five more, all caught:
- the pre-open link refusal;
- other pre-open path errors ignored;
- the post-open check removed, or reduced to its `Lstat` error;
- the backend handle left open on that refusal.

A check that the full configuration hash equals the generated one was removed before the first run, because
`VerifyContext` already implies it and no test could fail on it.

## 6. Not in W1

- Capture and publication (W2); readiness for the child and any effect on voting, building or validating (W3).
- Repairing `executor-behind` by committing the recorded block.
- Genesis continuity acquisition (W3); the 512-certificate and 1 MiB bounds are unchanged.
- Migration from the legacy certificate file, archive retrieval (#15), activation, `v0` removal, WithSealV1
  advertisement.

## 7. W2: witness capture and atomic publication

Claim: issuecomment-5687075006, base `30084e5f`. Nothing in this section changes W1's startup report, voting,
building, validating or the signing record.

### 7.1 Trigger

`Round.commitPrevious` commits a block only when the certificate in hand certifies the round this node proposed
for and names a block. After the executor's `Commit` returns `StatusValid` for that block, the round calls
`CommitObserver.ObserveCommit` with a `CertifiedCommit`:
- the certificate and its bound technical record, both deep-copied through canonical CBOR;
- the committed block's hash.

The call happens with the round lock held, so the observer must return promptly. `shardnode` defines the
interface and does not import `recordwiring`. The shard-node command attaches the capturer only when a record
store is configured.

These commit nothing and report nothing (`TestRound_ReportsOnlyCertifiedCommits`):
- a genesis round the executor did not move for;
- a quiet round;
- a repeat or re-delivery.

Commits made by #92 anchor recovery are not reported; W3 decides them with continuity.

### 7.2 The attempt snapshot

`Capturer.ObserveCommit` turns the commit into an immutable `Attempt`:
- a number;
- B's hash, the certified state root and the partition round, taken from the certificate's input record, which
  must name the committed 32-byte block;
- the certificate and technical record as canonical CBOR, never shared with the round.

A commit that cannot be snapshotted is `malformed` and attempts nothing.

One attempt is in flight at a time, and a single pending slot keeps only the newest committed block:
- a newer commit replaces the pending attempt, which is reported `superseded` and acquires nothing;
- a commit older than or equal to the pending round is `superseded` on arrival;
- a commit for a block and round already in flight, pending or published by this capturer is `duplicate`.

### 7.3 The capture sequence

`Capturer.Run` works off the round lock and never takes the finality gate:

1. **Acquire** witness(B) with `registrywitness.Acquire` by B's exact hash (`debug_getRawHeader`, `eth_getProof`
   by `blockHash`), bounded by `--certified-record-capture-timeout`. It is verified under the W1 deployment's
   proof context. There is no number, tag, head or zero-cursor fallback.
2. **Bind:** the verified witness must prove the certificate's state root, and its `RoundAuthorized` must be the
   certificate's round (`witness-mismatch`). The block number comes from the verified witness.
3. **Prepare** B's record with `certifiedstore.Prepare`, still off the round lock and outside the finality gate.
   It verifies the record, and verifies the current head record and binds it to its key, and decides staleness
   (§7.4).
4. **Decide under the finality gate** (review 5215297453, P1). Capture holds the node's `FinalityGate`, which
   every finality-changing executor call takes: the round's commits and builds, and recovery's commit. Under it:
   - it reads the executor's head, which must be exactly B by the witness's number, B's hash and the state root
     (`executor-moved`, `executor-unavailable`);
   - it runs `certifiedstore.Commit`, the one store transaction.

   The executor cannot move between "the head is exactly B" and "B's record is durable". A commit arriving
   meanwhile waits for the transaction, and one already holding the gate is seen by the head read. Only the
   head read and the store transaction happen under the gate: acquisition and all verification are done
   before it. `Head` is the only executor call capture makes. `Node.SetCommitObserver` installs the node's
   gate on the round even when recovery is off, so the round's commits take it in every configuration.

### 7.4 Stale and out-of-order completion

`certifiedstore.Prepare` reads the current head and decides from the verified head record, never from its key
(review 5215297453, P2):
- The head record is decoded and verified under the deployment's context, and the head key must be the
  canonical key of that verified record. A missing, damaged, foreign, unverifiable or wrongly keyed head is
  refused and not replaced (`ErrRecordUntrusted` or the named verification refusal). `Load` applies the same
  binding.
- A record that would replace a head of the same or a later partition round, or a genesis record that would
  replace an ordinary head, is refused (`ErrStaleRecord`, reported as `stale`). Republishing the head record is
  allowed.

`certifiedstore.Commit` then requires, inside its transaction, that the head is byte for byte the one `Prepare`
decided against (`ErrHeadChanged`, also reported as `stale`). The transaction itself verifies nothing. A late
or reordered completion cannot replace a newer durable head even if another process published it
(`TestPublishNeverReplacesALaterHead`, `TestTheHeadKeyIsBoundToItsVerifiedRecord`,
`TestCommitRequiresTheHeadPrepareDecidedAgainst`).

### 7.5 States and outcomes

The states stay separate:
- **Executor-applied:** the round reported the commit.
- **Witness-verified:** step 2 passed.
- **Durable:** `Publish` returned nil.

Every other outcome leaves the prior record as the head, writes and deletes nothing, reports nothing as
durable-ready, and causes no executor action.

| Outcome | Meaning |
| --- | --- |
| `published` | B's record is the durable head |
| `duplicate`, `superseded` | not started: the block is already handled, or a newer committed block replaced it |
| `malformed` | the commit could not be snapshotted |
| `witness-unavailable` | the client did not provide witness(B), including a block behind its proof window (#15 owns later retrieval) |
| `witness-invalid` | the client's answer is not a valid witness for B's hash |
| `witness-mismatch` | the witness verified but proves another state root or round |
| `executor-unavailable`, `executor-moved` | the head could not be read, or is no longer exactly B |
| `stale` | the verified head already names this or a later round, or the head changed after preparation |
| `publish-failed` | the store refused the record or failed |
| `stopped` | the capturer stopped first; a pending attempt is reported the same way |

Each outcome is logged with the attempt number, round and block.

**Deployment requirement.** The execution client's proof window must cover the capture lag. Pinned reth's
default window is the head only, so a child committed before capture completes makes witness(B) unavailable.

### 7.6 Shard-node command

With `--certified-record-store`, `startCertifiedRecord` does the following after the W1 reload:
- builds the capturer over `--eth-url`;
- attaches it with `Node.SetCommitObserver`;
- runs it until the command exits, stopping it before closing the store.

Without the flag, nothing is attached.

### 7.7 Tests

| Test | Covers |
| --- | --- |
| `TestCapturePublishesEachCommittedBlock` | two blocks captured and published in turn; the stored identity, number and round; exactly `debug_getRawHeader` and `eth_getProof` for B's hash, once; one head read per attempt |
| `TestCaptureFailuresKeepThePriorRecord` | missing witness, expired proof window, another block's witness, a certificate naming another round or state than the witness, an unreadable executor head, an executor at another block, and executor heads differing from B in exactly one of hash (another block at the same height and state), number or state root; a later durable record, a record the store refuses, a store that fails; each keeps the prior head and the stored keys unchanged |
| `TestCaptureDuplicateDeliveryAcquiresOnce` | re-delivery after publication and while in flight |
| `TestCaptureWhileTheNodeAdvances` | the executor commits the next block while capture is in flight; newer commits replace a pending attempt; an older commit delivered after a newer one |
| `TestCaptureAcrossRestart` | stopped before publication: in-flight and pending attempts stopped, W1 reload finds the executor ahead of the prior record; stopped after publication: W1 reload is durable-ready for B |
| `TestCaptureRefusesAMalformedCommit` | a commit naming another block than its certificate, and an empty commit |
| `TestPublishNeverReplacesALaterHead` | the store's stale refusal for an earlier round, another block at the head's round, the genesis record, and the genesis record with its certificate round advanced past the head's; republishing and later rounds allowed; an unparsable head key |
| `TestRound_ReportsOnlyCertifiedCommits`, `TestRound_AnUncopyableCommitIsNotReportedAndDoesNotFailTheRound` | the round hook with the fake executor; a commit that cannot be copied is not reported and does not fail the round |
| `TestCapturePublicationIsSerializedWithFinality` | review 5215297453 P1: the executor moving during verification is `executor-moved`; a commit started after the final head read waits on the gate and proceeds only once B's record is durable; the store head changing after preparation is `stale` (`ErrHeadChanged`) with nothing written; a commit already holding the gate is seen by the head read |
| `TestRound_CommitsWaitForTheFinalityGate`, `TestNodeSetCommitObserverInstallsTheNodeGate` | the round's commit waits for a held gate; attaching an observer installs the node's gate on a round without recovery and keeps an installed one |
| `TestTheHeadKeyIsBoundToItsVerifiedRecord` | review 5215297453 P2: an authentic record under an earlier round's key, an unverifiable head, a head naming a missing record, and a head of another deployment are refused on load or publication and not replaced |
| `TestCommitRequiresTheHeadPrepareDecidedAgainst` | `Commit` refuses a changed head, the head moved to an identical copy under another key, the head record's bytes changed under the same key, an empty store that gained a head, and another store's preparation; an unchanged head commits |

The capture tests use:
- the real bbolt store;
- certificates signed and verified against the configured trust base;
- a JSON-RPC stand-in that serves the signed chain's real headers and proofs by exact hash and records every call;
- an executor stand-in that answers only `Head`, so any other executor call panics the test.

**Mutations.** An uncommitted script disabled each rule in turn against its package's tests, with a 300 s timeout,
and restored and compared the sources after each. All 24 are caught:
- **Store (6):** the stale check removed, republishing the head refused, an ordinary record over genesis refused,
  genesis allowed over an ordinary head, another block at the head's round allowed, and an unparsable head
  overwritten.
- **Capture (15):**
  - the witness state-root and round bindings;
  - the executor head's number, hash and state-root comparisons, and its error;
  - duplicate detection, and remembering the published block;
  - which commit the pending slot keeps (older and newer);
  - stale reported as a publish failure, and unavailable reported as invalid;
  - stopping not distinguished, and a pending attempt not reported on stop;
  - a malformed commit accepted.
- **Round hook (3):** the report removed, originals passed instead of copies, and an uncopyable commit reported.

The first run caught 19. Four survived because each negative case changed several conditions at once, and they
are caught after one-condition cases were added: genesis at an advanced round, and executor heads differing only
in number, hash or state root. One did not compile and is caught once fixed.

The repair of review 5215297453 added eleven more, all caught:
- the head key's binding to its verified record;
- an unverifiable head replaced;
- the same round allowed, and genesis allowed over an ordinary head;
- `Commit` not comparing the head name, not comparing the head record's bytes, or accepting another store's
  preparation;
- publication decided without the finality gate;
- `ErrHeadChanged` reported as a publish failure;
- the round ignoring an installed gate;
- the node not installing its gate for the observer.

The first run of these caught seven. The head-name and head-bytes checks each survived because the other covered
every case changed so far, and are caught after cases that change only one of them. The `ErrHeadChanged`
mapping and the node's gate installation had no test reaching them, and are caught after the store-head-change
capture case and `TestNodeSetCommitObserverInstallsTheNodeGate` were added.

### 7.8 Not in W2

- Readiness for B's child, authenticated quiet continuity, the explicit genesis path including the genesis
  record, capture of recovery-applied blocks, and any voting, building or validating effect: W3.
- **What W3 must add before it gates anything on the record** (review 5215297453). Capture is triggered only by
  the round's own certified commits, and repeats, re-deliveries and anchor-recovery commits report nothing. An
  attempt that fails transiently, such as `witness-unavailable`, `executor-unavailable` or `publish-failed`, is
  therefore not retried by W2. A readiness gate built on the record needs:
  - a bounded retry trigger for transient failures;
  - capture after reconciliation or recovery commits.

  Without these, one unavailable proof could leave a node permanently not ready.
- Retrieving a witness after the proof window: #15.
- Existing stock execution has no SealRegistry and is not a positive execution lane for this path.

#10, #11, #12 and #14 stay open.

## 8. W3a: readiness preparation and bounded retry

W3 is split so the evidence predicate and mutable-state boundary can be reviewed before Round uses either.
W3a installs no runtime readiness gate. The existing opt-in W2 capturer does gain bounded retries; the default
path without `--certified-record-store` remains unchanged.

### 8.1 Observation and continuity

`recordwiring.Observations` retains copied, certificate-bound UC/TR pairs under the existing 512-certificate
and 1 MiB complete-bundle bounds. Exact redelivery is idempotent. A snapshot is keyed by exact source and held
certificate bytes and copied before its lock is released.

`Readiness.Prepare` owns a copy of the caller's held certificate before any store or trust lookup. It then:

1. loads and re-verifies the durable head and obtains an opaque byte-identity token for it;
2. requires the executor at the exact recorded number, block hash and state root;
3. obtains the observed chain whose source is the exact record certificate and whose terminal is the exact
   held certificate;
4. for an ordinary record, applies `VerifyAnchorEvidence` unchanged and binds its anchor back to the record;
5. for genesis, applies the separate `VerifyGenesisContinuity` entry point. It uses the same authentication,
   assigned-round, repeat and terminal-identity rules, while requiring a genuine no-block source at configured
   genesis state. It then calls `GenesisParentEligible` with the held certificate's authenticated assignment
   and the record's verified snapshot, enforcing E1 through E4.

After authentication, every continuity certificate must name the deployment's pinned root epoch and every
bound technical record must name its pinned shard epoch. An authentic chain from another registry profile is
not readiness evidence for this deployment.

The ordinary #92 predicate still refuses a no-block source. State equality never selects a source or terminal.
The returned `PreparedReadiness` is opaque and bound to the `Readiness` instance that created it.
`Revalidate` performs only mutable checks: exact held bytes, unchanged observation version, byte-identical
durable head and exact executor identity. It performs no trust, signature or proof work; W3b owns calling it at
the finality boundary before Build and vote.

### 8.2 Genesis record

The checked deployment retains a copy of `registrygenesis` witness(EVM genesis). `PublishGenesis` accepts only
a genuine authenticated no-block UC/TR whose state and previous state equal configured genesis. It prepares
and verifies the record off the finality gate, then under the gate requires the executor exactly at configured
block 0 and commits it. It never fills a nil root-chain initial state or synthesizes a certificate. Current
stock startup can therefore remain without a genesis record until the execution profile provides genuine
configuration-bound genesis certification; fixtures establish composition only.

### 8.3 Capture retry

One W2 capture episode makes at most three witness-acquisition attempts, with a bounded delay. Only unavailable
evidence is retried. Invalid evidence, certificate/witness mismatch, malformed input, staleness and executor
movement remain terminal for that episode. A proof-window refusal stops the local episode but retains the
immutable attempt; it is not a permanent ban on B, and #15 or a later provider may make evidence available.

After an unavailable episode is exhausted, `RetryPending` starts one new bounded episode from the retained
immutable attempt without a new transaction or commit notification. Calls coalesce while work is pending or
in flight. W3b owns bounded backoff/scheduling, including reconciliation triggers. W3a proves the mechanism by
making an initially unavailable proof available later and publishing the original attempt.

## 9. W3b-1: the readiness gate in Round

W3a built the predicate and left it inactive. W3b-1 lets a Round consult it, behind a second opt-in flag, and
withholds leadership and the signature when the node cannot prove readiness for the held certificate's child.
Recovery-source capture and the composed lifecycle tests are W3b-2 and are not in this unit.

### 9.1 Opt-in

`--certified-record-gate` is a boolean, default false. It requires `--certified-record-store`; set alone it stops
startup with a named refusal. With the store and without the gate, the node behaves exactly as W3a: it reloads,
reports, captures and publishes, and no vote changes.

The gate is a separate flag rather than an effect of the store because readiness demands that the durable head
record name the executor's current head (`Prepare` refuses otherwise). Capture is asynchronous, so a node whose
record has not yet caught up with its executor is not ready, and a node with no record at all is never ready
until W2 capture or `PublishGenesis` produces one. Abstaining is the correct answer for a node that cannot prove
what its executor stands on, and it is not an acceptable side effect of asking for a record store.

### 9.2 What Round gains

Round must not import `recordwiring` (`recordwiring` imports `shardnode`, and the reach guards hold). It gains
two interfaces and two `Node` setters instead, both installed only with the gate:

```go
// ReadinessTicket is an opaque prepared result. Only its producer can make one.
type ReadinessTicket interface{ Valid() bool }

// ChildReadiness decides whether this node may act on the certified-block record's child (#14 W3b).
type ChildReadiness interface {
	// Prepare does all expensive store, witness, trust and continuity verification. It is called with
	// the round lock held and the finality gate free.
	Prepare(ctx context.Context, held *types.UnicityCertificate) (ReadinessTicket, error)
	// Revalidate does only the decisive mutable-state checks. It is called inside the finality gate.
	Revalidate(ctx context.Context, ticket ReadinessTicket, held *types.UnicityCertificate) error
}

// CertificateObserver is fed every authenticated certificate and its technical record.
type CertificateObserver interface {
	ObserveCertificate(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error
}
```

`recordwiring.PreparedReadiness` already satisfies `ReadinessTicket`. `recordwiring` supplies the adapters:
`NewChildReadiness(*Readiness) shardnode.ChildReadiness` and `NewCertificateObserver(*Observations)
shardnode.CertificateObserver`. Neither adapter adds a check; each forwards to the W3a entry point.

`Node.SetCertificateObserver` and `Node.SetChildReadiness` follow `SetCommitObserver`: after `New`, before `Run`.

### 9.3 Feeding the observations

Round calls the certificate observer at the one site where an authenticated certificate and its technical record
arrive together, beside `r.evidence.Observe` (round.go, the retention block). The rules are that block's rules:
it runs before anything fallible, a refusal is logged and never fails the round, and being observed authorizes
nothing. Without the gate no observer is installed and the call is not made.

### 9.4 Where the verdict is applied

`Prepare` runs once per round, after the two re-delivery answers and immediately before the leadership decision,
and only when `identityErr` is nil: a round that already abstains on P-id needs no store, witness or trust work.
Its ticket and its error live for that round only.

| Point | Rule |
| --- | --- |
| Leadership | Not ready and this node is the leader: decline to lead exactly as P-id declines. `Build` is not called, nothing is finalized, the round returns nil. |
| Build | `Revalidate` runs inside `buildFinal`'s finality-gate hold, after the gate is taken and before `executor.Build`. A refusal returns `errReadinessRevoked`; the round abstains and returns nil rather than failing the certificate. |
| Vote | Immediately after P-id's abstention block and before P-sign, Round takes the finality gate for `Revalidate` alone and releases it. A refusal withholds the signature only. |

Withholding is the whole of it, as with P-id. The block is still built or verified, `r.pending` is still recorded,
and `commitPrevious` still applies what the shard certifies, so a not-ready node stays a warm follower and its
own captures can make it ready again without recovery.

Between the vote's revalidation and the signature the round lock excludes every commit and build in this process,
including the recovery applier's, which runs only under it. What can still intervene is a capturer publication,
which replaces the durable head with a later certified block. That does not invalidate the statement being signed
about the round in hand; the next certificate's `Prepare` re-establishes readiness against the new head. This is
the boundary, stated rather than closed.

### 9.5 Reporting

Health gains `certifiedRecordReadiness` and `certifiedRecordReadinessDetail` (both `omitempty`, both empty without
the gate), set on every round the gate evaluates to `ready` or to the refusal. The non-voting reason names record
readiness so it is distinguishable from P-id and from a signing refusal. Two IR-divergence metric reasons are
added: `record_readiness_declined_leadership` and `record_readiness_abstained`.

### 9.6 Not in W3b-1

- Capture of blocks committed by anchor recovery (#92) and the composed restart/recovery lifecycle tests: W3b-2.
- Any change to W1 startup, W2 capture, the store, the proof path or the default ungated node.
- Making the gate the default, and any activation decision for a deployment.

### 9.7 Tests

| Test | Covers |
| --- | --- |
| `TestGateFlagRequiresTheRecordStore` (cmd) | `--certified-record-gate` alone stops startup with the named refusal; with the store it installs both hooks |
| `TestRecordGateIsOffWithoutTheFlag` | with the store and no gate flag no `ChildReadiness` and no `CertificateObserver` are installed and voting is unchanged |
| `TestReadyRoundIsUnchanged` | a ready round produces byte-identical signed request bytes to the same round without the gate |
| `TestNotReadyDeclinesLeadership` | the leader's `Prepare` refuses: `executor.Build` is never called, nothing is signed, the round returns nil, health and the metric name record readiness |
| `TestReadinessRevokedInsideTheFinalityGate` | `Revalidate` refuses inside `buildFinal`'s hold: no `Build`, the round abstains and returns nil rather than returning an error |
| `TestNotReadyAbstainsFromTheVote` | `Prepare` succeeded and the vote's `Revalidate` refuses: the block is still built or verified, `r.pending` is recorded, nothing is signed, and the next certificate still commits |
| `TestVoteRevalidationHoldsTheFinalityGate` | the gate is held for the vote's `Revalidate` and released before the signer is called |
| `TestPrepareIsSkippedWhenIdentityAlreadyRefuses` | `identityErr` non-nil: `Prepare` is not called |
| `TestCertificateObserverRefusalDoesNotFailTheRound` | an observer refusal is logged and the round proceeds and signs |
| reach guards | unchanged: only the shard-node command imports `recordwiring`, and `shardnode` imports neither it nor `certifiedstore` |

## 10. W3b-2: capture of recovery-applied blocks

W2 reports only the blocks the round itself commits. `CommitObserver` says so: commits made by anchor
recovery (#92) are not reported, so the block a returning node was brought to by evidence never gets a
record, and the gate of §9 then refuses readiness for its child until an ordinary round commits again.
That is the gap this unit closes. It is stacked on W3b-1 and assumes §9 is merged.

### 10.1 Which certificate certifies a recovered block

The held certificate does not. `reconcile` drives recovery for the certificate the round was asked to
build on, and across a quiet tail that certificate carries no block hash at all: the target comes from
`continuity.recoveryTarget`, which names the last state-changing certified block, and that block may be
many rounds older than the one in hand. A record bound to the held certificate would therefore name one
certificate and contain another certificate's block, which is exactly the confusion `certifiedstore`
refuses.

The certificate that certifies the recovered block is `AnchorEvidence.Source`, with `SourceTechnical`
bound to it. `VerifyAnchorEvidence` authenticated both, and `ErrEvidenceSourceQuiet` already guarantees
the source names a block. They are the pair the record needs, and they are currently discarded: the
requester reduces verified evidence to an `ExecutionAnchor`, and `VerifiedTarget` carries only that
anchor and `For`, the binding of the held certificate.

So W3b-2 is first a plumbing change. `VerifiedTarget` gains the authenticated source pair, carried from
the verification that produced it and copied like every other retained certificate:

```go
type VerifiedTarget struct {
	Anchor *ExecutionAnchor
	For    CertificateBinding
	// Source certified Anchor's block, with the technical record bound to it. Both come from the
	// AnchorEvidence this target was verified from, never from the held certificate.
	Source          *types.UnicityCertificate
	SourceTechnical *certification.TechnicalRecord
}
```

`ApplyResult` gains the same pair for the attempt it reports, taken from the target it applied.

### 10.2 Reporting the commit

`applyVerifiedAnchor` reports the commit after the applier succeeded and after its own revalidation
against the snapshot has installed the anchor, not before: a target that does not explain the state this
round is building on is not installed, and it must not be recorded either. The report is
`notifyCommit`'s existing path with the source pair and `res.Target.BlockHash`, so the capturer's
contract is unchanged and it cannot tell a recovery commit from an ordinary one.

`ObserveCommit` is documented as being called with the round lock held. `applyVerifiedAnchor` drops the
lock across `recovery.apply` and retakes it, and the report goes after it is retaken, so that holds.

`CommitObserver`'s doc comment is amended: recovery commits are now reported, and repeats, re-deliveries
and quiet certificates still commit nothing and are still not reported.

### 10.3 Ordering against the durable record

A recovery commit can move the executor to a block older than the store's head record, and it can also
move it past one. Neither is a new refusal: `Capturer` already decides staleness from the record it is
publishing against under the finality gate, and `certifiedstore` already refuses a record that does not
extend what it holds. W3b-2 adds no new ordering rule; it establishes by test that the existing ones
answer the recovery case, including the case where an ordinary commit and a recovery commit for the same
block are both reported.

### 10.4 Composed lifecycle

The last piece of F6d is one test that runs the units together rather than each in isolation: a node
with the store and the gate, driven through ordinary rounds, a restart, a recovery, and capture, with
the vote asserted at each stage. It is a composition of existing fixtures, and its purpose is to catch
the interactions the per-unit tests cannot see.

### 10.5 Tests

| Test | Covers |
| --- | --- |
| `TestVerifiedTargetCarriesTheAuthenticatedSource` | the source pair reaching `VerifiedTarget` and `ApplyResult` is the one `VerifyAnchorEvidence` authenticated, copied, and never the held certificate |
| `TestRecoveryCommitIsReportedWithItsOwnCertificate` | a recovery across a quiet tail reports the source certificate that names the committed block, not the held certificate, and the block hash is the applied target's |
| `TestRecoveryCommitIsNotReportedWhenNothingIsInstalled` | an attempt whose target does not explain the snapshot state installs nothing and reports nothing |
| `TestRecoveryCapturePublishesARecord` | the capturer publishes a record for a recovery-applied block, and the gate of §9 then finds readiness for its child |
| `TestRecoveryAndOrdinaryCommitForTheSameBlock` | both reported: the second is refused as `CaptureDuplicate` and no record is damaged. `ErrStaleRecord` is not reachable for the same block, because the capturer's round comes from the certificate's `InputRecord.RoundNumber` and the witness must show the same `RoundAuthorized`, so the record's round equals the head's and the store sees a republish. The stale case is a different block at the same or an earlier round, covered by `TestCaptureFailuresKeepThePriorRecord` |
| `TestCertifiedRecordLifecycle` | §10.4, composed: ordinary rounds, restart, recovery, capture, with the vote asserted at each stage |

### 10.6 Observing the authenticated recovery chain

Reporting the commit is not enough on its own. `Readiness.Prepare` builds continuity from the record's
certificate to the held certificate out of the observation history, and that history is fed from exactly
one place: the arrival site in `HandleCertificate`, which sees only what this node received live. A node
that fell behind and was brought back by evidence never received the source certificate or the tail
between it and the certificate it holds. So after a recovery and a capture, the record names a
certificate the node cannot connect to anything, and the gate of §9 abstains indefinitely. That is the
state the record exists to repair, so W3b-2 must close it rather than leave §10.5's readiness claim
resting on a test that observes the source by hand.

`VerifiedTarget` therefore also carries the authenticated tail, copied like the source pair:

```go
	// Tail is every certificate from the round Source assigned, up to and including the one this
	// node holds, each with its bound technical record. It is the chain a later Prepare needs.
	Tail []EvidenceLink
```

At the same point that reports the commit, after the lock is retaken and after the snapshot revalidation
has installed the anchor, Round feeds the certificate observer the source pair and then each tail link in
order. The rules are the existing feed's rules: it authorizes nothing, and a refusal is logged rather
than allowed to fail the round. Nothing is observed when the target is not installed.

This costs no trust. `VerifyAnchorEvidence` authenticated every certificate in the bundle against the
configured trust base before the target existed, which is the same standard the live arrival site
applies, and `AnchorEvidenceLimits` bounds the bundle at verification. The observation history keeps its
own 512-certificate and 1 MiB bounds and evicts under them as before. The held certificate is already
observed by the time `reconcile` runs, so source plus tail completes the chain rather than starting a
second one.

| Test | Covers |
| --- | --- |
| `TestRecoveryFeedsTheAuthenticatedChainToObservations` | the source pair and every tail link are observed, in order, and are exactly the bundle's authenticated pairs |
| `TestNothingIsObservedWhenTheTargetIsNotInstalled` | an attempt whose target does not explain the snapshot state observes nothing, as it reports nothing |
| `TestRecoveryObservationRefusalDoesNotFailTheRound` | a refusal from the observer is logged and the round proceeds |
| `TestGateBecomesReadyAfterRecoveryAndCapture` | end to end with no certificate observed by hand: a node that recovers, captures and publishes finds readiness for the recovered block's child |

`TestRecoveryCapturePublishesARecord` and `TestCertifiedRecordLifecycle` drop their manual observation of
the source, which was standing in for this feed.
