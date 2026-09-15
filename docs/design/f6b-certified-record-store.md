# F6b (#14): the certified-record store

Issue: #14, bounded storage slice (claim issuecomment-5680988132). Base: `integration/enshrined-evm` at
`36427257`. Status: **inactive storage package** (`certifiedstore`). Contract: `f6a-certified-record-crash-contract.md`.

`certifiedstore` implements the record, head pointer and retention of the F6a contract over bbolt. It publishes
a record only after the record verifies, in one transaction, and it loads the head record by re-verifying
everything against configuration the caller supplies. Nothing in production imports it
(`certifiedstore/inert_test.go`). Startup, executor commits, readiness for B's child, continuity and network
acquisition are not wired; those belong to the node wiring unit.

## 1. Interface

| Item | Behaviour |
| --- | --- |
| `Open(path, Settings)` | opens or creates the bbolt file with default options, refuses a handle opened without syncing, creates the bucket |
| `Settings.Retain` | how many non-genesis records are kept, counting the one being published; 1 to 65 536 |
| `Publish(ctx, Context, Record)` | encodes the record, **verifies it first**, then one `Update` transaction: put record, move head, delete the oldest non-genesis records beyond `Retain` |
| `Load(ctx, Context)` | reads the head record and re-verifies it; returns an opaque `Loaded` with copying accessors |
| `Context` | network, partition and shard ids, `fullShardConfHash`, the `registryproof.Context`, and a trust base store keyed by root epoch. All of it comes from configuration, never from the store |

`Record` carries the real `types.UnicityCertificate` and `certification.TechnicalRecord`, B's identity and
`witness(B)`. The stored form is the F6a encoding: the record as canonical CBOR in a versioned envelope with a
SHA-256 digest, bounded at 1 MiB before decoding. It has no signing state
(`TestTheStoreHoldsNoSigningState`).

**Keys**, in one bucket `certified-record/v1`:
- `head`, naming the current record's key;
- `record/genesis`;
- `record/<partition round, 20 digits>/<block hash hex>`.

## 2. Verification

`Load`, and `Publish` before it writes, check in the F6a §6 order:
1. configuration well-formed (`ErrConfig`);
2. record version (`ErrRecordVersion`);
3. stored context equal to configuration (`ErrWrongContext`);
4. certificate partition, shard and shard configuration hash (`ErrWrongContext`);
5. certificate authentication through `UC.Verify` against the trust base for the certificate's root epoch
   (`ErrCertificate`);
6. technical record hash equal to `UC.TRHash` (`ErrTechnicalRecord`);
7. the block rule (`ErrWrongBlock`):
   - an ordinary record's certificate names B;
   - the genesis record's hash is the configured `evmGenesisHash`, and its certificate is no-block genesis
     history at the genesis state;
8. `registryproof.Verify` of the witness (`ErrWitness`), with its number and state root equal to the record's
   (`ErrWrongBlock`).

Before these, `Load` refuses a missing head (`ErrNoRecord`), a head naming an absent record, an oversized,
undecodable or digest-mismatched value, and a payload version that differs from its envelope
(`ErrRecordUntrusted`). **There is no fallback:** an older retained record is never substituted
(`TestLoadRefusalsAndNoFallback`).

## 3. Publication and retention

- A record that does not verify is never written, so no partial or unverifiable record becomes current
  (`TestPublishRefusesARecordThatDoesNotVerify`, which also requires the store to be byte-identical afterwards).
- The record, the head pointer and every retention deletion are in the same bbolt transaction.
- Retention sorts the other non-genesis keys and deletes the oldest until `Retain`, counting the record being
  published, is met. It never deletes `record/genesis` or the key being published, and republishing the current
  record deletes nothing (`TestRetentionIsBoundedAndTransactional`).
- Because the deletions are in the transaction, a failed publication cannot prune its predecessor.

## 4. Failure evidence

**Injected failures in one process** (`TestInjectedFailuresLeavePriorOrNewState`).
- **Setup:** blocks 0 to 3 published under `Retain` 3, then block 4 published under `Retain` 1. That publication
  writes record 4, moves the head and deletes three records.
- **Checkpoints:** a failure is injected at each of before publication, after the record put, after the head
  put, after each of the three retention deletions, before commit, and after commit.
- **Before commit:** the store is **byte-identical** to the prior state, and `Load` returns block 3, before and
  after reopening the file.
- **After commit:** the store holds the complete new state, and `Load` returns block 4. An error reported after
  commit does not mean nothing was written; a caller must reload.
- **Recovery:** the same publication then succeeds from every checkpoint.

**Process termination** (`TestProcessKilledAtEachCheckpoint`).
- A child process, the test binary re-executed, publishes block 4 and sends itself `SIGKILL` at each of the same
  checkpoints, so no deferred rollback or close runs.
- The parent checks that the child died by `SIGKILL`, reopens the real bbolt file, and requires the complete
  prior state, or after commit the complete new state.

**What this evidence is.**
- It shows bbolt's commit ordering and meta-page selection hold up when the **process** ends at each point.
- It is not power-loss evidence. After `SIGKILL` the operating system still holds every page the process
  wrote, so these tests cannot show what survives a power failure, a lost device write cache, or a filesystem
  that does not honour sync.

## 5. What a successful commit guarantees, and what it does not

bbolt v1.4.0 with default options (`NoSync` false; `Open` refuses a handle where it is true) commits in this
order (`tx.go` `Commit`, `write`, `writeMeta`):

1. rebalance and spill the changed pages, write a new freelist, grow the file if needed;
2. write the dirty pages, then **sync the file**;
3. write the new meta page, then **sync the file** again.

A crash before step 3 completes leaves the previous meta page as the valid one on reopen, so the previous
transaction is what the file contains. `Commit` returns only after both syncs return without error.

The sync is `fdatasync` on Linux. On macOS it is Go's `File.Sync`, which issues `fcntl(F_FULLFSYNC)` and
falls back to `fsync` only where the filesystem does not support it (Go `internal/poll/fd_fsync_darwin.go`).

**Guaranteed by the software stack, assuming the syscalls are honoured.** After `Publish` returns nil, the
record, head pointer and retention deletions are in the file as one unit, and a later `Open` and `Load` see
them, or see an older complete state, never a mixture.

**Still dependent on the operating system, filesystem and device.**
- The device and filesystem must honour the sync, including a volatile write cache flushed on
  `F_FULLFSYNC` or fdatasync. A device or virtualization layer that acknowledges a flush without persisting
  it can lose a committed transaction.
- **The directory entry of a newly created file.** bbolt writes and syncs the new file's initial pages, but it
  does not open or sync the parent directory. A crash shortly after the store is first created may lose the
  file itself. The wiring unit should create the store before the node reports readiness, or sync the directory.
- Storage errors reported asynchronously and swallowed by the filesystem after a successful sync are outside
  what this code can detect.
- Whole-store rollback (a restored backup or cloned disk) is not detected by the store. The F6a contract
  handles it with the executor's head and continuity to the held certificate.

## 6. Tests

`go test -race ./certifiedstore/` passes: 11 top-level tests, including 8 injected-failure and 8
process-termination checkpoints. `go test -race ./registryproof/` also passes.

| Test | Covers |
| --- | --- |
| `TestPublishAndReloadAcrossReopen` | publish genesis and three blocks, close, reopen, load and verify; accessors return copies |
| `TestGenesisRecordReloads` | the no-block genesis certificate persisted and reloaded |
| `TestPublishRefusesARecordThatDoesNotVerify` | another block's witness, an unsigned certificate, another deployment's configuration, an uncommitted technical record, an ordinary record whose certificate names no block, a genesis record whose certificate names a block, a block-0 record for a header at the genesis state root other than the configured EVM genesis, a missing certificate; each leaves the store byte-identical |
| `TestLoadRefusalsAndNoFallback` | missing head record, bit flip, truncation, an oversized value, an oversized envelope that would otherwise decode, a payload version that differs from its envelope, a future version, another deployment's record, a stored context naming another network while the certificate and witness still verify, another block's witness, an uncommitted technical record, a false height, an unknown root epoch, a malformed configuration, an empty store; an older record is present and never used |
| `TestRetentionIsBoundedAndTransactional` | retain 1, 2 and 8; republishing the current record; genesis kept; settings validation |
| `TestInjectedFailuresLeavePriorOrNewState`, `TestEveryCheckpointIsReached` | in-process failures at every checkpoint, before and after reopen |
| `TestProcessKilledAtEachCheckpoint` | `SIGKILL` at every checkpoint, reopen of the real file |
| `TestTheStoreHoldsNoSigningState`, `TestLoadedIsOpaque`, `TestNoProductionPackageImportsTheStore` | no signing state, opaque result, inertness |

**Mutations** (an uncommitted script disabling each rule in turn against the whole package, 300 s timeout;
mutations that did not compile were fixed and rerun): 27 of 31 caught, covering publication order, the head move, retention inside the
transaction, the retention count, genesis and current-key protection, deletion order, settings, the size bound,
envelope version, digest, payload version, every verification step, and the witness accessor copy. The
retention-outside-the-transaction mutation deletes in a second transaction after the first returns, including
after a failure; a delete issued inside the open transaction would deadlock on bbolt's single writer lock and
test nothing. Survivors, each explained:
- The genesis certificate's "names no block" (V7) and "previous state is the genesis state" (V8) checks survive
  alone and are caught together. `UC.Verify` applies `InputRecord.IsValid`, under which an unchanged state hash
  requires a nil block hash and a changed one requires a block hash, so with `ir.Hash` bound to the state root
  each check implies the other for any authenticated certificate. Both are kept.
- The record version check inside `verify` (V13) is redundant: `Load` reaches it only after the envelope version
  and payload version checks, and `Publish` encodes the current version itself.
- Keeping bbolt memory past the read transaction (S11) is not observable here: the decode copies, and no remap or
  concurrent writer occurs during it. The clone is kept because bbolt documents the memory as valid only inside
  the transaction.

Certificates are really signed with a fixed secp256k1 key and verified against a test trust base. The
deployment is the `registrygenesis` vector, and non-genesis blocks carry finalized registry storage in real
state tries.

## 7. Not in this unit

- **Wiring:** no startup, executor-commit, readiness, continuity or network-acquisition wiring.
- **Genesis continuity:** the wiring unit must provide the genesis continuity path explicitly; the existing #92
  predicate and provider accept only block-naming sources (F6a §6.1).
- **Other units:** no migration from `FileStore`, archive retrieval (#15), activation, `v0` removal or WithSealV1
  advertisement.
- **Signing record:** untouched.

#10, #11, #12 and #14 stay open.
