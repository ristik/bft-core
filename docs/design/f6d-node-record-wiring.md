# F6d (#14): node wiring of the certified-block record, W1

Issue: #14, node lifecycle wiring (claim issuecomment-5685890196). Base: `integration/enshrined-evm` at `3ad216a3`
(#160). Contract: `f6a-certified-record-crash-contract.md`. Store: `f6b-certified-record-store.md`.

Node wiring is delivered in three reviewed units:

| Unit | Scope |
| --- | --- |
| **W1 (this)** | deployment context built once; store opened with its directory entry durable; restart reload with the executor compared by exact identity; reported, no effect on voting |
| W2 | witness capture after the round commits B, and atomic publication, off the round lock and outside the finality gate |
| W3 | readiness for B's child: live continuity, #92 anchor evidence for ordinary records, a separate configuration-bound genesis continuity path, gating alongside P-id |

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

#10, #11, #12 and #14 stay open.
