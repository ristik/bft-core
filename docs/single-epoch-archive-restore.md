# Replace a shard validator with empty BFT and execution disks

This command restores the paired Engine API shard across any number of missed
root epochs when `--trust-history-profile-2` is enabled. The archive must
contain every EVM block from the configured genesis through the pinned tip,
including each handoff acknowledgement block. A tip at genesis needs no archive
replay; start a fresh node through the ordinary genesis procedure instead.

1. Stop the old shard and keep its **external signing authority running**,
   outside the BFT and EL disk-loss domain. Keep its signing record and client
   credential. If the key was lost, enroll a new key through a certified
   handoff before restoring that validator. The command probes the authority's healthy
   high-water state before replay; after replay, every restored voting attempt
   is gated by that state. The authority itself atomically refuses a lower
   assigned round or different bytes at its high-water round. Local-key mode
   is refused. The authority must accept the pinned current epoch and key.
2. Supply empty BFT paths (`--execution-journal`, its `.trust` sibling, and
   `--luc-store`) and an empty local `--archive-store`. Start the pinned ureth
   client on a new execution datadir with the finalized genesis. Disable
   discovery and configure static EL peers only for the paired client's normal
   operation; the recovery data itself comes from the two archive replicas.
3. Independently obtain the current trust-base BodyID and the latest certified
   UC and technical record. Write the UC and TR as canonical CBOR files. Supply
   the genesis trust base to `--trust-base`. With profile 2 enabled, the node
   verifies each missed handoff and requires the final verified BodyID to match
   `--trust-body-id`.

   > **STOP.** `--trust-base` must be the trust base at the genesis root epoch.
   > A current (later-epoch) trust base cannot replace it: restore replays from
   > block 1 and needs the genesis-era trust and every missed handoff verified
   > forward from it. A restore with any other epoch is refused before anything
   > is built or written, with `restore trust anchor is not the genesis root
   > epoch`, naming both epochs. The current BodyID is still mandatory, in
   > `--trust-body-id`; it is a different input.
4. Run `ubft shard-node restore` with the same network, shard, genesis,
   `--full-shard-conf`, Engine API, and identity flags used by `shard-node run`,
   plus:

   ```text
   --executor engine-api --execution-journal NEW_JOURNAL \
   --archive-store NEW_ARCHIVE --archive-prune \
   --archive-replica PEER_1 --archive-replica PEER_2 \
   --signing-authority-socket SURVIVING_SOCKET --signing-authority-credential CREDENTIAL \
   --tip-uc TIP_UC_CBOR --tip-tr TIP_TR_CBOR --trust-body-id 0xBODY_ID
   ```

   Add `--trust-history-profile-2` for cross-epoch restore. Configure current
   root peers through `--bootstrap-address` and retain the two static archive
   replicas. The root peers and replicas are availability sources; their bundle
   bytes never become trust anchors.

The restorer fetches each e→e+1 bundle from current roots, previous roots,
then archive replicas. It verifies each proof and full snapshot under epoch e
from its local trust history, installs the successor, and compares the final
BodyID with the operator pin. Archive replicas store bundles by deployment
context and successor epoch; the publisher pushes each installed bundle to
both replicas and reads it back.

The restorer checks the pinned certificate and trust base before replay. For
a quiet tip it asks each replica for the latest certified record at or below
the tip's shard round, then requires that record's resulting state hash equal
the tip's state hash. For a block tip it fetches the exact certified block.
Every record is checked against the configured subject and its own UC epoch,
then replayed through paired seal import from genesis. The first EVM block at
each handoff carries the installed acknowledgement transition, even if it has
no user transactions. The final Engine head, state root,
certified journal candidate, and restore anchor must agree before the normal
readiness gate can release signing. A failed or hostile replica is bypassed per
record. The frontier resumes only after two replicas acknowledge later blocks. If a configured replica was replaced, follow the one-replica-at-a-time rule in `docs/operations/m2-runbook.md` §4 ("Replacing a configured archive replica"); replacing both or reordering the pair is refused with `frontier.ErrContext`.

The command refuses a copied BFT journal, a non-genesis or non-finalized fresh
EL head, a nonempty local archive, an incompatible archive/context/version,
wrong genesis or execution identity, a missing handoff, wrong epoch or forged
records, local-key signing, and an absent or unhealthy authority or pin. A failed restore may have imported blocks or
written journal state: restart from **new empty disks**. Generic EL P2P, snap,
and pipeline sync do not establish the paired seal history and cannot be used
as a restore source; the pinned client and Engine API checks remain mandatory.

## Sources lost or lying during a restore

The restore has two phases. The **fetch walk** goes from the pinned tip to genesis, authenticates each record against the configured
subject and its own epoch, and retains it in the new local archive. The **replay** then imports the local copies into the execution
client. Sources (the two replicas, and the roots for handoff bundles) are used only in the walk and, for a body that is still missing
afterwards, in the observation backfill. What the tests establish
(`archivewiring/restore_source_experiments_test.go`, in process, with the real server, framing and retry policy; no process lane):

| Source behaviour | Result | Test |
|---|---|---|
| One replica gone partway through the walk | the other replica serves the rest; the restore completes | `TestArchiveRestoreSurvivesLosingOneReplicaDuringTheFetchWalk` |
| Both replicas gone partway through the walk | after the bounded wait (`FetchRetry.Total`, 150 s by default) the restore ends with `ErrRestore` and `archive.ErrUnavailable`. Nothing reached the journal or the execution client: no restore pin, no observation, EL at genesis. With the sources back, the same restore completes | `TestArchiveRestoreLosingBothReplicasDuringTheFetchWalkEndsCleanlyAndResumes` |
| Both replicas gone once the replay has begun | the replay needs no source; the restore completes and opens no further stream | `TestArchiveRestoreReplayDoesNotNeedTheSources` |
| The replay itself fails partway (here the execution client refuses block 3) | not rolled back: the EL stays past genesis and no pin is recorded. A second restore on the same disks is refused before any fetch (`EL head must be the checked genesis`). Restart from new empty disks, as above | `TestArchiveRestoreFailedReplayIsNotResumedOnTheSameDisks` |
| A replica that accepts the stream and never answers | each exchange ends at `Limits.Deadline`; the other replica serves; with both silent the restore ends after the bounded wait | `TestArchiveRestoreBypassesAReplicaThatAcceptsAndNeverAnswers`, `TestArchiveRestoreEndsWhenBothReplicasAcceptAndNeverAnswer` |
| A replica asked for one block that answers with another block's genuine, correctly certified record | the answer does not echo the request (`ErrReplica`) and is bypassed; with every replica doing it the restore ends with `ErrRestore`, `ErrReplica` and keeps nothing | `TestArchiveRestoreBypassesAReplicaThatAnswersWithAnotherBlocksRecord`, `TestArchiveRestoreRefusesWhenEveryReplicaAnswersWithAnotherBlocksRecord` |

A record that is delivered and fails authentication is never retried (`TestArchiveRestoreVerificationFailureIsNotRetried`), and the pin
checks of the next section apply to whatever a source serves. These tests do not show a source process killed or lying during a live
restore on a devnet, and they use a fixture execution client, so the failed-replay row says nothing about what a real reth leaves on disk
beyond the instruction to start from empty disks.

## Incompatible stores: the refusal boundary

Fresh genesis removes migration development; it does not remove the silent-load refusal. The restore and the run commands read only
stores written by this version for this deployment, and refuse everything else by name. Nothing is migrated, imported or rewritten.

| Store | Incompatible when | Refusal | Evidence |
|---|---|---|---|
| BFT journal (`--execution-journal`, `.trust`, `.handoffs`) and the LUC checkpoint | any of these paths already exists at restore | `restore requires a fresh BFT data directory: <path> already exists` (a copied journal, the profile-2 siblings) | `cli/ubft/cmd/shard_node_restore_test.go` `TestRestoreCommandAcceptsProfile2AndRequiresFreshState` |
| Journal database, legacy or unknown bucket | the file was written by an older layout (legacy bucket) or holds an unknown bucket | `configuredprogress.ErrVersion`, at open | `configuredprogress/codec_test.go` `TestOpenIsolationAndMalformedState` |
| Journal database, origin | the journal is for another configured origin, or its version, origin or limits changed | `configuredprogress.ErrContext` | `configuredprogress/journal_test.go` `TestJournalRejectsCorruptForeignAndVersionedRecords` |
| Journal database, record | a record is damaged | `configuredprogress.ErrUntrusted` (envelope digest) | same test |
| Journal database, record version | a record carries another version | `configuredprogress.ErrContext` | same test |
| Journal database, descriptor | a legacy or other-version identity descriptor | `configuredprogress.ErrVersion` | `configuredprogress/m2_identity_test.go` `TestM2IdentityRefusesLegacyDescriptor`, `TestM2DescriptorVersionRefused` |
| Archive store, manifest | the manifest magic is not the one for the record's version | `archive.ErrCorrupt`; the file is not rewritten | `archive/archive_test.go` `TestManifestOfAnotherVersionIsRefusedNotMigrated` |
| Archive store, record | a nonempty slot that version 1 requires empty; a missing slot | `archive.ErrInvalid` when written, `archive.ErrUnavailable` when read | `archive/archive_test.go` `TestVersionOneAccountingSlotIsEmptyAndRequired` |
| Local archive directory | not empty at restore | `restore archive directory <dir> is not empty; supply a fresh directory` | code only (`cli/ubft/cmd/shard_node_run.go`, restore branch); no test reaches it |
| Legacy LUC checkpoint beside an execution journal (run) | the checkpoint file exists | `execution journal requires fresh D2 lane state: legacy LUC checkpoint exists at <path>; no automatic migration` | code only; no test reaches it |
| Execution client | its head or finalized block is not the checked genesis | `EL head must be the checked genesis on an empty disk` | `archivewiring/restore_source_experiments_test.go` `TestArchiveRestoreFailedReplayIsNotResumedOnTheSameDisks` |
| Archive replica pair | a configured replica was replaced and both or the order changed | `frontier.ErrContext` (the one-replica-at-a-time rule above) | `configuredprogress/journal_frontier_rotation_test.go` `TestMalformedReplicaPairChangeIsRefusedAtStartup` |

The boundary is therefore: **a store is either created by this version in this deployment or it is refused.** The supported way to meet a
refusal is a fresh authenticated restore on new empty disks. Out of scope: an interrupted upgrade (a process stopped between writing the journal and the archive, then started on a different binary)
and an old-format file store put through the command line. The owner's greenroom decision is fresh genesis and no migrations, so there is no
upgrade path to interrupt and no old-format store to import; both are met by the refusal and a fresh restore, as above. The two "code only"
rows are not exercised by a test; that is accepted for #21 (owner decision, relayed by the orchestrator, 2026-10-20).

## Freshness assumption

The replicas and root peers are availability sources, never trust anchors. A restoring node accepts
a history only if (1) every record's certificate verifies under the trust base of **its own epoch**,
derived forward from the genesis-epoch `--trust-base` through the verified handoffs, and (2) the
replayed head, state root and certified tip equal the pin the operator obtained independently:
the latest certified UC and technical record and the current `--trust-body-id`. A continuation that
is signed only by keys retired at a handoff, or that does not lead to the pinned tip, is refused
(`archivewiring/restore_retired_key_test.go`); the restore ends with `ErrRestore` after bypassing
the record, leaves no restore pin, and leaves the EL at its genesis head. The guarantee is only as
fresh as the pin: a pin taken from a stale replica or a stale tip restores a stale but genuine
history. The operator must therefore obtain the tip and BodyID from the current deployment (a quorum
of current roots or an independent operator record), not from the replica being restored from.

## H3 note

A deployment whose EVM assignment changes is no longer single-epoch for the shard configuration. The archive
namespace stays anchored to the immutable deployment identity (the genesis full configuration hash); a
record's own configuration travels with it (`certifiedstore` record v2, mint bundle v2) and the committed
handoff bundles carry the assignment candidates a restoring node needs to re-derive its configuration
history. Restore across a missed supersession history needs every consecutive bundle; an incomplete span is
a typed unavailable result. See [design/h3-evm-assignment.md](design/h3-evm-assignment.md).
