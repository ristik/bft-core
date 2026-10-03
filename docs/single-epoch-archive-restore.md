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
