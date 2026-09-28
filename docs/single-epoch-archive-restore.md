# Replace a shard validator with empty BFT and execution disks

This command restores a **single root epoch** of the paired Engine API shard.
The archive must contain every block from the configured genesis through the
pinned tip. Cross-epoch replay is deferred to profile-2 enablement. A tip at
genesis needs no archive replay; start a fresh node through the ordinary genesis
procedure instead.

1. Stop the old shard and keep its **existing external signing authority
   running**, outside the BFT and EL disk-loss domain. Keep its signing record
   and client credential. The command probes the authority's healthy
   high-water state before replay; after replay, every restored voting attempt
   is gated by that state. The authority itself atomically refuses a lower
   assigned round or different bytes at its high-water round. Local-key mode
   is refused. If the authority was lost, this flow is unavailable: a new key
   requires a later certified handoff.
2. Supply empty BFT paths (`--execution-journal`, its `.trust` sibling, and
   `--luc-store`) and an empty local `--archive-store`. Start the pinned ureth
   client on a new execution datadir with the finalized genesis. Disable
   discovery and configure static EL peers only for the paired client's normal
   operation; the recovery data itself comes from the two archive replicas.
3. Independently obtain the current trust-base BodyID and the latest certified
   UC and technical record. Write the UC and TR as canonical CBOR files. The
   trust base supplied to `--trust-base` must hash to `--trust-body-id`.
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

The restorer checks the pinned certificate and trust base before fetching. For
a quiet tip it asks each replica for the latest certified record at or below
the tip's shard round, then requires that record's resulting state hash equal
the tip's state hash. For a block tip it fetches the exact certified block.
Every record is checked against the configured subject and trust, then replayed
through paired seal import from genesis. The final Engine head, state root,
certified journal candidate, and restore anchor must agree before the normal
readiness gate can release signing. A failed or hostile replica is bypassed per
record. The frontier resumes only after two replicas acknowledge later blocks.

The command refuses a copied BFT journal, a non-genesis or non-finalized fresh
EL head, a nonempty local archive, an incompatible archive/context/version,
wrong genesis or execution identity, wrong epoch or forged records, profile 2,
local-key signing, and an absent or unhealthy authority or pin. A failed restore may have imported blocks or
written journal state: restart from **new empty disks**. Generic EL P2P, snap,
and pipeline sync do not establish the paired seal history and cannot be used
as a restore source; the pinned client and Engine API checks remain mandatory.
