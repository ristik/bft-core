# Retention and installation of the signed trust-base entries (UTB PR4)

Continues `utb-vote-endorsement.md`. Enabled by `--utb-genesis`/`--utb-genesis-id` on the root (or `consensus.WithUTBStore`); without it nothing changes.

## Deployment

- `ubft trust-base utb-genesis --trust-base <genesis trust-base.json> --out utb-genesis.cbor` builds the genesis entry (the one builder, zero predecessor, no
  signatures) and prints its EntryID. A root is started with `--utb-genesis utb-genesis.cbor --utb-genesis-id 0x…`: the entry is authenticated by the pin
  alone. Profile 2 is required. The Q3 history of such a root has a UTB genesis epoch (`q3active.Config.UTBGenesis`), so the first handoff is endorsed too,
  and every activation must carry the UTB tuple (the envelope is one choice for the whole chain: `q3format.WithV3` refuses a change).
- `utbstore` (default `<home>/root-utb-entries.db`) is the permanent store of finalized entries; `Open` re-verifies the whole stored chain from the pin.

## Retention with the commit

`BlockStore.ProcessQc` makes the endorsed entry of a committing certificate durable **before** the certificate is inserted, committed or published
(`UTBRetention`, backed by `utbstore.Append`: strict decode, member limit, `VerifySuccessor` from the stored predecessor, atomic write). A failure leaves the
certificate unapplied (`ErrUTBRetention`), and a retry is not mistaken for a stale certificate. Replays (restart, recovery) and the later certificates of the
same epoch carry the same unsigned entry and are idempotent; a different valid witness is accepted and the first stored one kept. A certificate that commits
a round below the committed root (recovery replays one) is neither bound nor retained: the entry was retained when that round committed, and the commit
refuses it as before. The finalized tip is separate from the locally activated epoch: `utbstore` knows only the former.

## Installers

When the old epoch is a UTB epoch, `InstallEpochBundle` (V2) and `InstallVerifiedEpoch` (Q3) call `retainInstalledUTB` before anything is installed: the
verified old commit proof must carry the old committee's endorsement of exactly the entry the installed epoch implies (the verified body's or history
entry's facts with the record's actual activation round, linked to the store's finalized entry of the old epoch), and that entry is appended to the store.
No store configured (`ErrUTBStoreMissing`), no endorsement or another entry (`ErrUTBMismatch`), or a proof the old committee did not endorse
(`handoff.ErrProof`) refuses the install with nothing installed or retained. The Q3 install now also passes the new epoch's UTB flag to the trust-base store
(`InstallVerified` compares the whole signing configuration with the history's).

## Historical proofs and carriage

Every verifier of an old commit proof (the installers, the shard follower, the closure, the Q3 history) goes through
`handoff.VerifyOldCommitProofSigning`, which now applies the old epoch's envelope rule, verifies the certificate's endorsement strictly, and in a UTB epoch
refuses a committing certificate without one. The endorsement travels in the commit certificate the bundle, the Q3 link and the closure witness already carry,
so no new field is needed. A receiver therefore rebuilds the same entry from the verified body and its own finalized predecessor, as above. Shard-side
retention and the range/UCResp distribution of the entries are PR5/PR6.

## Not here

Shard nodes do not keep an entry store yet; the SDK/aggregator-facing distribution (UCResp attachment, GetTrustBase) and the export are PR5/PR6. The V2
installer is tested through the check it calls (`retainInstalledUTB` with the bundle fixture), because `InstallEpochBundle` needs a profile 2 recovery history.
