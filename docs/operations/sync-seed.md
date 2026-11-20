# Sync from a seed (VT-11, bft-core#1151)

A new validator starts as a follower from a **public seed** and catches up from peers. No access to our servers is needed: the seed is untrusted data
that the importer verifies from two things it holds itself, the **pinned UTB genesis EntryID** and (optionally) its own shard configuration.
Any synced validator can export and serve a seed; we also publish snapshots (owner input 11).

## How a node syncs today, and what each piece trusts

| Component | How it syncs today | Trust anchor | Manual step or host dependency |
|---|---|---|---|
| Root chain (VR / Q3 roots) | A root with the genesis trust base and bootnodes recovers committed blocks from its peers; a joiner or lagging root takes the activation bundle of each epoch from root peers (`--install-handoff-epoch`, in-process switch) and its VR sources from a quorum of incumbents (#1202); retained records are public reads (`--records-public-reads`) | The genesis trust base (`--trust-base`) and, with UTB, the **pinned genesis EntryID**: every later trust base is a signed successor of the one before | Bootnodes. There is **no root-chain checkpoint start**: a root replays from genesis (cost grows with the chain) |
| Trust-base history (UTB) | `GetTrustBase` libp2p stream (`gettrustbase.Sync`): pages appended through the store's authenticated `Append`; offline `trust-base utb-export / utb-import / utb-verify` | The pinned genesis EntryID; each entry carries a quorum of its predecessor's members | A peer to ask, or a bundle file shipped by the release |
| EVM shard archive | Archive replicas (`--archive-replica`, `archivewiring`), `shard-node restore` replays verified records from the pinned tip; `--follow-source` runs a root-free follower | The **restore pin**: a tip UC and TR plus the trust BodyID, authenticated against the trust base of the UC's own root epoch (`rootinput.AuthenticateHistoricalObservationV2`). Archive records are availability data, never an authority | The pin was a manual, out-of-band step (`docs/operations/bootstrap-trust-pin.md`); lanes derived it from an incumbent's archive files (`scripts/h4-restore-pin`), which is not a trust decision. Restore requires the **signing authority** and refuses local keys (#1220 / `shard_node_run.go`): unchanged |
| ureth (reth state) | Driven by its shard node over the engine API from the archive and peers; reth's devp2p carries gossip. No snapshot import exists | The certified block: the checkpoint UC commits the header hash (`InputRecord.BlockHash`) and the state root (`InputRecord.Hash`) | None, but a long chain means a long replay. A reth snapshot is **not** in seed v1 |
| Aggregator | Its own MongoDB state; in UTB mode its trust bases come from the signed history | The pinned genesis EntryID | Not a validator component; not covered by the seed |

## What the seed is

A directory (any web server can serve it; `ubft seed serve` is the minimal read-only one):

| File | Content | Verified against |
|---|---|---|
| `utb-bundle.cbor` | the complete signed trust-base history, genesis to tip (the GetTrustBase bundle encoding) | the pinned genesis EntryID: `types.VerifyTrustBaseBundle` |
| `tip-uc.cbor`, `tip-tr.cbor` | the certified checkpoint of the shard: the restore pin's own canonical CBOR format | the UC's seal against the trust base of **its root epoch**, taken from the verified history; the TR against the UC's TR hash |
| `manifest.json` | format `unicity.seed.v1`; SHA-256 and size of every file; the network, tip, and checkpoint claims; the archive frontier (the shard node's certified tip, prune frontier, restore base, archived activation-bundle epochs); the exporter's execution head | every claim must equal what the verified bytes say |

The **seed's identity** is the SHA-256 of the exact manifest bytes, which commit to every file hash.

What is deliberately not in it: archive records and the execution state. The follower fetches and replays them from archive replicas and peers, each step
authenticated against the verified checkpoint, as `shard-node restore` does today. The manifest's frontier and execution head are informational: they say
how far the exporter was, and let status report progress.

## Verification (`seed fetch`, `seed import`)

1. Manifest shape (strict JSON, no unknown fields, bounded) and every file's size and SHA-256.
2. The history decodes (consecutive entries, linked by predecessor EntryID) and **verifies from the pinned genesis**; the manifest's genesis, tip epoch,
   tip EntryID and network id equal the history's.
3. `--min-epoch N` (optional floor) refuses a history that ends below N. The checkpoint's root epoch must exist in the history: a checkpoint newer than the
   history is a stale or truncated history and is refused.
4. The checkpoint UC and TR are canonical CBOR; the TR hash equals the UC's; the UC verifies against the trust base of its root epoch; with
   `--full-shard-conf` it must be of this node's partition and shard.
5. The manifest's partition, shard, rounds, block hash, state root and shard configuration hash equal the certificate's.

`seed fetch --from URL --from URL2 ...` takes the manifest from every source and **refuses when any two differ** (it prints each digest and its
sources). `--min-sources N` requires N agreeing sources; an unreachable source is reported, not counted as agreement. Files are downloaded under the
manifest's sizes and hash-checked, from any agreeing source. Redirects are refused.

What a seed cannot give: freshness. A valid seed is a point in the past; an attacker who serves an old but valid seed can only make the follower start
earlier, and the follower then catches up from peers that authenticate every later step. Use `--min-epoch`, several sources, or compare the checkpoint's
root round with a public RPC if staleness matters to you.

## Commands

```sh
# on a synced validator (root with --utb-genesis, shard node with its archive; the pin is yours from the release)
ubft seed export --root-rpc http://127.0.0.1:RPC --utb-genesis-id 0xPIN --archive /path/to/shard/archive \
  --shard-status http://127.0.0.1:SHARD_RPC --eth-rpc http://127.0.0.1:8545 --out ./seed
ubft seed serve  --dir ./seed --utb-genesis-id 0xPIN            # read-only; loopback by default; or give ./seed to any web server

# on the new validator
ubft seed fetch  --from https://a.example/seed --from https://b.example/seed --min-sources 2 --utb-genesis-id 0xPIN \
  --full-shard-conf full-shard-conf.json --out ./seed
ubft seed import --dir ./seed --home $UBFT_HOME --utb-genesis utb-genesis.cbor --utb-genesis-id 0xPIN \
  --root-utb-db root/root-utb-entries.db --shard-utb-db evm/shard-utb-entries.db --source https://a.example/seed
```

The root's `GET /api/v1/utb/bundle` (public, read-only, only with `--utb-genesis`) serves the history to `seed export`.
After import, restore the shard node from the seed's checkpoint with `--tip-uc seed/tip-uc.cbor --tip-tr seed/tip-tr.cbor --trust-body-id ...` (signing
authority, as always), start the root and the execution client, and follow `ubft validator status`:

```
catch-up: public head 1204, local head 1180, behind 24, rate 3.10 blocks/s (head 0.10/s), time to head: 8s
sources: public RPC https://rpc.example; seed 0x... (https://a.example/seed, https://b.example/seed)
seed: imported 2026-11-20T12:00:00Z, trust-base tip epoch 1, checkpoint root epoch 1 round 412, shard round 130
```

`--sample` (default 3 s) is the window over which the local and public heads are sampled for the rate; `--sample 0` skips the rate. The ETA is the gap over
the net closing rate: "caught up" within two blocks, "not closing" when the node is not gaining on the head.

Then join through `ubft validator apply` as usual.
