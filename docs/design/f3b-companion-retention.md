# F3 (#11): companion retention and serving

Issue: #11. Base: `integration/enshrined-evm` at `9b5d0e1c` (the #205 merge).
Companion repository: [`ristik/ureth`](https://github.com/ristik/ureth) at `bdf2504f` (the #22 merge).

This is a delivery plan, not a design. The design is accepted and is
`d2-reth-system-call-fee-profile.md` §2 "Companion retention on sync". Nothing here reopens it.
What this adds is the split into reviewable units, in the way `f3-engine-seal-delivery.md` split the
three Engine API siblings into U3a to U3g.

## 1. The gap this closes

`f3-acceptance-ledger.md` §2.2 records the state plainly:

> **Companion persistence and transport: not met.** `getPayloadWithSealV1` returns a companion, but
> nothing persists one and nothing transports one between nodes. D2 §"Companion retention on sync"
> requires retention against a published horizon and archival serving for historical import and
> proof export. No unit delivered either, and no unit claimed to.

That is the only remaining line of #11's work breakdown with no delivery at all. Everything else
outstanding in the ledger needs a running paired deployment and belongs to M1's gate under #41.
Retention does not: it is a store, a policy and a read method, and all three are testable in
`ureth`'s own test suite.

D2 states the obligation in three parts:

1. a full node **retains every companion it has certified, indefinitely**, next to the block/UC
   association (D6 §"proof export");
2. a pruned node **publishes its retention horizon** and **serves `unavailable` past it**;
3. a block whose companion cannot be produced on request **is not re-servable** and cannot be used
   as a historical proof subject, but this **does not un-certify it**.

Part 3 is a consequence, not an implementation obligation, and it constrains the units only in that
a missing companion must never be reported as a defect in the block.

## 2. Scope

**In scope**: the durable store, the retention policy and horizon, and the read surface on the node
that holds the companion.

**Out of scope, named so the plan is not read as claiming them:**

| Not delivered here | Where it belongs |
| --- | --- |
| the `sealCompanion` field on bft-core's `ProposalEnvelope` | activation of the seal path, #10. bft-core does not call the seal methods at all today, so the field would be inert on arrival |
| devp2p import populating the execution-input registry | U3j below, which is named but not scoped; it depends on the transport above |
| the peer-facing archival proof service keyed by `(network, partition, shard, blockHash)` | F7, #15, which is blocked on F6 and whose prerequisite slice (`f7-parent-registry-witness-archive.md`, which is headed "Proposed design only" and is **not** acceptance of F7) explicitly excludes canonical root-input companions |
| any Measured evidence from a running client | M1, #41 |

So this plan closes §2.2's **persistence** half and the **serving** half that lives on the node
itself. It does not close §3.2 ("a syncing node obtains and verifies companion data"), whose
*obtain* half needs the transport and whose *verify* half is settled as the shard node's
responsibility, not the execution client's (`f3-engine-seal-delivery.md` §4).

## 3. Three decisions the units inherit

### 3.1 The store is the fork's own, not a reth table

No F3 unit has edited an upstream file **to add Unicity behaviour**: every Engine API sibling, the
bounded kernel and the node wiring live entirely under `crates/unicity`. That is the property a
companion table in `reth-db`'s `tables!` registry would break, and it would additionally put fork
data inside the environment reth's own consistency checks and migrations manage.

The narrower wording matters, because upstream files *have* been edited. An earlier draft of this
section claimed none had, which contradicts the repository's own `UNICITY.md` inventory. They fall
into three kinds:

- **Lint-baseline repairs**: twelve upstream Rust files, all from `2315f0e3a fix(ci): repair
  baseline checks` (ureth #9). The entire diff is comment rewrapping to the nightly width, one
  redundant `clone()` in `crates/trie/sparse/src/arena/mod.rs`, and one rustdoc link in
  `crates/net/network/src/config.rs`. None of it mentions Unicity.
- **CI configuration**: `.github/workflows/lint.yml`, whose complete history since the fork point
  is four commits: the wasm and RISC-V target removals and the toolchain pin from ureth #9, and the
  `deny` reusable-workflow pin from ureth #13.
- **Manifests and one build exclusion**, which exist to make the Unicity crates visible at all:
  three workspace member lines and two local dependency entries in `Cargo.toml`, the matching
  `Cargo.lock` entries, and one line in `.github/scripts/check_wasm.sh`.

That last line deserves naming rather than filing under "CI repair", because it is the closest thing
to a counterexample to the claim above. It came from `72444b39e` (ureth #8, branch
`f3/payload-execution`) — a **feature** unit, not a CI one — and the line it adds names a Unicity
crate: `reth-unicity-payload` is excluded from the wasm check because it wraps the native
transaction pool. A build exclusion is not behaviour, so the claim holds; but it is the one upstream
edit an F3 feature unit made, and it should be visible rather than absorbed into a list of repairs.

It is also now dead, and by a sharper route than it first appears. The exclusion was added by
ureth #8 and rendered unreachable by `ad1b4b76f ci: drop the wasm target` in ureth #9 — the very
next CI pull request, and the same one that made the twelve lint-baseline repairs. It was
load-bearing for exactly one pull request. Nothing under `.github/` references `check_wasm.sh` any
more, so both the script and its Unicity exclusion are dead. Removing them is not this plan's
business, but a later fork-delta cleanup should.

The store is therefore a **separate MDBX environment** under the datadir, opened and owned by a new
`crates/unicity/store` crate. `reth-libmdbx` is already a workspace dependency, and `tables!` is
`#[macro_export]`ed if the implementation prefers to reuse reth's table machinery against its own
environment. Either route is acceptable; editing an upstream file to register a table is not.

A file-per-companion layout was considered and rejected: "retains indefinitely" on a live chain
makes the directory unbounded in entry count, and the pruning path would then be a directory walk.

### 3.2 What "certified" means on the execution side

D2 says a node retains every companion **it has certified**. Certification is a bft-core notion: it
is the unicity certificate over the round, and the execution client never sees one. Read literally
against an execution client the phrase has no referent, so the units need a rule that is faithful to
its intent without inventing a verdict the client cannot reach.

The intent is that a node retains the companions of blocks **in its own chain**, because those are
the blocks it can be asked to re-serve. So:

- **Write on both seal paths.** `newPayloadWithSealV1` receives a companion and validates the block
  against it; `getPayloadWithSealV1` produces one. Both write, keyed by block hash. Writing only on
  import would lose the leader's own companions: the leader's path through `engineapi/adapter.go` is
  `Build` (`forkchoiceUpdated`), `Seal` (`getPayload`) and `Commit` (`forkchoiceUpdated`), and only a
  follower's `Verify` calls `newPayload`. The leader never imports the block it built.
- **Canonicality decides retention, at prune time, not at write time.** A write is cheap and the
  block's fate is not yet known when it happens. Pruning removes an entry whose block hash is not
  the canonical block at its number, once that number is deeper than the node's reorg window, and
  removes any entry below the horizon.

This is one pruning rule rather than a provisional/retained state machine, and it reaches the same
end state. It means a node briefly holds companions for blocks that lost a reorg, which is correct:
until the reorg resolves, either could be the one it is asked to serve.

### 3.3 `unavailable` and `unknown` are different answers

D2 requires a pruned node to "serve `unavailable` past" its horizon. A lookup therefore has three
outcomes, not two, and conflating the last two would be a real loss of information:

| Outcome | Meaning |
| --- | --- |
| **found** | the companion, byte-identical to what was stored |
| **unavailable** | this node cannot produce the companion **and** has published a retention horizon. The horizon accompanies the answer, and it is the node's retention boundary, not a claim about the queried block's number |
| **unknown** | this node has no record of the block hash and has never published a horizon |

Neither is a statement about the block's validity or certification, per D2 part 3.

The boundary between the last two is **deliberately lossy**, and stating it precisely here is the
point of this section. A store that kept a tombstone per pruned hash could distinguish them, but
that tombstone set is exactly the unbounded set pruning exists to drop. Without tombstones, once a
horizon is published an absent hash cannot be told apart from a pruned one, so it answers
**unavailable**; **unknown** is reachable only on a node that has never pruned. A caller therefore
cannot infer from **unavailable** that the block is below the horizon.

A full node's horizon is unset, and it therefore never answers **unavailable**.

## 4. The units

Each unit is one `ureth` pull request.

| Unit | Scope |
| --- | --- |
| **U3h** | the store: a `crates/unicity/store` crate holding a durable, block-hash-keyed companion store with the three-outcome lookup of §3.3, a settable horizon, and pruning. No node wiring, no RPC, no reth component. Testable end to end on its own, including reopen-after-write. Delivered as [`ureth` #22](https://github.com/ristik/ureth/pull/22) |
| **U3i** | the wiring and the read surface: write on both seal paths, prune under the policy of §3.2, publish the horizon, and expose the lookup as a `unicity_` namespace method on the standard RPC. This is the unit that makes retention observable |
| **U3j** | *named, not scoped here.* devp2p import re-deriving the verified inputs and populating the execution-input registry, which is §3.2's *obtain* half. It needs the transport that §2 places under #10, and it should not start before that exists |

### 4.1 U3h in detail

A new crate, depending on `reth-unicity-execution` for `SealCompanion` and on `reth-libmdbx`.

Required behaviour:

- `put(block_hash, block_number, companion)` is durable on return: a reopen of the store in a fresh
  process observes it. Durability is the store's own `sync`, not the caller's.
- `get(block_hash)` returns the three-outcome result of §3.3. A **found** result is byte-identical
  to what was stored, which means the encoding is fixed and round-trips exactly. The natural choice
  is the same canonical CBOR codec U3a fixed for `RootInputV2`, extended over the companion's
  `witnesses` and `provenance`; whatever the implementation picks, a round-trip test is required in
  both directions, as U3a's was.
- `set_horizon(number)` and `horizon()`. The horizon is durable and monotonic: it never moves
  backwards, because a node that has pruned cannot un-prune and must not advertise otherwise.
- `prune_below(number)` removes every entry with `block_number < number` and raises the horizon to
  `number`, in that order, so a crash between the two leaves entries present below an unraised
  horizon rather than a horizon covering entries already gone. State the ordering in the code, not
  only here.
- `remove(block_hash)` for the non-canonical case of §3.2. It is a separate operation from pruning
  and does not touch the horizon.

Required tests, at minimum:

- a companion written, the store dropped and reopened, and the companion read back byte-identically;
- a full node (no horizon) answers **unknown** for an unseen hash and never **unavailable**;
- after `prune_below`, a pruned block answers **unavailable** carrying the horizon, and a retained
  block still answers **found**;
- the horizon refuses to move backwards;
- `remove` does not change what a later `get` reports for any other key. The removed key then reports
  whatever any absent hash reports under §3.3: **unknown** on a store with no horizon, and
  **unavailable** once one exists. Both cases are worth a test, because the second is the one a
  reader expecting "removed means unknown" would get wrong.

Explicitly not in U3h: any reth type beyond `SealCompanion`, any provider, any notion of
canonicality. The crate is told what to store and what to drop.

### 4.2 U3i in detail

Wiring, so the interesting failures are of reach, not of logic.

- `getPayloadWithSealV1` writes the companion it returns; `newPayloadWithSealV1` writes the companion
  it accepted, **only** when it returns `VALID`. An `INVALID` import must not leave a companion
  behind for a block the node rejected.
- A store write that fails must not change the RPC verdict. A block is valid or not on its own
  terms, and D2 part 3 says an unproducible companion does not un-certify a block. The failure is
  logged and surfaced through the horizon, never through `PayloadStatus`.
- Pruning runs under the policy of §3.2 against the node's canonical chain.
- Configuration: one flag for the retention horizon, defaulting to **retain indefinitely**, which is
  D2's full-node behaviour. A pruned node opts in.
- `unicity_getSealCompanionV1(blockHash)` and `unicity_sealCompanionHorizonV1()` on the standard RPC
  namespace, not the `engine` namespace: the consumers are proof export and an operator, not a
  consensus client over the JWT channel. The `engine_*WithSealV1` surface is unchanged, and so is
  the capability list, which matters because U3g fixed it and bft-core #205 requires the three
  together.

Required tests, at minimum:

- a built payload's companion is retrievable by block hash after `getPayloadWithSealV1`;
- an accepted import's companion is retrievable after `newPayloadWithSealV1`;
- a rejected import leaves no entry;
- a store failure on the write path does not change a `VALID` verdict;
- the RPC reports **unavailable** with the horizon for a pruned block and **unknown** for a hash the
  node never saw.

## 5. Evidence this plan can produce

Following the classes in `f2-execution-prerequisites.md` §0: U3h and U3i together take companion
retention from nothing to **API** — "implemented and tested callable code, with no production call
site".

**Not Wired**, and the distinction is the whole job of this section. f2 §0 defines **Wired** as "a
running shard-node path calls the code", and nothing will call these two units on delivery. §2 puts
the `ProposalEnvelope` field out of scope precisely because bft-core does not call the seal methods
at all today, and §4.2's read surface sits on a `unicity_` namespace whose consumers are proof
export and an operator, not a shard round.

`f3-engine-seal-delivery.md` §7 records that U3a to U3f are API and that U3g is the first unit able
to claim Wired, and only for the paths the bft-core adapter actually drives. U3h and U3i do not
change that, and companion retention becomes Wired only when #10 activates the seal path.

**Measured** remains M1's under #41, as it does for every other F3 unit.

An earlier draft of this section claimed **Wired** and then described API in the same sentence —
"exercised through the node's own paths in its own test suite, with no running paired deployment",
which is the definition of API and concedes the absence Wired requires. It also credited the classes
to `f3-acceptance-ledger.md`, which does not define them and never uses the word Wired. Recording
the error rather than deleting it, because a section whose only job is to state what evidence exists
is the worst place in the document to overclaim, and because U3i's brief inherits this paragraph.

## 6. What still will not close #11

After U3h and U3i, #11's outstanding items are: the transport and the devp2p obtain half (§2, U3j),
real-reth runs of anything, and #10's activation of the seal path. The ledger's §4 conclusion stands
and this plan does not propose closing the ticket.
