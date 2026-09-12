# The shard-node role, and how to implement it

This is for whoever writes the *next* `Executor` — the second adapter after `engineapi`, or the
third client after `aggregator-go`/`rugregator` decide to adopt this framework instead of their own
hand-rolled copy of the same protocol. `docs/shard-protocol.md` describes the wire protocol
normatively, independent of this repo's Go. This document is the Go side: the interface you
implement, what the framework guarantees you, and what it demands back.

## Contents

1. [What `shardnode/` is and isn't](#1-what-shardnode-is-and-isnt)
2. [The `Executor` interface](#2-the-executor-interface)
3. [What the framework guarantees](#3-what-the-framework-guarantees)
4. [What it demands from you](#4-what-it-demands-from-you)
5. [The conformance suite](#5-the-conformance-suite)
6. [Wiring it into `ubft shard-node run`](#6-wiring-it-into-ubft-shard-node-run)

---

## 1. What `shardnode/` is and isn't

`shardnode` is a reusable client for the shard-node *role*: anything that certifies state-root
transitions against the BFT Core root chain. It owns everything on the Unicity side of that
relationship — the libp2p connection to the root chain, UC classification, `InputRecord`
construction, the round state machine, crash recovery — and knows nothing about what a "block" is.
That is the entire point: `docs/adr/0001-executor-boundary.md` explains why, but the short version is
that every shard-specific concern (Ethereum, an accumulator, anything else) lives behind one
interface, `Executor`, so this package never has an opinion about it.

Two implementations exist today:

- `shardnode/executortest` — a deterministic in-memory `Fake`, for testing the framework itself. Its
  block is `H(parent ‖ number ‖ entries)`: no gas, no persistence, the entire point being that two
  independent `Fake` instances given the same inputs produce byte-identical output.
- `engineapi` — drives an Ethereum execution client (reth) over the standard Engine API. See
  `docs/engine-api-adapter.md` for that adapter specifically.

If you're building a third, this document — and the conformance suite in §5 — is what you implement
against. You should not need to read `shardnode`'s internals to do it.

## 2. The `Executor` interface

```go
type Executor interface {
    Head(ctx context.Context) (BlockRef, error)
    Commit(ctx context.Context, hash Hash) (Status, error)
    Build(ctx context.Context, p RoundParams) (BuildID, error)
    Seal(ctx context.Context, id BuildID) (Block, error)
    Verify(ctx context.Context, b Block, p RoundParams) (Status, error)
}
```

Five methods, defined in `shardnode/executor.go` with full doc comments — read that file alongside
this one, it is the source of truth. In outline:

- **`Head`** — what does this executor currently consider canonical? Called once per round.
- **`Build`** / **`Seal`** — leader only. `Build` starts a block on top of `p.Parent`; `Seal` finalizes
  it. Split into two calls because a real execution client's own API is (`engine_forkchoiceUpdated`
  to start, `engine_getPayload` to collect) — an executor with no such split can just do all the work
  in `Build` and have `Seal` be a lookup.
- **`Verify`** — every validator, leader included, runs this against the round's candidate block
  before submitting anything. `p` is the same `RoundParams` the leader had, so an executor can
  recompute what the block's parameters *should* be and catch a leader that lied, rather than only
  checking self-consistency.
- **`Commit`** — called once a Unicity Certificate has actually certified `hash`. This is also the
  crash-recovery primitive: see §4.

`RoundParams` is the one Unicity concept an `Executor` needs to understand — round number, epoch,
timestamp, the certificate's `SealHash` (for round-derived randomness, with your own domain-separation
prefix — never re-hash the certificate itself), the leader's node ID, and the parent `BlockRef`. Turning
that into concrete block parameters (an EVM header's `timestamp`/`prevRandao`/etc.) is your job, not
the framework's — see `engineapi/params.go`'s `DeriveAttributes` for a worked example.

`Status` mirrors the Ethereum Engine API's four payload outcomes (`Valid`, `Invalid`, `Syncing`,
`Accepted`) — not because the framework assumes an Ethereum executor, but because every execution
layer this framework is likely to wrap needs the same four states. If your executor's own model is
binary (valid/invalid), just never return `Syncing`/`Accepted` — the framework handles their absence
correctly.

## 3. What the framework guarantees

- **You will never be asked to un-commit a block.** The framework only calls `Commit` after a Unicity
  Certificate has certified that hash. There is no rollback path in this interface because there is
  never a reason for one — once the root chain has certified something, it is final.
- **`Build`/`Seal` only run on the round's leader.** `Verify` runs everywhere, leader included.
- **You get the same `RoundParams` twice for the same round** — once (implicitly) via `Build`'s `p`
  if you're leader, and again via `Verify`'s `p` for self-verification. They are byte-identical; you
  can rely on that to recompute-and-compare rather than trust-and-forward.
- **Quiet rounds are visible to you, not silently absorbed.** A round with nothing to certify still
  calls `Build`/`Verify` — with zero entries — so your `Head` after that round can correctly report
  "nothing changed" rather than a synthetic re-hash of the same state. See `docs/shard-protocol.md`
  §6 for why a value that merely *looks* different every round, even when nothing happened, would
  break the framework's ability to construct a correct `InputRecord`.

## 4. What it demands from you

- **`Build`/`Seal`/`Verify` must be deterministic.** Two honest executors given the same `RoundParams`
  and the same parent must produce byte-identical `Block.StateRoot`/`Hash` — this is the whole basis
  for quorum. `shardnode/determinism_test.go` (C2.4 in the build plan) is what exercises this at the
  framework level: it replays one UC stream through several in-process validators, rotating who
  leads, and checks every validator converges to identical committed state.
- **`BlockSize`/`StateSize` must be derived from the block's own content, never something ambient**
  (wall-clock timing, local buffer sizes). The root chain hashes both into its quorum key alongside
  the `InputRecord` — two validators reporting different sizes for byte-identical state is exactly as
  fatal to quorum as disagreeing on the state root itself.
- **`Commit` must be idempotent and callable speculatively — not assumed to always follow a
  `Build`/`Seal`/`Verify` triple from the same process lifetime.** This is the one place the framework
  calls `Commit` with no local memory of ever having produced that block: a restarted node's
  in-memory round state doesn't survive the restart, but a real executor's on-disk data (reth writes
  a block to disk the moment `newPayload` succeeds, before any `forkchoiceUpdate` makes it canonical)
  may still have it. `round.go`'s `reconcile` retries `Commit` directly against the root-chain-certified
  hash before giving up — see `docs/adr/0001-executor-boundary.md` decision 2 for the full account,
  including what this recovery mechanism does *not* cover (the executor itself losing the block —
  disk loss, a different machine).
- **No method may block indefinitely without honoring `ctx` cancellation.** The round loop enforces
  T2-derived deadlines through it.

## 5. The conformance suite

`shardnode/executortest/conformance.go` is a reusable test suite every `Executor` implementation
should pass — not a suggestion, the actual gate. It drives an executor through genesis, a build/seal/
verify/commit cycle, a quiet round, and a rejected-block case, checking the invariants in §3 and §4
directly rather than via the full round machinery. Run it against your implementation the same way
`shardnode/executortest`'s own tests do, and again the same way `engineapi`'s tests do against a mock
Engine API server.

Passing the conformance suite does not, on its own, prove your executor works against a live root
chain — that needs the C1/C2 live gates `docs/engine-api-adapter-plan.md` §7 describes. It does mean
the framework will not misbehave because of something structurally wrong in how your executor reports
status or state.

## 6. Wiring it into `ubft shard-node run`

`cli/ubft/cmd/shard_node_run.go`'s `buildExecutor` is the dispatch point — `--executor <name>`
selects which `Executor` gets constructed. Adding a third means adding a case there (and whatever
flags your executor needs, following `engineapi`'s `--engine-url`/`--eth-url`/`--jwt-secret` as the
pattern for adapter-specific configuration living in the CLI layer, not in `shardnode` itself).

If your executor benefits from its own preflight checks (the way `engineapi` does — see
`docs/engine-api-adapter-plan.md` §8's "What `doctor` checks"), contribute them to
`cli/ubft/cmd/shard_node_doctor.go`'s `adapterChecks`, gated on `--executor <your name>`. That split
between framework checks (always run) and adapter checks (contributed) is itself a test of the
boundary: if a check cannot be assigned to one side or the other cleanly, something about the
interface is wrong.
