# ADR 0001: The executor boundary

## Status

Accepted. Implemented in `shardnode/` (framework) as of this ADR's commit; `engineapi/` (the
reth-driving Executor) is planned, not yet built — see `docs/engine-api-adapter-plan.md`.

## Context

A shard node is a role: anything that certifies state-root transitions against the BFT Core root
chain. The role has one implementation today (the aggregator, in `aggregator-go`/`rugregator`, each
with its own hand-rolled copy of the root-chain protocol) and this project adds a second (an Engine
API adapter driving reth). Both need the same handshake/UC-feed/round machinery; they differ only in
what a "block" is and what its state root means.

That split has to live somewhere concrete: an `Executor` interface in `shardnode/`, implemented once
by a deterministic in-memory fake (`shardnode/executortest`, used to prove the framework with no
external process) and once by the Engine API adapter (`engineapi`, planned).

Three design questions had to be settled before either implementation could be written safely, and
review of the initial plan draft found real gaps in the first two.

## Decision 1: No Ethereum noun crosses the `Executor` interface

`shardnode/executor.go` is written in Unicity's vocabulary — `Hash`, `Block`, `BlockRef`, `RoundParams`,
`Status`. Nothing from the Engine API (payload, forkchoice, JWT) appears in it. Every
`ExecutionPayloadV3`, every `PayloadAttributesV3`, every JSON-RPC method name is confined to the
`engineapi` package.

This is not fastidiousness. Reorgs, ordered transactions, and gas metering are Ethereum-specific
assumptions that hold for `engineapi` but not for an accumulator-style executor (the aggregator's own
RSMT batches are order-independent sets, not ordered sequences — see the companion architecture
document's "the two execution layers are not symmetric"). Keeping those assumptions out of
`shardnode/round.go` is what makes a second, non-EVM `Executor` implementation additive later rather
than a rewrite. It is enforced by an import check in CI: `shardnode/` must never import `engineapi/`.

Consequence: `go.mod` keeps `github.com/ethereum/go-ethereum` as an *indirect* dependency (pulled in
by libp2p) rather than promoting it to direct. Engine API V3 types are hand-rolled in
`engineapi/types.go` against captured reth responses, not imported from go-ethereum's `beacon/engine`
package — a few hundred lines of structs is a smaller cost than pulling go-ethereum's dependency tree
into the root chain's build.

## Decision 2: `Commit` is idempotent and doubles as the recovery primitive

### The gap review found

The initial plan draft claimed durable-proposal handling could simply be dropped from the
aggregator-go port: "an executor that never commits an uncertified block has nothing to abandon."
Review correctly rejected this as unsafe. Tracing it against the actual implementation confirmed a
real bug, not just an overclaim:

`round.go` tracks what it last submitted — round number, block hash, whether a commit is owed — in an
in-memory field (`pendingSubmission`) on the `*Round` value. That field does not survive a process
restart. If the process crashes after submitting a certification request but before processing its
confirming UC, restart loses it. On restart, `commitPrevious` (which drives `Commit`) becomes a no-op
because it has nothing to act on — even though the root chain may have already certified that round
using the request sent just before the crash. The next `HandleCertificate` call then finds the
executor's own head diverging from what the certificate says is certified, with no path back except a
hard failure demanding manual intervention.

This is a real, reachable state, not a hypothetical: a single-validator shard's own request can be
certified before the requesting process even receives the confirmation, purely because BFT quorum for
one validator is met the instant the root chain processes the request.

### The fix, and why it's narrower than the alternative

Two designs were available. The fuller one — matching what review proposed and what aggregator-go's
own durable-proposal machinery does — persists the complete outbound candidate (round, block hash,
parent hash, both state roots, exact IR and size fields, the serialized proposal itself) before
sending the request, and adds explicit `Abort`/`Reconcile` operations to the `Executor` interface so a
restarted process can replay or discard it deliberately.

The narrower one, which is what's implemented: on divergence, retry `Commit` once, using the
certificate's own `InputRecord.BlockHash` field — a value the framework didn't need to remember,
because the certificate that just arrived already carries it. If the executor still holds that block
(reth's `newPayload` persists to disk *before* any `forkchoiceUpdate` makes a block canonical, so a
crash between submitting and certifying does not lose it), `Commit` succeeds and the round proceeds
exactly as if nothing happened. If the executor doesn't have it, `Commit` reports `Syncing` and the
framework fails loudly — the same "needs recovery" message as before, not a regression, just no longer
the *only* outcome.

```go
// shardnode/round.go, reconcile — the recovery path
blockHash := Hash(uc.InputRecord.BlockHash)  // NOT exp.PreviousHash (a state root) —
                                              // Commit is keyed by block hash everywhere
                                              // else in this file, and the certificate
                                              // that just arrived is the one place that
                                              // value survives a crash.
status, err := r.executor.Commit(ctx, blockHash)
```

Getting this right on the first attempt required two corrections, both caught by tracing the fix
against the actual `Fake` executor rather than reasoning abstractly:

1. **Key by block hash, not state root.** The first version retried `Commit` using
   `exp.PreviousHash` — the certified *state root* — because that's the value the divergence check
   itself compares against. But `Commit`'s contract (and every real implementation's internal
   bookkeeping, `Fake` included) keys committed blocks by *block hash*. A state root and a block hash
   are different values with different provenance; using the wrong one makes the lookup fail even when
   the executor genuinely has the block. `uc.InputRecord.BlockHash` is the correct key, and it's
   available precisely because the certificate that triggers reconciliation is the same certificate
   that would have supplied it to `pendingSubmission.hash` in the non-crash path.

2. **Quiet certificates have no block to recover.** `InputRecord.BlockHash` is nil by construction
   whenever a round was quiet (state didn't move — see `shardnode/inputrecord.go`'s `BuildInputRecord`).
   `Commit(ctx, nil)` correctly reports `Syncing` in that case, and reconciliation correctly fails: a
   quiet round has nothing to recover *because there was nothing built*, and if the executor's head is
   still wrong after that, the actual problem is that several rounds' worth of state were missed
   entirely — a genuine resync gap, not something a single retry can paper over.

This was proven, not asserted: `shardnode/round_recovery_test.go` reproduces exactly the scenario
review specified as an acceptance gate — build a round with real state-changing entries, discard the
`*Round` value without letting it process the confirming UC (modeling a crash), construct a *fresh*
`*Round` against the *same* `Executor` instance (modeling a restart where reth's data survived), and
feed it the confirming UC. It recovers via `Commit` with no error, never resubmits for the
already-certified round, and proceeds to the next round normally.

### Scope this does and does not cover

**Covered:** a same-host restart where the executor's own data survived — true of reth, whose block
store is durable independent of any BFT Core process.

**Not covered:** the executor itself losing the block — disk loss, pruning, a different machine
entirely. Recovering that would need the fuller persisted-candidate design review described. That is
deliberately deferred, not silently dropped: if C3's fault injection (see the build plan) surfaces a
concrete case the narrower mechanism doesn't handle, build the fuller one then, with a real failure
to design against rather than a hypothetical.

**Implication for every `Executor` implementation:** `Commit` must be idempotent and safe to call
speculatively — not assumed to always follow a `Build`/`Seal`/`Verify` triple from the same process
lifetime. This is now part of the interface's contract, documented on `Commit`'s doc comment in
`shardnode/executor.go`, not just here.

## Decision 3: `engineapi` pins an exact fork schedule and capability set

### The gap review found

A chain spec that activates "every fork at block 0" is not a stable target for a V3-only adapter.
`ExecutionPayloadV3`/`engine_newPayloadV3`/`engine_getPayloadV3` are valid for Cancun; Prague requires
`engine_newPayloadV4`/`engine_getPayloadV4` and adds `executionRequests`, and later forks add further
structures and method versions again. `engine_exchangeCapabilities` reports what a *client build*
supports, not what a *specific chain spec* has scheduled — a chain spec generated with every fork
active at genesis could schedule Prague to activate immediately even on a reth build that also speaks
V4, silently requiring calls this adapter never makes.

### The fix

- `engineapi/genesis` (the `ubft engine-api genesis` command) generates a chain spec with an explicit,
  named schedule: Shanghai and Cancun active at genesis (timestamp 0); Prague, Osaka, and later forks
  left unscheduled rather than also placed at 0.
- The adapter's startup path calls `engine_exchangeCapabilities` and requires the *exact* V3 method
  set — refusing to start if a required method is missing, and logging (not silently ignoring) any
  additional capability offered that this build doesn't use, since that's the signal a newer fork was
  scheduled than the adapter was built for.
- The reth release is pinned to an exact version in deployment tooling, not left to float — two builds
  disagreeing on an edge case is indistinguishable from a real state-transition bug until you already
  suspect a version mismatch.

### Upgrading past Cancun

When a later fork needs supporting, the upgrade is: hand-roll the new method set and payload version
(mirroring how V3 was built against captured responses in `engineapi/types.go`), extend the startup
capability check to require the new set, extend the chain-spec generator to schedule the new fork, and
re-run the golden-vector and conformance suites — the `Executor` interface itself does not change,
since it was already written above the Engine API's own versioning.

## Consequences

- `shardnode/` and `engineapi/` can be developed, tested, and reasoned about independently; the
  conformance suite in `shardnode/executortest` is the only contract between them.
- Recovery correctness depends on the executor's own durability guarantees, which must be documented
  per-implementation (this ADR does it for `engineapi`; a future aggregator `Executor` would need the
  equivalent statement for its own storage).
- Fork-schedule pinning means this adapter does not "just work" against an arbitrary reth chain spec —
  deployment tooling (`ubft engine-api genesis`, `doctor`) exists specifically because that failure
  mode is otherwise silent until a scheduled fork activates mid-operation.
