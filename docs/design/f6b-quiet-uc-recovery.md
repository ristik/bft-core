# F6b stage 2: recovery state machine and authenticated execution anchor

Issue: [#92](https://github.com/ristik/bft-core/issues/92). Parent F6 ([#14](https://github.com/ristik/bft-core/issues/14));
related F2 ([#10](https://github.com/ristik/bft-core/issues/10)), harness [#88](https://github.com/ristik/bft-core/issues/88),
investigation [#16](https://github.com/ristik/bft-core/issues/16).

Stage 1 ([#94](https://github.com/ristik/bft-core/pull/94), merged `9e8e2cc8`) reproduced the defect:
a node behind a state-changing certified block, receiving a **quiet** certificate, asks its executor
to commit an **empty** hash, because `Round.reconcile` takes its target from
`uc.InputRecord.BlockHash` and a quiet certificate carries nil there by construction.

This is the design record required before any runtime change. **No behaviour is changed by this PR.**

## 1. A measurement that changes the design

The recovery path's stated premise, in `round.go` and in ADR 0001, is that

> reth writes a block to disk the moment `newPayload` succeeds, before any `forkchoiceUpdate` makes
> it canonical

**That is false for the pinned client.** `scripts/reth-payload-retention.sh` tests it directly
against reth `189c0df32617afc488e0f091dbface1bd72cceb4`, with no Unicity code involved:

| Observation | Result |
| --- | --- |
| `newPayload` a block, never `forkchoiceUpdated` | `VALID`, head stays at the parent |
| `eth_getBlockByHash` for it, **before** any restart | returns nothing |
| `forkchoiceUpdated` to it, **before** any restart | **`VALID`** — it becomes canonical |
| Restart with the same datadir, then `eth_getBlockByHash` | **gone** |
| `forkchoiceUpdated` to it after the restart | **`SYNCING`** |

So an accepted-but-never-finalised payload is **live-process state, not durable state**. The
canonical head persists across the restart; the un-finalised block does not.

Two consequences for this ticket:

- **The in-process case is genuinely recoverable.** Executor alive, framework lost its in-memory
  pending record: `forkchoiceUpdated` to the certified hash still succeeds. This is what
  `TestRound_CrashAfterSubmitBeforeUC_...` models, and it is real.
- **The cross-restart case is not**, in the way stage 3 assumed. After a shard-node process restart
  the payload is not sitting in the executor waiting to be finalised — reth answers `SYNCING`,
  meaning *acquire it*, not *it is invalid*. "Retained-local-payload recovery" therefore covers a
  narrower scope than the ticket's phrasing suggests, and missing-payload acquisition (#92 stage 4)
  is on the critical path for restarts rather than an optional companion.

This is measured against default persistence settings on this pin. A different configuration might
retain more; the point is that it must be **verified**, not assumed, and today it is not retained.

## 2. Five distinct things the code currently conflates

| # | Concept | Where it lives now | Survives a shard-node restart? | Reconstructible? |
| --- | --- | --- | --- | --- |
| 1 | **Latest authenticated UC/TR observation** | `BFTClient.luc` (in memory), seeded from the checkpoint | Yes, via `FileStore` | From the root chain, by re-handshaking |
| 2 | **Retained authenticated execution anchor** — the certified *block hash* for the latest non-quiet certified round | **does not exist** | — | Only from a certificate that carries it, i.e. a non-quiet UC |
| 3 | **Locally validated payload** — a block the executor accepted but never finalised | reth, in process | **No** (§1) | Only by re-acquiring it |
| 4 | **Applied executor head** | reth's canonical head | Yes | — |
| 5 | **Durable checkpoint** | `shard-node-luc.json`, one latest UC | Yes | — |

The defect is entirely explained by #2 being absent. The framework has #1 and #5, both of which hold
the *latest* certificate — which is quiet, and therefore carries no block hash — and it has no memory
of the last certificate that did.

## 3. What an anchor is, and how it is authenticated

An **execution anchor** is `(blockHash, stateRoot, partitionRound, rootRound, epoch, shardConfHash)`
taken from a certificate this node itself verified, for the latest round whose `InputRecord.BlockHash`
is non-nil.

Rules, each of which exists because its opposite is unsafe:

- **Only from a UC that passed `UC.Verify`** against the trust base for its root epoch, for this
  node's partition and shard. Never from a peer's claim, and never from the checkpoint's own
  assertion about its epoch.
- **Never selected by state-root equality.** A state root does not uniquely identify an execution
  block: two blocks can produce the same post-state. The anchor is a *block hash*, and the state root
  is only a cross-check after application.
- **Bound to context.** An anchor is usable only while `partitionID`, `shardID`, epoch and
  `shardConfHash` match the running configuration. On any mismatch the node refuses to resume rather
  than approximating cross-epoch verification (#92 item 6).
- **The quiet interval is spanned by carrying the anchor forward**, not by searching history. Each
  quiet certificate extends the anchor's validity; it does not replace it. No historical scan of the
  certificate chain is required, so there is no unbounded search to bound.
- **Ambiguity fails closed.** If the retained anchor does not match the certified `PreviousHash` the
  node is being asked to build on, it is not the right anchor and must not be applied.

## 4. Transition table

`certifiedPrev` is `exp.PreviousHash`, the state the next round must build on. "Abstain" means: do
not build, do not submit, retain evidence, and remain recoverable.

| State | Incoming certificate | Anchor | Executor | Action | Vote? |
| --- | --- | --- | --- | --- | --- |
| head == certifiedPrev | any | — | — | build normally | yes |
| head != certifiedPrev | **non-quiet** | from this UC | payload present (in-process) | `Commit(uc.BlockHash)`, require `VALID`, re-read head, require `head.StateRoot == certifiedPrev` | yes, after |
| head != certifiedPrev | **non-quiet** | from this UC | payload absent (`SYNCING`) | abstain; record `unavailable`, retry on later certificates | **no** |
| head != certifiedPrev | **quiet** | retained, matches `certifiedPrev` | payload present | `Commit(anchor.blockHash)` — the fix; same post-checks | yes, after |
| head != certifiedPrev | **quiet** | retained, matches | payload absent (`SYNCING`) | abstain; `unavailable`, retry | **no** |
| head != certifiedPrev | **quiet** | **none retained** | — | abstain; `no-anchor` — *today this is `Commit(nil)`* | **no** |
| head != certifiedPrev | quiet or non-quiet | retained, **does not match** `certifiedPrev` | — | abstain; `anchor-mismatch`, do not apply | **no** |
| any | any | anchor from a different epoch/config/shard | — | refuse to resume, explicit diagnostic | **no** |
| head != certifiedPrev | **repeat** UC | as for the round it repeats | — | as above; a repeat carries the same IR, so it neither adds nor invalidates an anchor | per row |
| head != certifiedPrev | round gap (non-consecutive) | retained | — | abstain unless the anchor matches `certifiedPrev` exactly; a gap is not licence to accept an arbitrary head | **no** |

Explicitly forbidden in every row: `Commit(nil)`, substituting a state root for a block hash,
downgrading validation, and clearing stored authority to get past a failure.

**Unavailable is not invalid.** `SYNCING` means the executor does not have the payload; `INVALID`
means it rejected it. The first is retryable and expected after a restart (§1); the second is a
fault. They must not share a diagnostic.

## 5. Retry, duplicate suppression and the observation cursor

`BFTClient.handleCertificationResponse` advances `c.luc = &cr.UC` **before** calling
`driver.HandleCertificate`, and returns early for `UCDuplicate`. Two consequences:

- A driver or store failure leaves the observation cursor **ahead of** what was actually applied and
  durably recorded. `Submit` selects root nodes from that cursor, so the two must not be conflated.
- A retransmission of the same certificate after a failed apply is classified `UCDuplicate` and
  dropped, so **the failure is never retried** by that route.

The minimal contract for stage 3:

1. Keep **observed** (cursor for `Submit` and non-equivocation) separate from **applied** (executor
   head reconciled) and **durable** (checkpoint written). Advance each only on its own success.
2. Never mark applied or durable before application succeeds.
3. Duplicate suppression must not swallow a retry when the previous attempt failed to apply: a
   certificate that is a duplicate *of the observation* but whose round was never applied is a
   retry opportunity, not a no-op.
4. Retry must be idempotent: `Commit` on an already-canonical hash is a no-op returning `VALID`, so
   repeating it is safe.

## 6. Persistence ordering and migration

Adding the anchor to the checkpoint is a **format change**, and #14 owns the durability contract.
The minimal shape: extend the existing versioned CBOR envelope (issue #86) with an optional anchor
field, bump the format version, and reject an unknown version as today. Ordering: the anchor is only
written together with the certificate that established it, so a torn write cannot produce an anchor
that no certificate supports.

`FileStore` writes to a temp file and renames. **A rename is not an fsync**: this covers a process
restart, not power loss. That distinction stays with #14 and is not claimed here.

## 7. Fixture plan for stage 3

Positive:

1. Non-quiet UC, payload present in-process → recovers, head equals certified state.
2. Quiet UC after a missed non-quiet round, anchor retained, payload present → recovers via the
   anchor. **This is the case that fails today.**
3. Several consecutive quiet UCs → the anchor is carried forward unchanged and still recovers.
4. Repeat UC over a missed round → same outcome as the round it repeats.
5. Retry after a failed apply → the second attempt is not suppressed as a duplicate and succeeds.
6. `Commit` on an already-canonical hash → `VALID`, no duplicate effects.

Negative, each asserting **abstention plus a distinct diagnostic**, never a vote:

7. Quiet UC, no anchor retained → `no-anchor`; today's `Commit(nil)` must be gone.
8. Anchor present but not matching `certifiedPrev` → `anchor-mismatch`.
9. Payload absent (`SYNCING`) → `unavailable`, distinct from invalid, retryable.
10. Executor returns `INVALID` for the anchor → fault, not retried as unavailable.
11. Anchor from a different epoch / `shardConfHash` / shard → refuse to resume.
12. Unsigned or unverifiable certificate offered as an anchor source → rejected before use.
13. Process restart at each boundary: after apply before checkpoint, after checkpoint before
    observation advance, and between.

Real-client evidence, kept separate from the unit fixtures: an isolated `scripts/reth-chaos.sh`
follower-restart scenario showing positive work before and after, and agreement on certified target,
canonical block, state and receipts. Per §1 that scenario needs payload acquisition, so a clean
**fail-closed** result — abstain with `unavailable` — is the honest intermediate milestone, and
stage 3 should not be expected to make a restarted node self-heal without stage 4.

## 8. Scope held open

This record does not implement anything. It does not explain any particular real-reth scenario in
#88, does not claim #16's fake-executor stall shares this cause, and does not address power-loss
durability (#14) or the stale-certificate taxonomy (#93).
