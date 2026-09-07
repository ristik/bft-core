# F6b stage 2: recovery state machine and authenticated execution anchor

Issue: [#92](https://github.com/ristik/bft-core/issues/92). Parent F6 ([#14](https://github.com/ristik/bft-core/issues/14));
related F2 ([#10](https://github.com/ristik/bft-core/issues/10)), harness [#88](https://github.com/ristik/bft-core/issues/88),
investigation [#16](https://github.com/ristik/bft-core/issues/16).

Stage 1 ([#94](https://github.com/ristik/bft-core/pull/94), merged `9e8e2cc8`) reproduced the defect:
a node behind a state-changing certified block, receiving a **quiet** certificate, asks its executor
to commit an **empty** hash, because `Round.reconcile` takes its target from
`uc.InputRecord.BlockHash` and a quiet certificate carries nil there by construction.

This is the design record required before any runtime change. **No behaviour is changed by this PR.**

## 1. What was measured, and exactly what it means

`scripts/reth-payload-retention.sh` tests payload availability against reth
`189c0df32617afc488e0f091dbface1bd72cceb4` with no Unicity code involved. Two blocks are used and
they are **not interchangeable**:

- **B1** — built, accepted by `newPayload`, then explicitly finalised **in-process**.
- **B2** — built, accepted by `newPayload`, **never made canonical**, then the execution client is
  restarted on the same datadir.

| Observation | Result |
| --- | --- |
| B1: `forkchoiceUpdated` while the client lives | **`VALID`** — becomes canonical |
| B2: `forkchoiceUpdated` after the **execution-client** restart | **`SYNCING`** |
| The finalised canonical parent after that restart, asserted by hash | intact |
| `eth_getBlockByHash` for a non-canonical block, before *or* after restart | `null` |

**Exact conclusion: after an execution-client restart, a payload that was accepted but never made
canonical is unavailable for immediate forkchoice.** `SYNCING` reports incomplete
validation/availability — it is not proof the payload is invalid, and not a disk-state diagnosis.
`eth_getBlockByHash` does not expose a non-canonical block even before a restart, so it cannot
independently show the bytes are gone.

An earlier revision of this section generalised that to "a shard-node restart loses the payload".
**That does not follow, and is withdrawn.** The script restarts the execution client; no shard node
takes part in it.

### 1.1 Restart matrix

| Scenario | Shard process | Execution client | Needed payload | Recovery path |
| --- | --- | --- | --- | --- |
| **Shard-only restart** | restarts | **stays alive** | **available** — this is exactly B1's control: the executor is the same live process, it still holds the block | apply the anchor via `Commit`; no acquisition needed |
| **Execution-client restart** | alive | restarts | **unavailable for immediate forkchoice** (B2) | abstain with `unavailable`; acquisition (stage 4) required |
| **Full-pair restart** | restarts | restarts | unavailable, same as above | as above |
| **Power loss** | both | both | **not measured** | out of scope here; parent #14 |

So stage 4 is required **when the payload is actually unavailable**, which the executor reports, not
because a shard process restarted. A shard-only restart — the common case, and the one
`TestRound_CrashAfterSubmitBeforeUC_…` models — is fully recoverable with a retained anchor and no
new acquisition mechanism.

### 1.2 Limits of this evidence

- Only B2's specific lifecycle was restart-tested; B1 was finalised first, so the two blocks do not
  share a history and the run does not show that *every* accepted-but-unfinalised block behaves
  identically.
- The payload was built by this same client. A control that imports a payload produced elsewhere
  would test a different code path and would strengthen any general claim.
- Default persistence settings on one pin. Another configuration may retain more.

## 2. Five distinct things the code currently conflates

| # | Concept | Where it lives now | Survives shard-only restart? | Survives execution-client restart? |
| --- | --- | --- | --- | --- |
| 1 | **Latest authenticated UC/TR observation** | `BFTClient.luc`, seeded from the checkpoint | yes, via `FileStore` | yes |
| 2 | **Retained authenticated execution anchor** — certified *block hash* of the latest non-quiet certified round, with its source UC | **does not exist** | — | — |
| 3 | **Locally validated payload** — accepted, not finalised | the execution client, in process | **yes** (client untouched) | **no**, per §1 |
| 4 | **Applied executor head** | the client's canonical head | yes | yes |
| 5 | **Durable checkpoint** | `shard-node-luc.json`, one latest UC | yes | yes |

The defect is entirely explained by **#2 being absent**: the framework holds only the latest
certificate, which is quiet and carries no block hash, and has no memory of the last one that did.

## 3. The anchor: identity, authentication, continuity

### 3.1 What it is

An **execution anchor** is the tuple

```
(blockHash, stateRoot, partitionRound, partitionEpoch, rootRound, rootEpoch, shardConfHash)
```

together with **its source certificate** — the verified UC whose `InputRecord.BlockHash` is that
`blockHash`. The source UC is retained, not just the tuple, because the tuple alone is an assertion;
the UC is the evidence for it.

**A state root is not an identity.** Two different execution blocks can produce the same post-state,
so nothing may select, accept or validate a block by state-root equality. The anchor is a block hash;
the state root is only ever a secondary cross-check.

### 3.2 Authentication

- The source UC must pass `UC.Verify` against the trust base **from the configured store** for its
  **root** epoch, for this node's partition and shard. Never from a peer's claim, never from the
  checkpoint's own assertion about which epoch it belongs to.
- **Root epoch and partition epoch are separate.** The trust base is selected by root epoch; the
  anchor's usability is governed by partition epoch and `shardConfHash`. A change in either means the
  anchor is not usable and the node refuses to resume rather than approximating cross-epoch
  verification.
- **After a restart the checkpoint is not authority.** The retained anchor and its source UC are
  re-verified against the configured trust base before the anchor may be used, exactly as
  `verifyRestoredLUC` does for the latest UC today.

### 3.3 Continuity across quiet intervals

Carrying an anchor forward is **not** by itself proof that nothing happened in between. An anchor
stays valid only across a chain of certificates this node **itself observed and verified**, where
every step is one of:

- a **quiet** UC whose `PreviousHash == Hash` and whose round is exactly `previous round + 1`; or
- a **repeat** UC, which carries the same input record as the round it repeats and therefore neither
  advances nor invalidates the anchor.

Any other step — a non-quiet UC, or a **gap** in partition rounds — ends the anchor's validity. A
non-quiet UC supplies a new anchor. A gap means a state-changing round may have occurred unobserved,
and **a missed non-quiet interval can return to the same state root by a different block**, so
matching `certifiedPrev` after a gap proves nothing. In the initial single-epoch scope the node
**fails closed on any gap** rather than inventing a match-based fallback.

What is persisted alongside the anchor, and re-verified on restart:

| Field | Why |
| --- | --- |
| anchor tuple | the target |
| **source UC** (complete) | evidence for the tuple; re-verified against configured trust |
| **latest UC** (complete) | already persisted today |
| `continuityRounds` — the count of consecutive verified quiet/repeat steps since the source | lets a restart check the chain is unbroken without replaying history |
| `continuityFromRound` — the source's partition round | with the latest UC's round, makes any gap detectable arithmetically |

Retention is bounded by construction: exactly two certificates and two integers, regardless of how
long the shard idles. There is no historical search, so there is nothing to bound.

## 4. Transition table

Two preconditions apply to **every** row that ends in a vote. Neither is optional and neither is
implied by state equality:

- **P-ctx — authenticated context.** The certificate verified against the configured trust base for
  its root epoch, for this partition and shard, with partition epoch and `shardConfHash` matching the
  running configuration.
- **P-id — exact certified execution-head binding.** The executor's head **block hash** equals the
  certified block hash for the state being built on — the anchor's `blockHash`, or this UC's own
  `InputRecord.BlockHash` when it is non-quiet. Comparing state roots is not sufficient: two blocks
  can share a post-state.

An earlier revision of this table had a fast path keyed on `head == certifiedPrev`. Since
`certifiedPrev` is `exp.PreviousHash`, a **state root**, that row permitted voting with no verified
anchor and no context check — contradicting §3. It is removed; the already-applied case is now an
ordinary row with the same preconditions as every other.

`certifiedPrev` = `exp.PreviousHash` (the state the next round builds on). **Abstain** = do not
build, do not submit, retain evidence, stay recoverable.

| # | Situation | Anchor | Executor payload | Action | Vote? |
| --- | --- | --- | --- | --- | --- |
| 1 | head already matches, **P-ctx and P-id hold** | present, matches | — | build normally | **yes** |
| 2 | head state matches `certifiedPrev` but head **block hash ≠** certified block hash | any | — | abstain, `head-identity-mismatch` — same state, different block | **no** |
| 3 | head behind, UC **non-quiet** | from this UC | available | `Commit(uc.BlockHash)`; require `VALID`; re-read head; require **both** `head.Hash == uc.BlockHash` **and** `head.StateRoot == certifiedPrev` | **yes**, after |
| 4 | head behind, UC non-quiet | from this UC | `SYNCING` | abstain, `unavailable`; **retain the anchor**; retry on later certificates | **no** |
| 5 | head behind, UC non-quiet | from this UC | `INVALID` | abstain, `invalid-payload` — a fault, not retried as unavailable | **no** |
| 6 | head behind, UC **quiet**, continuity intact (§3.3) | retained, `anchor.stateRoot == certifiedPrev` | available | `Commit(anchor.blockHash)` — **the fix**; same post-checks as row 3 | **yes**, after |
| 7 | head behind, UC quiet, continuity intact | retained, matches | `SYNCING` | abstain, `unavailable`; retain the anchor; retry | **no** |
| 8 | head behind, UC quiet | **no anchor retained** | — | abstain, `no-anchor` — *today this row is `Commit(nil)`* | **no** |
| 9 | head behind, any UC | retained but `anchor.stateRoot != certifiedPrev` | — | abstain, `anchor-mismatch`; do not apply | **no** |
| 10 | head behind, any UC | retained, state root matches, but **continuity broken by a round gap** | — | abstain, `continuity-gap`; **do not** accept on matching state root (§3.3) | **no** |
| 11 | **repeat** UC | as for the round it repeats | as for that row | same as the row it repeats; a repeat neither advances nor invalidates the anchor | per row |
| 12 | anchor or UC from a different partition epoch / `shardConfHash` / shard | — | — | refuse to resume, explicit diagnostic | **no** |
| 13 | **genesis** — no prior certified block exists | none, legitimately | — | permitted only when the executor head is the configured genesis block **by hash** and the certificate is the shard's first; never a general "no anchor, accept current state" bypass | **yes**, under those exact conditions |

Forbidden in every row: `Commit(nil)`, substituting a state root for a block hash, downgrading
validation, and clearing stored authority to proceed.

**Unavailable is not invalid.** `SYNCING` means the executor does not have the payload — expected
after an execution-client restart (§1.1) and retryable. `INVALID` means it rejected the payload — a
fault. They must never share a diagnostic, and an `unavailable` result must **not** erase the anchor:
the authority to retry is exactly what would be lost.

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

Positive — each asserting both post-conditions (`head.Hash` **and** `head.StateRoot`):

1. Non-quiet UC, payload available → recovers; head block hash equals the certified block hash.
2. Quiet UC after a missed non-quiet round, anchor retained, continuity intact, payload available →
   recovers via the anchor. **This is the case that fails today.**
3. Several consecutive quiet UCs → anchor carried forward, `continuityRounds` advances, still recovers.
4. Repeat UC over a missed round → same outcome as the round it repeats.
5. Retry after a failed apply → not suppressed as a duplicate; second attempt succeeds.
6. `Commit` on an already-canonical hash → `VALID`, no duplicate effects.
7. **Shard-only restart** (executor untouched, per §1.1) → anchor re-verified from the checkpoint
   against configured trust, payload available, recovers with no acquisition.
8. Genesis: first certificate, executor at the configured genesis block by hash → permitted.

Negative — each asserting **abstention plus a distinct diagnostic**, never a vote:

9. Quiet UC, no anchor retained → `no-anchor`; today's `Commit(nil)` must be gone.
10. **Same state root, different block hash** → `head-identity-mismatch`. Two blocks constructed to
    share a post-state; the node must refuse even though state equality holds. This is the fixture
    that pins P-id.
11. Anchor present, state root does not match `certifiedPrev` → `anchor-mismatch`.
12. **Stale anchor after a round gap whose state root happens to match** → `continuity-gap`. The
    anchor is not resurrected by a coincidental match.
13. Payload `SYNCING` → `unavailable`, distinct from invalid, retryable, **anchor retained**.
14. Payload `INVALID` → `invalid-payload`, not retried as unavailable.
15. Anchor or UC from a different partition epoch / `shardConfHash` / shard → refuse to resume.
16. Unsigned or unverifiable certificate offered as an anchor source → rejected before use.
17. Checkpoint containing an anchor whose source UC fails re-verification after restart → refuse;
    the tuple is not authority (§3.2).
18. Genesis rule not usable as a bypass: executor at an arbitrary non-genesis state with no anchor →
    `no-anchor`, not accepted.
19. Process restart at each boundary: after apply before checkpoint, after checkpoint before
    observation advance, and between.

Real-client evidence, separate from the unit fixtures: an isolated `scripts/reth-chaos.sh`
**shard-only** restart showing positive work before and after, and agreement on certified target,
canonical block, state and receipts. Per §1.1 that case does **not** need acquisition, so it is the
scenario stage 3 can actually close. The execution-client and full-pair restarts are expected to
reach a clean fail-closed `unavailable` until stage 4 exists, and that is the correct intermediate
result rather than a failure of stage 3.

## 8. Scope held open

This record does not implement anything. It does not explain any particular real-reth scenario in
#88, does not claim #16's fake-executor stall shares this cause, and does not address power-loss
durability (#14) or the stale-certificate taxonomy (#93).
