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
| **Shard-only restart** | restarts | **stays alive** | **not lost *by the restart*** — the executor is the same live process (B1's control). This is **not** a guarantee it holds the payload: it may never have received the block while the shard was down, or may have discarded it. Availability is what the executor reports, never what the restart category implies | attempt the anchor via `Commit`; if `VALID`, done with no acquisition. If `SYNCING`, row 7 applies here too |
| **Execution-client restart** | alive | restarts | **unavailable for immediate forkchoice** (B2) | abstain with `unavailable`; acquisition (stage 4) required |
| **Full-pair restart** | restarts | restarts | unavailable, same as above | as above |
| **Power loss** | both | both | **not measured** | out of scope here; parent #14 |

So stage 4 is required **when the payload is actually unavailable**, which the executor reports, not
because a shard process restarted. That conditional holds in **every** restart category, including
shard-only: what B1 supports is that a shard-only restart does not *by itself* destroy the payload,
not that such a restart is unconditionally self-healing. A shard-only restart in which the executor
does hold the block — the common case, and the one `TestRound_CrashAfterSubmitBeforeUC_…` models —
recovers with a retained anchor and no new acquisition mechanism.

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

Carrying an anchor forward is **not** by itself proof that nothing happened in between. The anchor
was established by a source UC at partition round `r_a`, binding block `A` and state `S`. It remains
the execution head at a later round `r_n` **only if every partition round in `(r_a, r_n]` was
quiet at `S`** — a single state-changing round in that interval replaces the head, and this node did
not see it.

#### 3.3.1 The previous revision's proof was unsound. Counterexample.

The previous revision persisted two integers — `continuityFromRound` and `continuityRounds` — and
checked them arithmetically against the retained endpoints. Review supplied a counterexample that
**needs no forged signature**:

| Partition round | What actually happened | In the checkpoint? |
| --- | --- | --- |
| 10 | source UC binds block `A`, state `S` | **yes**, genuine |
| 11 | *omitted* — state changes `S → T` | no |
| 12 | *omitted* — binds a **different block `C`**, state returns to `S` | no |
| 13 | latest UC, quiet at `S` | **yes**, genuine |

With `continuityFromRound = 10` and `continuityRounds = 3`, every check the previous revision
specified passes: both retained UCs verify against the trust base, the context matches, the state
roots agree, and `13 − 10 = 3` matches the counter. **But the execution anchor is `C`, not `A`.**

The defect is structural, not a missing check. Neither retained certificate signs any statement about
rounds 11 and 12. The counters are **locally written, unsigned bytes** — the one input an attacker or
a corrupted file controls freely — and re-verifying two endpoint signatures cannot distinguish this
history from an intact quiet interval. This is precisely the stale-anchor/same-state-root case that
§3.3 forbids while running, reintroduced through the restore format.

A second, independent defect in the same arithmetic: **repeat UCs do not advance the partition
round.** A count of quiet *and repeat* steps can therefore never be compared against a partition-round
difference at all, even setting the authentication problem aside.

Both are fixed the same way: **stop deriving continuity, and retain the evidence that proves it.**

**This is reproduced, not argued.** `shardnode/continuity_counterexample_test.go` builds the four
rounds above as **genuinely signed** certificates and runs both candidate rules over them, in the
same reproduction-first shape stage 1 (#94) was accepted in:

- it asserts the premise — round 11 really changes state, round 12 really returns to `S` while
  binding a **different** block, so the true anchor really is `C`;
- it asserts the previous revision's rule **accepts** the checkpoint (the defect), so the fixture
  cannot be passing because the history is malformed;
- it asserts the corrected rule **refuses** it, and keeps refusing when the unsigned counters are
  edited to any value that would make arithmetic succeed;
- it includes positive controls — an intact quiet run is accepted, a run with one round missing is
  refused — so the corrected rule is not merely refusing everything.

The test contains both rules as local functions. It is an executable specification: it wires into no
runtime path, and **this PR still changes no behaviour**.

#### 3.3.2 What is actually admissible as evidence

Only the certificates. A UC at round `k` with `PreviousHash == Hash == S` is the root chain's signed
statement that round `k` did not change state. A **contiguous** run of such certificates covering
every certified round after `r_a` up to `r_n` is a proof of the interval; nothing shorter is.

There is no chaining shortcut available. A quiet UC does not reference the previous round's
certificate, so round `k`'s certificate says nothing about round `k − 1`. The evidence must therefore
be the sequence itself, and it must be **complete** — never sampled, never summarised, never
truncated with the endpoints reconciled by arithmetic.

**"Contiguous" is not "consecutive", and the difference is not academic.** Certified partition
rounds are not consecutive integers: the root chain names the next round in each certificate's
`TechnicalRecord`, and it skips numbers whenever a round is abandoned. Measured on a four-validator
real-reth devnet, the very first certificate of the run did it — `partitionRound=0 … nextRound=2` —
and a later one went `partitionRound=5 … nextRound=7`.

So the contiguity test is **"is this the round the previous certificate assigned"**, not "is this
number one higher". The assignment is authenticated: the technical record's hash is committed in the
certificate and checked before classification, so the expected next round is evidence rather than a
guess. It is also *stricter* than the arithmetic version in the direction that matters — any
certificate other than the assigned one means one was genuinely missed, including a repeat that
would have reassigned the number.

A first implementation used `through + 1`, and every routine skip therefore invalidated the anchor of
every honest node at the same moment. Under the voting gate below that stopped them all voting, and
the shard fell under quorum within two minutes of starting. `TestContinuityState` now pins both
directions.

**In-memory versus on-disk is the distinction that makes this affordable.** While the process runs,
in-process state is sound evidence: this node verified each certificate as it arrived, and process
memory is not an attacker-supplied input. The counterexample attacks the **restore** path
specifically, where the file is the only witness. So:

- **running — deciding.** Keep the anchor, `continuityThrough` (the highest partition round through
  which the interval has been verified quiet) and the round the last certificate **assigned** as
  next. Each observed certificate either extends the interval to the assigned round (quiet, at the
  anchor's state root), leaves it unchanged (a repeat of a round already covered), replaces the
  anchor (non-quiet), or **invalidates** it (a certificate for a round that was not the assigned
  one, or a quiet certificate at a different state root). The live vote decision reads this, not the
  file.
- **running — recording.** The same certificates are appended to the persisted evidence set as they
  are verified, because the *next* restart can only use what was written before it. Accumulation is
  a write-path concern; it is not what the running node consults to decide.
- **restore.** Re-derive continuity from the retained certificates alone (§3.3.4). Nothing about
  continuity is accepted as a stored assertion.

The two paths must agree by construction, so `continuityThrough` is **derived from the same
predicate** the restore check applies to the retained set, rather than being a separate hand-written
rule that could drift from it.

`continuityFromRound` and `continuityRounds` are **removed from the format**. A stored count is not
evidence, and keeping one invites trusting it.

#### 3.3.3 Bounds, and what happens at the limit

An idle shard certifies a quiet round forever, so the **persisted** evidence set is unbounded in
principle and must be capped. The live path is not: in-process continuity is a single anchor plus
`continuityThrough`, which does not grow.

An earlier revision conflated the two and gave two incompatible answers — "discard continuity and
stop voting at the limit", then "a running idle node is unaffected". Only one can be implemented.
**The two are now separated explicitly, and the live answer is the one that holds.**

| | Live (process running) | Restored (after restart) |
| --- | --- | --- |
| What carries continuity | in-process anchor + `continuityThrough` | the retained certificate sequence |
| Grows with idle time? | **no** | yes, one certificate per quiet round |
| Behaviour at the limit | **unaffected — keeps voting** | no continuity claim; non-voting until recovery |

**Exhaustion is a restart-evidence limit, not a voting limit.** A running node has *observed* every
intervening certificate itself; that knowledge is sound regardless of how much of it it managed to
write down. Stopping it from voting would be both unnecessary and actively harmful: an idle
validator set that stopped voting at the limit could never produce the non-quiet certificate that
would reset the evidence set, so the shard would wedge exactly when nothing was happening — the one
situation the bound is reached in. So the limit **never** affects a running node.

| Limit | Initial value | Rationale |
| --- | --- | --- |
| `maxContinuityUCs` | 512 certificates | bounds restore-time verification work |
| `maxContinuityBytes` | 1 MiB encoded | bounds file size independently of validator-set size, which drives per-UC size |

Whichever binds first applies.

**What happens when the persisted set would exceed a bound.** The node does **not** truncate —
dropping certificates and reconciling the endpoints arithmetically is the unsound construction of
§3.3.1. Instead it writes an explicit **non-restorable** state:

- the **source UC is still retained**, because it is what a later recovery needs in order to know
  which anchor was in force;
- the continuity sequence is dropped and the checkpoint records `continuityExhausted` with the round
  at which it happened;
- the running node continues voting, unaffected (above).

On restart from such a checkpoint the node has an authenticated anchor and no proof the interval was
quiet, so it abstains with `continuity-capacity-exhausted` — distinct from `continuity-gap`, because
one is an availability limit this node chose and the other is a soundness refusal. It stays
non-voting until it obtains authenticated recovery evidence (stage 4).

**Bounds are enforced locally; the file's declared bounds are informational.** The limits are written
into the checkpoint so a reader can tell a deliberate refusal from a truncated file, and for **no
other purpose**. A file declaring larger bounds does not get them: the locally configured
`maxContinuityUCs` / `maxContinuityBytes` always govern, and a file declaring bounds above them is
rejected as malformed. The declared count and size are validated **before** any sequence is allocated
or verified, so a hostile file cannot cause unbounded allocation or verification work by claiming a
large set — the check precedes the work rather than discovering the problem part-way through it.

**Repeat UCs.** A repeat carries the same input record as the round it repeats and does not advance
the partition round. Evidence is therefore keyed **by partition round**: a repeat for round `k` is
admissible as evidence for round `k`, is stored at most once, and never extends the covered interval.
This makes the double-counting defect unrepresentable rather than merely checked for.

**Round arithmetic.** Partition rounds are `uint64`. `r_n - r_a` is computed only after establishing
`r_n >= r_a`; a retained set whose rounds are not strictly increasing, or whose first round is not
`r_a + 1`, or whose last round is not the latest UC's round, is rejected outright rather than
repaired.

#### 3.3.4 What is persisted, and what is re-derived on restore

| Field | Trusted on restore? | Why |
| --- | --- | --- |
| **source UC** (complete) | **no — re-verified** | establishes the anchor tuple and authenticates it |
| **latest UC** (complete) | **no — re-verified** | already persisted today |
| **continuity evidence**: the complete quiet-UC sequence for `(r_a, r_n]` | **no — re-verified** | the proof itself |
| anchor tuple (block hash, state root, round) | **no — re-derived from the source UC** | stored for readability; never read as authority |
| `appliedRound` | yes, as a *claim about this node*, never about the chain | §5: says what was reconciled, not what is true |

Restore is a verification, not a load. For the anchor to be usable afterwards, **all** of the
following must hold, re-derived from the retained certificates alone:

1. Every retained UC verifies against the trust base **from the configured store**, selected by that
   certificate's own **root** epoch, for this partition and shard.
2. Every retained UC's **partition** epoch and `shardConfHash` match the running configuration
   (§3.2 — root epoch and partition epoch are separate).
3. The source UC is **non-quiet** and its `InputRecord.BlockHash` is the anchor's block hash.
4. Every continuity UC is **quiet**, which means all three of: `PreviousHash == Hash`, `Hash` equals
   the anchor's state root, **and `BlockHash` is empty**. The block-hash clause is not implied by the
   other two — a certificate claiming an unchanged state root while carrying a block hash is
   malformed rather than quiet, and `BuildInputRecord` produces a nil `BlockHash` for a quiet round
   by construction. In practice it is **defence in depth**: `InputRecord` validation inside
   `UC.Verify` already refuses "state hash didn't change but block hash is not nil", so such a
   certificate cannot be signed into existence and condition 1 excludes it first (verified in
   `shardnode/continuity_counterexample_test.go`). The clause is stated anyway, because the restore
   path should not depend on a rule enforced elsewhere in order to be correct. A single non-quiet
   certificate in the set is a contradiction, not a gap.
5. Their partition rounds are exactly `r_a + 1, r_a + 2, …, r_n` — contiguous, strictly increasing,
   no duplicates, no gaps.
6. The final continuity UC carries the **same canonical input-record bytes** as the latest UC,
   under the verified context in conditions 1-2. A repeat may have a later root seal without
   changing that record; retain at most one verified representative for that partition round.
7. The declared and actual set sizes are within the **locally configured** capacity limits (§3.3.3),
   checked before the sequence is allocated or verified.

**The empty interval is its own case.** Conditions 5 and 6 assume at least one continuity
certificate, which is wrong when the source UC *is* the latest UC — the anchor was established by the
most recent certificate and no quiet rounds have followed it. That is the ordinary state of a shard
that just certified a block, not a degenerate one. So, explicitly: when `r_n == r_a`, the source and
latest UC must carry **the same canonical input record** under conditions 1-2 (a reissued root seal
is allowed), the evidence set must be **empty**, and conditions 4-6 do
not apply; conditions 1-3 and 7 still do. A non-empty evidence set with `r_n == r_a`, or a source and
latest whose input records differ while claiming the same round, is rejected.

Any failure means **no continuity claim**, not a downgraded one: the node abstains with a diagnostic
naming which condition failed, and retains the file for diagnosis rather than rewriting it.

## 4. Transition table

Three preconditions apply to **every** row that ends in a vote. None is optional or implied by state equality:

- **P-ctx — authenticated context.** The certificate verified against the configured trust base for
  its root epoch, for this partition and shard, with partition epoch and `shardConfHash` matching the
  running configuration.
- **P-id — exact certified execution-head binding.** The executor's head **block hash** equals the
  certified block hash for the state being built on — the anchor's `blockHash`, or this UC's own
  `InputRecord.BlockHash` when it is non-quiet. Comparing state roots is not sufficient: two blocks
  can share a post-state.

- **P-sign — signing authorization.** A restored node must satisfy the independent monotonic signing
  contract in §6.1 before voting. A verified checkpoint and matching executor head alone do not
  satisfy it. Until #14 supplies that contract, restored nodes may observe and reconcile but remain
  non-voting; every “yes” below is conditional on this gate.

An earlier revision of this table had a fast path keyed on `head == certifiedPrev`. Since
`certifiedPrev` is `exp.PreviousHash`, a **state root**, that row permitted voting with no verified
anchor and no context check — contradicting §3. It is removed; the already-applied case is now an
ordinary row with the same preconditions as every other.

`certifiedPrev` = `exp.PreviousHash` (the state the next round builds on). **Abstain** = do not
submit, retain evidence, stay recoverable.

**What "abstain" withholds, corrected by measurement.** This said "do not build, do not submit". The
first clause defeats the third. A node that does not build also never runs `Verify`, so its execution
client never receives the round's payload, so it can never commit that block and is permanently
behind — the opposite of "stay recoverable", and on a real devnet it is what turned a single
unprovable head into a node that never rejoined. So an abstaining node still builds or verifies the
round's block, disseminates it if it is the leader, and commits what the shard certifies; what it
withholds is the **signed certification request**. Nothing is signed while the node cannot prove
which certified block it stands on, which is the entire safety content of these rows, and the next
non-quiet certificate installs an anchor matching its head and re-arms it with no operator action.

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
| 10 | head behind, any UC | retained, state root matches, but **continuity not established** (§3.3.4 conditions 4-6 — a gap, a non-quiet certificate in the set, or a set not ending at the latest UC) | — | abstain, `continuity-gap`; **do not** accept on matching state root (§3.3) | **no** |
| 10a | **live**, UC quiet | in-process continuity intact; the *persisted* evidence set would exceed a bound | as in rows 1/6/7 | Persist the non-restorable state (source UC retained, sequence dropped, `continuityExhausted` recorded). Then apply the normal head/availability checks: row 1 if already reconciled, row 6 if recovery succeeds, row 7 if unavailable. Capacity exhaustion grants no exception to P-ctx, P-id or P-sign | **only after the applicable row permits it** |
| 10a-r | **restored**, head behind, UC quiet | checkpoint records `continuityExhausted`; anchor present, no sequence | — | abstain, `continuity-capacity-exhausted` — an availability limit this node chose, distinct from row 10's soundness refusal | **no** |
| 10b | head behind, UC quiet | anchor and evidence present on disk, but a retained certificate **fails re-verification** on restore | — | abstain, `continuity-unverified`; retain the file for diagnosis, do not rewrite it | **no** |
| 11 | **repeat** UC | as for the round it repeats | as for that row | same as the row it repeats; a repeat neither advances nor invalidates the anchor, and never extends the covered interval — evidence is keyed by partition round (§3.3.3) | per row |
| 12 | anchor or UC from a different partition epoch / `shardConfHash` / shard | — | — | refuse to resume, explicit diagnostic | **no** |
| 13 | **genesis** — no prior certified block exists | none, legitimately | — | permitted only when the executor head is the configured genesis block **by hash** and the certificate is the shard's first; never a general "no anchor, accept current state" bypass | **yes**, under those exact conditions |

Forbidden in every row: `Commit(nil)`, substituting a state root for a block hash, downgrading
validation, clearing stored authority to proceed, and **accepting a continuity claim that was not
re-derived from retained certificates** (§3.3).

**P-id is required of every process, including one that may not vote.** P-sign and P-id answer
different questions — whether this node may SIGN, and whether it may make its execution client
FINALIZE — and an intermediate revision collapsed them by skipping the identity check entirely for a
restored process, on the grounds that it could not vote anyway. That exempted exactly the node with
no anchor from the check that stops it finalizing an unproven parent. Inability to vote is not
standing to finalize.

**Replay of one authorization produces one signed request.** The delivery layer re-drives a
certificate whose application failed, and writing the checkpoint is part of applying one — so an
ordinary store failure after a round had been built and sent re-entered the round, rebuilt the
candidate against whatever the executor held by then, and signed a DIFFERENT input record for the
same round under the same authorizing certificate. A single transaction arriving between the two
deliveries is enough. The round is therefore idempotent in its authorization: the certificate, its
root round and the round it assigns are retained with the signed request, and a re-delivery of that
same authorization re-sends those exact bytes rather than rebuilding. A genuinely new authorization —
a repeat certificate at a later root round, assigning a fresh round — is a different key and
rebuilds, which is correct.

**Building is not a neutral act, so leadership is gated where voting is.** `Executor.Build` asks the
execution client to move its forkchoice to the parent — engineapi sends head, safe **and finalized**
as `p.Parent.Hash` — so a leader that builds on a head it cannot prove is certified has already made
the client finalize that head before any vote is withheld, and nothing later undoes a finalization.
A node that fails P-id therefore declines to LEAD. It still follows: `Verify` is `newPayload` only,
which stores the payload without moving the forkchoice, so an abstaining follower keeps receiving
payloads and stays able to recover. Every finality-changing Engine call is reached only from
authenticated certified ancestry.

**Row 2 has no recovery path in stage 3, and that is not an oversight.** A node whose executor sits
on a different block at the certified state has diverged in a way no target this design can name will
fix: it is not behind, so there is nothing to commit forward to, and stage 4's payload acquisition
does not apply either. It abstains, says so, and needs a resync. What matters here is that it stops
rather than signs.

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
   head reconciled). Advance each only on its own success.
2. **"Durable" is not one thing, and treating it as one produced a contradiction.** An earlier
   revision said "never mark applied or durable before application succeeds", which cannot be
   reconciled with §5.1 persisting a verified-but-unapplied anchor — the whole point of which is to
   write authenticated evidence *before* it has been applied. There are two durable facts, written
   at different times:

   - **durable-observed / durable-evidence** — "these certificates verified". May be written as soon
     as verification succeeds, and **must** be, since an anchor that is not on disk cannot survive
     the restart it exists for.
   - **durable-applied** — "the executor head was reconciled to this round". Written **only** after
     `Commit` returned `VALID` and the re-read head matched by block hash *and* state root.

   Writing the first must never advance the second. The rule that survives is the narrow one:
   **never advance the applied claim before application succeeds.**
3. **The crash between those two writes is a normal state, not a torn one.** Evidence on disk with
   `appliedRound` behind it means "authenticated, not yet applied, retry" — exactly §5.1's
   verified-but-unapplied anchor. It must be reachable in the fixture contract (§7), not merely
   assumed to be handled.
4. **`appliedRound` is not a voting authority.** It records what this node believes it did, so it is
   checked against the live executor head rather than believed — and, per §6.1, it is replayable
   like everything else in the file, so it can never by itself establish that resuming is safe.
   Describing it as "a local claim" is a statement about what it means, not a licence to trust it.
5. Duplicate suppression must not swallow a retry when the previous attempt failed to apply: a
   certificate that is a duplicate *of the observation* but whose round was never applied is a
   retry opportunity, not a no-op.
6. Retry must be idempotent: `Commit` on an already-canonical hash is a no-op returning `VALID`, so
   repeating it is safe.

### 5.1 Persisting a verified-but-unapplied anchor

Rows 4, 7 and 10a-r end with the node holding an anchor it has **authenticated** but has **not
applied** — the executor reported `SYNCING`, or continuity could not be claimed. (Row 10a is not one
of these: a live node at the persistence limit keeps voting, and only its *next* restart is
affected — §3.3.3.) That state must
survive a restart, because the authority to retry is exactly what would otherwise be lost. It must
also not be mistakable for progress.

Three fields, advanced independently, and never collapsed into one:

| Field | Meaning | Advanced when |
| --- | --- | --- |
| `observedRound` | the cursor `Submit` and non-equivocation use | a certificate is observed and verified |
| `appliedRound` | the round the **executor head was actually reconciled to** | `Commit` returned `VALID` **and** the re-read head matched by block hash *and* state root |
| `anchor` + continuity evidence | authenticated, possibly unapplied | the certificates establishing it verified |

So `anchor.round > appliedRound` is a **normal, expected, retryable** state, not a corrupt one. Its
meaning is precise: *this node has proof of what the certified execution head is, and has not yet
succeeded in making its executor agree.* Concretely:

- **Verification and application are separate writes.** The anchor is written when its certificates
  verify. `appliedRound` is written only after the executor confirms. A crash between them leaves a
  retryable anchor, which is the desired outcome, not a torn state to repair.
- **An unapplied anchor never satisfies a "we are up to date" check.** Any read path that asks
  whether the node may vote consults `appliedRound` and the live executor head, never the anchor's
  presence.
- **`unavailable` must not erase the anchor.** Row 4 and row 7 abstain *and keep* it. Only a
  non-quiet certificate replaces an anchor; only a failed re-verification (row 10b) invalidates one,
  and that path refuses rather than rewriting.
- **On restore the executor is the authority on what is applied.** `appliedRound` is a claim about
  this node's own past actions, so it is checked against the live executor head rather than believed:
  if the head does not match, the node reconciles or abstains, and does not treat the stored value as
  established. It is also replayable (§6.1), so it is never on its own a reason to resume signing.

## 6. Persistence ordering and migration

Adding the anchor and its evidence to the checkpoint is a **format change**, and #14 owns the
durability contract. The minimal shape: extend the existing versioned CBOR envelope (issue #86) with
an optional anchor field carrying the source UC, the continuity sequence and the capacity limits in
force when it was written; bump the format version; reject an unknown version as today.

Ordering: the anchor is only written together with the certificates that establish it, so a torn
write cannot produce an anchor that no certificate supports. Because every field that matters is
re-verified on restore (§3.3.4), a *partially* written file cannot produce a wrong accept either — it
produces a refusal.

**Why the file is not authenticated, and why that is acceptable here.** The alternative design is a
separately authenticated local checkpoint: sign or MAC the file and trust its contents on restore.
That is a legitimate option, but it needs an explicit integrity **and freshness** trust contract —
which key, held by whom, protected how, and what stops a valid-but-stale file from being replayed.
The current plain CBOR file has no such contract. A checksum is not one: it detects accidental
corruption and nothing else. Neither is a key the node generates and stores beside the file it
protects, which authenticates the file to whoever can write the file.

Retained evidence removes the *integrity* half of the question. The certificates are already signed
by the root chain and the node already has the trust base needed to check them, so **the checkpoint
is untrusted input** — its only job is to make the evidence available; every conclusion about the
anchor is re-derived from signatures the file cannot forge.

**It does not remove the freshness half, and an earlier revision of this section wrongly claimed it
did** ("freshness comes from the round sequence rather than from the file's own claims"). That is
false, and §6.1 is what replaces it.

`FileStore` writes to a temp file and renames. **A rename is not an fsync**: this covers a process
restart, not power loss. That distinction stays with #14 and is not claimed here.

### 6.1 What retained certificates prove, and the separate contract they do not supply

**The boundary, stated exactly.** The retained certificates prove the execution anchor **relative to
the `latest` UC included in the same file**. They do not prove that this file is the most recent one,
and they do not authorise rolling back anything.

This is not a weakness in the predicate; it is what the predicate is *for*, and review demonstrated
it directly on the corrected design. Take a checkpoint whose `latest` UC is round 12 while the shard
has in fact reached round 13. Its evidence for `(10, 12]` is complete, contiguous and correctly
signed, so §3.3.4 establishes continuity — **correctly**: rounds 11 and 12 really were quiet, and
block `A` really was the execution anchor as of round 12. Every signature, every context check and
every consecutive-round check holds. **An entire older checkpoint replays perfectly.**
Reproduced in `shardnode/continuity_counterexample_test.go`.

Nothing else available at restore closes it either:

- **The certificates cannot.** Round 12's certificate says nothing about whether round 13 exists.
- **The executor cannot.** After a run of quiet rounds the executor is at the same block whatever the
  current round is, so its head cannot say which partition rounds this node has already observed —
  still less which it has already **signed**.

**Why this matters more than an availability question.** Restoring an older file rolls the
observation cursor backwards. §5 keeps that cursor separate from applied state, but the cursor is
also what stops this node from acting twice in one round: a node resumed from a stale file can
re-enter partition rounds it has already voted in, and sign again. That is a safety problem, not a
liveness one.

**The contract required, and where it lives.** Before a restored node may vote it needs a
**monotonic, crash-safe, non-rollback record of the highest partition round it has signed in**, with
these properties:

1. **Monotonic.** It only ever increases. A restore that would lower it is refused; the node stays
   non-voting rather than resuming at an earlier round.
2. **Independent of the replayable evidence file.** Whatever supplies it must not be satisfiable by
   presenting an older copy of itself — which is exactly the property the certificate tuple lacks, so
   it cannot be another field in the same checkpoint.
3. **Checked before signing, not before loading.** Restoring a historical anchor for *diagnosis* is
   harmless; signing on the strength of one is not.

**This design does not supply that record, and must not be read as if it did.** It is a durability
and freshness contract, which is #14's subject. What this document fixes is the *anchor* problem;
what it must not do is let a historical file authorise resumption on its own. Concretely, for
stage 3: the retained tuple establishes what the execution head was as of its own `latest` UC, and
nothing more. Voting additionally requires the monotonic record above; until #14 provides it, a
restored node may reconcile its executor and observe, but a design that votes purely on a restored
checkpoint is incomplete by construction.

## 7. Fixture plan for stage 3

Positive — each asserting both post-conditions (`head.Hash` **and** `head.StateRoot`):

1. Non-quiet UC, payload available → recovers; head block hash equals the certified block hash.
2. Quiet UC after a missed non-quiet round, anchor retained, continuity intact, payload available →
   recovers via the anchor. **This is the case that fails today.**
3. Several consecutive quiet UCs → anchor carried forward, the retained evidence set grows by one
   certificate per round, still recovers.
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

**Restore fixtures the counterexample requires** (§3.3.1). Every one of these builds its checkpoint
from **genuinely signed** certificates — a forged signature would be caught by existing verification
and would prove nothing about this design:

20. **The counterexample itself, and it must be refused.** *(Already reproduced against the
    proposed predicate in `shardnode/continuity_counterexample_test.go`; stage 3 repeats it against
    the real checkpoint/restore path.)* Genuine source UC at round 10 (block `A`,
    state `S`), genuine latest quiet UC at round 13 at `S`, and the omitted rounds 11 (`S → T`) and
    12 (different block `C`, back to `S`) **absent from the evidence set**. Expected:
    `continuity-gap` — rounds 11 and 12 are missing from the sequence, so condition 5 of §3.3.4
    fails. Under the previous revision this case **voted**, with the anchor pointing at `A` while the
    real execution head was `C`; the fixture asserts the vote no longer happens.
21. **Edited counters cannot rescue it.** *(Reproduced.)* The same history, with any locally-writable field an
    implementation might be tempted to keep (a count, a "from" round, a length) set to whatever value
    would make arithmetic succeed. Expected: identical refusal, because no such field is read. This
    is the regression test for *the format*, not just the checker.
22. **Truncation is refused, not accepted.** *(Reproduced.)* A genuine but **incomplete** evidence set — the first
    and last certificates of a long quiet run, with the middle removed. Expected: `continuity-gap`,
    never an endpoint-arithmetic acceptance.
23. **Positive control with repeats that do not advance the partition round.** A quiet interval
    containing repeat UCs with repeated root seals: the partition rounds covered are still exactly
    contiguous, each round appears once, and the node **recovers**. Without this control, fixtures 20-22
    could all be passing because the checker refuses everything.
24. **Positive control, plain.** A complete, contiguous, correctly signed quiet run of length `n`
    (2 < `n` < `maxContinuityUCs`) → continuity established, recovers.
25. **Capacity exhaustion: live and restored are different rows and need different tests.**
    a. *Live* — a quiet run exceeding `maxContinuityUCs`, and separately one exceeding
       `maxContinuityBytes`: the running node **keeps voting** (row 10a), the evidence set is **not**
       silently shortened, the source UC is still retained, and the checkpoint records
       `continuityExhausted`. Assert the vote happens; a test that only checks the persisted state
       would pass on a node that had wrongly stopped.
    b. *Restored* — starting from that checkpoint: abstain with `continuity-capacity-exhausted`
       (row 10a-r), distinct from `continuity-gap`, so an operator can tell an availability limit
       this node chose from a soundness refusal.
    c. *An idle validator set does not wedge.* With every node past the limit, the shard must still
       certify quiet rounds — which is the reason (a) votes. Without this the bound would make the
       non-quiet certificate that resets it unreachable.
    d. *Declared bounds cannot raise local ones.* A checkpoint declaring `maxContinuityUCs` or
       `maxContinuityBytes` above the locally configured values is rejected as malformed, and the
       declared size is validated **before** any sequence is allocated or verified — assert no
       large allocation or verification occurs for a file that merely claims a large set.
26. **Re-verification is real, not a load.** A checkpoint whose evidence set is complete and
    contiguous but where one certificate's signature does not verify against the configured trust
    base → `continuity-unverified` (row 10b), and the file is retained rather than rewritten.
27. **Verified-but-unapplied anchor survives restart** (§5.1). Restart with `anchor.round >
    appliedRound`: the anchor must still be present and retryable, must not be read as "up to date",
    and a later `Commit` returning `VALID` must be what advances `appliedRound`.
28. **The crash between durable-evidence and durable-applied** (§5 item 3). Write the evidence, kill
    the process before `Commit`, restart: the anchor is present, `appliedRound` is behind it, the
    state is recognised as retryable rather than torn, and nothing treats the node as up to date.
    Assert the reverse ordering never occurs — `appliedRound` ahead of evidence that was never
    written is the failure this ordering exists to prevent.
29. **Whole-checkpoint replay is refused as a resumption authority** (§6.1). Present a *complete,
    correctly signed, internally consistent* checkpoint whose `latest` UC is older than what this
    node has already observed and signed. Continuity **must** verify — it is genuine historical
    continuity — and the node must nonetheless **not** resume voting from it, nor lower its observed
    or signed watermark. This is the fixture that pins the boundary: the certificates are not the
    freshness contract. Reproduced against the predicate in
    `shardnode/continuity_counterexample_test.go`; stage 3 repeats it against the real restore path
    once #14 supplies the monotonic record.
30. **The empty interval** (§3.3.4). Source UC *is* the latest UC, evidence set empty → continuity
    holds. And the malformed variants: a non-empty evidence set with `r_n == r_a`, and a source and
    latest that differ while claiming the same round → both rejected.
31. **A quiet certificate carrying a block hash cannot be signed into existence** (§3.3.4
    condition 4). Matching state roots with a non-empty `BlockHash` → `UC.Verify` refuses it, so it
    never reaches the continuity check. The fixture pins that the clause is defence in depth and
    records why it looks redundant, so it is not removed as dead weight.

Fixtures 20-26 need no execution client: they are checkpoint-in, decision-out, which is what makes
them cheap enough to run on every change. What they do need is a builder that produces **genuinely
signed** certificates for arbitrary histories, including the histories the node must refuse — the
test trust base already supports this, and it is the reason a forged-signature fixture is not the
interesting case.

Real-client evidence, separate from the unit fixtures: an isolated `scripts/reth-chaos.sh`
**shard-only** restart showing positive work before and after, and agreement on certified target,
canonical block, state and receipts. Per §1.1 that case needs no acquisition **if the executor retains the payload**.
Stage 3 may demonstrate reconciliation; resumed voting additionally waits for P-sign / #14. The execution-client and full-pair restarts are expected to
reach a clean fail-closed `unavailable` until stage 4 exists, and that is the correct intermediate
result rather than a failure of stage 3.

## 8. Implementation status

Stage 3 (first PR) implements the **live** half of this design and stops deliberately short of the
persisted half.

**Implemented** — `shardnode/anchor.go`, `Round.HandleCertificate`, `Round.reconcile`,
`BFTClient.handleCertificationResponse`:

- the execution anchor and the verified quiet interval, maintained in process across quiet and
  repeat certificates (§3.3.2's "running — deciding");
- `reconcile` taking its recovery target from that anchor instead of the certificate in hand, which
  is the #92 defect: `Commit(nil)` is now unrepresentable, not merely avoided;
- **a commit target that comes from the certificate, never from the pending proposal.** `r.pending`
  is what this node built or verified for the round it last submitted; committing is a different act
  — for the Engine adapter it sets head, safe and FINALIZED — and may only apply to a block the root
  chain has certified. The two were conflated, and a transport failure was enough to expose it: a
  failed `Submit` ended the round with the next proposal installed as pending, the delivery layer
  recorded the certificate as unapplied, the retransmission re-entered the round, and the
  uncertified proposal was finalized. `commitPrevious` now commits only when the certificate is for
  the round this node proposed for, commits the block the certificate names rather than the one this
  node proposed, and commits nothing at all when the round was certified quiet;
- **the send separated from the application.** `ErrSubmissionFailed` marks a failure to put an
  already-applied round's request on the wire. The delivery layer treats it as applied, so a
  retransmission is not re-driven; the send itself is retried, bounded, with the identical signed
  bytes, because a retry must never put different bytes for one round on the wire;
- **the genesis identity read from the executor's chain configuration** (`Executor.GenesisBlock`,
  block zero), not from the first head this process observed. A new process can attach to an
  executor that has already committed blocks, so "this process has not committed" is not "nothing
  has committed" — an arbitrary tip was accepted as genesis. The nil-state genesis path additionally
  refuses to run at all unless the executor is at that block;
- **continuity keyed on the round the previous certificate ASSIGNED** (§3.3.2), not on consecutive
  round numbers, and the genesis exception compared against the executor's own genesis block rather
  than against "block number 0". Both corrections come from the real-reth lane, and both were
  defects that a fake-executor suite could not show: the first stalled a live shard under quorum in
  two minutes, the second re-opened the same-state/different-block hole the P-id check exists to
  close;
- **P-id enforced on every round that could end in a vote**, not only on the recovery path.
  `HandleCertificate` used to consult this file only when the state roots differed, so a round whose
  state root already matched was built and signed with no anchor, identity or continuity check at
  all — the unsound fast path this table removed, still present in the code. Rows 1, 2, 8 and 13 are
  now decided at the same state root, by what the node can prove about the BLOCK
  (`continuityState.checkHeadIdentity`, `shardnode/round_identity_gate_test.go`). The verdict is
  applied at the signing gate — the round is still built, verified and committed — for the reason
  recorded under the transition table: refusing to build makes the node unrecoverable rather than
  safe, and the failing node re-arms itself once a non-quiet certificate matches its head;
- row 13's genesis exception, narrowed and made structural. It is needed for a reason the fake never
  showed: "genesis is always non-quiet" makes the shard's first certified round carry a block hash
  even when nothing moved, while `round.go` does not commit a round whose state did not move — so
  against reth the certificate names a block the client built and discarded, and the executor sits
  at genesis. For that one anchor the comparison is therefore made against the executor's own
  genesis block, **by block number 0 at the certified state root**, not by block hash and not by
  state equality alone. The first state-changing round replaces the anchor and every comparison
  after it is by block hash. Measured on `scripts/reth-paired-devnet.sh`, which is where a
  hash-only check would have stopped every validator from round 2 onward on an idle shard;
- both P-id post-conditions after a `VALID` commit — the executor's head must match the certified
  **block hash** *and* the certified state root;
- **P-sign enforced for restored processes** (below);
- **observation ordered before application.** The certificate is folded into the continuity state
  before the fallible `commitPrevious`, so a transient `SYNCING` no longer discards the certified
  block hash that the retry needs. `anchor.round > appliedRound` is §5.1's normal retryable state,
  and it is now reachable rather than lost;
- **applied kept separate from observed at the delivery layer** (§5 point 5). A certificate whose
  delivery to the driver failed is recorded as unapplied, so its retransmission is a retry instead
  of a suppressed duplicate; the mark is cleared on success, so a completed round is never driven —
  or signed — twice;
- `unavailable` (retryable, anchor retained) kept distinct from `invalid` (a fault);
- the refusal rows named individually — `no-anchor`, `continuity-gap`, `anchor-mismatch`,
  `head-identity-mismatch` — so a log line maps to a transition-table row. `no-anchor` (row 8) and
  `continuity-gap` (row 10) are kept apart on the live path too, because they are different operator
  situations: never having observed a certified block resolves itself on the next non-quiet
  certificate, while having lost the thread of evidence for one means this node has missed certified
  history and needs to resync.

**Not implemented:** persisting the anchor and its evidence (§3.3.4, §6), and stage 4's
missing-payload acquisition. Both stay out of this PR.

### P-sign, and the claim that was wrong

An earlier revision of this section said that because nothing is restored today there is no restored
anchor to gate, so "the gate is trivially satisfied". **That was false, and the code matched it.**
`Node.New` already loads a persisted certificate, authenticates it, calls `SeedLUC` — and then built
an unrestricted `Round`. A restarted node therefore resumed voting from its next certificate, on the
strength of a checkpoint that verification proves *genuine* but never proves *current*: an entire
older checkpoint replays perfectly (§6.1), restoring one rolls the observation cursor backwards, and
that cursor is what stops this node acting twice in a round. The absence of a restored *anchor* was
never the barrier — nothing consulted the anchor before signing (see P-id above), and one non-quiet
certificate installs one a round later anyway.

And the gap is not hypothetical. The checkpoint is written by `persistingDriver` *after*
`HandleCertificate` returns, and `HandleCertificate` has by then already submitted for the next
round. A stored certificate for round N therefore always coexists with a vote cast in round N+1:
`luc.RoundNumber` is behind the highest signed round **by construction**, not by accident. Restart,
receive the repeat certificate for N+1 that the root chain sends on timeout, and the node is back in
a round it has already voted in — free to submit a different input record for it, from a different
executor state or a different leader's block. §6.1's "an older checkpoint replays perfectly" is the
general statement; this is the ordinary case of it that happens on every clean restart.

So P-sign is now enforced, in the only way available before #105 exists: `Node.New` marks a resumed
process **non-voting for its lifetime** (`Round.MarkRestored`), and `resumeFrom` performs that and
`SeedLUC` together so restoring the cursor without the gate is not expressible in the file. Such a
node observes every certificate, maintains its continuity state, reconciles its executor and reports
its status — a warm follower, not a dead one — and its refusal to vote is visible in `Health`
(`voting: false` with a reason) rather than only in logs.

The cost is deliberate and larger than the previous revision implied: **a restarted validator
contributes nothing to quorum until it is restarted again with #105's contract in place.** A shard
that restarts more than `f` validators has a liveness problem until then. That is the fail-closed
side of a safety question the design cannot answer today, and it is the side this document requires;
the alternative is a node that may sign twice in one round, which no operator can detect.

`TestRestoredNodeIsNonVoting` drives the real sequence — `LoadLUC`, `verifyRestoredLUC`,
`resumeFrom`, then certificates through the real `Round` — and asserts both halves: nothing is
signed, and a subsequent non-quiet certificate does not re-authorize. It replaces
`TestAnchorIsNotRestoredFromDisk`'s signing half, which asserted only that two zero-valued `Round`
structs had no anchor and so passed while the node signed. When #105 lands, both tests must be
**replaced** by assertions that a restored node votes exactly when the monotonic record permits —
not deleted.

The remaining visible consequence is unchanged and still intended: a node that restarts mid-interval
has no anchor, so a quiet certificate makes it abstain with `no-anchor` rather than resuming — a
refusal with a named reason, in place of a `Commit(nil)` that could not have worked either.

## 9. Scope held open

This record does not address power-loss durability (#14), the signing contract (#105), missing-payload
acquisition (stage 4), any particular real-reth scenario in #88, or the stale-certificate taxonomy
(#93); nor does it claim #16's fake-executor stall shares this cause.

**Stage 4 continues in `f6b-quiet-tail-anchor-recovery.md`.** The live half implemented here recovers
a node once a certificate NAMES a block. Measurement then established the case it cannot reach: a
node that returns during a quiet interval receives an unbounded number of authentic certificates,
none of which names anything, and stays at `no-anchor` indefinitely. That record specifies the
authenticated evidence chain a returning node must obtain from outside itself, and explains why the
retained-history direction sketched in §6 cannot close it — the block was certified while the node
was down, so no local file can hold evidence for it.
