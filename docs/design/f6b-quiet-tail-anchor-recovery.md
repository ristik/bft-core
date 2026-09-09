# F6b stage 4: authenticated anchor recovery across a quiet tail

Issue #92. Companion to `docs/design/f6b-quiet-uc-recovery.md` (stage 2/3, referred to below as
**the stage-2 record**), which this record extends rather than replaces. Section numbers of the form
§3.3.1 refer to that document; sections of this one are numbered plainly.

**Scope of the PR this record ships in: design and fixtures only.** It adds a pure verification
predicate (`shardnode/anchorevidence.go`) and its acceptance fixtures
(`shardnode/anchorevidence_test.go`). Nothing calls the predicate from production code, no transport
is added, and no recovery behaviour changes. P-id and P-sign are untouched, and nothing here
authorises a restored node to sign — see §9.

---

## 1. The gap, as measured

The stage-3 implementation closed the case where a node that fell behind is later told about a
block: a non-quiet certificate installs an execution anchor, and `reconcile` recovers to it. What it
cannot close is the case where **no such certificate ever arrives** because the shard has nothing to
do.

Measured on a four-validator devnet against pinned reth, from a clean committed head
(`bba34435`, run `20260909T130136Z-28752`, scenario `quiet-restart`, T2 = 5s;
`docs/design/f1-baseline.md` §5.7.3):

| | |
|---|---|
| Certified block produced while validator 2's pair was down | block 3 |
| Certificates validator 2 accepted after returning | 168 deliveries over **20** distinct partition rounds (140 were retried deliveries of a round already seen) |
| Non-quiet certificates among them | **0** |
| Anchor transitions | 168 × `transition=unchanged` |
| Refusal, every round, for the whole 120s observation | `no-anchor` |
| Certification requests submitted | 0 |
| Executor head at the end of the quiet interval | block 2; the shard's head was block 3 |
| Recovery after a single injected transaction | on the **first** poll |

The feed was healthy — the subscription-renewal fix from #109 is in this revision, and the node
received every round. The node was not starved of certificates; it was starved of **certificates
that name a block**. A quiet certificate carries `BlockHash = nil` by construction, so a returning
node can receive an unbounded number of perfectly authentic certificates and still have no target to
recover to.

**Therefore the missing capability is authenticated evidence that names a block.** It is not payload
fetching (§8), not feed liveness (fixed), and not a longer timeout.

### 1.1 Why local retained evidence cannot supply it

The obvious cheap answer — persist the continuity state and reload it — does not solve this problem,
for a reason that is independent of durability engineering:

> **A node cannot hold local evidence for a block that was certified while it was down.**

The block the executor is missing was certified during the outage. Whatever this node persisted, it
persisted *before* that certificate existed. Retained history is the right tool for a node that
observed the block and then crashed; it is no tool at all for a node that was absent when the block
was certified — which is precisely the measured case above. The stage-2 record's §6.1 makes the
complementary point from the other side: a retained file is internally perfect forever, so it can be replayed, and it can
never testify that it is current.

So the evidence has to come from **outside** this node: from a peer, or from the root chain. That is
what the rest of this record specifies.

---

## 2. What the returning node must obtain

The unit is a **chain**, not a certificate.

```
AnchorEvidence
  Source          the non-quiet UC that certified the block   (names BlockHash)
  SourceTechnical the TechnicalRecord bound to it             (assigns the next round)
  Tail[]          every UC from the round Source assigned, in order,
                  up to and including the UC this node already holds,
                  each with its bound TechnicalRecord
```

Three things make the chain necessary rather than decorative:

1. **A source certificate alone proves nothing about now.** It says a block was certified at some
   past round. It cannot say the shard has been quiet since, and if the shard was not quiet then the
   source is not the last certified block and is the wrong recovery target.
2. **State equality is not history.** §3.3.1's counterexample: a missed non-quiet interval can
   return to the *same state root* behind a *different block*. A predicate that accepted a source
   because its state matches what the node holds would accept the wrong block hash — and the block
   hash is what P-id gates signing on. Fixture:
   `TestAnchorEvidence_SameStateDifferentBlockIsNotHistory`.
3. **The chain has to end where this node stands**, or it is a claim about the past. The stage-2
   record's §6.1 replayable checkpoint is exactly a complete, correctly signed chain that ends too early. Fixture:
   `TestAnchorEvidence_ReplayOfAnOlderCompleteBundle`.

### 2.1 Contiguity is by assigned round, never `+1`

Each link must be the round its predecessor's **TechnicalRecord assigned**, not `previous + 1`.
Certified partition rounds are not consecutive: the root chain abandons rounds, and on the devnet
the very first certificate did it (`partitionRound=0 … nextRound=2`). The stage-2 record's original
`through+1` test invalidated every honest node's anchor at the first skip and stalled the shard
below quorum in two minutes (§3.3.2). The assignment is authenticated — the technical record's hash
is committed in `UC.TRHash` — so "the round the previous certificate said would come next" is
evidence, not a guess, and it is *strictly tighter* than a gap test on round numbers.

The predicate therefore checks the technical record's binding explicitly. An unbound record would let
whoever serves the evidence choose the assignment that contiguity is judged against. Fixture:
`a technical record the certificate does not commit to is refused`.

### 2.2 The terminal binding: the chain must end at *the* certificate this node holds

The first form of this check compared the chain's last certificate to the held one by **partition
round and state root**. Review reproduced two ways past it with genuinely signed certificates, and
the reproductions are now fixtures:

- a round-16 certificate at the same round that **names a block** rather than being quiet. It is a
  different signed statement about round 16, and the block hash is precisely what P-id gates signing
  on;
- a round-16 certificate in a **different shard epoch**. The chain's epoch contract (§3.1) never
  fired, because the held certificate was never put through it.

The check is now: the held certificate is put through **the same authentication and the same
recovery context as the evidence** — trust base, partition, shard, configuration, epoch — and then
the two input records are compared by **`InputRecord.Bytes()`**, the canonical encoding the root
chain's signatures actually cover. That encoding is what `uc.go` already uses to decide equivocation;
it distinguishes nil from empty, and it cannot silently omit a field that the type grows later, as a
hand-written field list would. A fixture that differs *only* in the input record's timestamp — same
round, same state, same nil block, validly signed — pins that the comparison is the encoding and not
a summary of it.

"Held" means this node verified the certificate when it was **delivered**. The recovery context is a
different question from the delivery context, and re-asking it costs one signature verification.

**Two things are deliberately outside the comparison**, so that honest evidence is not refused:

- the **root round**. A repeat certificate re-certifies the same partition round at a later root
  round after a timeout, and holding one is ordinary.
- the **signature set**. Different honest providers may have observed different valid subsets.

**A mismatch is `ErrEvidenceConflict`, not `ErrEvidenceUnconnected`.** Two authenticated certificates
making different statements about one round is a fact about the certified history; no third party
can adjudicate it, and it must surface as a refusal rather than as a reason to look for a provider
that agrees (§4.1). `ErrEvidenceUnconnected` is reserved for the honest, retryable case: the chain
simply does not *reach* the round this node holds.

### 2.3 Repeat normalisation inside the tail

A repeat certificate re-certifies an already-certified round, at a later root round, with the **same
input record** and a **new technical record** — hence a new assignment. It is the ordinary product of
a root-chain timeout, so a literal transcript of what a provider observed contains repeats, and the
first form of this predicate rejected such a transcript as a `Gap`, making honest evidence
unrepresentable. Review reproduced that too.

The rule, in full:

> A tail link whose partition round equals the round just accepted is a **repeat** if its input
> record is byte-identical under `InputRecord.Bytes()` **and** its root round is strictly later. A
> repeat supersedes the **assignment** only. It does not extend the verified interval, because the
> interval is keyed by partition round (§3.3.3) and a repeat covers a round already covered.

Two failure modes fall out of it and are fixtures:

- **same round, different input record** → `Conflict`, exactly as at the terminal binding. The
  provider has handed over two authenticated statements that disagree.
- **same round, same input record, root round not strictly later** → `Gap`. Without this, a provider
  could replay one repeat to rewrite the assignment freely, which is the value contiguity is judged
  against.

---

## 3. Verification against locally configured trust, only

Every certificate in the bundle is verified against:

- the **trust base** from this node's own store, looked up by the **root epoch the certificate
  names**. Nothing travelling with the evidence may supply, hint at, or override a trust base. An
  epoch with no configured trust base is a refusal, never an adoption — fixture:
  `an epoch with no configured trust base is refused, not adopted`;
- this node's own **partition ID, shard ID and shard-configuration hash**.

The context comparison is done explicitly and **before** signature verification, even though
`UC.Verify` would also reject a mismatched certificate. `UC.Verify` reports "wrong partition" the
same way it reports "bad signature", and those are different situations: a provider serving the
wrong chain versus a provider serving a forgery. Keeping them apart is the difference between an
operator reading `ErrEvidenceWrongContext` and one reading `ErrEvidenceUnauthenticated`.

**This applies to the node's own held certificate too**, not only to the bundle. It was verified on
delivery, but the delivery context and the recovery context are different questions, and §2.2's
epoch reproduction is what happens when only the bundle is checked.

Fixtures: `another partition`, `another shard of this partition`, `another shard configuration`,
`a held certificate is authenticated against this node's own context`.

### 3.1 Epoch transitions are refused, not guessed

A shard epoch change moves the validator set and the configuration with it. A chain that crosses one
is refused with a distinct outcome, `ErrEvidenceEpochChange`, rather than being decided by this
predicate. Saying "unsupported" is safe; a wrong answer here chooses a block hash. The epoch compared
is the **source's**, and every certificate in the bundle *and the held certificate* is held to it, so
an epoch change at either end of the chain fires the contract. Fixtures:
`a chain crossing a shard epoch boundary is unsupported, not guessed at`,
`a held certificate in another epoch fires the epoch contract`.

Recovery across an epoch boundary is left open (§10).

---

## 4. Resource bounds, retry, cancellation, named outcomes

The size and shape of the bundle are chosen by whoever serves it, so it is attacker-controlled work.

- **Bounds** (`AnchorEvidenceLimits`): `MaxCertificates` (default 512, the same order as the stage-2
  persisted-continuity bound) and `MaxBytes` (default 1 MiB).
- **Both bounds must be positive.** A zero previously meant "unlimited", which is the wrong default
  for a value an integration can forget to set: forgetting must fail loudly
  (`ErrEvidenceLimitsInvalid`), not silently remove the bound everything else relies on.
- **`MaxBytes` covers the COMPLETE bundle — every certificate *and* every technical record.**
  Measuring only the certificates was a real hole, not a tidiness point: `TechnicalRecord.Leader` is
  a string and `StatHash`/`FeeHash` are byte strings, all attacker-controlled, so a small certificate
  could carry a megabyte of technical record that `tr.Hash()` was then handed — *after* the
  certificate's signature had already been verified. Fixture: an oversized technical record is
  refused with `Exhausted` and the trust-base store is asserted **never consulted**.
- **Bounds are applied before any hashing or signature work**, so nothing an adversary puts in a
  bundle can buy cryptographic work before the bound has been applied.
- **Exceeding a bound is a named refusal, never a truncation.** A shortened chain is not evidence of
  anything, and silently accepting a prefix would reintroduce exactly the "stops short" hole of
  the stage-2 record's §6.1.
- **This is not a network allocation bound, and must not be mistaken for one.** By the time the
  predicate runs, a decoder has already materialised whatever arrived. **The transport that fetches
  a bundle must cap its own read and decode independently** — a frame cap on the wire, before
  decoding, at or below `MaxBytes`. That cap belongs to the transport decision (§6) and is stated
  here so it is not lost between the two.
- **Cancellation** is by `context.Context`, threaded to the trust-base lookup, so a caller waiting on
  a provider is not pinned by one.

### 4.1 Outcomes, and which of them another provider could fix

Retry is the caller's, not the predicate's. The predicate is pure and deterministic — the same
bundle yields the same verdict every time — and it exports `Retryable(err)` so the classification
lives with the outcomes rather than being re-derived at each call site.

Getting this wrong in the strict direction is the expensive one: **`Unconnected` is the ordinary case
of a peer that holds less than the requester needs**, and treating it as fatal would let a single
unhelpful or malicious peer end a recovery that its neighbour would have completed. Only refusals
that state something about the shard's own history, or about the caller, are non-retryable.

| Outcome | Meaning | Another provider could help |
|---|---|---|
| `ErrEvidenceMalformed` | structurally incomplete bundle | yes |
| `ErrEvidenceSourceQuiet` | the source names no block, so it cannot be an anchor | yes |
| `ErrEvidenceUnauthenticated` | a certificate did not verify against the configured trust base, or its root epoch has none | yes |
| `ErrEvidenceWrongContext` | wrong partition, shard or shard configuration, or an unbound technical record | yes |
| `ErrEvidenceGap` | a certificate is not the round its predecessor assigned, or a repeat did not follow at a later root round | yes |
| `ErrEvidenceNotQuiet` | a certificate after the source moved the state, so the source is not the last block | yes |
| `ErrEvidenceExhausted` | over the configured bounds | yes |
| `ErrEvidenceUnconnected` | the chain does not **reach** the round this node holds — stale or truncated | **yes** |
| `ErrEvidenceEpochChange` | the chain, or the held certificate, crosses an epoch boundary | no — every honest provider will say the same |
| `ErrEvidenceConflict` | two authenticated certificates disagree about one round | no — no third party can adjudicate this |
| `ErrEvidenceLimitsInvalid` | the caller passed no positive bound | no — a caller bug |

## 5. Four cursors, kept separate

The stage-2 record separates observation from application (§5). Recovery across a quiet tail needs
one more distinction, so this design names **four** cursors and forbids any code path from
collapsing them:

| Cursor | What it records | Moved by | Consequence of moving it wrongly |
|---|---|---|---|
| **Observed** | the highest partition round this node has verified a certificate for, and the assignment it carries | receiving and authenticating a certificate | a gap is missed; the anchor is trusted when it should not be |
| **Verified anchor** | the block hash and state root a chain of evidence proves is the last certified block | this predicate, or a live non-quiet certificate | the executor is asked to recover to the wrong block |
| **Applied** | what the executor has actually committed | the executor confirming a commit | P-id refuses; the node stops signing |
| **Signed** | the highest partition round this node has signed in — monotonic, crash-safe, non-rollback | signing, and nothing else | **equivocation**: a node resumed from a stale record signs twice in one round |

The verified anchor is a *new* cursor and not a synonym for either neighbour. It can be ahead of
Applied — that is the entire point of §7's "payload unavailable" case, where the target is known and
verified but the block body has not arrived yet — and it must never be read as touching Signed.
`Signed` is #14/#105's subject and is not supplied here; see §9.

---

## 6. Where the evidence comes from: the choice, and the recommendation

Three candidate sources, compared against the measured situation (§1) rather than in the abstract.

**(a) Local retained history.** *Rejected for this problem.* §1.1: the node cannot hold evidence for
a certificate that did not exist while it was running. It also cannot testify to its own currency
(the stage-2 record's §6.1). It remains useful for the *different* problem of a node that observed a block and crashed,
which is #14's subject — but it does not overlap with the case measured here, so implementing it
would not close #92.

**(b) Peer evidence retrieval** — ask other shard validators for the chain. Peers *receive* exactly
these certificates in the ordinary course of running, and they make availability depend on peers —
but *only* availability: a peer that lies, omits or truncates is caught by §2–§4, and the worst it
can do is fail to help. That is the property the predicate exists to guarantee.

It requires a new shard-internal request/response protocol alongside the existing dissemination
protocol (`/unicity/shard-payload/1.0.0`) **and the retention work in §6.1**, which an earlier
revision of this record wrongly claimed was already done.

**(c) Root-chain evidence retrieval** — ask the root chain to replay the certificates it issued.
Authoritative, and it needs no shard-side storage. But the root chain does not today serve historical
certificates on request, the subscription quota is already the scarce resource that caused #92's
earlier restart refusals (#109), and adding a per-shard-node historical query widens the root chain's
attack surface for a shard-local problem.

**Recommendation: (b), peer evidence retrieval, as the smallest implementation that closes the
measured gap** — one shard-internal request/response protocol plus a bounded in-memory serving
buffer (§6.1), no new *persistent* state, no root-chain change, and no new trust. (c) stays a
reasonable second source if peer availability proves insufficient in practice; (a) is orthogonal and
belongs to #14.

### 6.1 What a provider must retain — the missing enabling work

An earlier revision of this record asserted that peers "hold exactly these certificates … so nothing
new has to be stored". **That is wrong, and review was right to reject it as an implementation
basis.** What the code actually retains today:

- `continuityState` (`shardnode/anchor.go`) keeps the *anchor*, the round it covers and the next
  assignment. It keeps no certificates and no technical records at all.
- `FileStore.SaveLUC` (`shardnode/store.go`) **atomically overwrites** one certificate. There is one
  slot, deliberately, and no history.

So a peer today can *verify* the chain in §2 but cannot *serve* it. The enabling work is a bounded
serving buffer, specified here and implemented in a later PR:

**Contents.** A ring of `(UC, TechnicalRecord)` pairs in observation order, plus a pointer to the
most recent **non-quiet** entry — the source. Both halves are needed: the source names the block, the
ring supplies the tail. Nothing is added that the node does not already receive and authenticate.

**Bounds and eviction.** Bounded by entry count and by bytes, oldest-evicted-first, and sized so that
the buffer can serve a tail at least as long as `AnchorEvidenceLimits.MaxCertificates`. If evicting
would drop the current source, the buffer drops **the whole interval** and reports itself unable to
serve, rather than retaining a source it can no longer connect to the present. Bounded memory is not
optional here: the buffer's size is driven by how long a shard stays quiet, which is unbounded.

**Readiness, and named unavailable outcomes.** A provider is *ready* only once it holds a non-quiet
source and an unbroken tail from it to its own latest certificate. A freshly restarted peer is **not
ready** and serves nothing — its buffer is in memory, so a peer restart erases its serving capacity
entirely. Three distinct refusals, none of which is a verification failure and all of which the
requester should treat as "ask someone else":

| Provider outcome | When |
|---|---|
| `not-ready` | no non-quiet source observed since this process started |
| `evicted` | the requester's held round is older than the buffer's oldest entry |
| `behind` | the requester's held round is newer than anything this provider has observed |

**Assembling a chain while new certificates keep arriving.** The requester pins the request to the
certificate **it** holds — partition round plus the canonical input-record identity of §2.2 — and the
provider answers from a **snapshot** taken under the same lock that appends new observations. It
serves `[source … requester's held round]` and simply does not include anything later, so a
certificate arriving mid-assembly can neither lengthen nor truncate the answer. If the provider's own
view has moved past the requester's held round, that is normal and harmless: the extra entries are
outside the requested window. If the provider is *behind* the requester, it says so rather than
serving a short chain, because a short chain is refused at the far end anyway (§2.2) and saying so
lets the requester pick a better peer immediately.

**Why in-memory is enough for now.** The measured failure is a node returning into a *live* shard,
where peers have been running throughout — exactly the case an in-memory buffer covers. Persisting
the buffer would additionally cover "the whole shard restarted", which is a different scenario and
brings the durability and freshness problems of the stage-2 record's §6.1 with it. Deferred, not
forgotten.

**The security claim, stated so it can be checked:** an untrusted evidence provider may affect
**availability** — it can refuse, stall, or serve a chain that the predicate then rejects — and
nothing else. It cannot choose finality through an unauthenticated block hash, because the block
hash that becomes an anchor is only ever read out of a certificate that verified against this node's
own trust base and own configuration. The fixtures in §7 are the check on that claim: a forged,
truncated, re-contexted, epoch-shifted, replayed or oversized bundle all fail, and they fail with
distinct names.

---

## 7. Acceptance fixtures

`shardnode/anchorevidence_test.go`. Every certificate is genuinely signed and genuinely verified
against a trust base the "node" configures itself — there is no stub for the authentication step,
because authentication is the property under test. The fixtures are deterministic: fixed hashes,
fixed rounds, no clock, no network. Rounds are deliberately non-consecutive (10 → 12 → 16) so that
any reintroduction of `+1` arithmetic fails.

| Required case | Fixture | Refusal |
|---|---|---|
| Valid quiet-tail recovery, no new transactions | `QuietTailRecoversWithoutNewTransactions` | — (accepted; block hash, round 10) |
| Missing middle evidence | `a missing middle certificate is a gap, not a shortcut` | `Gap` |
| Altered middle evidence | `an altered middle certificate no longer authenticates` | `Unauthenticated` |
| Unbound technical record | `a technical record the certificate does not commit to is refused` | `WrongContext` |
| Interval not actually quiet | `a non-quiet certificate inside the tail is refused` | `NotQuiet` |
| Source names no block | `a source that names no block is refused` | `SourceQuiet` |
| Wrong partition / shard / config | `another partition`, `another shard of this partition`, `another shard configuration` | `WrongContext` |
| Wrong / unknown epoch | `a chain crossing a shard epoch boundary…`, `an epoch with no configured trust base…` | `EpochChange`, `Unauthenticated` |
| Same state, different block | `SameStateDifferentBlockIsNotHistory` | `Gap` |
| Replay of an older complete bundle | `a correct chain that stops short…`, `the same chain replayed after the node has moved on…` | `Unconnected` |
| Exhausted bounds | `too many certificates`, `too many bytes`, `bounds are checked before any signature work` | `Exhausted` |
| Payload unavailable, verified target retained | `VerifiedTargetSurvivesAnUnavailablePayload` | — |

Added in this revision, from review:

| Case | Fixture | Refusal |
|---|---|---|
| Held certificate names a block (different statement about the round) | `a held certificate naming a block is a different statement about that round` | `Conflict` |
| Held certificate names a block at an unchanged state | `a held certificate naming a block at an UNCHANGED state cannot exist` | `Unauthenticated` (invalid input record — recorded so the reason is not confused with the row above) |
| Held certificate in another epoch | `a held certificate in another epoch fires the epoch contract` | `EpochChange` |
| Held certificate differing only in a field the state does not show | `a held certificate differing only in a field the state does not show conflicts` | `Conflict` |
| Held certificate at a different state | `a held certificate at a different state conflicts` | `Conflict` |
| Held certificate not authenticated in the recovery context | `a held certificate is authenticated against this node's own context` | `Unauthenticated` |
| Held repeat certificate (must be accepted) | `a repeat certificate for the held round…` | — |
| Repeat inside the tail updating the assignment (must be accepted) | `a repeat that updates the assignment is accepted` | — |
| Repeat replayed at the same root round | `a repeat must follow at a strictly later root round` | `Gap` |
| Two disagreeing certificates for one round inside the tail | `two certificates for one round that disagree are a conflict, not a repeat` | `Conflict` |
| Oversized technical record | `an oversized technical record is refused before any trust-base work` | `Exhausted`, trust base asserted never consulted |
| Bound measured over the whole bundle | `the bound is measured over certificates and technical records together` | `Exhausted` |
| Missing (non-positive) bound | `a missing bound is a refusal, not unlimited` | `LimitsInvalid` |
| Retry classification of every outcome | `RetryClassification` | — |

**Mutation check.** Each load-bearing check was individually disabled and the suite re-run, to
confirm the fixtures are not passing for an unrelated reason:

| Check disabled | Fixtures that fail |
|---|---|
| assigned-round contiguity | `a missing middle certificate is a gap…`, `SameStateDifferentBlockIsNotHistory` |
| chain reaches the held partition round | `a correct chain that stops short…`, `the same chain replayed after the node has moved on…` |
| terminal input-record identity | `a held certificate naming a block…`, `a held certificate differing only in a field the state does not show…` |
| held certificate authenticated in the recovery context | `…at an UNCHANGED state cannot exist`, `…in another epoch fires the epoch contract`, `…authenticated against this node's own context` |
| repeat input-record identity | `two certificates for one round that disagree are a conflict, not a repeat` |
| repeat root-round monotonicity | `a repeat must follow at a strictly later root round` |
| bundle size bound covering technical records | `an oversized technical record…`, `the bound is measured over certificates and technical records together` |

The reviewer's three independent reproductions (`review112_test.go`) were also run against this
revision: all three now fail their `require.NoError` / `require.ErrorIs(Gap)` assertions, which is
the direction that means the reproduced behaviour is gone.

---

## 8. Payload acquisition is a separate decision

The assignment asked for the existing reth ancestor-acquisition path to be traced before any custom
fetch mechanism is proposed. Traced, from `reth2.log` in run `20260909T130136Z-28752`:

```
13:02:46.670  Canonical chain committed number=2                       <- executor head before the outage
13:03:15.640  Loaded persisted peers count=3                           <- pair restarted; 3 peers throughout
              ... 2m37s of quiet certified rounds; head stays at 2 ...
13:05:52.951  Received forkchoice updated message when syncing
              head = safe = finalized = 0xfe3e6308…   (block 4)
13:05:52.970  State root job finished  elapsed=6.6ms
13:05:52.993  Block added to canonical chain number=3  (0xc4942523…)   <- the block missed during the outage
13:05:53.037  Block added to canonical chain number=4  (0xfe3e6308…)
13:05:53.080  Canonical chain committed number=4
```

**What this establishes, and only this.** In this run, the block missed during the outage was
**canonicalised through the existing client** after a forkchoiceUpdated named a descendant, with no
BFT-side fetch of any kind. The node was down when block 3 was certified and built nothing
afterwards, so it never received block 3 by `newPayload`.

**What it does not establish.** The logs do not identify the **acquisition source** and say nothing
about **availability in general**:

- they cannot distinguish "reth backfilled block 3 from its peers on receiving the forkchoice
  update" from "reth already held block 3 via P2P gossip during the outage and merely canonicalised
  it at the forkchoice update". The 42 ms is not a trace of a mechanism, and no inference is drawn
  from it here;
- one run with three connected peers and a two-block gap says nothing about a longer outage, a
  partitioned peer set, or a node with no peers holding the block.

An earlier revision of this record said "ancestor acquisition is already solved by the execution
client". That overstates the evidence and has been withdrawn. The accurate statement is: **no custom
payload-fetch mechanism is justified yet**, and the way to establish the existing path properly is an
RPC/network trace of the execution client, or a controlled peer-connectivity experiment that varies
which peers hold the missing block. That is the next measurement, not a design conclusion.

**Consequence for the design, which is unaffected either way.** Evidence retrieval and payload
acquisition stay separate decisions. The predicate answers only the first. A node that has a verified
anchor but cannot yet obtain the block body **keeps the verified target** and retries acquisition,
rather than falling back to `no-anchor` and re-verifying from scratch — which is what the verified-
anchor cursor in §5 is for, and what `VerifiedTargetSurvivesAnUnavailablePayload` pins.

---

## 9. What this design deliberately does not change

- **P-id is unchanged.** The executor's head must still equal the certified *block*, not merely the
  state root. Recovery supplies the block hash that makes P-id satisfiable; it does not relax it.
- **P-sign is unchanged.** A recovered executor is **not** authorisation to vote. Reaching the
  certified block makes a node correct; what makes it *safe to sign* is the monotonic, crash-safe,
  non-rollback record of the highest partition round it has signed in — the stage-2 record's §6.1 contract, #105's
  subject. Nothing in this record supplies it, and no path here may be read as supplying it. A node
  that recovers its executor through this mechanism stays non-voting until #105 lands.
- **No production behaviour changes in this PR.** The predicate is unwired by construction: the
  transport, the provider-selection policy and the resource policy around it are still open (§6),
  and the part whose correctness is decidable today is the predicate. Every later decision is to be
  checked against it, not the other way round.

---

## 10. Scope held open

Recovery across an epoch transition (§3.1); provider selection, rate limiting and the transport's own
frame cap for peer evidence retrieval (§4); implementing the serving buffer of §6.1, and whether it
is ever persisted; whether the root chain should serve historical certificates as a second source
(§6c); durable retained history and the signing record (#14, #105); and the acquisition-source
measurement §8 does not have. #16 remains open, including "Too deep reorg", and nothing here claims
to explain it.
