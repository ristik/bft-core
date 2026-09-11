# F6b stage 4: authenticated anchor recovery across a quiet tail

Issue #92. Companion to `docs/design/f6b-quiet-uc-recovery.md` (stage 2/3, referred to below as
**the stage-2 record**), which this record extends rather than replaces. Section numbers of the form
§3.3.1 refer to that document; sections of this one are numbered plainly.

**Scope note.** The predicate (§2–§5) and this record shipped in #112 as design and fixtures only.
The serving buffer of §6.1 shipped next, without transport or recovery wiring. The transport and the
serving integration of §6.2 shipped after it: a node retains what it observes and answers requests
for it. The requester coordinator of §6.3 shipped next, against injected transport and observation
interfaces: a node can now obtain and verify an anchor for the certificate it holds, and hold it as a
READY TARGET. The target applier of §6.4 shipped after it, against an injected executor and target
source. Production startup still constructs none of it and `Round` calls none of it, so no deployed
node recovers anything yet; that wiring, and the measured run against a real client, are the next
unit. The scope paragraph below describes #112 and is kept as written at
the time.

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

- **same round, different input record** → `CandidateSplit`. The provider has handed over two
  authenticated statements that disagree; the bundle is evidence of equivocation and is refused. It
  is a *different* outcome from the terminal `Conflict` of §2.2, because both halves came from this
  provider and neither is a statement this node made — see §4.1.
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

### 3.1 Epoch transitions refuse the candidate — and only the candidate

A shard epoch change moves the validator set and the configuration with it. A chain that crosses one
is refused with a distinct outcome, `ErrEvidenceEpochChange`, rather than being decided by this
predicate. Saying "unsupported" is safe; a wrong answer here chooses a block hash. The epoch compared
is the **source's**, and every certificate in the bundle *and the held certificate* is held to it, so
an epoch change at either end fires the contract.

Two corrections from review, both about how far that refusal reaches:

**The comparison happens AFTER signature verification, not before.** `InputRecord.Epoch` is a field
in a signed structure, but a provider can alter it in transit; checking it first meant one flipped,
unsigned byte of an otherwise genuine certificate produced `EpochChange` instead of
`Unauthenticated`. An altered certificate is a forgery and must be reported as one. Only a
certificate that actually verifies is allowed to say anything about epochs.

**An epoch-crossing candidate is not a fact about the shard.** Ordering alone would not have been
enough. *The source is selected by the provider*, so even a perfectly genuine old-epoch chain shows
only that **this** candidate crosses a boundary — another provider may hold a same-epoch source for
the very same held round. `EpochChange` is therefore **retryable** (§4.1): it refuses the candidate
and does not end the recovery attempt.

Fixtures: `a chain crossing a shard epoch boundary is unsupported, not guessed at`,
`a held certificate in another epoch fires the epoch contract`,
`a tampered epoch is a forgery, and the next provider is still consulted`,
`a genuine epoch-crossing candidate does not prove every candidate crosses one`.

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

The independent transport cap is now implemented; §6.2 records what it is and why it is not the
repository's shared framing helper.

### 4.1 Outcomes, and which of them another provider could fix

Retry is the caller's, not the predicate's. The predicate is pure and deterministic — the same
bundle yields the same verdict every time — and it exports `Retryable(err)` so the classification
lives with the outcomes rather than being re-derived at each call site.

**The rule**, stated so it can be applied to outcomes added later:

> A refusal may terminate the whole recovery attempt **only** if it is a conclusion about the shard's
> certified history drawn from something this node authenticated **independently of the candidate** —
> in practice, its own held certificate. Everything decided from bundle content is a statement about
> *this candidate*, and a candidate is chosen by the provider.

Getting this wrong in the strict direction is the expensive one: treating a candidate refusal as
fatal lets a single unhelpful or malicious peer end a recovery that its neighbour would have
completed. Review found exactly that, twice over, behind `EpochChange` — first reachable from an
unsigned byte, and then still wrong even once signed, because the provider chooses the source.

Applied, the rule leaves **two** non-retryable outcomes:

| Outcome | Meaning | Another provider could help |
|---|---|---|
| `ErrEvidenceMalformed` | structurally incomplete bundle | yes |
| `ErrEvidenceSourceQuiet` | the source names no block, so it cannot be an anchor | yes |
| `ErrEvidenceUnauthenticated` | a certificate did not verify against the configured trust base, or its root epoch has none | yes |
| `ErrEvidenceWrongContext` | wrong partition, shard or shard configuration, or an unbound technical record | yes |
| `ErrEvidenceGap` | a certificate is not the round its predecessor assigned, or a repeat did not follow at a later root round | yes |
| `ErrEvidenceNotQuiet` | a certificate after the source moved the state, so the source is not the last block | yes |
| `ErrEvidenceExhausted` | over the configured bounds | yes |
| `ErrEvidenceUnconnected` | the chain does not **reach** the round this node holds — stale or truncated | yes |
| `ErrEvidenceEpochChange` | **this candidate** crosses an epoch boundary | **yes** — the source is the provider's choice |
| `ErrEvidenceCandidateSplit` | two certificates **inside the bundle** disagree about one round | **yes** — both halves came from this provider |
| `ErrEvidenceConflict` | the candidate's terminal certificate and **this node's own** authenticated certificate disagree | no — one half of the contradiction is ours |
| `ErrEvidenceLimitsInvalid` | the caller passed no positive bound | no — a caller bug |

`CandidateSplit` is a refusal in its own right: two authenticated certificates for one round that
disagree are evidence of equivocation and the bundle must not be used. It is separated from
`Conflict` because the two differ precisely in whether this node contributed half of the
contradiction, which is the rule above.

**Retrying must be bounded.** `Retryable` says a further attempt is *not pointless*; it does not say
"loop". The caller carries a fixed attempt budget across providers, so that a supply of retryable
refusals cannot keep a recovery attempt alive indefinitely — which is the same reasoning as the
resource bounds in §4, applied to attempts instead of bytes.

Fixture `ACandidateRefusalDoesNotEndTheAttempt` models a caller consulting providers in turn and
asserts the observable consequence: the second provider **is** consulted after a tampered-epoch and
after a genuine epoch-crossing candidate, and is **not** consulted after a terminal conflict.

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
(Refined below: non-quiet entries live *in the ring* rather than behind a single pointer.)

**Bounds and eviction.** Bounded by entry count and by bytes — **both hard**, with no "keep at least
one entry" floor (see the correction below) — oldest-evicted-first, and sized so that
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
| `evicted` | the requester's held round, or the source that round needs, has fallen out of the ring |
| `behind` | the requester's held round is newer than anything this provider has observed |

**Older sources, not just the latest one.** A single "latest non-quiet source" pointer is not enough,
and the reason is worth stating because it is easy to get wrong: once a newer non-quiet certificate
arrives, a request pinned to an *older* held round can no longer be answered from that pointer — the
window `[source … older held round]` needs the source that was current *then*. The buffer therefore
retains non-quiet entries in the ring like any other, and assembly selects **the latest non-quiet
entry at or before the requester's held round**. If no such entry survives in the buffer, the answer
is an explicit unavailable outcome, never a chain from a source the requester's round does not follow.

**Eviction maps to a named outcome, not to silence.** Dropping the oldest entries can remove the
source a given request would have needed, and the provider must say which case it is rather than
serving something shorter: `evicted` when the requester's held round, or the source it would need,
has fallen out of the ring; `not-ready` when this process has observed no non-quiet source at all
since it started; `behind` when the provider has not itself reached the requester's held round.

**Assembling a chain while new certificates keep arriving.** The requester pins the request to the
certificate **it** holds — partition round plus the canonical input-record identity of §2.2 — and the
provider answers from a **snapshot** taken under the same lock that appends new observations. It
serves `[source … requester's held round]` and simply does not include anything later, so a
certificate arriving mid-assembly can neither lengthen nor truncate the answer. If the provider's own
view has moved past the requester's held round, that is normal and harmless: the extra entries are
outside the requested window. If the provider is *behind* the requester, it says so rather than
serving a short chain, because a short chain is refused at the far end anyway (§2.2) and saying so
lets the requester pick a better peer immediately.

**Implemented in `shardnode/evidencebuffer.go`** (`EvidenceBuffer.Observe` / `.Assemble`), with two
refinements that only became visible while writing it, both recorded here because they change the
contract rather than the code:

- **Sequence, epoch and repeat handling happen at observation time, not at assembly time.** The ring
  is therefore at all times a single unbroken same-epoch interval, one entry per partition round,
  each carrying the latest assignment for that round. Assembly reduces to choosing a window, which
  is what makes "never synthesise a proof" checkable by reading one function instead of auditing
  every path through two.
- **A duplicate is distinguished from a look-alike by the committed assignment.** Two certificates
  can carry the same input record at the same root round and still commit to *different* technical
  records. That is not a retransmission, it is a contradiction, and treating it as a duplicate would
  silently retain whichever arrived first. Duplicate requires identical input record, identical root
  round **and** identical `TRHash`; anything else for an already-retained round abandons the
  interval and rebuilds from the newest observation. Whether a shard node should also raise
  equivocation from that is #93's taxonomy and is not decided here.

Two further points the implementation makes explicit. Eviction is plain oldest-first, with no
special case for a source, because assembly asks the sharper question anyway — whether a source
survives *at or before the requested round*. And an observation is refused outright (rather than
retained) in exactly one case beyond malformed input: a technical record the certificate does not
commit to. The caller has already authenticated the certificate; that binding is re-checked because
what is retained will later be handed to somebody else, and the assignment inside it is what
contiguity is judged against at both ends.

**A bound with a floor is not a bound.** The first implementation kept the newest entry even when it
exceeded `MaxBytes`, so retention could sit a whole certificate above the configured limit — and
exactly where certificates are largest, since per-certificate size is driven by validator-set size.
Both bounds are now hard, and a pair that alone cannot fit is **refused** with a named outcome rather
than retained in violation of the limit: that is a *configuration* result, not malformed input (the
certificate may be perfectly genuine and simply larger than this node was configured to hold, and the
actionable response is to raise `MaxBytes`). The interval is abandoned with it, because a round this
node cannot retain is a round it can no longer prove an interval across, and the alternative — a
served chain with a hole where that certificate belongs — is precisely what the far end must refuse.

**Quiet means quiet *at the interval's state*, and both ends must say so identically.** The predicate
requires every certificate after the source to name no block **and** to stand at the source's state,
carried forward round by round (`ErrEvidenceNotQuiet`, §2). The first implementation classified
retention on the block hash alone, which is strictly weaker: a certificate that names no block and
stands at a state this interval never reached is quiet by that test, was retained as an ordinary
link, and could be served inside a window — a chain the buffer assembled successfully and the far end
then refused. That is not merely wasted work; it spends one of the requester's bounded attempts
(§4) on evidence the provider could see was unusable, and a provider that does that is
indistinguishable from one that is stalling. Observation therefore applies the predicate's own test,
and an interval that cannot satisfy it is abandoned rather than bridged. (An input record whose state
*changed* must name a block, so the shape that authenticates and still breaks this rule is the one
standing at another state, not the one that moves it — the moving one never verifies at all. The
buffer authenticates nothing itself, so it enforces both arms regardless.)

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

### 6.2 The wire, and the serving integration

Implemented in `shardnode/evidencetransport.go` (`ProtocolAnchorEvidence`,
`/unicity/shard-anchor-evidence/1.0.0`), with the retention side wired in `Round.HandleCertificate`.
One request, one response, one stream. What the transport decides and what it refuses to decide:

**It carries; it does not judge.** No signature is checked on this path, no trust base is consulted,
and the bundle is handed to the caller exactly as it arrived. Verification is
`VerifyAnchorEvidence` against the receiving node's OWN configuration (§3), and duplicating any part
of it here would create a second place where "is this evidence true" is answered — the place an
attacker would then work on. The transport's contract stops at delivery, and a test states it
directly: a bundle that arrives intact, within every bound, from a signer outside this node's trust
base is delivered by the wire and refused by the predicate.

**Bounds, and why they are the transport's own.** §4's bounds apply to a bundle this process already
holds, so by the time they run a decoder has allocated whatever arrived. These apply first:

| Bound | Default | What it stops |
|---|---|---|
| `MaxRequestBytes` | 4 KiB | an expensive "request" |
| `MaxResponseBytes` | `AnchorEvidenceLimits.MaxBytes` + 4 KiB | decoding a bundle the predicate would refuse anyway |
| `MaxCertificates` | 512, the predicate's own | carrying a chain already established as unacceptable |
| `Deadline` | 5 s | a stream opened and then left silent |
| `MaxPendingStreams` | 32 | streams that never become requests at all |
| `MaxPendingStreamsPerPeer` | 4 | one peer occupying the whole global budget |
| `MaxConcurrentServes` | 4 | one peer occupying a provider's assembly |

The order inside `readFrame` is the point: the DECLARED length is checked against the bound before
anything is allocated and before the decoder sees a byte, so a peer announcing a gigabyte costs one
varint. A fixture proves the ordering rather than asserting it — the reader refuses to yield
anything past the length prefix, so a bound applied after the body would fail loudly. The shared
helper (`network.deserializeMsg`) has no such cap, which is correct for protocols whose messages are
bounded by construction and wrong for this one; it is deliberately not reused, and the framing
convention it defines (uvarint length, CBOR body) is kept so the wire style stays the repository's.

**The response bound is not tighter than the predicate's**, and that is asserted, not assumed: two
bounds that disagree about the same bundle would mean a chain the predicate accepts being refused by
the transport carrying it. Hence the explicit wrapper allowance rather than a shared constant used
twice.

**Refusals are codes, not prose.** The outcome code is the whole of a response's meaning; the detail
string is diagnostic and is read by nothing on either side. An UNRECOGNISED code is a transport
failure — never silently mapped to a particular refusal, and never to success. Success is code zero
with a bundle, so a truncated or empty response cannot be mistaken for an answer, and a refusal that
arrives carrying a bundle is still a refusal. Each of those is a fixture, because each is a way a
hostile provider could otherwise steer a requester without forging anything.

**Admission is two tiers, and the first one is before the first byte.** Review found the original
single tier insufficient, and the reasoning is worth keeping: `MaxConcurrentServes` counts
*assembly*, which only a well-formed request reaches, so a peer that opens streams and sends nothing,
half a length prefix, or a body it never finishes never reaches it. Those streams were then bounded
only per stream, by the deadline, and not in aggregate — and **one request per stream is not one
request per connection**, because libp2p multiplexes as many streams over one connection as a peer
likes.

So a stream takes a slot *before anything is read* and holds it until the handler exits — through the
read, the assembly and the response write alike — and the slot is bounded **globally and per peer**.
Per peer matters on its own: a global bound alone is a bound on the whole shard's access to one
provider, and one peer holding all of it refuses every honest validator, which is the same
availability loss this protocol exists to repair arriving from the other direction. A stream that is
not admitted is **reset and told nothing** — writing a refusal into a stream whose peer may still be
writing its request is exactly the deadlock the read-first ordering avoids, and the reset says all
there is to say. Slots are released on every exit path, because one leaked by an early return is a
bound that erodes to zero over a process's life.

**These are this protocol's own bounds.** A libp2p resource manager, where one is configured, may
refuse streams before the handler runs, but nothing here relies on that: an unconfigured or
permissive host must not remove this protocol's limits.

**Within an admitted stream the request is read first, and only then is the assembly tier applied.**
Refusing after admission but before reading would leave a requester writing into a stream nobody
drains, which deadlocks on any transport that does not buffer; the read being refused is one bounded
frame, far cheaper than the assembly the second tier protects. Over that bound a request is refused
immediately rather than queued: a queue is somewhere for an attacker's work to accumulate. No loop,
so one stream is one request by construction rather than by policy.

**A provider applies the requester's bounds to its own answer.** Both ends know the shared defaults,
so a provider that can see its answer would be refused sends a named outcome instead — that is one
attempt saved for a requester whose attempts are bounded (§4).

**Requests are pinned, on the wire as in the buffer.** Round plus canonical input-record identity; a
request naming only a round is refused, because answering it would mean choosing which certificate
for that round the requester "probably" meant (§2.2).

**Cancellation acts on the stream, because nothing else can.** Once a read or a write has begun, a
context check cannot interrupt it — the goroutine is inside the transport, and a deferred reset on
the failure path runs only after that I/O has already returned. The client therefore watches the
context and **resets the stream** when it ends, which is what unblocks the I/O; the watcher is
stopped and joined before the call returns, so a completed exchange leaves nothing behind that could
reset a stream later. A cancelled or expired context is reported as itself rather than as whatever
I/O error the reset produced, because the latter says nothing about why the attempt ended. "Expired"
is decided from the DEADLINE, not from `ctx.Err()` alone: the stream's deadline is the context's, so
at the instant it passes two timers are due, and when the connection's fires first the I/O returns
`i/o timeout` while `ctx.Err()` is briefly still nil. A deadline that has passed is an expired
context whether or not its goroutine has run yet, and the caller is owed its own budget as the
reason rather than a socket error.

**One budget, not two.** The whole call — dialing included — runs under the caller's context narrowed
by `Deadline`, and the stream's deadline is that derived context's deadline. Setting `now + Deadline`
after dialing restarted a budget the caller had already begun spending, and ignored an earlier
deadline the caller had set.

The server half makes no such promise about an `io.ReadWriter`, and says so: `Serve` does bounded
blocking I/O on whatever it is given, and what makes a stalled peer bounded there is the deadline the
caller sets on the stream plus the finite admission slot — its context check only stops work that has
not started. A transport with no deadline support gives `Serve` no cancellation contract at all, and
that is a property of the transport rather than something `Serve` can supply.

**What this transport does NOT do.** It asks ONE provider, ONCE. Which providers to ask, in what
order, and how many attempts to spend are the requester's decisions, and they depend on what the
predicate said about the last candidate (§4.1) — a transport that also made them would be a recovery
mechanism whose policy could not be reviewed apart from its framing.

**The serving integration.** `Round.SetEvidenceBuffer` attaches a buffer, and
`Round.HandleCertificate` feeds it, before any fallible work and never able to fail the round — the
same ordering the anchor itself depends on (§5), for the same reason: a certificate that names a
block is retained when it VERIFIES, not when this node manages to act on it, so a transient executor
failure does not also erase this node's ability to help somebody else. A node with no buffer never
registers the protocol and serves nobody, and no round outcome changes either way. Nothing here
recovers anything: using somebody else's buffer to repair this node's own anchor is the next unit,
and P-id and P-sign are untouched.

**Deployment activation is deliberately still open.** `SetEvidenceBuffer` and
`EvidenceServer.Register` are API integration points; production startup calls neither yet, so no
deployed node serves evidence until that is wired — its own decision (which nodes serve, under which
bounds, and how the buffer's memory is accounted alongside the round path). Stated here so the gap
between "implemented" and "in service" is not mistaken for an oversight.

### 6.3 The requester coordinator

Implemented in `shardnode/evidencerequester.go`. The transport asks one provider once (§6.2) and the
predicate decides whether an answer is worth anything (§2–§4); neither of them decides *policy*, and
this is where that policy lives — in one place, so it can be reviewed apart from framing and apart
from verification.

**One feed, and it is what this node authenticated.** `Observe` takes every certificate the node
verifies, the same feed the serving buffer gets. The certificate the node is being asked to build on
is the last of them, rather than a second input that could disagree with the first. Bounded by
`MaxWitness`; an exact re-delivery is dropped, because appending it would make the witnessed sequence
unrepresentable as a chain — repeat normalisation requires a strictly later root round (§2.3), so a
duplicate reads as a gap.

**`Need` is the deduplication point, and it never waits for the network.** It decides whether to
start a recovery and returns; the outcome arrives through `Target` and `Status`. A caller holding the
Round lock therefore never blocks on I/O, and a shard delivering the same certificate to several call
sites — or one certificate per round while a fetch is out — cannot spawn parallel recoveries. Four
distinct reasons not to start, each a different situation:

| Reason | Meaning |
|---|---|
| already fetching | one recovery at a time; the running one re-checks the current certificate when it finishes |
| target already ready for this certificate | nothing to obtain |
| terminal conflict decided for this certificate | no provider can change it |
| backoff not elapsed | an explicit failure, **not** a quieter refetch |

The backoff earns its place: without it, a node that failed once would ask again on the next
certificate delivery, and a shard certifies a round every few seconds. One node's recovery would
become a load pattern on every other node, which is the availability loss this protocol exists to
repair, arriving from the inside.

**The predicate is the authority; nothing else is.** Transport success is not evidence — a bundle
that arrives intact from a well-behaved peer means nothing until `VerifyAnchorEvidence` accepts it
against this node's own partition, shard, configuration hash and trust-base store. A peer's refusal
DETAIL string is never consulted at all: it is diagnostic (§6.2), and a decision made from it would
be a decision made by the peer. A fixture states it directly — a structurally perfect chain, of
exactly the shape being asked for, signed by a root chain this node does not trust, delivered without
a single wire error, and refused.

**One bounded budget, spent across providers.** `MaxProviders` attempts, one pinned candidate at a
time, under one `Overall` deadline that `PerAttempt` narrows but never extends — so a single silent
peer spends its own share and not the recovery's. A refusal decided from bundle content costs one
attempt and moves on; only a contradiction with this node's own certificate ends the attempt (§4.1).
The epoch crossing is the case worth restating: it says *this candidate* crosses a boundary, not that
every candidate does, so the next provider is still asked — and a fixture has the second provider
recover from a same-epoch source after the first offered an older one.

**Carrying a result across a moving certificate is re-verification, never inference.** A fetch takes
time, and the certificate this node is being asked to build on can move while it is out. A result
verified against the older one does not authorise the newer one — *and matching state roots are not
an argument*, because a missed non-quiet interval can return to the same state root by a different
block (§3.3.1). So the bundle is EXTENDED with the certificates this node itself observed since, and
handed back to `VerifyAnchorEvidence` against the certificate now held. Every property that made the
original acceptable is re-decided over the longer chain; a second, weaker rule written here would be
a second place where history is inferred, and §3.3.1 is the counterexample to every version of it.

The fixture is that counterexample run forwards: while the fetch is out, two certified rounds move
the state away from B and back to B by a *different* block. The state root the node holds is the one
it asked about; the anchor it ends with is the block that actually produced it, reached by a second
request pinned to the new certificate — not the block the first answer named.

**A snapshot is a VERSION of an observation, not its content.** Each observation carries a
monotonic sequence number, and the extension starts after the entry with the snapshot's number.
Review found the content key — round plus canonical identity — wrong in both directions, and a repeat
certificate is what exposes it, because a repeat has the *same* round and the *same* input record as
the certificate it repeats. That is what makes it a repeat, so a content key names two observations
and something has to break the tie:

- taking the *first* match appends a repeat this node already holds to evidence that already ends at
  it. The duplicate sits at the same root round as the copy before it, and repeat normalisation
  requires a strictly later one (§2.3), so a **correct** answer is refused as a gap — and the retry
  budget is then spent obtaining the same correct answer again, until recovery fails;
- taking the *last* match drops a repeat observed after the snapshot, and with it the assignment the
  rounds after it are contiguous with, turning an honest tail into a gap.

There is no content key that separates the two cases. Both directions are fixtures.

**What this node retains is its own, and so is what a caller is handed.** Two halves, and review
found each of them separately, which is the reason both are written out here.

*Retention.* A bundle arrives through a decoder whose buffers this node does not own, and
`ExecutionAnchor`'s hashes are **slices into the certificate the anchor was derived from**. Retaining
a successful bundle as it arrived therefore left the verified target — and the bundle every later
extension is built on — aliasing memory a provider could still be writing to; cloning on the way out
of `Target` does not repair that, because what it clones is already the provider's. So the extended
bundle is CLONED FIRST, the clone is what `VerifyAnchorEvidence` is given, and that same clone is what
is kept. Cloning after verifying would be no better in kind, only smaller: the gap between the two is
a window in which the bytes verified and the bytes retained can differ. A copy that cannot be
completed is a refusal rather than a shorter bundle — a shortened chain is still structurally a chain,
and §4 is explicit that it is not evidence of anything.

*Handing out.* `Target` clones the hashes and `Contradiction` re-decodes the bundle, so a caller that
overwrites what it was given is not editing this node's verified target. The contradiction's bundle is
re-decoded on the way IN as well, for the same reason retention is: the record is meant to outlive the
attempt that produced it. `Status` carries only a COUNT of contradictions, so the cheap, frequent
snapshot stays cheap and the copying sits behind the call that needs it.

*And the lock.* The contradiction record is copied UNDER the lock, the bundle outside it. Taking the
record's pointer under the lock and dereferencing after was a data race on every scalar field of it,
`Count` included, because a running recovery increments `Count` under that same lock — and a
diagnostic read during a recovery is exactly what these accessors are for.

**Restarts are bounded, because a correct loop can still be a livelock.** A shard certifying blocks
faster than a fetch completes would restart the same recovery forever, every individual step
deciding correctly. `MaxRestarts` ends it and the node waits out the backoff. An interval that is no
longer witnessed — the snapshot evicted under `MaxWitness` — is refetched rather than assumed: this
node can no longer say what happened in between, and that is the whole of what it may conclude.

**Authenticated contradictions are kept, not logged away.** Two conflicting statements about one
round, both verified against this node's own trust base, are evidence that something unprovable
happened; a log line asserting it is not. The bundle is retained as it arrived, bounded to the first
such contradiction per recovery with later ones counted, so a provider cannot make a node retain
memory by disagreeing repeatedly. Only the contradiction with this node's OWN certificate is
terminal, and terminal for that certificate *by identity* — a later certificate for the same round is
a different authenticated statement and gets its own attempt. Equivocation inside a single bundle is
kept on the same terms and is **not** terminal: both halves came from one provider, and neither is a
statement this node made.

**Readiness is decided from the whole certificate, because the applier decides from the whole
certificate.** Review found the two halves disagreeing: readiness was keyed on the certificate's
IDENTITY and application on the full binding, and a repeat falls exactly in that gap — same round,
same input record, so the same identity, certified at a LATER root round. The requester answered
"already ready" and did nothing; the applier answered "that target was verified against another
certificate" and refused; the node sat between them making no progress while every unit fixture on
both sides passed. A repeat is an ordinary product of a root-chain timeout, so this is what a quiet
shard does whenever the root chain misses a round, not an edge case. `Need` and `Target` now compare
bindings, and the retained bundle is carried across the repeat locally, with no request.

Terminal conflicts keep the NARROWER key — the identity — and the difference is not an oversight.
Readiness asks *which certificate a target was verified against*, and a repeat is a different
certificate. A conflict asks *what was signed*, and a repeat re-certifies the byte-identical input
record: it is the same contradiction, and re-deriving it would spend attempts reaching a conclusion
already reached. Both are fixtures.

There is now a fixture that runs the real requester as the real applier's `TargetSource` over signed
certificates, because that disagreement is invisible to any test that asks only one half a question.

**Readiness is not application.** A verified anchor is stored as a target and answered against the
certificate actually held; it is retained, not discarded, when that certificate moves, so a caller
part-way through applying one does not lose it, and the next trigger can usually carry it forward
with no request at all. Committing it to an executor is a separate cursor (§5) and a separate unit,
and it is where the distinctions that belong to it live — an executor RPC that cannot be reached, a
payload that has not arrived, and a payload that is invalid are three different situations, and none
of them is a fact about the evidence. Nothing here authorises signing: P-sign (#105) is untouched, and
a recovered executor is not a licence to vote.

**Still unwired, deliberately.** The fetcher and provider source are interfaces; production startup
constructs no requester, `Round` neither observes into one nor asks it for a target, and no node
recovers anything from this code yet. The remaining decisions — which peers a node asks, how the
target reaches `reconcile`, and how the whole path behaves against a real reth node across a measured
quiet tail — are the next unit, and each of them is a policy question rather than a mechanism one.

### 6.4 Applying a verified target

Implemented in `shardnode/evidenceapply.go`. The requester holds a verified anchor; this decides
whether and how it reaches the executor. They are separate because §5's cursors are separate — a
target can be verified long before an executor can act on it, and "payload unavailable" is precisely
the state in which both are true at once. Collapsing them would mean either discarding proven evidence
because a client is still syncing, or reporting a node recovered because its evidence was good.

**A certificate, not a state root.** `Apply` takes a `CertificateBinding` — round, root round,
canonical input-record identity, and the state that round builds on — and this is a correction review
forced. The first revision compared `target.StateRoot` against the certified state, which is state
equality wearing a different hat: **across a quiet tail every certificate carries the same state
root**, so that comparison is equally true of a target verified three rounds ago against a certificate
this node has since moved past. §3.3.1 is why that is not good enough, and it is the same argument
this design uses everywhere else. The requester returns the binding WITH the target (§6.3), and the
two bindings are compared directly. A repeat — same round, same input record, a later root round — is
a different certificate, so the root round is part of the binding.

Three questions state equality cannot answer, and the binding does:

  - *Was this target verified against THIS certificate?* Compared as bindings, before anything is
    sent. A target for another certificate is not *wrong*; it is an answer to a question nobody asked.
  - *Is this a new opportunity to try?* Only a new certificate is one — see the budget below.
  - *Did the answer go stale while the attempt was in the executor?* Re-read after the commit and
    compared. A commit takes time, and the requester installing a target for a newer certificate
    meanwhile is its ordinary behaviour across a quiet tail, not a fault. If the target still names
    the same block, the commit was correct and the application stands; if it names a different one,
    the node is **not** reported recovered for a question the answer was never about.

**Three executor situations, kept apart.** They arrive looking alike — the node did not recover — and
each calls for a different response, so none may be reported as another:

| Situation | Executor said | Verdict | Target |
|---|---|---|---|
| **Unreachable** | nothing — the RPC failed | retryable; *nothing at all* is known, not even whether it applied the block | kept |
| **Payload unavailable** | `SYNCING` / `ACCEPTED` | retryable; the ordinary state after an execution-client restart (§1.1) | kept |
| **Payload invalid** | `INVALID` | a fault, not a wait; no number of attempts makes it valid | kept, and not retried |

Retaining the target through the first two is the load-bearing part: the authority to retry is exactly
what dropping it would remove, and this is the same stance the live path already takes ("retaining the
anchor and retrying on the next certificate"). Reading the head after a `VALID` commit can fail too,
and that is *unreachable* rather than success — whether this node recovered is then unknown, and
unknown is retryable.

**P-id is enforced by the comparison the live path uses**, not by a second copy of it: `reconcile` and
this both call `anchorHeadIdentity`, which was extracted for that reason. Two copies of a comparison
that gates signing is one copy too many — the weaker of them becomes the one that matters. Both halves
apply: the head must be the certified BLOCK, and it must be at the certified STATE. A commit reporting
success while the head is elsewhere is what P-id exists to catch, so it is a fault, and it is recorded
against the BLOCK HASH rather than the state — a later target naming a different block for the same
state is §3.3.1's own case and gets its own attempt. Row 13's genesis exception applies exactly where
it did before, and the executor's block zero is read only when that exception could apply.

**Bounded without stranding a recoverable node — and the budget is keyed on the CERTIFICATE.** The
first revision keyed it on the certified state, and review reproduced what that means: across a quiet
tail the state never changes, so the budget never renews, and a node whose executor was still syncing
spent its attempts and could never get another however available the payload had since become. That is
exactly the permanent failure the cap was meant to avoid, reached by the cap itself — and it strands
precisely the node this design exists for. Renewal is per certificate, which is the rhythm the live
path already has ("retaining the anchor and retrying on the next certificate") and is still bounded,
because certificates arrive at the shard's cadence rather than a retry loop's. Within one certificate,
attempts are spaced by a backoff and capped by `MaxAttempts`.

**One attempt is inside the executor at a time.** A commit is not a read: two in flight make "what did
the executor do" unanswerable, and the head read afterwards belongs to neither of them. The first
revision counted the attempt under the lock and released it before calling, so two callers could both
be admitted — review reproduced that too. It is a non-blocking slot rather than a mutex held across
the call, because a mutex would park whichever goroutine asked next behind a slow executor and the
caller is a round loop, and it is released on every exit path.

**What it never does.** It does not sign and does not make a node eligible to (P-sign, #105 — a
recovered executor is not a licence to vote). It does not re-verify evidence: `VerifyAnchorEvidence`
did that, and doing it again would be a second place where evidence is judged. It does not fetch
payloads — the executor's own ancestor acquisition is what obtained the missing block in every run
measured so far (§8), and that stays its business.

### 6.5 The lifecycle, wired

Implemented in `shardnode/evidencerecovery.go` (`RecoveryStack`), `shardnode/finality.go`
(`FinalityGate`), `Node.EnableRecovery`, and the two call sites in `Round`. `ubft shard-node run`
gains `--evidence-serve` (default **on**) and `--evidence-recover` (default **off**).

**Two switches, because they cost different things.** Serving retains certificates this node has
already authenticated and answers bounded requests: no new dependency, memory it can measure, and it
helps peers it could not otherwise help. Recovering depends on peers answering and ends in a
finality-changing executor call.

**Recovery refuses to start without the configured shard hash.** It is one of the four things a
bundle is judged against (§3), and the predicate compares it only when it has something to compare
against — so omitting it does not make that check lenient, it REMOVES it, and a node started that way
would accept a bundle certified under a configuration it does not run. The hash comes from the
deployment because that is where the shard configuration is; `Node.New` does not receive it (the gap
`verifyRestoredLUC` documents, F2/#10), and deriving it from a certificate would be exactly the
mistake — the certificate's own claim about its configuration is what is in question. A node that enables neither behaves exactly as it did before any of
§6 existed — same refusals, same names — which is what makes this a deployment decision rather than a
protocol change.

**Where recovery is attempted, and where it is not.** Only on the paths that already refuse:
`reconcile` when the live anchor cannot explain the state (`no-anchor`, `continuity-gap`), and the
identity check when the state agrees and this node still cannot name the block. Not on every
certificate — a node that can explain what it is being asked to build on needs no evidence, and
asking anyway would make every healthy node a permanent load on every other. The refusal still stands
if recovery fails, with the same name it had before.

**The finality gate.** Until now one lock did this job by accident: `Round.mu` is held across
`HandleCertificate`, and every finality-changing call happened inside it. That was never a statement
about finality — it is a round lock — and it stopped being sufficient the moment a second thing could
commit. Every call that makes the executor treat a block as canonical or final now takes the gate:
the round's own commit, reconcile's, `Build` (which sets head, safe and finalized on the parent
before any payload exists), and the applier's. Reads and `Verify` do not: `newPayload` tells the
executor about a block without making it canonical, and a validator's per-round Verify must not queue
behind a recovery commit. The round WAITS for the gate because it must proceed; the applier does NOT,
because its contract is one bounded attempt with an answer and its caller is a round loop — it
reports `busy` and the next certificate is the next opportunity.

**The gate spans the whole commit-and-confirm sequence**, not the commit alone. Held for the `Commit`
and released before the head was read, the confirmation was meaningless in the one case it exists
for: the round could commit something of its own in between, the head would then be that other block,
and a head that is not the committed block is recorded as a FAULT and never retried — so interference
by a perfectly correct round permanently refused a target that was correct too. "Commit this block
and confirm the executor is now at it" is one operation, and the gate is held across the commit, the
head read and the genesis read the row-13 exception may need.

**The attempt runs off the round lock.** `HandleCertificate` holds `Round.mu` throughout, and a
recovery attempt is up to three executor calls plus a chain re-verification — so under the lock,
nothing about this node could be read or configured until an executor answered. The shape is snapshot
→ execute → revalidate → install: every operand is copied out while the lock is held, the attempt runs
with it dropped, and the anchor is adopted only after the lock is taken again and the result still
explains the state THIS round was building on. Dropping a lock mid-operation is a claim about the
caller, so it is enforced rather than believed: `BFTClient.Run` drives certificates sequentially from
one goroutine, and a re-entry while the lock is dropped is a loud refusal instead of two interleaved
rounds.

**Two defects only wiring could show.** Both were invisible to all four unit suites, each of which
was correct about its own half:

  - *The one-certificate lag.* A certificate is observed at the top of a round and the recovery
    attempt happens inside that same round. An asynchronous carry finishes microseconds later — long
    before the next certificate and still after the attempt that needed it — so every attempt found a
    target for the PREVIOUS certificate, refused it as stale (correctly), started a carry, and the
    next attempt found a target for the certificate before it. Forever, on a shard doing nothing
    wrong. `EvidenceRequester.Refresh` carries a retained bundle onto the certificate held now,
    synchronously, using only what this node observed: bounded work, no network, safe under the round
    lock.
  - *Half a recovery.* Committing the certified block left the executor in the right place while
    `continuityState` still held no anchor — so P-id went on refusing, and the next certificate
    re-committed a block the executor already had. `continuityState.installVerified` adopts the
    anchor the predicate established, together with the interval it verified quiet. §5 already said
    the verified-anchor cursor is moved by "this predicate, or a live non-quiet certificate"; this is
    that sentence implemented. It authorizes no signing: P-sign is `restoredFrom` and #105, enforced
    separately, and a restored process that recovers its execution identity still does not vote.

### 6.6 The acceptance run, measured

`scripts/f6b-quiet-tail-recovery.sh`, against reth at the pinned commit
`189c0df32617afc488e0f091dbface1bd72cceb4`. Three validators, one reth each, on the shard's own
generated chain spec. It runs **two arms against the same devnet**, which is what makes it evidence
rather than a demonstration.

| | Control (`--evidence-recover` off, the default) | Recovery (`--evidence-recover`) |
|---|---|---|
| certificates after restart | 5, all quiet | 6, all quiet |
| anchor adopted | none | yes, one attempt, zero restarts |
| refusals | throughout: refused, adopted nothing, signed nothing | none in the certificates after adoption |
| voting | NON-VOTING | NON-VOTING |
| transactions executed | 0 | 0 |

The control arm is §1 reproduced on the merged revision: a node that returns behind a quiet tail
refuses for as long as the shard stays quiet, because nothing a quiet shard delivers can name the
block. The recovery arm is the same node, on the same devnet, differing by one flag.

**Two things the run corrected that no fixture had.**

*A round can be non-quiet without a transaction.* The first version of this lane asserted "no
transaction" by counting non-quiet rounds, and a run produced a non-quiet round 4 with an empty
chain spec on which no account can pay for gas. Quietness is a statement about the state root, not
about activity. The property is now asserted where it actually lives: **every canonical block on the
executor, genesis through head, contains zero transactions.**

*The applier committed unconditionally.* This is the defect the run existed to find, and it is
specific to the one anchor whose block the executor is not expected to hold. The shard's first
certified round is non-quiet by convention, so it names a block a real client builds and discards
without ever making canonical — and against an executor with no block identity at genesis,
`BlockHashOrFallback` puts the STATE ROOT in the certificate's block-hash field. On a devnet with no
transactions that is the only anchor there is. The node therefore asked reth to commit
`0x56e81f17…`, the empty-trie state root, and reth answered `SYNCING` — correctly, for ever. The
recovery was verified, the evidence was good, the executor was already exactly where the certificate
said, and the node recovered nothing.

`Apply` now asks the questions in the right order: *is the executor already on the certified block*,
using the head the caller has already read and the same `anchorHeadIdentity` comparison the live path
uses — and only then *make it be there*. A node already at the certified block adopts the verified
anchor with **no finality-changing call at all**, which is also the correct answer whenever a
recovery attempt races a commit that already succeeded. The executor's block zero is read once and
cached, since it is configuration and does not move.

**Adopting is still an adoption, so it happens inside the guards.** The first version answered
"already there" before all of them — no fault check, no in-flight slot, no gate, and no revalidation
of the target afterwards. Reading a head is not a finality change, but adopting an anchor is a
decision the round then acts on: `Round.applyVerifiedAnchor` installs it into the live continuity
state on the strength of this outcome. So a target already determined to be a fault could be adopted
if the head happened to match, and the head could be moving under a concurrent commit while it was
read. Both paths now enter the fault and in-flight guards, take the gate, and re-read the target
before the anchor is adopted.

The one thing kept apart is the attempt BUDGET, and deliberately: only a path that COMMANDS the
executor spends it. A node that is already correct must not be kept from saying so by an earlier
failure's backoff — nothing is being asked of the executor, so nothing needs rationing.

**And the head it decides from is read under the gate.** The first version used the one the caller
passed, which was read BEFORE the gate was taken — so between that read and the decision another
actor could have committed, and the anchor would be adopted on the strength of a head that no longer
exists. Under the gate nothing can move it, which is the only condition that makes "the executor is
already there" a fact rather than a recollection. The caller's head is still what an attempt REPORTS
when it refuses before reading one; it is no longer what any decision is made from.

**Provenance is an artifact, not a scrollback.** The run writes `artifacts/f6b-acceptance/<utc>/`
containing **copies** of every log the assertions read and a manifest naming the repository revision,
whether the worktree was clean, the `ubft` digest, the reth commit and whether it is pinned, each
arm's flags, how far the run got, and a SHA-256 of each copied log. Three details are the whole
point, and review found all three: it lives outside `test-nodes/`, which this lane and every other
one in the repository delete; it hashes copies, because a digest of a file a running node is still
appending to describes nothing anybody can check later; and it is written from the EXIT trap, so a
run that fails early still leaves a record of what it was. And failing to write one **fails the
run**: the first version returned success when `mkdir` failed, having already set its once-flag, so a
run with no artifact at all reported ALL CHECKS PASSED and no later attempt was made. For a lane
whose output IS the artifact, silently producing none is the same defect as counting a failed read as
a zero.

**The failure paths are self-tested, because a passing run does not exercise them.** Every defect
review found in this harness was in a path that only runs when something has already gone wrong: a
read that failed, a number that was malformed, a directory that could not be created. Those never
execute on a good run, so a green acceptance run says nothing about them — and each one turned a
failure into a PASS. `--self-test` exercises them with no reth and no root chain, asserting that each
failure path fails. It has already caught itself twice: helpers defined after the block made its
checks inert, and they reported PASS while testing nothing, which is the same class of defect as
everything they test. It asserts the PROPERTY rather than any particular guard — several guards are
mutually redundant, so removing one changes nothing while removing all of them fails the self-test by
name.

**A failed read is not a zero, and a failure in a subshell is not a failure.** `${c:-0}` over a
failed RPC counted as zero transactions, so an unreachable node produced a PASS asserting nothing had
executed — an assertion that cannot tell "I looked and saw none" from "I could not look" is not
evidence, and this lane's claim is a negative one. Worse, the helper reported it by calling `fail`
from inside a command substitution: that is a subshell, so `$failures` was incremented in a process
that then exited, the parent's counter never moved, and **the run exited 0 with failures on screen**.
Helpers now return non-zero and print to stderr; only the parent shell counts.

**What the run does NOT establish**, named rather than glossed:

  - *Not exact-block recovery against an ordinary block.* It exercises the genesis-round anchor,
    because that is the only anchor a shard with no transactions ever has — so row 13's exception is
    what satisfied P-id here, not a head-hash match against an ordinary certified block. That is now
    measured separately, by the lane in §6.7.
  - *Not evidence immutability.* What this measures is that serving cost the providers nothing —
    no observation or stream refused, and they went on certifying. That served evidence is not
    MUTATED is a stronger claim, established by fixtures that mutate a bundle and re-read it, not by
    a lane that cannot see inside a provider's buffer.

### 6.7 The missed-block acceptance run, measured

`scripts/f6b-missed-block-recovery.sh`, same pinned reth, same three-validator topology, run
`20260910T072801Z`, whose manifest records repository revision `3afd705b` and a clean worktree —
the later changes on this branch are documentation and reporting clarifications. Every number below
is that run's; three consecutive runs produced the same outcome. It exists for the one thing §6.6
names and cannot show: **P-id's ordinary
comparison**, a head-hash match against a certified block that is not the shard's first.

Row 13's exception is deliberately narrow — "the executor is at its own genesis block, at the
certified state", for one anchor only — but a lane that only ever exercises it has not measured the
ordinary path at all. So this lane is built so the exception *cannot* apply, and it asserts each
clause of that rather than assuming it: before the outage the executor is already past its genesis
block, and after recovery its head is block 3, whose hash is neither the executor's genesis hash nor
any state root. **If row 13 were widened to admit this run, the run would still pass** — which is
why the assertions read the executor's head number and hash directly instead of inferring recovery
from the absence of a refusal.

**Where the transactions are, and why that is the whole design of the lane.** Three transfers are
submitted, all of them before the recovering node returns: one while every validator is up, which is
what moves every executor off genesis and gives the run an ordinary anchor, and two into a peer's
mempool while validator 1 is stopped, which are what produce the blocks it misses. Injection then
stops, the shard is allowed to go quiet, and **nothing is submitted from the moment the node comes
back, in either arm**. The checked surviving executor holds exactly three transactions before the
first restart and during the
control; every executor holds exactly three at the end. The returning executor still holds only
the first transaction during the control, which is the lag this run measures. The F1
baseline's "recovery" came from a non-quiet round — that is, from new activity (§1) — and this lane
must be unable to report that result by accident.

| | Control (`--evidence-recover` off, the default) | Recovery (`--evidence-recover`) |
|---|---|---|
| certificate deliveries after restart | 6 (one distinct partition round, 21) | 8 (six distinct partition rounds, 21–26) |
| executor head | block 1, unchanged, while the shard is certified through block 3 | block 3 `0x0fcbe243…`, the certified block |
| refusals | 6 × `cannot identify the certified block to recover to` | 2 while evidence was being fetched, none in the 3 certificates after adoption |
| anchor adopted | none | yes, one attempt, zero restarts |
| voting | NON-VOTING | NON-VOTING, signed nothing |
| canonical transaction count | 3 on the checked survivor; 1 on the returning executor | 3 on every executor; all submitted before the restart |

**What the control arm establishes, which the quiet-tail lane could not.** Returning did not itself
recover the missed block during this observation. Its reth was running and peered throughout the
outage, and its
canonical head stayed at block 1 across six deliveries of the same certificate. This is a short
control observation, not a sustained multi-round recovery test or proof that it would remain behind
indefinitely. The refusal accompanied an executor observably behind the certified head.

**What the recovery arm establishes.** One flag apart, on the same devnet and the same executor, the
node obtained authenticated evidence in one attempt, drove its executor from block 1 to block 3, and
satisfied P-id by an exact block-hash match against the block the validators that stayed up agree
they certified — a value read from *them*, not from the recovering node's own log, and re-read at the
end of the run so a head that moved underneath the comparison could not have been the claim. It then
refused nothing over the certificates that followed, and it still did not vote.

**What it does not establish.** The acquisition source, still — see §8, which this run does not
close. reth1 logged `Received forkchoice updated message when syncing` and added blocks 2 and 3
within 40 ms of the commit, so it did not hold them *canonically* during the outage; whether it
fetched them then or already had the bodies buffered from gossip is not something a few tens of
milliseconds distinguishes, and no inference is drawn from it here. The run preserves `reth1.log` in its artifact so the
controlled peer-connectivity experiment §8 asks for has a starting point rather than a guess.

**The defect this lane found in itself, which is the same one twice over.** Its precondition —
"the shard is quiet again before the node comes back" — was written as *four quiet rounds in the
log*, and the log already held nine from before the transactions were submitted. The wait therefore
returned instantly, and one run in four restarted the node while the certificate naming the block it
had missed was still the newest one. The root chain hands a returning node the LATEST certificate,
so that node was handed the answer: it recovered by the live path with recovery OFF, its executor
went to block 3, and the control arm failed — correctly, and for the right reason, which is the only
part of this that went well. **That is the F1 baseline's recovery-from-new-activity (§1) arriving by
accident inside the lane built to rule it out**, and it is the same defect as counting a failed read
as a zero: an assertion satisfied by evidence from before the thing it is asserting about.

Quietness is now measured as a **tail** of quiet certification-request log entries after the most
recent non-quiet request in any provider's log. Both leaders and followers log requests, so this
count is not a count of distinct certified rounds. A new non-quiet request moves the boundary and
the count starts again. Each arm additionally checks that no provider logged a non-quiet request
while it ran.
This observes the provider processes rather than inferring quietness solely from the script
refraining from transaction submission.

**One implementation of the assertions, not five.** All five lanes source
`scripts/lib/f6b-acceptance-lib.sh`, and `--self-test` on any of them runs the same 71 checks over
the same helpers. Every one of those helpers guards a NEGATIVE claim, every one of them has been a
defect at least once, and a second copy in a second lane is the argument `anchorHeadIdentity` settles
in `shardnode/anchor.go`: two copies of a comparison that gates a conclusion is one copy too many,
because the weaker of them becomes the one that matters. The exactness cuts both ways there — a lane
that expected three setup transactions and found four has had activity it did not authorise, which is
the same defect as finding zero because the read failed.

### 6.8 Positive work after recovery, measured

`scripts/f6b-positive-work-after-recovery.sh`, same pinned reth `189c0df3`, same three-validator
topology. It answers the one acceptance clause the other four lanes are constructed so as not to
answer: **does a node that has recovered take part in work the shard produces afterwards?**

The other lanes stop transaction injection the moment the recovering node returns, and assert by
counting that nothing new executed. That is not a limitation to be relaxed — it is what makes
recovery attributable to the authenticated evidence rather than to new activity, and it is the whole
reason the F1 baseline's "recovery" was not recovery (§1). A lane that simply injected earlier would
be the baseline again under a new name: the certificate naming the new block would name the missed
block too, and the node would recover by the live path.

So this lane keeps that phase exactly as §6.7 built it, asserts the recovery in full, and only then
injects. **The order is the measurement**, and two checks hold it rather than leaving it to the
reader:

- not one non-quiet request entry is logged in the **closed window** from the restart to the
  injection mark. Closed, not open-ended: "since the restart" evaluated afterwards would be a
  statement about an interval that by then contains the new work. Counted in request entries and
  said so — quietness is logged by the leader and by every follower, so one certified round
  contributes several, and the first run of this lane reported "4 non-quiet rounds" for a phase that
  produced one block. The number was right and the unit was wrong; it is the correction §6.7 took.
- the pre-injection snapshot already contains adoption of the expected block. This check runs
  before submission; it does not measure adoptions across the subsequent interval.

The mark itself is a sub-second instant for the reason §8.1 established — a block certified 700 ms
into the next phase would otherwise belong to both windows.

The transaction goes to a **peer**, never to the recovered node's own executor, so no part of the
result depends on the recovered node being the entry point. What is then required of it: the shard
certifies a block beyond the recovered one; the recovered node's executor reaches it; and it agrees
with **every** survivor — read from them, at the same height — on block hash, on state root, and on
the receipt for the new transaction. The final transaction total on every executor must be the setup
total plus exactly one. This checks canonical transaction inclusions, not internal execution
attempts; replay idempotency is covered by the separate runtime fixtures.

**And it still does not vote.** Under P-sign (#105) a restored process is non-voting for its
lifetime, so "positive work after" cannot mean the recovered node signs the new block; it means the
node follows it, executes it, and agrees about it. Both halves are asserted — the agreement and the
continued silence — together with a check that the silence is not the node having gone back to
refusing rounds, which would be following nothing at all.

There is no control arm, deliberately. That a node with recovery off stayed behind during the observation window is §6.7's
result, measured on the same devnet one flag apart; repeating it here would double the runtime
without adding to this claim. What this lane must establish instead is that the node had *already*
recovered before the transaction existed, and that is what the two ordering checks do.

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
| Two disagreeing certificates for one round inside the tail | `two certificates for one round that disagree are a conflict, not a repeat` | `CandidateSplit` (retryable) |
| Oversized technical record | `an oversized technical record is refused before any trust-base work` | `Exhausted`, trust base asserted never consulted |
| Bound measured over the whole bundle | `the bound is measured over certificates and technical records together` | `Exhausted` |
| Missing (non-positive) bound | `a missing bound is a refusal, not unlimited` | `LimitsInvalid` |
| Retry classification of every outcome | `RetryClassification` | — |

Added after the second review round:

| Case | Fixture | Refusal |
|---|---|---|
| Tampered (unsigned) epoch byte, then a valid provider | `a tampered epoch is a forgery, and the next provider is still consulted` | `Unauthenticated`; second provider consulted |
| Genuine epoch-crossing candidate, then a suitable one | `a genuine epoch-crossing candidate does not prove every candidate crosses one` | `EpochChange`; second provider consulted |
| Terminal conflict must end the attempt | `a terminal conflict with this node's own certificate does end the attempt` | `Conflict`; second provider **not** consulted |

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
| epoch comparison placed after signature verification | `a tampered epoch is a forgery, and the next provider is still consulted` |
| `EpochChange` retryable | `RetryClassification`, `a genuine epoch-crossing candidate…` |
| `CandidateSplit` retryable | `RetryClassification`, `two certificates for one round that disagree…` |
| terminal `Conflict` non-retryable | `RetryClassification`, `a held certificate naming a block…`, `a terminal conflict … does end the attempt` |

The reviewer's independent reproductions were also run against each revision unchanged
(`review112_test.go`, then `review112_epoch_retry_test.go`): all four now fail their assertions,
which is the direction that means the reproduced behaviour is gone.

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
client". That overstated the evidence and was withdrawn; the replacement statement was that the way
to establish the existing path properly is a network trace of the execution client, or a controlled
peer-connectivity experiment that varies which peers hold the missing block.

**§6.7's run did not close it either**, and added one fact: in run `20260910T072801Z` the recovering
reth was running, peered and gossiping for the whole outage, and its canonical head did not move —
which is a statement about the fork-choice head and nothing more. Forty milliseconds between the
forkchoice update and the two blocks appearing does not distinguish a fetch from a buffered body.

### 8.1 The experiment, run — and the answer

`scripts/f6b-execution-peer-isolation.sh` is that controlled experiment, and it settles the question
for this configuration. Run `20260910T212808Z`, whose manifest records repository revision
`57a2c209` and a clean worktree; three consecutive runs produced the same outcome. One variable
changes across its two arms: the returning client's **execution-layer** peering. BFT transport is untouched throughout — libp2p bootnodes and localhost
engine/eth endpoints — so evidence retrieval has exactly the connectivity it always had.

Isolation is **read, never assumed, and read over the whole window rather than at its ends.**
`admin_removePeer` returns true for a peer that was never connected, for one already gone, and for
one it will re-dial a second later, so the premise is established from the subject's own peer count,
its own session list, and every survivor's session list. reth is run with `--no-persist-peers` for
the same reason: a client that reloads its peer file re-dials the sessions the experiment severed.

Three things that review found, each of which let a reading say `ok` while establishing nothing:

- **A failed read is not an empty peer list.** `admin_peers` parsed as `result or []` turned a
  JSON-RPC error, a missing result, an explicit null and a malformed body into "this client has no
  peers" — and with the peer count also unreadable, the check passed for a client nobody could see
  at all. It is the `${c:-0}` defect again, in the one place where the whole premise is a negative.
- **Both sides of an identity comparison have to be the same kind of thing.** The subject was
  identified by the 128-hex public key from its enode URL, while a peer list contains the 64-hex
  `admin_nodeInfo.id` — measured here as exactly that. The survivor-side half of the check could
  never match and was inert while reading as PASS. The lane now uses the admin id, compares whole
  lines case-normalised, and **proves the identity is one that can match** by requiring a survivor
  to list the subject by it while still peered.
- **Two samples either side of an interval say nothing about the interval.** The ten-second hold
  finished before the transactions were submitted and the next reading was taken after both
  receipts, so a connection that opened and closed in between passed both. Two independent records
  now cover the window from isolation to reconnect: a **monitor** sampling every second, where too
  few samples or a single unreadable one disqualifies the window, and the client's own **session
  events**, which are a complete record rather than a sample — a transient session between two
  samples would still be logged. The run below observed 54 s with 42 readings, all readable, all
  zero peers, and no session established at any point.

Reviewer follow-up: session-window timestamps are parsed as instants, including fractional seconds
at the start and the complete final marked second. Missing or unreadable event traces fail the
observation. The retained run above was checked against these corrected boundaries; it was not
rerun for this helper-only change.

The survivors keep their peering with **each other**, checked, so this is a targeted isolation and
not a network partition.

**Isolated arm.** With the subject's client holding zero execution peers for the whole window in
which blocks 2 and 3 were certified — and its own log recording no block beyond 1 — the node still
obtained and verified the anchor over BFT in one attempt, and named the survivors' certified block.
It then **failed closed**: `payload-unavailable`, `retryable=true`, the verified target retained and
retried, nothing adopted, the executor unmoved, nothing signed. The anchor was correct and the block
was simply not obtainable, which is the distinction the outcome vocabulary of §4.1 exists to make.

**Reconnected arm.** Execution peers restored; no transaction submitted, no shard node restarted, no
flag changed. Within about two seconds the client established its sessions and the trace names the
mechanism itself:

```
21:29:43  isolation confirmed; the observed window opens here
          54 s, 42 readings, every one readable, every one zero peers and no session
          - blocks 2 and 3 certified by the survivors inside it, the subject returns,
            verifies its anchor over BFT and fails closed
21:30:37  window closes: no session established at any point in it, then peers restored
          - no transaction submitted, no restart, no flag changed
21:30:39.418  DEBUG net: Session established  remote_addr=127.0.0.1:54293  client_version=reth/v2.5.0-189c0df
21:30:39.433  DEBUG engine::tree: received new engine message msg=DownloadedBlocks(1 blocks)
21:30:39.453  DEBUG on_downloaded_block{block_hash=0x669d0620… block_num=3}
21:30:39.538  DEBUG on_downloaded_block{block_hash=0xacd161ec… block_num=2}
21:30:39.666  INFO  Block added to canonical chain number=2
21:30:39.669  INFO  Block added to canonical chain number=3
21:30:39.669  INFO  Canonical chain committed number=3
```

**The answer, stated no wider than the evidence.** In this configuration the missed blocks are
acquired by the execution client's **own block download from its execution-layer peers**, prompted by
a forkchoice update naming a descendant it does not hold — not from gossip received during the
outage, which the isolation rules out, and not by any BFT-side fetch, of which there is none. The
receipts for both missed transactions on the recovered subject name the same block number and block
hash as on a survivor, so this is the same chain and not merely the same head hash. The interval
from the reconnect to the first session is about two seconds; from the first session to the committed
chain, 251 ms.

**What it still does not establish.** One run, three validators, a two-block gap, and peers that all
held the missing blocks. It says nothing about a longer outage, a partitioned survivor set, or a
client other than reth at this commit. Its negative arm was never exercised against a peer set that
could not help — that variation, not this one, is what bounds the mechanism rather than identifying
it, and §8.2 is that measurement.

**A negative would have been a result, and is separated from a broken observation.** The
not-acquired branch does not simply call the run a failure: it takes four fresh readings bounded to
the phase after the reconnect — the client is reachable, the certified block is still its verified
target, the outcome is still `payload-unavailable`, and it is never `payload-invalid` — and reports
a measurement of the mechanism's limit if they hold, or a failed observation if they do not. The
counts are phase-bound for the same reason the quietness check is a tail: the shard node is not
restarted between the arms, so a whole-log count in the second arm is satisfied by the first.

**So: no custom payload-fetch mechanism is justified.** The existing path is now identified rather
than assumed, and the fail-closed behaviour when it cannot deliver is measured rather than argued.

### 8.2 The bound: connected to peers that do not have the block

`scripts/f6b-unhelpful-peers.sh`. §8.1 separated CONNECTED from DISCONNECTED and identified the
acquisition path; it said nothing about connected-but-unhelpful, because every peer in it held the
missing blocks. A mechanism that is identified is not thereby bounded.

The subject is given execution peers that return absent for the requested blocks: two **bystander** reth clients on the
same chain spec, driven by no shard node, never peered to a validator. Three states of one variable
in one run — **isolated** while the blocks it will miss are created, **unhelpful** (connected only to
the bystanders), then **helpful** (the survivors added, nothing else changed).

The bystanders' ignorance is a checked premise, not a description of how the script was written:
every one of them is asked **by hash**, for the certified block *and its parent*, before the arm, at
its start and at its end — twelve lookups per run, every one answering `null`. `blockPresence`
refuses anything that is not an explicit null-or-block answer, because "I could not ask" must never
become "it does not have it". Connectivity is observed across the whole arm the same way §8.1
observes isolation, in the opposite direction: every sample readable, every sample holding at least
one peer, and no sample listing a survivor.

The table below describes clean run `20260911T005012Z-55649` at `452f6281`.
Two other clean runs at the same revision (`20260911T003905Z-36931` and
`20260911T004425Z-46124`) also reported not-acquired then acquired. Their acquisition-to-adoption
gaps were 6.081338 s and 0.722362 s; this run's was 0.920202 s. The failed mesh setup in
`20260911T003729Z-35393` is excluded from this result.

| | UNHELPFUL (bystanders only) | HELPFUL (survivors added) |
|---|---|---|
| execution peers | 2, for every one of 134 readings over 171 s | the same 2, plus survivors |
| anchor over BFT | obtained and verified in one attempt, naming the certified block | unchanged, retained |
| client behaviour | entered syncing on the forkchoice update; **no** block bearing the certified hash downloaded | sessions established, then the certified block and its parent arrive as **downloaded blocks** |
| executor head | block 1, unmoved | block 3, the certified block, at the certified state |
| outcome | 29 × `payload-unavailable`, never `payload-invalid`, nothing adopted, nothing signed | adopted in this arm, receipts matching a survivor's |

**The bound, stated no wider than the evidence.** Payload acquisition succeeds when — and in this
configuration only when — a connected execution peer holds the block. Being connected is not
sufficient. During the measured unhelpful-peer window the node **remained fail-closed**: it keeps the verified
target, reports the payload unavailable rather than invalid, does not move its executor, and does not
vote. That is `VerifiedTargetSurvivesAnUnavailablePayload` (§7) measured against a real client
instead of a fixture, and it is the behaviour §4.1's outcome vocabulary exists to make possible.

**ACQUISITION AND ADOPTION ARE SEPARATE COMPLETION CONDITIONS, and the lane now says which it is
talking about.** The executor canonicalising the block and the node recording that it adopted the
anchor are two events, and the second comes later: the control arm waited for the head and then
immediately asserted the node had logged its adoption — eight seconds before it did. Two runs in
three failed on that, and neither failure was about the property being asserted. The wait is now
bounded, anchored on the phase mark, and **specific to the expected block hash** — "the node logged
an adoption" and "the node logged the adoption of the block this arm is about" are different claims,
and only the second supports the conclusion. Fixtures pin both ways the weaker form goes wrong: an
adoption of another block after the mark, and an adoption of the right block before it, and a head
that advances with no adoption at all. It is the same lesson as the post-adoption certificate count
in §6.7.

**A phase boundary is an instant, not a second.** The whole-second convention that makes
`--to 22:03:24Z` cover that complete second is right for "was anything logged in this second" and
wrong for separating two arms: with a whole-second boundary, a download 700 ms into the next arm
belongs to both windows, and the arm that must show nothing reports the next arm's work. One run came
within 254 ms of failing on exactly that. The marks compared against the execution client's log are
now sub-second instants (`markNowUTC`). The node-log marks use the same precision; review added a
regression rejecting an adoption earlier in the same second as the phase mark.

**And nothing may already be listening on the ports a run needs.** One rerun reported "the execution
mesh never formed"; the cause was a previous run's clients still bound to the same ports, answering
every probe while this run's own clients failed to start. A lane that attaches to a devnet it did not
create is measuring something it cannot describe, so every lane now refuses to start in that
situation rather than reporting the symptom.

**Why the third arm is not decoration.** "It did not acquire the blocks" and "it had stopped trying"
produce the same head. The control arm changes one thing — peers that have the data — with no
restart, no flag change and no transaction, and the same client then downloads the same target
immediately. Without it the negative would be uninterpretable; the client's own trace, which shows it
entering syncing during the unhelpful arm and downloading nothing, says the same thing from the other
side.

**What it still does not establish.** Two bystanders, one gap of two blocks, one client at one
commit. It does not measure how long a node stays fail-closed before anything else degrades, a peer
set that holds *some* of the missing ancestors, or recovery once a helpful peer appears after a much
longer interval.

**One implementation of "which log lines fall in this interval".** There were three, and the
differences between them were defects rather than choices: `scripts/lib/f6b_events.py` now answers
that question for every lane. Comparing RFC3339 as text is wrong at second boundaries — review found
it in the window count, and the same line written again in a trace extraction produced an **empty
trace** for a run in which every event happened inside one second, which is evidence that looks like
"nothing happened" and means "nothing was compared". A banner line is not corruption, but a file with
no timestamped line at all is not an event log. And an unreadable stream is a failed observation,
never a zero. `markNow` now carries a sub-second UTC instant, because a naive mark cannot be
compared with an offset-bearing log line and a rounded mark can include events from the prior phase.

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

The reconciliation of #92's acceptance list against this work — which lines are met, by which merged
pull requests and which evidence, and what remains — is `docs/design/f6b-acceptance-ledger.md`. It
records every acceptance line as met and separates #92 from the follow-up scope carried on #10, #14,
#105 and #16. It does not close #92 and does not propose closure on its own authority.


Recovery across an epoch transition (§3.1); which peers a node asks and how that set is chosen
(§6.3 takes it as an injected source and decides nothing about it); production startup wiring for the buffer, the server, the requester
and the applier alike, and the measured acceptance runs against a real client across a quiet tail
(§6.6), after a genuinely missed block (§6.7), on work produced after the recovery (§6.8), and under
controlled execution-peer isolation (§8.1);
whether the serving buffer of §6.1 is ever persisted; whether the root chain should serve historical certificates as a second source
(§6c); durable retained history and the signing record (#14, #105); and how long a node stays fail-closed when no peer can
supply the payload (§8.2 measures that it does, not for how long, nor against a peer set holding only
some of the missing ancestors). #16 remains open, including "Too deep reorg", and nothing here claims
to explain it.
