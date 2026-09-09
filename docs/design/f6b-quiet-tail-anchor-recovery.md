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
was certified — which is precisely the measured case above. §6.1 makes the complementary point from
the other side: a retained file is internally perfect forever, so it can be replayed, and it can
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
3. **The chain has to end where this node stands**, or it is a claim about the past. §6.1's
   replayable checkpoint is exactly a complete, correctly signed chain that ends too early. Fixture:
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

### 2.2 What "ends where this node stands" means exactly

Same **partition round** and same **state**. The root round is deliberately not compared: a repeat
certificate re-certifies the same partition round at a later root round after a timeout, and holding
one is ordinary. Requiring the provider to have ended on the same root round would refuse honest
evidence for a reason unrelated to the shard's history. Fixtures:
`a repeat certificate for the held round is still the round the node holds` (accepted) and
`a chain ending at the held round but a different state is refused`.

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

Fixtures: `another partition`, `another shard of this partition`, `another shard configuration`.

### 3.1 Epoch transitions are refused, not guessed

A shard epoch change moves the validator set and the configuration with it. A chain that crosses one
is refused with a distinct outcome, `ErrEvidenceEpochChange`, rather than being decided by this
predicate. Saying "unsupported" is safe; a wrong answer here chooses a block hash. Fixture:
`a chain crossing a shard epoch boundary is unsupported, not guessed at`.

Recovery across an epoch boundary is left open (§10).

---

## 4. Resource bounds, retry, cancellation, named outcomes

The length of the chain is chosen by whoever serves it, so it is attacker-controlled work.

- **Bounds** (`AnchorEvidenceLimits`): `MaxCertificates` (default 512, the same order as the
  stage-2 persisted-continuity bound) and `MaxBytes` (default 1 MiB, measured on the canonical
  encoding the signatures cover, so it does not drift with validator-set size).
- **Bounds are checked before any signature work**, so an oversized bundle costs no verification.
  Fixture: `bounds are checked before any signature work`.
- **Exceeding a bound is a named refusal, never a truncation.** A shortened chain is not evidence of
  anything, and silently accepting a prefix would reintroduce exactly the "stops short" hole of
  §6.1. Fixtures under `TestAnchorEvidence_ExhaustedBounds`.
- **Cancellation** is by `context.Context`, threaded to the trust-base lookup. Verification of a
  bounded bundle is CPU work with a hard ceiling; cancellation exists so a caller waiting on a
  provider is not pinned by one.
- **Retry belongs to the caller, not the predicate.** The predicate is pure and deterministic: the
  same bundle yields the same verdict every time. A refusal that names a provider problem
  (`Exhausted`, `Unauthenticated`) is a reason to try a different provider; one that names a
  *shard-history* problem (`EpochChange`, `Unconnected`) is not, and retrying it against more peers
  only spends bandwidth.

Every outcome is a distinct sentinel error, so a log line maps to a case in this record rather than
to a generic failure:

| Outcome | Meaning |
|---|---|
| `ErrEvidenceMalformed` | structurally incomplete bundle |
| `ErrEvidenceSourceQuiet` | the source names no block, so it cannot be an anchor |
| `ErrEvidenceUnauthenticated` | a certificate did not verify against the configured trust base, or its epoch has none |
| `ErrEvidenceWrongContext` | wrong partition, shard or shard configuration, or an unbound technical record |
| `ErrEvidenceGap` | a certificate is not the round its predecessor assigned |
| `ErrEvidenceNotQuiet` | a certificate after the source moved the state, so the source is not the last block |
| `ErrEvidenceEpochChange` | the chain crosses an epoch boundary — unsupported, not decided |
| `ErrEvidenceUnconnected` | the chain does not end at the round and state this node holds |
| `ErrEvidenceExhausted` | over the configured bounds |

---

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
(§6.1). It remains useful for the *different* problem of a node that observed a block and crashed,
which is #14's subject — but it does not overlap with the case measured here, so implementing it
would not close #92.

**(b) Peer evidence retrieval** — ask other shard validators for the chain. They hold exactly these
certificates in the ordinary course of running, so nothing new has to be stored. It requires a new
shard-internal request/response protocol alongside the existing dissemination protocol
(`/unicity/shard-payload/1.0.0`), and it makes availability depend on peers — but *only*
availability: a peer that lies, omits or truncates is caught by §2–§4, and the worst it can do is
fail to help. This is the property the predicate exists to guarantee.

**(c) Root-chain evidence retrieval** — ask the root chain to replay the certificates it issued.
Authoritative, and it needs no shard-side storage. But the root chain does not today serve historical
certificates on request, the subscription quota is already the scarce resource that caused #92's
earlier restart refusals (#109), and adding a per-shard-node historical query widens the root chain's
attack surface for a shard-local problem.

**Recommendation: (b), peer evidence retrieval, as the smallest implementation that closes the
measured gap** — one shard-internal request/response protocol, no new persistent state, no root-chain
change, and no new trust. (c) stays a reasonable second source if peer availability proves
insufficient in practice; (a) is orthogonal and belongs to #14.

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
| Valid quiet-tail recovery, no new transactions | `QuietTailRecoversWithoutNewTransactions` | — (accepted; yields block hash and round 10) |
| Missing middle evidence | `a missing middle certificate is a gap, not a shortcut` | `Gap` |
| Altered middle evidence | `an altered middle certificate no longer authenticates` | `Unauthenticated` |
| Unbound technical record | `a technical record the certificate does not commit to is refused` | `WrongContext` |
| Interval not actually quiet | `a non-quiet certificate inside the tail is refused` | `NotQuiet` |
| Source names no block | `a source that names no block is refused` | `SourceQuiet` |
| Wrong partition / shard / config | `another partition`, `another shard of this partition`, `another shard configuration` | `WrongContext` |
| Wrong / unknown epoch | `a chain crossing a shard epoch boundary…`, `an epoch with no configured trust base…` | `EpochChange`, `Unauthenticated` |
| Same state, different block | `SameStateDifferentBlockIsNotHistory` | `Gap` |
| Replay of an older complete bundle | `a correct chain that stops short…`, `the same chain replayed after the node has moved on…` | `Unconnected` |
| Repeat UC held (must still be accepted) | `a repeat certificate for the held round…` | — |
| Conflicting certificate for the held round | `a chain ending at the held round but a different state…` | `Unconnected` |
| Exhausted bounds | three cases under `ExhaustedBounds` | `Exhausted` |
| Payload unavailable, verified target retained | `VerifiedTargetSurvivesAnUnavailablePayload` | — |

**Mutation check.** Each of the three load-bearing checks was individually disabled and the suite
re-run, to confirm the fixtures are not passing for an unrelated reason:

| Check disabled | Fixtures that fail |
|---|---|
| assigned-round contiguity | `a missing middle certificate is a gap…`, `SameStateDifferentBlockIsNotHistory` |
| chain ends at the held partition round | `a correct chain that stops short of the held certificate is refused` |
| chain ends at the held state | `a chain ending at the held round but a different state is refused` |

---

## 8. Payload acquisition is a separate decision — and the existing path already works

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

**What this establishes.** The missing ancestor (block 3) was never delivered to this node by
`newPayload` — the node was down when it was certified, and it built nothing afterwards. It was
canonicalised **42 ms after** a forkchoiceUpdated named a descendant, through reth's standard Engine
API handling, with no BFT-side fetch of any kind. Ancestor acquisition is therefore already solved
by the execution client, and no custom payload-fetch mechanism is justified by this evidence.

**What this does not establish, stated explicitly.** The logs cannot distinguish "reth backfilled
block 3 from its peers on receiving the forkchoice update" from "reth already held block 3 via P2P
gossip during the outage and merely canonicalised it at the forkchoice update". The 42 ms — which
includes executing the block and finishing a state-root job — makes the second more likely, but the
run carries no log line that decides it, and this record does not claim one. Either way the
conclusion for this design is the same: the standard Engine API path obtained the block, and client
divergence is not needed.

**Consequence for the design.** Evidence retrieval and payload acquisition stay separate decisions.
The predicate answers only the first. A node that has a verified anchor but cannot yet obtain the
block body **keeps the verified target** and retries acquisition, rather than falling back to
`no-anchor` and re-verifying from scratch — which is what the fourth cursor in §5 is for, and what
`VerifiedTargetSurvivesAnUnavailablePayload` pins.

---

## 9. What this design deliberately does not change

- **P-id is unchanged.** The executor's head must still equal the certified *block*, not merely the
  state root. Recovery supplies the block hash that makes P-id satisfiable; it does not relax it.
- **P-sign is unchanged.** A recovered executor is **not** authorisation to vote. Reaching the
  certified block makes a node correct; what makes it *safe to sign* is the monotonic, crash-safe,
  non-rollback record of the highest partition round it has signed in — §6.1's contract, #105's
  subject. Nothing in this record supplies it, and no path here may be read as supplying it. A node
  that recovers its executor through this mechanism stays non-voting until #105 lands.
- **No production behaviour changes in this PR.** The predicate is unwired by construction: the
  transport, the provider-selection policy and the resource policy around it are still open (§6),
  and the part whose correctness is decidable today is the predicate. Every later decision is to be
  checked against it, not the other way round.

---

## 10. Scope held open

Recovery across an epoch transition (§3.1); provider selection and rate limiting for peer evidence
retrieval; whether the root chain should serve historical certificates as a second source (§6c);
durable retained history and the signing record (#14, #105); the distinction the reth logs could not
make in §8. #16 remains open, including "Too deep reorg", and nothing here claims to explain it.
