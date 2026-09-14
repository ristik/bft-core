# F2c (#10): the runtime-wiring contract for the canonical root input

Base integration `4f0ec961`. This is a contract, not an activation: no call site is changed, no
derivation is switched, and `v0` still governs every block this branch builds. What it fixes is the
shape of the later wiring unit, so that unit is a mechanical change against agreed sources rather
than a set of decisions taken while editing the execution path.

The API being wired is `rootinput.Derive` (#136/#138, merged `c0a3ef5d`): explicit verifier-owned
context in, an authenticated verified representation plus the canonical input and its commitment
out. It is a pure function with no memory, so nothing below treats a successful call as permission
to build, sign or accept. Freshness belongs to the caller's own applied state, and signing belongs
to F6c.

## 1. Call sites

| Call site | Where it is today | What `Derive` would give it |
|---|---|---|
| **builder** | `Round.produceBlock` (`shardnode/round.go:1172`) on the leader, through `Executor.Build`/`Seal`; the Engine API implementation is `engineapi.Adapter.Build` (`adapter.go:244`) | the commitment the block must carry, and the round parameters `v1` derives from `(r, n)` |
| **follower / import** | `Round.verifyWithRetry` → `Executor.Verify` on every validator including the leader over its own output; `engineapi.Adapter.Verify` (`adapter.go:~380`) re-derives attributes rather than trusting the envelope | an independently derived commitment to compare against `ExecutionPayloadV3.ExtraData`, and the same `v1` parameters |
| **replay** | **no such call path exists in this repository** | see §2 |

### 2. Replay is missing, and is not the recovery predicate

An earlier draft of this survey named `VerifyAnchorEvidence` as the replay consumer. That was wrong
twice over, and the correction matters more than the mistake.

It is wrong about the wiring: the comment at the top of `shardnode/anchorevidence.go` still says
"nothing calls VerifyAnchorEvidence in production yet", and that comment is stale. It is called from
`EvidenceRequester` (`shardnode/evidencerequester.go:719` and `:799`), which `NewRecoveryStack`
builds and `Node.EnableRecovery` installs, reached from `cli/ubft/cmd/shard_node_run.go:233`. A file
comment is not evidence about call paths, and this survey should have read callers.

It is also wrong about the role, which is the part that would have done damage. `VerifyAnchorEvidence`
decides whether an evidence bundle authenticates *an execution anchor for the state this node is
being asked to build on*: which certified block the executor must commit to, across a quiet tail. It
authenticates no EVM payload, derives no canonical root input and validates no block body. Using it
as the replay acceptance test would let anchor recovery stand in for canonical-input replay, which
is precisely the substitution the owner's instruction forbids.

So the replay call path is recorded here as **missing**, and its contract is defined rather than
borrowed:

- **Inputs**: the stored `UnicityCertificate` and `TechnicalRecord` for the round being replayed, the
  configured identity (network, partition, shard, configuration hash), the certified parent that
  round built on, and the applied-state cursor as of that round. All of it either from the node's own
  configured context or from authenticated storage, never from the block being replayed.
- **Validation**: `Derive` against that context, then the block's own `extraData` compared with the
  derived commitment, then the D2 import rules (`evmroot.ValidateImport`) for anything about the
  body. A replay that cannot supply the cursor refuses; it does not fall back to an observed maximum.
- **What it is for**: establishing that a block already in the executor's chain is the one the
  certificate authorizes. It grants nothing. A replayed genuine authorization derives every time,
  which is exactly why acceptance has to be decided by the caller's applied state.

Whether the replay consumer is built at all is a separate unit. It is named here so the wiring unit
does not quietly acquire one.

**Built as `rootinput.AcceptBlock`** (F2d). It is the D1 half only: it takes its own copy of the block
binding before authenticating anything, establishes the authorization through `Derive`, then checks
the block's certified parent and its `extraData` commitment, reporting those two as separate failures
from each other and from a derivation refusal. Both checks are substantive: the commitment covers the
parent this node **pinned**, carried inside the canonical input, and says nothing about the parent the
header itself names, so a header can carry exactly the right `extraData` while naming another parent
and only the equality check rejects it. It stops at the header,
so it cannot be mistaken for a body check, and the body stays with `evmroot.ValidateImport`. It is
memoryless and grants nothing: a genuine block replays every time it is offered, and whether a round
may be answered again is the caller's applied state and, for signing, the record in #105 step 2. It is
wired nowhere.

## 3. Where each pinned input comes from, per call site

`Derive` refuses rather than selecting, so every one of these is the caller's to source. "Independently
trusted" below is about the *check*, not about where the bytes arrived from: a value may travel with the
block, but nothing about it may be taken on the sender's word, and nothing may be inferred from the
executor's own state. A certificate read out of a companion is evidence that this node then
authenticates against its own configured trust; that is why §3.1 is a stricter rule than local
re-selection, not a looser one.

| Pinned input | Builder | Follower / import | Replay (when built) |
|---|---|---|---|
| **authorization** (`uc`, `tr`) | any certificate that is valid, authorizes round `n`, and is not behind this node's own cursor. The builder **binds** it: its `O_-` is committed in `extraData` and the full `UC_-`/`TE_-` travel in the D2 companion (D1 §5.1) | **the certificate the block binds**, read from the companion and authenticated here against this node's own trust base, configured identity and committed cursor. Never re-picked from this node's own inbox (§3.1) | the certificate the stored block binds, re-authenticated on load against the same configured context |
| **certified parent** `h_parent` | the last state-changing certified block, from `continuityState.anchor` via `recoveryTarget`, which is what `Round.reconcile` already uses. **Not** `uc.InputRecord.BlockHash` read unconditionally: a quiet certificate carries none by construction, which is the #92 defect (`shardnode/round.go:380`). Until a certificate names a post-genesis block, the anchor is the authenticated genesis and the parent is the pinned genesis block hash, for whatever round the first payload is authorized, not only round 1 (amended by F4a #153, `f4a-seal-registry-contract.md` §7.3) | the same rule applied to the **bound** certificate's certified state (D1 §5.4: continuity is checked against `O_-.IR.Hash`, never a later local execution head), then cross-checked against the payload header's own `parentHash` | the parent recorded for that round in the replayed chain, cross-checked the same way |
| **configuration** | the node's configured `ShardConfHash`, threaded from startup (#134/#135). Never the certificate's own value | same | same |
| **committed seal-registry cursor** `lastAppliedRootRound` | **not available on this branch**: no seal registry exists, so the builder cannot source it from committed state. See §6 | same | same |
| **round** `n` | `TechnicalRecord.Round`, stated by the caller and cross-checked by `Derive` (`ErrNotPinned`), never read out of the record and trusted | same | same |

### 3.1 The follower validates a binding; it does not re-select

An earlier revision of this table said the follower uses "the same certificate this node authenticated
for this round, never the proposer's copy and never anything travelling with the block". That is wrong,
and it contradicts D1 §5.

Two honest nodes hold different valid certificates for the same shard round: duplicates from several
root nodes, and repeat certificates after a shard timeout. If each derived from whichever it holds,
they would compute different `extraData` for the same block, or a follower would refuse a valid
proposal because of delivery order. D1 §5 resolves this by making the choice part of the block: the
proposer binds one valid certificate, and the follower **validates that binding** rather than making
its own.

So the follower's contract is chosen-witness verification, and it is stricter than trusting the
proposer, not looser:

1. read the bound `UC_-`/`TE_-` from the companion;
2. authenticate them here, against this node's own configured trust base, partition, shard and
   configuration hash, by the same `rootinput.Derive` path a builder uses, with nothing accepted on the
   proposer's word;
3. recompute `extraData` and require it to equal the block's;
4. run `evmroot.ValidateBoundCertificate(ref, cert, n, lastAppliedRootRound)` against this node's own
   **committed** cursor, which is the single view-dependent input and is shared state rather than
   arrival order.

The distinction to keep: **peer-provided evidence is permitted; a peer-provided verdict is not.** A
certificate arriving in a companion is evidence, and it is re-verified here. A field, flag or type
saying the proposer already verified it is a verdict, and there is no parameter on `Derive` that
accepts one (§10, negative 8).

A later valid repeat the proposer did not bind is simply unused for this block. A repeat the follower
has *already applied* moves its committed cursor past the bound certificate, and then the block is
rejected and re-proposed against a current certificate, deterministically given committed state.

The negative case that matters for all three: the executor's current head is not a substitute for the
certified parent, and the highest root round this node has observed is not a substitute for the
committed cursor. `Derive` cannot catch either substitution, because both arrive as pinned inputs it
is required to trust. That is what makes this contract worth writing down rather than inferring at
the call site.

## 4. The `v1` parameter contract

`RoundParams` today (`shardnode/executor.go:31`) carries `Round`, `Epoch`, `Timestamp`, `SealHash`,
`Leader` and `Parent`. It is built in `produceBlock` from an `Expectation` and a seal hash, and the
`Expectation` (`shardnode/inputrecord.go:19`) is itself four scalars extracted from the certificate.
By the time an executor sees a round, the certificate is gone.

That is the authentication boundary problem, and adding a root-round integer does not fix it. `v1`
keys its derivations on `(r, n)` where `v0` keyed on `(u, n)`, so `r` is *necessary*; but an executor
handed `r` alongside the other scalars still cannot verify anything, because scalars carry no
authority. It would be trusting the framework's summary of a certificate rather than checking a
certificate.

The contract is therefore: **the round parameters carry the pinned authorization and the full pinned
context, not a widened tuple of scalars.** Concretely, the wiring unit hands the executor the
authenticated `rootinput.Result` for the round (which owns its copies of the certificate and
technical record, and carries the canonical input and commitment) together with the pinned context
that produced it. An executor that wants to check rather than trust can re-derive; one that does not
can read the commitment. Either way the value it acts on is one the framework has authenticated
against its own configured trust, and the scalars `v0` needed become derived views of it rather than
the interface.

On the follower side the same rule applies to a different object: what travels is the **block-bound**
authorization from the companion (§3.1), and the follower re-derives from that rather than from the
certificate its own inbox happens to hold. The parameter contract therefore carries the bound witness
on both paths; it is the same shape, sourced differently.

**`r` identifies an authorization; it is not a namespace and not a lock.** `v1` needs the root round
because it keys its derivations on `(r, n)`, and `r` is part of what identifies one authorization. It
must not be read as a key that partitions anything. A repeat certificate (identical input record, higher
`r`) is the same work, carrying no new commitment; treat `r` as a partitioning key and a repeat becomes
a second authorization able to license different bytes for a round already answered.

The seal-registry cursor is not the missing lock either. Its comparison is a freshness rule about
committed state, and freshness alone cannot stop two different requests under two successive valid
authorizations. The one-message-per-assigned-round lock belongs to the signing authority's record
(#140), keyed by the enrolled key and profile together with the assigned shard round. Root round
identifies derivation and authorization; it is never an independent signing namespace.

**Each boundary owns and checks its own snapshot.** That two call sites may hold the same certificate
value guarantees nothing on its own: a shared object or a shared type is not a shared check. Every
boundary takes its own copy, authenticates against its own configured context, and validates its own
binding, exactly as `rootinput.Derive` and the signing authority each do today. Consistency between
them is a property of both performing the check, never of one having performed it.

Two consequences to settle in the wiring unit, not here: whether `RoundParams` gains that field or is
replaced, and what the `executortest` fake does with it, since `Executor` is a published boundary
(ADR 0001) and `executortest` and `engineapi` both implement it.

## 5. `extraData`: what Go can enforce, and what it cannot

This is the sharpest boundary in the unit, and the reason activation stays gated.

**Stock `PayloadAttributesV3` has no `extraData` field** (`engineapi/types.go:67`). A builder using
the standard Engine API cannot ask an execution client to place the D1 commitment in the header it
produces. No amount of Go in this repository changes that, and extending the Engine API or modifying
reth is out of scope here by standing constraint.

**`ExecutionPayloadV3` does expose `ExtraData`** (`engineapi/types.go:29`). So the commitment is
*checkable* on both paths:

- on the builder side, after `getPayload`, by comparing the sealed payload's `ExtraData` with the
  derived commitment and refusing the round rather than certifying a block that does not carry it;
- on the follower/import side, by the same comparison before the block is accepted. The accepted
  model already states this rule: `evmroot.ValidateImport` rejects `extradata_mismatch` when
  `header.extraData != SHA-256(CBOR(canonical rootInput))` (`evmroot/d2import.go:394`).

The distinction to keep explicit: **fail-closed checking is not provision.** A builder that can only
reject produces no blocks at all once the rule is enforced, because nothing makes the execution
client write the commitment in the first place. Enforcement without the execution-side provision
mechanism converts a liveness-neutral check into a total halt. Therefore:

- the wiring unit may implement the checks;
- it must not enable them on the builder path until the accepted D2 execution-side provision
  mechanism exists and is tested, in the reth work (F3/`ureth`), and this repository can only state
  the requirement, not satisfy it;
- the follower/import check has the same dependency in practice, since there is nothing to compare
  against until blocks carry the commitment.

## 6. The seal-registry cursor

D1 §5 makes `lastAppliedRootRound` committed state. No seal registry exists on this branch: the
model has `SealRegistryCommitment` and `DerivedSealOutcomes` (`evmroot/d2import.go`), which are D2
constructs, and nothing in `shardnode/` or `engineapi/` maintains one. `Derive` therefore takes the
cursor as a caller-pinned input and names it as caller-pinned in its result.

Until the D2 registry exists, the wiring unit has exactly two honest options, and picking between
them is a design decision rather than an implementation detail: refuse to activate the cursor rule
(and say so), or pin the cursor from committed execution state once that state exists. Reading the
node's observed maximum is not a third option, and `evmroot.ValidateBoundCertificate` cannot detect
the substitution because the value arrives as an input.

The failure it causes is not the obvious one. An observed maximum includes valid certificates this
node has *not applied* (a repeat at root round 60 while its applied history ends at 40). Substituting
it does not let something through; it **rejects a block that committed state accepts**, and it makes
two nodes disagree about the same block according to what each happened to receive. A cursor set
below the committed value is the opposite and separate failure: it removes a refusal that committed
state would have made. Negatives 4 and 4b keep the two apart.

## 7. Genesis initialization

Settled explicitly, as the ticket requires, and consistent with what `rootinput` already implements.

The canonical API never produces the D1 §6 genesis-installation row: `certification.TechnicalRecord.IsValid`
rejects `Round == 0`, so no live technical record can authorize shard round 0, and `Derive` refuses
`n = 0` with `ErrUnsupported` naming that reason. Genesis is therefore **deployment configuration**,
not a derived tuple: the executor's block zero, reported by `Executor.GenesisBlock` from
configuration rather than from an observed head, and already bound at startup by the expected-genesis
check (#89).

The first tuple this API ever produces is the first post-genesis payload, at `n = 1` unless root timeouts advanced the technical record first (amended by F4a #153, §7.3 there), whose
`h_parent` is that pinned genesis block hash. The wiring unit inherits that rule; changing it is a
D1 revision, recorded in `docs/design/f2b-root-input-derivation-mapping.md` §5.1.

## 8. Refusals that must survive wiring

Named in `rootinput` and in the F2b mapping, and not to be softened into defaults by a call site:

| Refusal | Why it stands |
|---|---|
| non-empty pending transitions `D` | no authenticated feed of committed trust-base bodies or handoff acknowledgements reaches a shard node (`TrustBaseStore` resolves a `RootTrustBaseV1` per epoch; that is not the ordered committed-body sequence D1 means) |
| epoch **handoff** boundary | structurally valid, unauthenticable without those bodies |
| genesis `n = 0` | §7 |
| unknown root epoch, wrong configuration/partition/network, sub-quorum, stale cursor, unpinned round | each is a distinct named error; a call site that collapses them into one failure destroys the operator's ability to tell a misconfiguration from an attack |

A call site may add refusals. It may not convert one into a fallback.

## 9. Removing `v0`

`engineapi/params.go` computes `prevRandao = SHA-256(0x01 ‖ UnicityTreeRoot ‖ be64(n))` and
`parentBeaconBlockRoot` with `0x02`, keyed by `(u, n)`, with no `extraData` commitment at all. D1 §4
calls this `v0`, states that `v1` replaces it wholesale, and records that F2 deletes it. There is no
live deployment on `v0`, so no migration is specified.

The requirement for the wiring unit is that **`v0` and `v1` must never both be able to govern a
block.** `DeriveAttributes` is called from exactly two places (`engineapi/adapter.go:255` for build,
`:391` for verify), and `Verify`/`VerifyAgainst` recompute through the same function, so the
derivation has a single implementation point. Deletion is therefore preferable to a flag: replacing
the body of `DeriveAttributes` with the `v1` derivation (`evmroot.DerivePrevRandao`,
`evmroot.DeriveBeaconRoot`, `evmroot.DeriveTimestamp`) changes build and verify together and leaves
no second path to select.

If the unit nevertheless needs both present at once, the isolation requirement is that the choice is
made once per process from configuration, never per round and never per call site, and that a
follower's recomputation uses the same choice as the builder by construction rather than by
agreement. The negative in §10 exists to make the "both live" failure visible.

## 10. Required integration negatives

These are the cases the wiring unit must submit as tests, before activation. They are written against
the current tree, so each one is decidable now:

1. **`v0` and `v1` disagree for the same round.** Same `(SealHash, r, n)`, different `prevRandao` and
   `parentBeaconBlockRoot`. Establishes that a mixed deployment is a consensus split rather than a
   cosmetic difference, which is why §9 requires a single implementation point.
2. **Today's parameters cannot authenticate.** A fabricated `RoundParams`, authorized by nothing, is
   structurally indistinguishable from a genuine one: a seal hash is a value, not a certificate, so it
   carries no quorum, no inclusion path and no trust base for an executor to check. The same case
   shows that widening the tuple with `r` does not help, because `evmroot.DerivePrevRandao` is a total
   function of two integers and derives just as cleanly from an invented root round (§4).
3. **The executor head is not the certified parent.** A pinned parent taken from the executor's head
   after a quiet tail differs from the last state-changing certified block, and `Derive` accepts the
   wrong one without complaint, because it is a pinned input (§3).
4. **The observed maximum is not the cursor.** A realizable history: committed cursor at root round
   40, the block-bound authorization at 50, and a valid repeat at 60 observed but not applied.
   Validating against the committed cursor accepts; substituting the highest observed root round
   rejects a good block, and two nodes with different observations disagree about the same block. A
   cursor below the committed value is a separate case (4b), labelled as arbitrary or stale context
   rather than as the observed-maximum failure (§6).
   - **4b, an arbitrary low cursor removes a refusal.** Committed state has moved past a binding
     and refuses it; a lower cursor makes that refusal disappear. Distinct from 4 in both direction
     and cause.
5. **A payload whose `extraData` does not match is rejected**, and, which is the point of the
   negative, a payload built through stock `PayloadAttributesV3` carries no commitment to match, so
   enforcement without the execution-side provision mechanism halts the builder rather than
   protecting it (§5).
6. **Refusals stay distinct** across the wiring boundary: each `rootinput` error class still arrives
   at the call site as itself (§8).
7. **Asymmetric delivery agrees.** Two nodes with different observed sets, one holding a later valid
   repeat the proposer did not bind, derive byte-identical commitments from the block-bound
   certificate, and would derive different ones if either re-picked from its own view (§3.1).
8. **Evidence yes, verdict no.** A substituted or unauthenticated companion certificate is refused
   here rather than accepted on the proposer's word, and the derivation API exposes no parameter by
   which a caller could assert that something was already verified (§3.1).

## 11. What this unit does not do

No call site is activated, no derivation is switched, `v0` is not deleted, no Engine API is extended,
no reth change is proposed here, no signing is re-enabled, no PoS activation follows. #10 stays open;
the execution-side provision mechanism for `extraData` and the D2 seal registry remain prerequisites
that this repository cannot satisfy on its own.
