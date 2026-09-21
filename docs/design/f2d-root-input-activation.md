# F2d (#10): activating the canonical root input

Issue: #10, with #11 consuming it. Base: `integration/enshrined-evm` at the #210 merge.
Companion repository: [`ristik/ureth`](https://github.com/ristik/ureth) `unicity/main` at the #29 merge.

This is a delivery plan, not a design. The design is accepted and is `d1-canonical-root-input.md`
and `d2-reth-system-call-fee-profile.md` §2; the wiring shape is fixed by
`f2c-root-input-wiring-contract.md`, which exists precisely so that this unit is "a mechanical
change against agreed sources rather than a set of decisions taken while editing the execution
path". Nothing here reopens any of them.

## 1. Why this is possible now

F2c §11 closed by naming what stopped it:

> the execution-side provision mechanism for `extraData` and the D2 seal registry remain
> prerequisites that this repository cannot satisfy on its own.

**Both are now satisfied, from the other side.** F3 delivered the three `engine_*WithSealV1`
siblings (`f3-acceptance-ledger.md` §1), of which `engine_forkchoiceUpdatedWithSealV1` is the
mechanism that writes `extraData`, and the bounded `SealRegistry` kernel lives in
`crates/unicity/execution`. The blocker F2c recorded is gone, and nothing else in F2c has gone
stale: its cited call sites `engineapi/adapter.go:255` and `:391` are still the only two callers of
`DeriveAttributes`, verified against the current tree rather than assumed.

This is also the unit that moves F3 from **API** to **Wired** (`f2-execution-prerequisites.md` §0),
because it is the first thing that makes a running shard round call the seal methods at all.

## 2. Scope

**In scope**: making the adapter build and import through the seal siblings, carrying the companion
between nodes, replacing `v0` with `v1`, and submitting F2c §10's negatives.

**Out of scope**, named so the plan is not read as claiming them:

| Not delivered here | Where it belongs |
| --- | --- |
| devp2p import re-deriving inputs for a peer-gossiped seal block | U3j in `f3b-companion-retention.md` §4, still unscoped |
| the archival proof service for historical companions | F7 (#15), blocked on F6 |
| real-reth runs, synchronisation and launch tests | M1's gate, #41 |
| PoS activation, signing changes, issuance | separate tickets; F2c §11's list still applies |

## 3. The ordering constraint, which is the one real decision

F2c §5 warns that "a payload built through stock `PayloadAttributesV3` carries no commitment to
match, so enforcement without the execution-side provision mechanism halts the builder". That fixes
the order: **the build must route through the seal siblings before the commitment is enforced on
verify.** Switching the derivation first and enforcing immediately would stop block production.

So the units land as: transport, then build, then import, then the derivation switch. The
intermediate states are internally mixed — a block whose `extraData` is `v1`-derived while its
`prevRandao` is still `v0`-derived — and that is acceptable only because this is an integration
branch with no deployment. **No intermediate unit may be released**, and D2 §7's `v0` removal is
what closes the sequence.

## 4. The units

| Unit | Scope |
| --- | --- |
| **W1** | `ProposalEnvelope` gains `sealCompanion`, with codec vectors. Inert on its own, but it is what W2 populates and W3 consumes, and it is the transport `f3-acceptance-ledger.md` §2.2 records as absent |
| **W2** | the build path: `Client.RequireSealCapabilities()`, `Adapter.Build` through `engine_forkchoiceUpdatedWithSealV1` with `sealBuildInput = {rootInput, transitions}`, and `Adapter.Seal` through `engine_getPayloadWithSealV1`, publishing the returned companion into the envelope |
| **W3** | the import path: `Adapter.Verify` runs `VerifyCompanionWitnesses` (`evmroot/d2import.go:237`) **before** calling `engine_newPayloadWithSealV1`. This is the authentication boundary and it is the shard node's, never the execution client's |
| **W4** | replace the body of `DeriveAttributes` with the `v1` derivation (`evmroot.DerivePrevRandao`, `DeriveBeaconRoot`, `DeriveTimestamp`) and delete `v0` |
| **W5** | F2c §10's eight integration negatives |

## 5. Decisions the units inherit

### 5.1 `v0` is deleted, not flagged

F2c §9 requires that "`v0` and `v1` must never both be able to govern a block" and prefers deletion
to a flag, because `DeriveAttributes` is a single implementation point and replacing its body
changes build and verify together, leaving no second path to select. Take that route.

This appears to conflict with F2c §10's first required negative, which compares `v0` and `v1`
outputs for the same round. It does not: freeze `v0`'s expected values as **test vectors** rather
than keeping the code live. The negative's purpose is to establish that a mixed deployment is a
consensus split rather than a cosmetic difference, and a frozen vector shows that as well as live
code while removing the second derivation path the section exists to forbid.

### 5.2 The authentication boundary does not move

`VerifyCompanionWitnesses` runs in the shard node, before `newPayloadWithSealV1`, and reth accepts
that verdict over the JWT-authenticated channel. This was settled in `f3-engine-seal-delivery.md`
§4 and is restated here only because W3 is the first unit that can actually get it wrong. Its
inputs are verifier-owned: `VerifiedCert` and `ExpectedTransitions` are derived from the node's own
authenticated state, never deserialized from a peer's companion.

### 5.3 The follower validates a binding; it does not re-select

F2c §3.1 and its negatives 7 and 8. A follower derives its commitment from the **block-bound**
certificate, not from its own observed set, so two nodes with different observations agree. W3 must
not add any parameter by which a caller could assert that something was already verified.

## 6. The negatives, mapped

F2c §10's eight cases, with the unit that submits each:

| Case | Unit |
| --- | --- |
| 1. `v0` and `v1` disagree for the same round | W4, as frozen vectors per §5.1 |
| 2. today's parameters cannot authenticate | W5 |
| 3. the executor head is not the certified parent | W2 |
| 4. the observed maximum is not the cursor, and 4b an arbitrary low cursor removes a refusal | W5 |
| 5. `extraData` mismatch is rejected | W3 |
| 6. refusals stay distinct across the wiring boundary | W2 and W3 |
| 7. asymmetric delivery agrees | W3 |
| 8. evidence yes, verdict no | W3 |

Each is decidable against the current tree, as F2c states; none waits on a deployment.

## 7. Evidence this plan can produce

Following `f2-execution-prerequisites.md` §0: W1 to W5 take the seal path from **API** to **Wired**,
because a running shard round calls the methods. **Measured** remains M1's under #41, and Wired
"says nothing by itself about real execution-client evidence" — every unit here is exercised against
the adapter's own tests, not a running reth.

## 8. What still will not close #10 or #11

For #10: real-reth runs and the D1-vectors-against-an-independent-implementation clause of its
acceptance list. For #11: the devp2p obtain half, real-reth runs and synchronisation. Neither ticket
closes on this plan, and §2's out-of-scope table is the list of why.
