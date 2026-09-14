# F2b (#136): where each canonical root-input field comes from

This is the first commit of #136: the contract, traced and pinned, before any derivation code. Every
canonical D1 field is mapped to **the signed commitment or the locally pinned context that supplies
it**, read from the accepted profile (`docs/design/d1-canonical-root-input.md`, ADR 0003), the accepted
executable model (`evmroot/`) and the live certificate pipeline at integration `bca4fb3f`. Where a
field cannot be sourced that way in the current single-configuration profile, it is named here as a
refusal, not approximated.

Nothing in this document invents a field, domain or transition rule. Where the accepted profile and the
live pipeline disagree, that is recorded in §5 as a question for design review rather than settled here.

## 1. What already exists, and what F2b adds

| | |
|---|---|
| `docs/design/d1-canonical-root-input.md` | the normative profile: field inventory, deterministic CBOR, domains, selection rule, round types |
| `evmroot/` | the accepted executable model: `RootOrigin`/`RootInput` with `Validate`, `Encode`, `ExtraData`, an independent CBOR encoder, `RootOriginFromCertificate`, `ValidateBoundCertificate`, the certified-round clock, and the published vectors (`evmroot/testdata/vectors.json`) |
| **F2b adds** | a production derivation boundary that takes **real** `*types.UnicityCertificate` + `*certification.TechnicalRecord` plus an explicit verifier-owned context, **authenticates them**, and returns the canonical input with its commitment — reusing `evmroot`'s encoding and constants, never a second codec |

`evmroot` is an ordinary package (no build tags; it depends only on the standard library,
`network/protocol/certification` and `bft-go-base/types`), so production code can import it as the
single canonical encoder.

The gap F2b closes is authentication, not encoding: `RootOriginFromCertificate` maps committed content
onto `O_-` and is signature-free by design, but it **does not verify anything** — not the seal, not the
inclusion paths, and notably not that the technical record it is handed is the one the certificate
commits to. A caller holding a `VerifiedCert`-shaped value or an `Authenticated` flag from a peer is
exactly what must not be accepted.

## 2. `rootInput` fields

`v`, the domain constants and the encoding come from `evmroot`; none is restated here.

| Field | Source kind | Live source | Notes |
|---|---|---|---|
| `v` (profile version) | fixed constant | `evmroot.ProfileVersion` | 1; a change is a profile bump, not an option |
| `α` network id | **pinned local context** | configured `PartitionDescriptionRecord.NetworkID` | must equal `UnicitySeal.NetworkID`; a mismatch is a refusal, never a reason to adopt the certificate's value |
| `β` partition id | **pinned local context** | configured `PartitionDescriptionRecord.PartitionID` | enforced cryptographically: `UC.Verify(..., partitionID, ...)` checks `UnicityTreeCertificate.Partition` on the authenticated path |
| `σ` shard id | **pinned local context** | configured `ShardID.Bytes()` | enforced by `UC.Verify(..., shardID, ...)` through the shard-tree certificate |
| `n` authorized shard round | **signed commitment**, via TR | `TechnicalRecord.Round` | the TR is bound to the certificate by `uc.TRHash`; see §3 |
| `e_cert` certified epoch | **signed commitment** | `uc.InputRecord.Epoch` | |
| `e_auth` authorized epoch | **signed commitment**, via TR | `TechnicalRecord.Epoch` | boundary classified by `evmroot.EpochBoundary`; see §4 for which boundaries are supported |
| `h_parent` | **caller-pinned certified parent** | `RoundParams.Parent.Hash` (`shardnode.BlockRef`), reconciled to the certified parent by `Round.reconcile` | never the node's later local execution head, never an `eth_getBlockByNumber` answer; null only for genesis installation (§5) |
| `O_-` root origin | **signed commitment** | `evmroot.RootOriginFromCertificate(uc, tr)` | committed content only: no signature map, no shard-tree path, no unicity-tree path — which is what makes alternate valid quorum subsets agree byte-for-byte |
| `TE_-` technical record | **signed commitment**, via TR | `TechnicalRecord` `(Round, Epoch, Leader, StatHash, FeeHash)` | |
| `D` pending transitions | **authenticated committed bodies** | *no live source* | see §4: empty in the supported profile, and a non-empty requirement is a named refusal |

`O_-`'s own fields map straight onto the certificate: `α`/`r`/`e_r`/`t_r`/`u` from
`UnicitySeal.{NetworkID, RootChainRoundNumber, Epoch, Timestamp, Hash}`, `IR` from
`uc.InputRecord` `(RoundNumber, Epoch, PreviousHash, Hash, Timestamp, BlockHash)`, and `TRHash` /
`ShardConfHash` from the certificate. The model already does this mapping; F2b's job is to authenticate
the inputs before calling it and to own the bytes afterwards.

**Not sourced from**, for every field above: the wall clock, the current peer view, the execution
client's head, a checkpoint's own claim, or anything travelling with an evidence bundle. `t_r` is the
certificate's own sealed timestamp, not local time; the EVM header timestamp is derived later by
`evmroot.DeriveTimestamp(t_r, parentTimestamp)` from the pinned parent.

## 3. What the verifier must check before any of this counts

The derivation is only meaningful after the certificate is authenticated against **verifier-owned**
context. The full list, in the order F2b will apply it:

1. **Trust base by root epoch**, from the node's configured store, keyed by `uc.GetRootEpoch()`. An
   unknown epoch is a refusal; the certificate's own claim about its epoch is what is in question.
2. **`uc.Verify(tb, SHA256, β, σ, configuredShardConfHash)`** — quorum signatures against that trust
   base, shard-tree and unicity-tree inclusion paths, partition, shard, and the **configuration
   commitment** (the binding #134/#135 added; the configured hash is local, never the certificate's).
3. **Technical record binding**: `tr.HashMatches(uc.TRHash)`. The model computes `tr.Hash()` for `O_-`
   but never compares it, so without this step a caller could pair a genuine certificate with someone
   else's technical record and still produce a well-formed `rootInput`. `cr.IsValid()` performs this
   check on the live delivery path; the derivation API must not depend on having come through it.
4. **Network cross-check**: configured `α` equals `UnicitySeal.NetworkID`.
5. **Pinned round/parent/cursor**: `TE_-.Round == n` (the round the caller pinned), the caller's pinned
   certified parent, and the seal-registry cursor rule from D1 §5 —
   `evmroot.ValidateBoundCertificate(ref, cert, n, lastAppliedRootRound)`. The authorizing certificate
   is **pinned by the caller**, never selected from the verifier's locally observed set.
6. **`RootInput.Validate()`** — the model's own structural rules (version, epoch boundary, `TE` agreement,
   digest widths, the parent-hash rule, non-empty transition bodies).

Only then are `Encode()`/`ExtraData()` meaningful, and the verified representation is what is retained.

## 4. Supported profile, and what is refused

**Supported now** — same configuration, same epoch, one pinned authorizing certificate:

| Round type (D1 §6) | Supported | Why |
|---|---|---|
| successful (`h ≠ h'`, `h_b` present) | yes | all fields available from the certificate and the pinned parent |
| quiet (`h = h'`, `h_b` null) | yes | same; no block carries the commitment, but the tuple is well defined |
| repeat (identical `IR`, higher `r`) | yes, as input | D1: no new commitment; the earlier block's `extraData` stands. The cursor rule in §3.5 is what distinguishes a stale binding from a current one |
| first post-genesis payload (`n ≥ 1`, certified input record still genesis history, `h_parent` = pinned genesis block hash; `n` exceeds 1 when initial rounds timed out, amended by F4a #153) | yes | the pinned genesis hash is deployment context the node already binds at startup (#89's expected-genesis check) |

**Refused, by name, rather than approximated:**

| Situation | Refusal | Requirement recorded on |
|---|---|---|
| `D` non-empty — the EVM is missing committed trust-base bodies or handoff acks | there is **no authenticated feed of committed bodies to a shard node** in this codebase. `TrustBaseStore` resolves a `RootTrustBaseV1` per root epoch; it is not the ordered canonical committed-body sequence D1 means, and no handoff-ack channel exists. An empty list, a bool verdict or a provider-supplied "expected transitions" list would each be an invention | #10 / H-series (D3 `TrustBaseBodyV2`, D4 handoff) |
| epoch **handoff** boundary (`e_auth == e_cert + 1`) | structurally valid per `evmroot.EpochBoundary`, but authenticating *that the successor assignment is the committed one* needs the same missing committed bodies. Supported only once that evidence exists | #10 / H-series |
| epoch boundary anything else | invalid — `RootInput.Validate` rejects it | — |
| **genesis installation** (`n = 0`) | cannot be built from a live technical record at all: `certification.TechnicalRecord.IsValid()` rejects `Round == 0` ("round is unassigned"), so no TR authorizing round 0 can exist on this pipeline. D1 §6 defines the row, and the model can express it, but the production boundary cannot source it from a certificate + TR pair | §5, for design review |
| **canceled** attempt | never committed to a block by D1; not an input this API produces | — |

## 5. Points for design review, not to be settled in code

1. **Genesis installation vs `TechnicalRecord.IsValid`.** D1 §6's genesis-installation row authorizes
   shard round 0 with a null parent, while the live technical record type refuses `Round == 0`. Either
   the row is not produced by this boundary (genesis is installed from deployment configuration, and
   the first tuple this API ever produces is the first post-genesis payload at `n ≥ 1`, round 1 unless root timeouts came first, as amended by F4a #153), or D1/the
   record type needs an explicit statement of how a round-0 authorization is represented. F2b will
   implement the first reading and refuse `n = 0` with that named reason; changing it is a D1 revision.
2. **Seal-registry cursor.** D1 §5 makes `lastAppliedRootRound` committed state. No such registry
   exists in this repository yet, so F2b takes it as an explicit caller-pinned input and names it as
   caller-pinned in the result. It must not be read from the node's observed maximum.
3. **`χ` (chain id)** is bound by D1 §7 to configuration and checked per block, but it is not a
   `rootInput` field; the adapter's existing startup chain-id binding (#89) covers it. No new check here.
4. **`v0` deletion.** D1 §4 says F2 deletes `engineapi/params.go`'s `v0` derivation
   (`0x01`/`0x02` prefixes over raw concatenation, keyed by `(u, n)`, no `extraData`). F2b introduces
   the `v1` derivation as a pure API and **activates no call site**, so `v0` stays until the wiring
   unit; they must not both be live afterwards.

## 6. What the following commits implement

One pure API, usable identically by a builder, a follower validating a leader's block, and a replay
consumer, with no ambient state: explicit context in, authenticated verified representation plus
canonical input and commitment out, refusals named per §4. Input, witness and context byte slices are
owned (cloned) on the way in, so a caller mutating them afterwards cannot change the retained result.
Acceptance compares exact canonical bytes against the accepted D1 vectors and against the independent
CBOR oracle the model already cross-checks with, proves alternate valid quorum subsets agree, and
establishes each negative fixture's premises so an unrelated failure cannot satisfy it.
