# ADR 0008: Historical trust, proof and custody profile (D6)

## Status

Proposed (D6, issue #8). Revised after the first review (#82): live certificate
age is measured against the **imported certified origin**, not a checkpoint
round; the proof models use **real hash-linked header chains and Merkle paths**
that fail on a broken link / wrong root / below-threshold seal / wrong digest,
not trusted booleans; **`BridgeLedger.Solvent()`** checks `Balance + Shortfall ==
L − P` with no deficit (not just `L ≥ D ≥ P`); checkpoint freshness is a
**derived, strict** policy.

Revised again after the second review (#82):

- **The shared seal now authenticates `r*` itself.** `AnchorSeal` carries `r*`,
  the epoch, the assignment id, a real-key `WeightSet` and a `Signatures` map;
  `VerifySeal()` **derives** the threshold as `RootQuorumThreshold(TotalWeight)`
  (never supplied — a zero threshold is impossible) and verifies each signer's
  secp256k1 signature over `AnchorSealStatement(r*, epoch, assignmentID)`.
  Unsigned seals, forged signer entries, substituted roots and cross-epoch
  replays all fall short of the derived threshold.
- **Shard paths authenticate their partition/shard/config.** Each
  `ShardAnchorPath` carries a certified `ConfigHash`, and the path folds from
  `shardAnchorLeaf(pid ‖ shardID ‖ configHash ‖ shardStateRoot)`, so relabelling
  `7/0 → 99/attacker` no longer recomputes to `r*`.
- **`ProofBundle` separates structural availability from verification** —
  `CarriesEvidence()` (has the pieces) vs `OfflineVerify()` (actually checks the
  seal + path + subject). A live bundle with only a receipt no longer passes.
- **Checkpoint freshness** — `ConsensusMinRoundPeriodSeconds` bracketed the
  per-round estimate.

Revised again after the third review (#82):

- **Offline verification no longer trusts the assignment supplied by the proof.**
  `OfflineVerify` takes a `VerifierTrustAnchor` — the verifier's own
  authenticated `ChainContext`, `Epoch`, trust-base `BodyIdentity`, `Weights`
  and `FreshnessPolicy`. The bundle's carried assignment/epoch/id are untrusted:
  they must match the anchor, and the seal is re-checked against **`t.Weights`**,
  so an attacker's one-member assignment with a valid attacker signature (even
  copying the honest `AssignmentID`) does not verify.
- **The freshness "floor" is honest about what consensus guarantees.**
  `Pacemaker.AdvanceRoundQC` advances immediately on a QC, so there is no
  enforced minimum successful-round duration. The round-count arithmetic is now
  `RoundBasedAdvisorySeconds()` (advisory only). The safety limit is derived
  solely from `EnforcedRealTimeFloorSeconds` — a real wall-clock guarantee
  supplied as an authenticated input; `FreshnessPolicy.Supported()`/`Valid()`
  are false without one. `MinRoundPeriodSeconds` must be in
  `[ConsensusMinRoundPeriodSeconds, MaxObservedRoundPeriodSeconds]` — a
  conservative floor is a lower bound, so an arbitrarily large value is rejected
  too.
- **`shardAnchorLeaf` is length-delimited** — moving a byte across the
  `shardID`/`configHash` boundary no longer preserves the hash.

Freeze once re-reviewed by a cryptography reviewer
and a custody-accounting reviewer, neither the author. Depends on ADR
0003/0006/0007. Closes the M0 design set.

## Context

`appendix-evm.tex` and `appendix-bridging.tex` specify historical trust and
custody but the prototype has none of it, and several places need an explicit
"this is not constant-size / not globally observable" disclaimer so no consumer
builds on a stronger guarantee than exists.

## Decision

Adopt the profile in
[`docs/design/d6-historical-trust-proof-custody.md`](../design/d6-historical-trust-proof-custody.md):

1. **Three separate quantities** — the trusted checkpoint (content: network id,
   root/config commitment, authenticated EVM head), its freshness limit (client
   policy in **elapsed time** = `Δ_hold × min round period`), and `W_cert` (a
   round window). Plus the key cache count. None substitutes for another.
   Mandatory nesting `W_cert ≤ Δ_ev < Δ_hold`. Evidence-verification keys are
   retained past the admission cache until every evidence and retirement
   obligation is discharged.

2. **Historical authentication** — a block outside `W_cert` is authenticated by an
   Ethereum parent-header chain from a recent authenticated EVM head, **linear in
   distance**, **explicitly not constant-size**. Retired-key signatures alone are
   insufficient.

3. **Shared-seal multi-shard anchor** — one seal `C*` / root `r*`, verified once
   against **real signatures over `r*`** and a **derived** quorum threshold; one
   shard path per touched shard, each folding from a leaf that **binds the
   certified partition/shard/config**; each transaction leaf checked under its
   own shard state root. Path count grows with touched shards; seal verification
   does not.

4. **Custody accounting** — `NativeSupply = S_0 − Burn`; `native_uct` / `wuct` /
   `bridged` are distinct claims; the vault's native balance is not
   double-counted (`bridgedOutstanding ≤ vaultNative`, WUCT separate).
   `O = L − D ≥ 0`, `C = D − P ≥ 0`, `L ≥ D ≥ P`, checked at every intermediate
   custody state. `GlobalSupplyObservable = false`.

5. **Refreshable lock witness** — a fresh proof of the same permanent lock digest
   refreshes backing without changing token identity; digests are undeletable.

6. **Bridge type restriction** — whole transfers and burns only; no split/merge/
   mint-reason extension. Direct and succinct redemption implement the same
   semantic relation (network, config, trust-base, nullifier, lock refs, release
   leaves) with different witness formats.

## Deliverables

- `evmroot/d6checkpoint.go` (`FreshnessPolicy` with `EnforcedRealTimeFloorSeconds`
  / `Supported()` / advisory round arithmetic), `d6proof.go`
  (`VerifierTrustAnchor`, length-delimited `shardAnchorLeaf`), `d6custody.go`,
  `d6seal.go` (deterministic real-key seal fixtures).
- `evmroot/testdata/d6-vectors.json` — checkpoint/windows (enforced-floor vs
  advisory, unsupported / too-fast / too-slow rejections), historical-block
  authentication (constant-size false, header count grows), multi-shard anchor
  (verifying case + relabel / unsigned / forged / substituted-root / wrong-epoch
  negatives), proof-bundle offline verification (forged self-supplied
  assignment, stale checkpoint), lock-witness refresh, supply/backing, custody
  walkthrough, token profile, redemption relation.
- `evmroot/cmd/d6vectors` + `TestD6_VectorsMatchGolden`.

## Consequences

- `H1` (multi-epoch trust-base storage), `H5` (checkpoint production / client
  verification), `F7` (archive / offline execution-proof export), `B1`–`B7`
  (bridge builtins, TokenVerifier, shared-seal assembly, BridgeVault, refreshable
  mint backing, redemption) implement against this profile.
- The M0 gate (issue #40) now has R0 + D1–D6 evidence.
- No implementation may claim constant-size old proofs or a global
  Execution-layer supply figure.

## Alternatives considered

- **Fold the refreshed witness into token identity.** Rejected: identity would
  change every time backing is refreshed, breaking equality of the "same" token.
- **A single "trust window" parameter.** Rejected: the spec deliberately keeps
  checkpoint freshness (elapsed time), `W_cert` (rounds) and the key cache
  (count) independent, because they are re-derived from different inputs.
- **Claim an MMR now.** Rejected: the MMR is optional compression; the
  header-chain and state-proof paths are the required baseline and are linear.
- **Trust a supplied seal threshold and a signer name list.** Rejected on
  re-review: a supplied threshold can be zero and a name is not a signature. The
  threshold is derived from the authenticated assignment and each signer must
  present a signature over `r*`.
- **Key the shard→root association by a caller-supplied `(partitionID, shardID)`.**
  Rejected: relabelling then passes. The identity is hashed into the leaf that
  folds to `r*`.
- **Let `SelfContained` mean "has non-empty fields".** Rejected: it conflated
  structural availability with a successful offline check. Split into
  `CarriesEvidence` and `OfflineVerify`.
- **Verify the live seal against the assignment carried in the proof bundle.**
  Rejected on the third review: an attacker supplies their own one-member
  assignment and signature. `OfflineVerify` derives the assignment from the
  verifier's own authenticated `VerifierTrustAnchor` and re-checks against it.
- **Derive a real-time protection guarantee from `Δ_hold` rounds × a per-round
  period.** Rejected: consensus advances immediately on a QC and guarantees no
  minimum successful-round duration; a larger assumed period only inflates the
  number. The round arithmetic is advisory; the safety limit comes only from an
  enforced wall-clock floor, and the policy is reported unsupported without one.
