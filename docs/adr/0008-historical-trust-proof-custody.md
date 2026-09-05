# ADR 0008: Historical trust, proof and custody profile (D6)

## Status

Proposed (D6, issue #8). Freeze once reviewed by a cryptography / proof reviewer
and a custody-accounting reviewer, neither the author. Depends on ADR 0003 (D1),
ADR 0006 (D4), ADR 0007 (D5). Closes the M0 design set.

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

3. **Shared-seal multi-shard anchor** — one seal `C*` / root `r*`, verified once;
   one shard path per touched shard; each leaf checked under its own shard state
   root. Path count grows with touched shards.

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

- `evmroot/d6checkpoint.go`, `d6proof.go`, `d6custody.go`.
- `evmroot/testdata/d6-vectors.json` — checkpoint/windows, historical-block
  authentication (constant-size false, header count grows), multi-shard anchor
  (one seal, two paths), lock-witness refresh, supply/backing, custody
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
