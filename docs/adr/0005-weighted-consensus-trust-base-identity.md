# ADR 0005: Weighted consensus and trust-base identity (D3, v2)

## Status

Proposed (D3, issue #5). Freeze once reviewed by a Go consensus / protocol
reviewer other than the author. Depends on ADR 0003 (D1). No supersession;
`RootTrustBaseV1` verification stays valid under version 1.

## Context

The prototype's consensus is count-based in more places than "verify signatures":

- `NodeInfo.IsValid` hard-requires `Stake == 1`.
- QC and TC assembly (`vote_register.go`) compare `len(signatures)` to the
  threshold.
- Timeout amplification (`pacemaker.go`) compares a vote **count** to
  `GetMaxFaultyNodes()`, itself `len(RootNodes) − QuorumThreshold`.
- `VerifyQuorumSignatures` sums `stake` but silently drops invalid signatures and
  has no overflow guard.
- Trust-base identity (`Hash`) folds in the signature map; `SigBytes` excludes
  only signatures, not an endorsement witness.

Under PoS the paired EVM must use the **same** effective weights as the root
assignment, and `evm-partition.tex` §"Validity" is explicit that signature counts
cannot substitute for weights in quorum formation, timeout handling or
quorum-impossibility reasoning. D3 is the gate that removes every count-based
decision before `Q1`–`Q4` build weighted consensus.

## Decision

Adopt trust-base **version 2** and the weighted arithmetic in
[`docs/design/d3-weighted-consensus-trust-base.md`](../design/d3-weighted-consensus-trust-base.md):

1. **Weights** are unsigned 64-bit counts of the atomic denomination `u`, capped
   per-member (`2⁴⁰`) and in total (`2⁴⁸`) so `2·W` stays exact. Zero weight is
   not a member; ids are unique.
2. **Thresholds** — root `⌊2W/3⌋+1`, EVM/shard `⌊W/2⌋+1`, faulty-weight bound
   `W − (⌊2W/3⌋+1)` — over effective weights, recorded explicitly in the body.
3. **Every quorum/timeout/impossibility path** (the 15-row inventory) decides on
   a sum of unique authorised signer weights with checked wide intermediates,
   never a count. An unknown or duplicate signer rejects the certificate;
   overflow fails closed.
4. **Trust-base body identity v2** is `SHA-256(CBOR(body))` over a canonical body
   that excludes the current-epoch signatures **and** the old-epoch endorsement
   witness; `predecessorHash` is the v2 identity of the current trust base.
5. **Legacy** `RootTrustBaseV1` keeps version 1 and its existing `SigBytes` /
   `Hash`. Nothing reinterprets a v1 body as v2.
6. **Genesis** QC authenticity stays an explicit rule, not a weighted quorum.

## Deliverables

- `evmroot/d3weights.go` — `WeightSet` (checked `TotalWeight`), the three
  thresholds, `SignerWeight`, `QuorumReached`, `TimeoutAmplifies`,
  `QuorumImpossible`, `TrustBaseBodyV2` with witness-free identity.
- `evmroot/testdata/d3-vectors.json` — `> 2/3` root, `> 1/2` shard, faulty-weight
  timeout amplification, duplicate signers, minority-stake / majority-identities,
  overflow bounds, and trust-base identity stability.
- `evmroot/cmd/d3vectors` + `TestD3_VectorsMatchGolden`.

## Consequences

- `Q1` (weighted root quorum / pacemaker), `Q2` (weighted shard requests /
  impossibility certificates), `Q3` (activation / compatibility) and `Q4`
  implement against this profile.
- `D4` (epoch handoff) consumes the v2 body shape and the endorsement-outside-
  identity rule; `D5` (accountability) consumes the `f_W` bound and the
  signed-vote-domain requirement.
- The change is a genuine break in `bft-go-base` and `rootchain/consensus`, but
  v1 and v2 agree on any equal-weight set, so a PoA deployment can activate v2
  with no behavioural change and PoS turns on real weights later.

## Alternatives considered

- **Keep counts, gate PoS separately.** Rejected: `evm-partition.tex` forbids
  count substitution in exactly the timeout / impossibility paths that are
  hardest to retrofit safely; auditing them once, now, is cheaper than twice.
- **Float or big-int weights.** Rejected: unsigned 64-bit with caps keeps every
  sum exact and deterministic across implementations; `⌊2W/3⌋` needs no rounding
  policy.
- **Fold the endorsement into body identity.** Rejected: endorsement composes
  after body selection; including it would make identity depend on which
  old-epoch signers happened to endorse.
