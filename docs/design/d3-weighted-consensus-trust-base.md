# D3 — Versioned weighted consensus and trust-base identity

Issue: [#5 D3](https://github.com/ristik/bft-core/issues/5) · Milestone: M0 ·
Prereq: [#3 D1](https://github.com/ristik/bft-core/issues/3) ·
Trust-base version: **v2** · Status: **proposed for freeze**

D3 audits **every** quorum and timeout path — not only signature verification —
and replaces each count-based test with one over authenticated voting power. It
defines unique signer weight, weight units, overflow bounds and a versioned
trust-base body identity that excludes endorsement witnesses, while keeping the
legacy v1 verification available unchanged under its own version.

Model: [`evmroot/d3weights.go`](../../evmroot/d3weights.go). Vectors:
[`evmroot/testdata/d3-vectors.json`](../../evmroot/testdata/d3-vectors.json).
Decision record: [ADR 0005](../adr/0005-weighted-consensus-trust-base-identity.md).

Specification basis: `docs/pos/specification/bft.tex`, `governance.tex`,
`appendix-evm.tex` §§ Validity, Candidate Record, Trust Base Record Derivation,
Evidence.

---

## 1. Weight model

- A member weight `bᵥ` is an **unsigned 64-bit** count of the configured atomic
  UCT denomination `u` (`appendix-evm.tex` §"Candidate Record"). Eligible
  collateral must reserve at least `u·bᵥ` per assignment; fractional residual
  collateral confers no extra voting power.
- `W = Σ bᵥ` over the active assignment.
- **Per-member cap** `MaxMemberWeight = 2⁴⁰`, **total cap** `MaxTotalWeight = 2⁴⁸`.
  Below the total cap, `2·W` cannot overflow `uint64`, so every threshold
  computation stays exact in a checked wide intermediate. A weight of `0` is not
  a member. Membership identities are unique.
- Thresholds:
  - **root consensus**: `⌊2W/3⌋ + 1`
  - **EVM / shard attestation**: `⌊W/2⌋ + 1`
  - **faulty-weight bound** (for timeout amplification and impossibility):
    `f_W = W − (⌊2W/3⌋ + 1)`
- The EVM uses **exactly the same effective weights** as the root assignment
  authorising its shard round. No assumed bound on the number of seats
  substitutes for the paired EVM's actual weighted threshold. Under PoA all
  `bᵥ = 1` and the weighted rules reduce to the current counts — the v1 and v2
  arithmetic agree on an equal-weight set, which is what makes the change safe to
  activate.

## 2. Inventory of quorum / timeout paths and their replacements

Every path below currently decides on a **count** (of signatures, of nodes, of
votes) or on `GetMaxFaultyNodes()` (defined as `len(RootNodes) − QuorumThreshold`,
documented "only works if one node == one vote"). The replacement is a sum of
**unique authorised signer weights** against the matching weighted threshold,
computed with checked wide intermediates.

| # | Path | Location (pinned prototype) | Current basis | v2 replacement |
|---|---|---|---|---|
| 1 | Node stake constraint | `bft-go-base/types/root_trust_base.go` `NodeInfo.IsValid` | hard `Stake == 1` | `bᵥ ∈ [1, MaxMemberWeight]`, unique id, checked |
| 2 | Quorum-threshold derivation | `root_trust_base.go` `NewTrustBase` | `totalStake*2/3+1` (= count) | `⌊2W/3⌋+1` over effective weights, recorded explicitly in the body |
| 3 | `GetMaxFaultyNodes` | `root_trust_base.go` | `len(RootNodes) − QuorumThreshold` | `f_W = W − (⌊2W/3⌋+1)` |
| 4 | QC assembly | `rootchain/consensus/vote_register.go` `InsertVote` | `len(quorum.signatures) >= GetQuorumThreshold()` | `SignerWeight(distinct authorised) >= ⌊2W/3⌋+1` |
| 5 | TC assembly | `vote_register.go` `InsertTimeoutVote` | `len(timeoutCert.Signatures) >= GetQuorumThreshold()` | weighted sum ≥ root threshold |
| 6 | Timeout amplification ("f+1 jump") | `rootchain/consensus/pacemaker.go` `voteCnt > quorum.GetMaxFaultyNodes()` | vote **count** > faulty-node count | timeout-voting weight `> f_W` |
| 7 | QC signature verification | `rootchain/consensus/types/quorum_certificate.go` `Verify` → `RootTrustBaseV1.VerifyQuorumSignatures` | sums `stake` but silently drops invalid sigs, no overflow guard, uniqueness only implied by map keys | sum unique authorised signer weights, checked wide add, reject unknown/duplicate signer, reject overflow |
| 8 | TC signature verification | `timeout_certificate.go` `Verify` | `signedVotes += stake; < GetQuorumThreshold()` | same weighted rule; drives #6 |
| 9 | Vote-buffer / recovery readiness | `rootchain/consensus/consensus_manager.go` (`len(x.voteBuffer) >= GetQuorumThreshold()`) | **count** of buffered votes | weight of buffered, authorised, distinct-signer votes ≥ root threshold |
| 10 | `f+1` recovery trigger | `consensus_manager.go` ("received at least f+1 votes") | vote count | received distinct-signer weight `> f_W` |
| 11 | Shard request collection ("weighted matching requests") | `rootchain/consensus/storage/sharding.go` `ValidRequest`; `appendix-evm.tex` §"Certification Request" | count of matching `BlockCertificationRequest`s | sum of unique shard-validator effective weights `≥ ⌊W_e/2⌋+1` |
| 12 | Quorum-impossibility | `rootchain/consensus/types` `IRChangeReq` "no quorum possible" | remaining **nodes** cannot reach threshold | `current_weight + remaining_unvoted_weight < threshold` |
| 13 | Config endorsement | `appendix-evm.tex` §"Trust Base Record Derivation" | — | old-epoch **unique signer weight** ≥ old root threshold; composed only after consensus selects the same handoff body |
| 14 | Trust-base body identity | `root_trust_base.go` `SigBytes` (excludes only `Signatures`), `Hash` (includes them) | v1 | v2 canonical body excludes **signatures and endorsement witness**; `PredecessorHash` = v2 body identity of the current trust base |
| 15 | Genesis QC exemption | `quorum_certificate.go` `Verify` (skips sig check for `GenesisRootRound`) | unchanged | unchanged — genesis authenticity is an explicit rule, not a weighted quorum |

Model coverage: rows 1–3 → `WeightSet.TotalWeight` / `RootQuorumThreshold` /
`ShardAttestationThreshold` / `FaultyWeightBound`; rows 4–5, 7–9, 11 →
`SignerWeight` / `QuorumReached`; rows 6, 10 → `TimeoutAmplifies`; row 12 →
`QuorumImpossible`; rows 13–14 → `TrustBaseBodyV2`.

## 3. Weight arithmetic rules

- **Unique signer weight.** A signer appearing twice in a QC/TC signature set is
  a malformed certificate: the set is rejected, never counted twice.
- **Authorised only.** A signature from an id not in the active assignment
  contributes zero and, in the strict verification path, rejects the certificate
  (it is not silently dropped).
- **Checked intermediates.** `Σ` uses `math/bits.Add64`; any carry, any member
  over `MaxMemberWeight`, or a total over `MaxTotalWeight` fails closed. No agent
  silently rescales a contract-provided weight.
- **Thresholds are integers** computed once from `W` and stored in the trust-base
  body, so every consumer uses the same value rather than re-deriving it.

## 4. Versioned trust-base identity (v2)

`TrustBaseBodyV2` canonical body (deterministic CBOR, D1 §3 rules), field order
normative:

```
[ version, networkId, epoch, epochStart,
  [ [id, weight], … ]        ; members, sorted bytewise by id
  rootThreshold,             ; ⌊2·ΣWeight/3⌋+1
  stateSummary,              ; agreed frozen transition state
  changeRecordHash,          ; candidate body hash + committed handoff binding
  predecessorHash ]          ; v2 body identity of the current trust base
```

- **Excludes** the current-epoch signature map **and** the old-epoch endorsement
  witness. Endorsements compose only after consensus has selected the same
  handoff body; endorsement serialisation is separate from body identity
  (`appendix-evm.tex` §"Trust Base Record Derivation").
- `predecessorHash` is the **v2 body identity** of the current trust base — never
  a hash that folded in its signatures.
- Identity = `SHA-256(CBOR(body))`.
- **Legacy preserved.** `RootTrustBaseV1` keeps its `Version = 1`, its
  `SigBytes()` (excludes only `Signatures`) and its `Hash()` (includes
  signatures). A v1 trust base verifies under v1 rules; a v2 trust base under v2
  rules. Nothing reinterprets a v1 body as v2.
- The endorsement-signature domain binds network, protocol version, predecessor
  and transition attempt (that is D4's wire concern; D3 fixes only that the
  witness is outside body identity).

## 5. Acceptance mapping

| D3 acceptance clause | Evidence |
|---|---|
| inventory names every count-based path and its replacement | §2 (15 rows) |
| vectors: `> 2/3` root weight | `root_quorum` (21≥17 pass, 16<17 fail, 17==17 boundary) |
| vectors: `> 1/2` shard weight | `shard_quorum` |
| vectors: configured faulty-weight bound for timeout amplification | `timeout_amplification` (8>7 amplifies, 7==7 does not) |
| vectors: duplicate keys / signers | `duplicate_signers`; `TestD3_DuplicateSignerNotDoubleCounted` |
| vectors: minority stake with majority identities | `minority_stake_majority_identities` (4/5 members = weight 14 < 17); `TestD3_ThresholdsOverWeightNotCount` |
| vectors: sum overflow | `overflow_bounds` (`member_over_cap`, `total_over_cap`); `TestD3_OverflowBounds` |
| no assumed seat bound substitutes for the EVM's weighted threshold | §1 last paragraph; `ShardAttestationThreshold` takes `W`, not a seat count |
| legacy verification preserved under its own version | §4 "Legacy preserved" |

## 6. Reproduce

```
go test ./evmroot/... -run TestD3
go run ./evmroot/cmd/d3vectors            # print the vector set
go run ./evmroot/cmd/d3vectors -update    # regenerate testdata/d3-vectors.json
```
