# D6 — Historical trust, proof and custody profile

Issue: [#8 D6](https://github.com/ristik/bft-core/issues/8) · Milestone: M0 ·
Prereqs: [#3 D1](https://github.com/ristik/bft-core/issues/3),
[#6 D4](https://github.com/ristik/bft-core/issues/6),
[#7 D5](https://github.com/ristik/bft-core/issues/7) · Status: **proposed for freeze**

D6 fixes the historical-trust and custody boundaries: the trusted-checkpoint
contents and freshness policy (kept separate from the round-denominated
certificate-admission window and the key cache), EVM proof export and historical
header ancestry, refreshable lock witnesses, shared-seal multi-shard anchors,
the frozen bridge type restriction and direct/succinct relation, and native
supply / bridge liability accounting.

Model: [`evmroot/d6checkpoint.go`](../../evmroot/d6checkpoint.go),
[`evmroot/d6proof.go`](../../evmroot/d6proof.go),
[`evmroot/d6custody.go`](../../evmroot/d6custody.go). Vectors:
[`evmroot/testdata/d6-vectors.json`](../../evmroot/testdata/d6-vectors.json).
Decision record: [ADR 0008](../adr/0008-historical-trust-proof-custody.md).

Specification basis: `docs/pos/specification/appendix-evm.tex` §§ Execution
Evidence and Historical Trust, Execution Proof Export; `appendix-bridging.tex`
§§ Shared Anchor for Inclusion Checking, Redemption, Accounting;
`appendix-token.tex`; `governance.tex` §"Economic Invariants".

---

## 2. Checkpoint, windows, key retention — three separate things

| Concept | Unit | Purpose |
|---|---|---|
| **trusted checkpoint** | content | trust initialisation: network id, committed root/config commitment, authenticated EVM head. A client verifies subsequent transitions, not an arbitrary chain signed by retired keys. |
| **checkpoint freshness limit** | **elapsed time (seconds)** | a **derived client policy** — see below. Re-derived if pacing/churn/protection change. |
| **`W_cert`** | **certified root rounds** | the live certificate-admission window, measured against the **current authenticated origin**. |
| **key cache** | **count of keys** | recent trust-base bodies held for ordinary admission. |

These do not substitute for one another.

**Mandatory nesting** (`NestingValid`): `W_cert ≤ Δ_ev < Δ_hold`.

### Live certificate admission — measured against the imported origin

`AdmitLiveCertificate(certRound, importedOriginRound, wCert, signerEpochActive)`:

1. `certRound ≤ importedOriginRound` — a future certificate is retried after root
   progress, not admitted;
2. `importedOriginRound − certRound ≤ wCert` — **the age is measured against the
   current authenticated origin, not a checkpoint round**. A certificate 900
   rounds behind the origin with `W_cert = 10` is **not live** (the earlier
   version compared to `checkpointRound` and wrongly admitted it);
3. the signer epoch was active at `certRound`.

A certificate outside the `W_cert` window is **not rejected** — it goes to the
historical checkpoint/ancestry path (§3), never expired-key signatures alone.
Checkpoints belong to that separate path and are **not an input** to this check.
Vectors: `live_certificate_admission` (fresh / within / at-boundary admitted;
`stale_past_window`, `future_ahead_of_origin`, `signer_epoch_inactive` rejected).

### Checkpoint freshness — derived, strict

`FreshnessPolicy` derives, in elapsed seconds:

```
minRealTimeProtection  = Δ_hold·minRoundPeriod − Δ_ev·minRoundPeriod − churnMargin
maxCheckpointStaleness = minRealTimeProtection − acquireLatency        (and strictly < minRealTimeProtection)
```

so that a client refreshing at the last permitted moment still completes the
refresh **before** any key backing the anchor could become withdrawable
(`acquireLatency` is left as headroom).

The re-review asked for a **justified, enforced** lower bound on `minRoundPeriod`
— an illustrative period is not a guarantee. `ConsensusMinRoundPeriodSeconds` is
that floor: the root chain's own round machine cannot finalise a certified round
faster than one network propagation delay plus the two BFT voting phases
(propose→vote→commit) at the minimum permitted round timeout, so no smaller
per-round time is physically reachable. It is **not** a tuning knob.
`FreshnessPolicy.Valid()` now rejects any policy with
`MinRoundPeriodSeconds < ConsensusMinRoundPeriodSeconds` (as well as any
pacing/protection combination that cannot support a positive, strictly-safe
limit). A deployment may *raise* `MinRoundPeriodSeconds` above the floor for
slower observed pacing, but not below it. Vector `checkpoint_freshness_policy`
(`staleness_strictly_less_than_protection: true`, `policy_valid: true`,
`enforced_min_round_period_seconds`, `policy_below_enforced_floor_rejected: true`);
`TestD6_CheckpointFreshnessDerivedAndStrict`.

**Key retention** (`KeyRetentionRequired`): an evidence-verification key is
retained until every associated evidence **and** retirement obligation is
discharged, even after it leaves the ordinary admission cache. Retention must not
be curtailed to permit a withdrawal.

## 3. Proof export and historical authentication

The models here use **real hash-linked fixtures**, not trusted booleans: a
`Header.Hash()` is `SHA-256(be64(number) ‖ parentHash ‖ payload)` (a real client
uses `Keccak(RLP(header))`; the linkage property is identical), and the anchor /
lock paths are actual Merkle paths folded with `hashNode(a,b) = SHA-256(a ‖ b)`.

**`ProofBundle` — structural availability vs offline verification**: the
first-review `SelfContained` returned `true` for any live-mode bundle with a
non-empty context and subject, without carrying any certificate/receipt proof.
Now the two are separate:

- `CarriesEvidence()` — **structural only**: the bundle has the pieces its mode
  needs (live mode: a `LiveAnchor`, a `LiveLeaf`, and a non-empty `Receipt`;
  ancestry mode: a non-empty header chain). It runs no verification.
- `OfflineVerify(trustedHeadHash)` — **actually verifies**. Live mode: the
  carried anchor's seal verifies (real signatures over `r*`), the leaf recomputes
  under its shard path to `r*`, and the leaf **is** the subject. Ancestry mode:
  `AuthenticateOldBlock` walks the header chain to `trustedHeadHash`.
- `SelfContained` is retained as an alias for `OfflineVerify` — it now means
  "verifies offline", not "has non-empty fields".

Vectors `proof_bundle_offline_verification`: `live_with_verifying_anchor`
(carries + verifies), `live_receipt_only_no_certificate_proof` (a receipt but no
anchor — neither carries nor verifies), `live_anchor_below_threshold`
(structurally complete, seal below the derived quorum — does not verify);
`TestD6_ProofBundleOfflineVerification`.

**Historical header ancestry** (`AuthenticateOldBlock(subjectHash, chain,
trustedHeadHash)`): walks a `[]Header` from a recently authenticated head
(`chain[n-1].Hash() == trustedHeadHash`) down to the subject
(`chain[0].Hash() == subjectHash`), checking `chain[i].ParentHash ==
chain[i-1].Hash()` and consecutive numbers. Cost is **linear** (`HeaderCount`
grows: 500 vs 20 for a shallower distance) and **never constant-size**
(`ConstantSize == false`). A **broken link** or a **wrong trusted head** fails.
Retired-key signatures are not part of this path at all. Vectors
`historical_block_authentication`; `TestD6_HistoricalAuthWalksARealChain`.

**Shared-seal multi-shard anchor** (`VerifyAnchoredHistory`). The first-review
model had two holes the re-review flagged:

1. **Signer names were treated as evidence** and the threshold was supplied — so
   an `AnchorSeal` with a valid `WeightSet`, no signers and `Threshold = 0`
   verified. Now `AnchorSeal` carries `RootStateRoot` (`r*`), `Epoch`,
   `AssignmentID`, the `WeightSet` (members carry **real** secp256k1
   `ConsensusKey`s — `d6Assignment`), and a `Signatures` map. `VerifySeal()`:
   - **derives** the threshold as `RootQuorumThreshold(TotalWeight)` — it is
     never supplied and is always ≥ 1;
   - requires a non-empty `r*` and a non-empty signature set;
   - verifies **each** claimed signer's secp256k1 signature over
     `AnchorSealStatement(r*, epoch, assignmentID)` against that member's key,
     and sums only the weight of signers whose signature checks out.
   A substituted `r*`, a replay under another epoch, a different assignment, or a
   forged signer entry all leave `VerifySeal` short of the derived threshold.
2. **Shard paths did not authenticate the partition/shard/config** — the path
   folded from the bare `ShardStateRoot`, and the caller-supplied
   `PartitionID`/`ShardID` were just map keys, so relabelling `7/0 → 99/attacker`
   still verified. Now each `ShardAnchorPath` carries a certified `ConfigHash`,
   and the path folds from a **bound leaf**
   `shardAnchorLeaf(pid, shardID, configHash, shardStateRoot) =
   SHA-256("UNICITY_SHARD_ANCHOR_LEAF" ‖ be64(pid) ‖ shardID ‖ configHash ‖
   shardStateRoot)`. Relabelling any of those changes the leaf, so it no longer
   recomputes to the certified `r*`. A path with no `ConfigHash` is rejected.

Each `AnchoredLeaf` still recomputes to its **own shard's** authenticated state
root. Path count grows with touched shards; seal verification runs **once**.
Vectors `multi_shard_anchor` — `two_aggregator_shards_one_seal` verifies
(weight 21 ≥ derived threshold 17, 2 paths); `leaf_path_does_not_recompute`,
`seal_below_threshold`, `unsigned_seal_zero_weight`,
`forged_signer_entry_not_counted`, `relabelled_shard_path_rejected`,
`substituted_root_no_valid_signatures`, `wrong_epoch_seal_rejected` all fail;
`TestD6_MultiShardAnchorRecomputesPaths`.

## 4. Custody, supply and bridge liability accounting

**`GlobalSupplyObservable = false`** — there is no globally observable
Execution-layer supply. Public monitoring reports known liabilities and coverage
of observations, not an exhaustive circulating-supply measurement.

**Native supply**: `NativeSupply = S_0 − Burn`; protocol execution creates no
additional UCT.

**Three distinct claims** — `native_uct`, `wuct`, `bridged`. WUCT is a **separate
composability wrapper** backed 1:1 by its **own contract's native**; a WUCT
custody path cannot call an ERC-20 balance as native custody. `VaultBacking.Consistent`
requires **`bridgedTotalLiability (O + C) ≤ vaultNativeBalance`** *and*
`WUCTSupply ≤ WUCTContractNative` — no cross-counting, and the vault must cover
the **full** liability it owes, not just `O`.

**Bridge liability ledger + solvency** (`appendix-bridging.tex` §"Accounting"):
`O = L − D`, `C = D − P`, `Owed = O + C = L − P`. The earlier model checked only
`L ≥ D ≥ P`, which passes for `L = D = 100, P = 0, Balance = 0` even though the
vault owes 100 and holds nothing. **`BridgeLedger.Solvent()`** now requires the
accounting identity to close and no deficit:

```
L ≥ D ≥ P   AND   Balance + Shortfall == L − P   AND   Shortfall == 0
```

Vectors `custody_solvency` (`insolvent_zero_balance` — the review's case — is
`solvent: false`; `insolvent_recorded_deficit`, `insolvent_identity_not_closed`
also false); `TestD6_CustodySolvencyEquation`.

**Intermediate custody states** (`WalkCustody`): `locked` (native into the vault,
`Balance += amount`) → `burned` (Execution-layer, vault unchanged) →
`redemption_credited` (`D += amount`) → `paid` (`Balance −= amount`, `P +=
amount`). `Solvent()` holds at **every** step (`custody_walkthrough`;
`TestD6_CustodyWalkthroughSolventThroughout`).

**Refreshable lock witness** — `LockWitness{Digest, RootStateRoot, Path}` with a
real `Verify()` (`evalPath(Digest, Path) == RootStateRoot`).
`RefreshLockWitness(tokenIdentity, digest, old, fresh)` requires `fresh.Verify()`
and `fresh.Digest == old.Digest == digest`; it returns that the
**`TokenLockIdentity = SHA-256(CBOR([tokenIdentity, digest]))`** is unchanged
(identity omits the witness) and that the backing was genuinely refreshed
(`old.RootStateRoot != fresh.RootStateRoot`). A fresh witness that does not
recompute, or is for a different digest, is rejected. Vectors
`lock_witness_refresh`; `TestD6_LockRefreshRealProofs`.

**Bridge type restriction** (`InitialEnshrinedProfile`): whole-token transfers
and burns only — **no split, no merge, no arbitrary mint-reason extension**.
Enforced by the type verifier, all SDKs and both redemption relations. Supporting
splits later needs a versioned type/relation that follows recursive provenance to
original locks; it is not enabled by importing a generic split verifier.

**Direct / succinct** (`SameSemanticRelation`): both paths implement the **same
semantic redemption relation** on the common admitted token profile — binding
network, configuration, live trust-base context, nullifier transition, lock
references and release leaves — with different witness formats, budgets and
batching. Direct verification is atomic and metered; an over-budget history uses
the succinct path.

## 5. Acceptance mapping

| D6 acceptance clause | Evidence |
|---|---|
| proof/accounting vectors distinguish native UCT, WUCT and bridged claims | §4; `supply_and_backing` (`O + C ≤ vault`, WUCT vs its own contract native); `TestD6_CustodySolvencyEquation` |
| live age measured from the current authenticated origin, not a checkpoint | §2 "Live certificate admission"; `live_certificate_admission.stale_past_window` (`admitted: false` for a 900-round-old cert with `W_cert 10`), `future_ahead_of_origin`, `at_window_boundary`; `TestD6_LiveCertMeasuredFromImportedOrigin` |
| the proof vectors carry real evidence, not assumed booleans | §3 real hash-linked headers + Merkle paths + real secp256k1 seal signatures; `historical_block_authentication` (broken linkage / wrong head fail), `multi_shard_anchor` (bad leaf / below-threshold / unsigned / forged signer / relabelled path / substituted root / wrong epoch all fail), `proof_bundle_offline_verification` (receipt-only does not verify), `lock_witness_refresh` (wrong digest fails); `TestD6_HistoricalAuthWalksARealChain`, `TestD6_MultiShardAnchorRecomputesPaths`, `TestD6_ProofBundleOfflineVerification`, `TestD6_LockRefreshRealProofs` |
| the shared seal authenticates r* itself and the shard paths authenticate their partition/shard/config | §3; `AnchorSeal.VerifySeal` derives the threshold and checks signatures over `AnchorSealStatement(r*, epoch, assignmentID)`; `shardAnchorLeaf` binds partition ‖ shard ‖ configHash into the leaf; `multi_shard_anchor.relabelled_shard_path_rejected`, `unsigned_seal_zero_weight`, `forged_signer_entry_not_counted`, `wrong_epoch_seal_rejected` |
| a proof bundle's structural availability is distinct from successful offline verification | §3 "`ProofBundle` — structural availability vs offline verification"; `CarriesEvidence` vs `OfflineVerify`; `proof_bundle_offline_verification`; `TestD6_ProofBundleOfflineVerification` |
| an old block is authenticated without trusting retired signatures alone | §3; header-chain path only; retired keys are not an input |
| fresh lock evidence leaves token identity unchanged | §4; `lock_witness_refresh.fresh_proof_same_digest` (`token_identity_unchanged: true`, `historical_backing_refreshed: true`) |
| a history touching two aggregator shards verifies with one seal plus the necessary paths | §3; `multi_shard_anchor.two_aggregator_shards_one_seal` (`seal_verified_once: true`, `shard_path_count: 2`) |
| no claim of constant-size arbitrarily old proofs | §3; `historical_block_authentication[*].constant_size = false`, `header_count` 500 vs 20 |
| no claim of globally observable Execution-layer supply | §4; `global_execution_layer_supply_observable = false`; `TestD6_NoGlobalSupplyClaim` |
| custody solvency is checked, not just `L ≥ D ≥ P` | §4 `BridgeLedger.Solvent()` (`Balance + Shortfall == L − P`, `Shortfall == 0`); `custody_solvency`, `custody_walkthrough`; `TestD6_CustodySolvencyEquation`, `TestD6_CustodyWalkthroughSolventThroughout` |
| checkpoint freshness is derived and strict, not asserted, and rests on an enforced per-round floor | §2 "Checkpoint freshness"; `ConsensusMinRoundPeriodSeconds` floor enforced by `FreshnessPolicy.Valid()`; `checkpoint_freshness_policy.staleness_strictly_less_than_protection = true`, `policy_valid`, `policy_below_enforced_floor_rejected = true`; `TestD6_CheckpointFreshnessDerivedAndStrict` |
| live cert age ⊂ evidence window ⊂ retirement protection | §2; `window_nesting_and_key_retention.nesting_valid`; `TestD6_WindowNestingAndKeyRetention` |
| bridge type restrictions, config/hash bindings, direct/succinct relation | §4; `token_profile`, `redemption_relation`; `TestD6_TokenProfileForbidsSplitMergeMintExt`, `TestD6_DirectAndSuccinctSameSemanticRelation` |

## 6. Reproduce

```
go test ./evmroot/... -run TestD6
go run ./evmroot/cmd/d6vectors            # print the vector set
go run ./evmroot/cmd/d6vectors -update    # regenerate testdata/d6-vectors.json
```
