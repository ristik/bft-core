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
| **checkpoint freshness limit** | **elapsed time (seconds)** | a **client policy** = `Δ_hold (rounds) × min round period (s)` — the minimum real-time protection implied by round pacing and collateral retention. Re-derived if pacing/churn/protection change. |
| **`W_cert`** | **certified root rounds** | the live certificate-admission window. |
| **key cache** | **count of keys** | recent trust-base bodies held for ordinary admission. |

These do not substitute for one another. `CheckpointFreshnessLimitSeconds` is not
`W_cert` and not the key count.

**Mandatory nesting** (`NestingValid`): `W_cert ≤ Δ_ev < Δ_hold` — live
certificate age fits inside the evidence window, which fits inside retirement
protection.

**Live certificate admission** (`AdmitLiveCertificate`): the round is within
`W_cert` of the checkpoint, the signer epoch was active at the claimed root
round, and the round is not ahead of the imported origin. A certificate outside
`W_cert` is **not rejected** — it must be authenticated via the
checkpoint/ancestry path (§3), never by expired-key signatures alone. A future
(not-yet-imported) anchor is retried after root progress.

**Key retention** (`KeyRetentionRequired`): an evidence-verification key is
retained until every associated evidence **and** retirement obligation is
discharged, even after it leaves the ordinary admission cache. Retention is
bounded by governed limits and must not be curtailed to permit a withdrawal.

## 3. Proof export and historical authentication

**`ProofBundle`**: version, chain context (full network/partition/shard/genesis/
execution identity), subject header, the block's UC, an authentication path to a
trusted checkpoint, and the requested receipt/tx or account/storage path. It is
**self-contained for offline verification** once the recipient has a sufficiently
recent trusted checkpoint — no external query during verification (assembling a
fresh bundle may need a proof service).

**Historical header ancestry** (`AuthenticateOldBlock`): for a block outside live
certificate admission, the path is an **Ethereum parent-header chain** from a
recently authenticated EVM head down to the subject. Hash linkage, heights and
chain configuration are checked. Its cost is **linear in the distance**
(`HeaderCount` grows) and it is **explicitly not a constant-size historical
proof** (`ConstantSize == false`, always). A future accumulator could compress
the path; this profile makes no such claim. An old certificate signed by retired
keys alone is insufficient — this path is what authenticates it instead.

**Shared-seal multi-shard anchor** (`VerifyAnchoredHistory`): one root seal `C*`
and its Unicity Tree root `r*`; an `AnchorBundle` supplies, for every touched
shard, the certified input/configuration record plus its path through the shard
tree and Unicity Tree to `r*`. The seal's unique weighted signatures are
**verified once**. Each transaction leaf is then checked **under its own
authenticated shard state root**, not directly under `r*`. The number of shard
paths **grows with the touched shards** even though seal verification is shared;
a leaf on a shard with no anchor path fails. Vector `multi_shard_anchor`: a
history touching two aggregator shards verifies with one seal + two paths.

## 4. Custody, supply and bridge liability accounting

**`GlobalSupplyObservable = false`** — there is no globally observable
Execution-layer supply. Public monitoring reports known liabilities and coverage
of observations, not an exhaustive circulating-supply measurement.

**Native supply**: `NativeSupply = S_0 − Burn`; protocol execution creates no
additional UCT.

**Three distinct claims** — `native_uct` (an account balance), `wuct` (the
wrapped-native ERC-20 contract balance), `bridged` (an Execution-layer claim
backed by vault native UCT). WUCT is a **separate composability wrapper**; a WUCT
custody path cannot call an ERC-20 balance as native custody. `VaultBacking.Consistent`
requires `bridgedOutstanding ≤ vaultNativeBalance` — the vault's native holdings
back bridged claims and are **not double-counted** against WUCT.

**Bridge liability ledger** (`appendix-bridging.tex` §"Accounting"): `L`
cumulative locked native value, `D` cumulative redemption value credited after
verified burns, `P` cumulative paid to claimants (including relayer shares).
`O = L − D` (outstanding backing), `C = D − P` (unpaid credits). Invariant
`L ≥ D ≥ P` ⇒ `O ≥ 0`, `C ≥ 0`. Rewards, treasury and bridge liabilities cannot
spend one another's backing.

**Intermediate custody states** (`WalkCustody`): `locked → burned →
redemption_credited → paid`. A burn on the Execution layer does not move the
vault ledger — the lock still backs it until redemption is credited; crediting
moves `D`, payment moves `P`. Invariants hold at every intermediate state
(vector `custody_walkthrough`).

**Refreshable lock witness** (`RefreshLockWitness`): a recent proof of the **same
permanent lock digest** refreshes historical backing without changing token
identity — identity is a function of `(tokenIdentity, permanentLockDigest)` only
and does not include the refreshed witness. Lock digests remain provable after
redemption and cannot be deleted to reclaim storage.

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
| proof/accounting vectors distinguish native UCT, WUCT and bridged claims | §4; `supply_and_backing`; `TestD6_SupplyAndBackingNotDoubleCounted` |
| an old block is authenticated without trusting retired signatures alone | §3; `historical_block_authentication`; `TestD6_OldBlockAuthenticatedWithoutRetiredSignatures` |
| fresh lock evidence leaves token identity unchanged | §4; `lock_witness_refresh`; `TestD6_LockRefreshLeavesIdentityUnchanged` |
| a history touching two aggregator shards verifies with one seal plus the necessary paths | §3; `multi_shard_anchor`; `TestD6_MultiShardAnchorOneSealManyPaths` |
| no claim of constant-size arbitrarily old proofs | §3; `historical_block_authentication[*].constant_size = false`, `header_count` grows |
| no claim of globally observable Execution-layer supply | §4; `global_execution_layer_supply_observable = false`; `TestD6_NoGlobalSupplyClaim` |
| checkpoint contents/freshness separate from `W_cert` and the key cache | §2; `checkpoint_and_windows`; `TestD6_CheckpointFreshnessSeparateFromWCertAndKeyCache` |
| live cert age ⊂ evidence window ⊂ retirement protection | §2; `checkpoint_and_windows.nesting_valid` |
| bridge type restrictions, config/hash bindings, direct/succinct relation | §4; `token_profile`, `redemption_relation`; `TestD6_TokenProfileForbidsSplitMergeMintExt`, `TestD6_DirectAndSuccinctSameSemanticRelation` |

## 6. Reproduce

```
go test ./evmroot/... -run TestD6
go run ./evmroot/cmd/d6vectors            # print the vector set
go run ./evmroot/cmd/d6vectors -update    # regenerate testdata/d6-vectors.json
```
