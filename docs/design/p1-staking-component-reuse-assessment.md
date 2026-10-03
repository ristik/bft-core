# P1 — Staking component reuse assessment

Issue: [#27 P1](https://github.com/ristik/bft-core/issues/27) · Milestone: M4S ·
Prereqs: [#6 D4](https://github.com/ristik/bft-core/issues/6),
[#7 D5](https://github.com/ristik/bft-core/issues/7) · Status: **proposed for owner
acceptance** (see "Open for owner acceptance" at the end; [ADR 0012](../adr/0012-validator-entity-model.md)
overrides older prose here, see section 1.1)

P1 is an assessment ticket. It produces **a reviewed reuse decision**, not
contract code: which parts of the Polygon PoS staking contracts can serve the
enshrined-EVM PoS lifecycle, which are dropped, and what assumes each dropped
duty. No contract code is vendored by P1; the contract repository is
`unicity-pos-contracts` (section 2.1); the toolchain is chosen in
[P2](https://github.com/ristik/bft-core/issues/30); parameter values and any
security audit are separate.

Model: [`evmroot/p1reuse.go`](../../evmroot/p1reuse.go) (types + `Validate`),
[`evmroot/p1matrix.go`](../../evmroot/p1matrix.go) (`BuildP1ReuseMatrix`).
Fixture: [`evmroot/testdata/p1-reuse-matrix.json`](../../evmroot/testdata/p1-reuse-matrix.json).
Decision record: [ADR 0011](../adr/0011-staking-component-reuse.md).

Specification basis: `docs/pos/specification/governance.tex` §§ "Stake Registry",
"Election", "Trust Base Derivation", "Rewards", "Slashing", "Fees", "Economic
Invariants", "Upgrade and Delivery Boundaries"; `docs/adr/0006` (D4),
`docs/adr/0007` (D5).

---

## 1. Target lifecycle the reuse must serve

The reuse is judged against the lifecycle D4 and D5 already froze, not against
Polygon's checkpoint model.

- **Registry and reservation.** A stable staking account binds owner and
  consensus-key roles, bonded self-stake and status (`governance.tex` §"Stake
  Registry"). Bonding changes available collateral; **election fixes the
  effective weight and reserves the matching collateral for that assignment**.
  The first PoS deployment MAY disable delegation and use self-bond only.
- **Election.** A deterministic snapshot at a certified root-round threshold
  selects at most `N_max` validators by effective stake, canonical tie-break,
  and commits a candidate with the snapshot's rounds, next epoch, configuration
  version, complete identity/key/weight records, thresholds and predecessor body
  hash (`governance.tex` §"Election"). Stake changes after the snapshot do not
  modify it.
- **Handoff.** The root handoff is an ordered state transition: verify the
  certified contract output (root validators **do not re-run the staking
  algorithm**), prepare under the old quorum, construct and endorse the next
  trust-base body, commit, resume (`governance.tex` §"Trust Base Derivation";
  `docs/adr/0006`).
- **Retirement.** `Bonded → RetirementRequested → Draining → Released`
  (`evmroot/d5retire.go`). `R_ret` is recorded only on an authenticated
  acknowledgement that the stake backs **no active or prepared successor**.
  Withdrawal requires `now ≥ max(R_ret + Δ_hold, inheritedProtectionUntil)`, the
  forced-inbox position cutoff through `LiabilityDeadlineRound`, and no pending
  timely evidence. `Δ_hold > Δ_ev + Δ_incl + Δ_exec`, `W_cert ≤ Δ_ev < Δ_hold`.
- **Rewards.** Assigned voting weight per **certified root interval**, not
  measured availability: `R_ν(I) = 𝓔(I)·b_ν/W_e`, `𝓔(I) = min(ρ_e·|I|,
  Pool_free)` (`governance.tex` §"Rewards"). No proposer bonus. Idle assigned
  validators are still paid — an explicit initial-policy limitation.
- **Slashing.** Objective double-signing only, over the D5 vote domain
  `(accountableKey, network, messageDomain, votingEpoch, votingRound)`
  (`evmroot/d5vote.go`, `docs/adr/0007`). Accepted evidence charges the
  attributable active or retiring collateral once, credits a bounded bounty,
  sends the remainder to treasury. Jailing excludes from future elections.
  **Downtime slashing and QC-omission jailing are disabled.**
- **Custody boundary.** Money custody, withdrawal accounting, allocation,
  wrapper and vault contracts are **immutable** in the initial profile; stake
  custody and its fixed slash/exit rules are separated from election policy
  (`governance.tex` §"Upgrade and Delivery Boundaries").

### 1.1 Where ADR 0012 overrides this section

- "Owner and consensus-key roles" and "distinct consensus/node roles" (row 6,
  section 5): a validator is authenticated only by its BFT Core consensus key and
  P3 binds only that key. Owner/withdrawal roles are unaffected.
- The "forced-inbox position cutoff through `LiabilityDeadlineRound`" in the
  Retirement bullet, row 1, row 3's note and section 5: the I-track is deferred,
  and what replaces it is an open owner question. Read the inbox cutoff as a
  deferred safeguard, not a launch dependency; the `Δ_hold` and pending-evidence
  gates stand.
- Weights apply at the root/validator-entity level only; aggregator shards are
  unweighted; validator-set changes are coupled; only positive certified proofs
  are required of the EVM.

## 2. Pinned upstream candidates and licences

Revisions read 2026-09-06 from the public GitHub API; pins, licence files,
dependency layout and the facts in the table re-verified 2026-10-03.

| Source | Repo | Revision | Licence | solc | State |
|---|---|---|---|---|---|
| `matic-contracts` | `github.com/maticnetwork/contracts` | `eef5359…` (`main`, 2024‑03‑01); tag `v0.3.11` = `9564ece3…` | GPLv3 root `LICENSE` (see 2.1) | 0.5.17 / ^0.5.2 | **archived** ~2024‑03; no upstream security stream |
| `pos-contracts` | `github.com/0xPolygon/pos-contracts` | `ffa83a7…` (`main`, 2026‑08‑05, "main mirrors deployed on‑chain bytecode") | GPLv3 root `LICENSE` (see 2.1) | 0.5.17 / ^0.5.2 (adds `*POL` entry points) | maintained; same `StakeManager` / `ValidatorShare` / `StakingInfo` units |

**Dependency layout — corrected.** An earlier revision of this section said both
pins "depend on `openzeppelin-solidity` 0.5.x". That was wrong on both halves and
conflated two separate axes:

- `matic-contracts` pins **`openzeppelin-solidity` 2.2.0** in `package.json`
  (verified at `eef53596`). `0.5.x` is the **Solidity pragma generation**, not
  the dependency version.
- `pos-contracts` pins **no `openzeppelin-solidity` at all** (verified at
  `ffa83a74`). The OZ sources are **vendored** under `contracts/common/oz` and
  imported by relative path; the only OZ package present is
  `@openzeppelin/test-helpers`, a test dependency. The two pins therefore do
  **not** share a dependency layout, and each vendored file needs its own licence
  notice recorded.

### 2.1 Licence: what is established, and what is not

**Corrected finding.** The earlier revision inferred that the staking contracts
must be Apache‑2.0 because `bft-core` is Apache‑2.0 and the custody contracts are
immutable, and concluded from that that no upstream source could ever be used.
**Neither premise supports the conclusion, and it is withdrawn.** Immutability is
a property of deployed bytecode and says nothing about licensing; a platform's
licence does not determine the licence of a separate artifact.

**The destination is now declared rather than inferred** (`Destination` in
`evmroot/p1reuse.go`, and a required field of the matrix):

| Field | Value |
|---|---|
| Repository | `unicity-pos-contracts` — separate from `bft-core` |
| Licence | **GPL‑3.0 proposed** (not selected; the owner decides, #85) |
| Boundary | Separate repository, source tree and build; **no linking**. The platform interacts with deployed contracts only across the EVM ABI and the certified-input boundary. It does not import, compile or link contract source, and neither side derives from the other's source. |
| Determination owner | Repository owner, before any file is copied |

Under that boundary a GPL‑3.0 contract set and an Apache‑2.0 platform can
coexist, and **a GPL‑3.0 source port is licence-permitted**. Separate
repositories are not by themselves a legal determination — the boundary above is
what the conclusion rests on, and the owner confirms it. This document is an
engineering assessment, not legal advice.

**Licence facts at the pins, with their uncertainty retained.**

- Both `package.json` files declare `"license": "MIT"` while both root `LICENSE`
  files are **GPLv3** (all four verified). This conflict is **recorded, not
  resolved**. It does not establish MIT permission; equally, it means a
  repository-level label is **not** a complete per-file `GPL-3.0-only`
  provenance analysis.
- Neither the root `LICENSE` nor GitHub's badge establishes **GPL-3.0-only**
  rather than "or later" or a per-file mixture; this document does not assert it.
- `pos-contracts` `StakeManager.sol` at `ffa83a74` has **no SPDX header** — it
  begins directly with `pragma solidity 0.5.17;`. Its per-file licence is
  inherited by argument, not stated.
- Before any file is copied: record per-file notices and the licences of every
  imported dependency, and resolve the conflicting repository-level scope.

References for the compatibility direction used above:
[ASF](https://www.apache.org/licenses/GPL-compatibility),
[FSF](https://www.gnu.org/licenses/gpl-faq.en.html#MereAggregation).

## 3. Component reuse matrix

Dispositions: **independent-implementation** (study the publicly documented
algorithm and implement it locally, recording where the understanding came from —
no upstream bytes), **remove** (drop; name any accounting duty it carried and
where that duty goes), **defer-not-applicable** (out of scope for self-bond; kept
as a reference for a later optional upgrade), **vendor-port** (copy upstream
source, gated on compatibility with the *declared* destination licence).

**`vendor-port` is available** under the GPL‑3.0 destination (§2.1). No row uses
it at this revision, and that is an engineering judgement about these particular
units (§4), **not** a licence prohibition.

**Not "clean-room".** The earlier revision called the first disposition
clean-room. No clean-room process was performed: there was no separated
specification team, no separated implementation team that never saw the original,
and no records proving separation. "No verbatim copying" is not a clean-room
process, and the term is withdrawn in favour of independent implementation with
documented provenance.

| # | Upstream unit | Purpose | Disposition | Replacement / where the duty goes | Removed upstream test |
|---|---|---|---|---|---|
| 1 | `StakeManager.stakeFor/restake/unstake/unstakeClaim`; `WITHDRAWAL_DELAY = 2¹³` epochs | Bonding + fixed-delay unbond claim | independent-implementation | D5 `Reservation` + `ProtectionParams`; delay is `Δ_hold` in **certified root rounds** with `Δ_hold > Δ_ev+Δ_incl+Δ_exec`, plus the forced-inbox position cutoff and the pending-evidence gate. Requesting retirement does not start the clock. (The inbox cutoff is deferred by ADR 0012, section 1.1.) Local home: **P2**. | `StakeManager.Staking.js` `describe('unstake')` / `describe('unstakeClaim')`, and the `WITHDRAWAL_DELAY` cases in `StakeManager.test.js` / `ValidatorShare.test.js` (verified, 3.3) → D5 `TestD5_WithdrawalGates` |
| 2 | `StakeManager.checkSignatures/_increaseRewardAndAssertConsensus/rewardPerStake/CHECKPOINT_REWARD/_updateRewardsAndCommit`; proposer bonus + `combinedStakePower` split | Checkpoint-submission-driven reward accrual & consensus assertion | **remove** (checkpoint coupling) | Duty *(sizes a per-interval pool, applies a proposer bonus, splits by validator vs delegator stake power every checkpoint)* → accounting replacement **`assigned-weight-reward`**: `R_ν(I)=min(ρ_e·\|I\|,Pool_free)·b_ν/W_e` over certified root-round progress; no proposer bonus. | none named: no test is pinned for the reward/proposer-bonus/stake-power split (unverifiable, 3.3) |
| 3 | `StakeManager.slash` + `SlashingManager.updateSlashedAmounts` + `verifyConsensus` (Heimdall-checkpoint-signed batch) | Apply a slashing batch validated by Heimdall consensus signatures | **remove** (Heimdall/checkpoint path) | Duty *(debit offender validator+delegation stake, credit a reporter, update totals, jail)* → accounting replacement **`objective-slashing-penalty`**: D5 `SlashableConflict` + S1/S2; charge attributable collateral once, bounded bounty, remainder to treasury, duplicate-offence guard, jail excludes future elections. | `SlashingManager.test.js` slash-list, jail and unstake cases only; it has **no** signature-rejection case (wrong as first stated, 3.3) → D5 `TestD5_SlashableConflictDomain`, S1/S2 vectors |
| 4 | `SlashingManager.updateSlashedAmounts`: reporter bounty, proposer share, remainder routing (there is **no** amount cap; a larger-than-stake amount reverts in `StakeManager.slash` via `SafeMath` underflow) | Penalty arithmetic for an authenticated batch | independent-implementation | Re-implemented in **S2** against D5 collateral attribution; CEI on the bounty credit. Local home: **S2**. See §3.1 — de-duplication is **not** upstream. | `test/units/staking/SlashingManager.test.js` @ `eef53596`; it does **not** cover the invariants first listed, see 3.2 and 3.3 |
| 5 | `ValidatorShare` — `exchangeRate`, `withdrawExchangeRate`, `buyVoucher`/`sellVoucher(_new)`, `_calculateReward`, `_calculateRewardPerShareWithRewards`, `EXCHANGE_RATE_PRECISION`, `getLiquidRewards`; the commission formula is in `StakeManager._getValidatorAndDelegationReward` | Delegation share issuance, commission, per-delegator reward math | **defer-not-applicable** | Initial mode is self-bond only; delegation calls are rejected (roadmap P2). Deferred to a future delegation upgrade, which carries **its own** historical share/commission-loss tests through rotations and exits. Kept as an algorithm reference (exchange-rate accumulator in `ValidatorShare`; `reward.sub(validatorReward).mul(commissionRate).div(MAX_COMMISION_RATE)` in `StakeManager`). | entire `ValidatorShare` / voucher suite — out of scope for M4S self-bond; re-added only if delegation is enabled |
| 6 | `StakingNFT` (ERC‑721 validator ownership) + `validatorAuction` (`startAuction`/`confirmAuctionBid`/`dethroneAndStake`) | Transferable validator slots + slot auctions | **remove** | Duty *(move reward/stake bookkeeping on NFT transfer; auction escrow; dethrone refund)* → accounting replacement **`validator-identity-bookkeeping`**: P3 stable **non-transferable** staking account, owner key, the root consensus key only (ADR 0012), proof-of-possession, unique active bindings; membership changes only through the certified election. | NFT transfer/approval, auction, dethrone cases |
| 7 | `StakingInfo` — `getStakerDetails`, `getAccountStateRoot`, `updateNonce` (account-state-root getter + event logger; `verifyConsensus` is in `SlashingManager`, not here) | Off-chain indexing events + checkpoint account-state-root verification | **remove** (checkpoint helpers) | Duty → accounting replacement **`root-certified-lifecycle`**: the root consumes the **certified contract output** and does not re-run the staking algorithm (`governance.tex` §"Trust Base Derivation" step 1). P5 emits the deterministic snapshot identity + candidate fields; P2 emits a minimal bonded/reserved/slashed event set. | none exist: no `StakingInfo` Merkle-proof or account-state-root test at either pin (wrong, 3.3) |
| 8 | `Registry` / `Governable` / `GovernanceLockable` / `UpgradableProxy` | Mutable contract address book + upgradeable proxies over custody logic | **remove** (carries no value accounting duty) | Address indirection + a proxy admin that can replace custody. `governance.tex` §"Upgrade and Delivery Boundaries": custody is **immutable**; stake custody & fixed slash/exit rules are separated from election policy; policy changes get bounded permissions + timelocks (roadmap P7). **No upgradeable proxy over custody.** | proxy-admin / registry-swap cases |
| 9 | `StateSender` (state-sync to Bor; no `IStateReceiver` exists at either pin) + `topUpForFee` / `claimFee` (Heimdall fee token) | Cross-chain state sync + separate Heimdall fee balance | **remove** (bridge coupling) | State-sync unneeded in Setup 2 (each operator runs a paired reth node; the root feeds certified progress through the mandatory state feed). Duty *(Heimdall fee escrow)* → accounting replacement **`fee-accounting`**: T3 `FeeCollector` + independent `Treasury`; priority fees via protocol balance accounting without calling contract code. | `topUpForFee`/`claimFee` cases in `StakeManager.test.js`; no `StateSender` test exists (3.3) |
| 10 | OZ primitives the staking set actually imports — `SafeMath`, `Math`, `IERC20`, `Ownable` (`openzeppelin-solidity` 2.2.0 at `matic-contracts`, vendored `common/oz` at `pos-contracts`; no `ReentrancyGuard` in `contracts/staking`) | Checked arithmetic, access control, reentrancy guards at solc 0.5 | **remove** (library swap, no accounting change) | solc ≥ 0.8 built-in checked arithmetic + a current audited library (OpenZeppelin 5.x or Solady) pinned in **P2**; explicit `unchecked` only where proven safe. `SafeMath` 0.5 is obsolete. | none in either repo: OZ's own tests are not vendored (wrong, 3.3) |

Disposition counts: 3 independent-implementation, 6 remove, 1
defer-not-applicable, 0 vendor-port.

### 3.1 Row 4 correction: what is upstream and what is new

The earlier revision attributed **per-offence de-duplication** to upstream
`SlashingManager`. **It does not exist upstream.** Reading
`updateSlashedAmounts` at `eef53596` shows exactly two guards:

```solidity
slashingNonce = slashingNonce.add(1);
require(slashingNonce == _slashingNonce, "Invalid slashing nonce");
...
require(verifyConsensus(keccak256(abi.encodePacked(bytes(hex"01"), data)), sigs), "2/3+1 Power required");
```

A monotonically increasing **batch** nonce, and authentication of a
consensus-signed **batch**. Neither derives a canonical offence identity, so the
same offence appearing in two different batches would be charged twice; nothing
upstream prevents it. It is therefore not evidence for D5 canonical-offence
de-duplication.

**Further:** there is **no `SlashingManager` at the `pos-contracts` pin at all** —
`contracts/staking` has no slashing directory there. This unit is attributable
only to `matic-contracts`, and only at that pin.

**New Unicity design and new tests**, with no upstream counterpart to reference
and no upstream review to inherit:

1. **Objective evidence validation** — authenticated conflicting votes, not a
   consensus-signed batch.
2. **Canonical offence identity** — D5 `SlashableConflict` over
   (`accountableKey`, `network`, `messageDomain`, `votingEpoch`, `votingRound`),
   and de-duplication keyed by it.
3. **Historical collateral attribution** through key rotation, delegation change
   and queued withdrawal.

Only the bounty / proposer-share / remainder **arithmetic shape** is a reference. There is no amount cap in `updateSlashedAmounts` or `StakeManager.slash` at the pin.

### 3.2 Removed upstream tests: pinned references

The earlier revision pinned `test/units/staking/SlashingManager.test.js` @
`eef53596` and listed three invariants it was said to cover. Reading the file
(283 lines) shows it covers **none of them**; the table is corrected to what the
file does cover.

| Upstream test | What it actually asserts | Local disposition |
|---|---|---|
| `test/units/staking/SlashingManager.test.js` @ `eef53596`, "should slash validators" | two validators slashed 100 each: `Slashed` event of 200, validator amounts fall to 900 | **retained**, as an S2 vector over D5 collateral attribution (stake debit by the slashed amount) |
| same, "should slash validator:jail and send checkpoint" / "jail/unjail" / "jail => unstake" | jailed validator leaves the validator set and total stake; checkpoint continues with the rest | **retained** in effect: S2 jail excludes the offender from future elections; checkpoint part **not retained** |
| same, "when validator is slashed to 0" | zero-amount validator is unstaked in the current epoch and can `unstakeClaim` | **retained**, as a full-slash/retirement vector in S2/P4 |
| same, "Slashing:delegation" | slash reduces `delegatedAmount` pro rata | **not retained** (delegation deferred) |
| — | rejects a batch whose `_slashingNonce` is not stored + 1; rejects a batch without 2/3+1 signatures | **no upstream test exists** for either (the contract enforces both; the suite never exercises the rejection); not retained, since the trigger is replaced by D5 authenticated conflicting votes |
| — | bounty / proposer share / remainder split | **no upstream test** asserts the split (it checks event counts only); the S2 arithmetic vector is **new** |
| — | canonical offence identity / de-duplication | **new** (3.1) |
| — | objective evidence validation | **new** (3.1) |
| — | historical collateral attribution through rotation | **new** (3.1) |

The remaining rows' suite-level references are still coarse; they are adequate
for `remove` rows, where the duty rather than the test is what must be re-homed,
and each such duty is named in section 5. Section 3.3 records which were checked.

### 3.3 Verification of the upstream mappings (2026-10-03)

Every component and test mapping in the matrix was checked against clones at the
pins: `matic-contracts` =
[`eef53596`](https://github.com/maticnetwork/contracts/tree/eef53596046eda70a53653a8e5ff79b1cbf0a4f9)
(`main`, 2024-03-01, archived) and `pos-contracts` =
[`ffa83a74`](https://github.com/0xPolygon/pos-contracts/tree/ffa83a740dff3f4764277d855faf6c9388e06d90)
(`main` 2026-08-05; `main` has not moved). Tag `v0.3.11` resolves to
`9564ece3a0647b0da18a1a2a51baffb5f661893f`. Source facts re-checked: both root
`LICENSE` files are the GPLv3 text; both `package.json` say `"license": "MIT"`;
`matic-contracts` pins `openzeppelin-solidity` 2.2.0, `pos-contracts` has none and
vendors `contracts/common/oz`; `pos-contracts` `StakeManager.sol` begins with
`pragma solidity 0.5.17;` and has no SPDX line; `contracts/staking` has a
`slashing/` directory only at `matic-contracts`. All verified.

Component mappings (the "Upstream unit" column):

| Row | Verdict | Evidence |
|---|---|---|
| 1 `StakeManager` bonding / unbond, `WITHDRAWAL_DELAY = 2**13` | verified | `StakeManager.sol` `stakeFor` L449, `unstake` L414, `unstakeClaim` L462, `WITHDRAWAL_DELAY` L94 (`matic`); L456/404/471/93 (`pos`) |
| 2 reward / checkpoint units | verified | `checkSignatures`, `_increaseRewardAndAssertConsensus`, `rewardPerStake`, `CHECKPOINT_REWARD`, `_updateRewardsAndCommit`, `combinedStakePower` exist at both pins |
| 3 `slash` + `updateSlashedAmounts` + `verifyConsensus` | verified (at `matic` only) | `StakeManager.slash` L686-; `SlashingManager.sol` `updateSlashedAmounts` L38, `verifyConsensus` L91; `pos` has `StakeManager.slash` but no `SlashingManager` |
| 4 "amount cap, bounty, remainder" | **wrong** | no cap exists; bounty, proposer share and remainder do (`SlashingManager.sol` L53-84) |
| 5 `ValidatorShare` units incl. `commissionRate` formula | **wrong** (location) | exchange-rate and voucher units are in `ValidatorShare.sol`; the commission formula is in `StakeManager._getValidatorAndDelegationReward` (`matic` L1035-1040, `pos` L1022-1027) |
| 6 `StakingNFT`, auction functions | verified | `StakingNFT.sol`; `startAuction`, `confirmAuctionBid`, `dethroneAndStake` in `StakeManager.sol` |
| 7 `StakingInfo` incl. `verifyConsensus` | **wrong** (in part) | `getStakerDetails`, `getAccountStateRoot`, `updateNonce` exist; `verifyConsensus` is in `SlashingManager` (`matic`) and absent at `pos` |
| 8 `Registry`, `Governable`, `GovernanceLockable`, `UpgradableProxy` | verified | all four contracts exist at both pins |
| 9 `StateSender`, `IStateReceiver`, `topUpForFee`, `claimFee` | **wrong** (in part) | `StateSender`, `topUpForFee`, `claimFee` exist; no `IStateReceiver` at either pin |
| 10 OZ 0.5.x `SafeMath`, `ERC20`, `Ownable`, `ReentrancyGuard`, `Math` | **wrong** (in part) | staking set imports `SafeMath`, `Math`, `IERC20`, `Ownable`; no `ReentrancyGuard`; OZ is 2.2.0, not 0.5.x |

Test mappings (the "Removed upstream test" column; row 4 split into its three invariants):

| Row | Verdict | Evidence |
|---|---|---|
| 1 unstake / unstakeClaim / `WITHDRAWAL_DELAY` | verified (file level) | `test/units/staking/stakeManager/StakeManager.Staking.js` `describe('unstake')` L361, `describe('unstakeClaim')` L591; `WITHDRAWAL_DELAY` in `StakeManager.test.js` L142 and `ValidatorShare.test.js` L1685 |
| 2 checkpoint reward / proposer bonus / stake-power split | unverifiable | no test is named; only incidental references (`CHECKPOINT_REWARD`, `proposerBonus` in `StakeManager.Staking.js` L814-831); no stake-power split case found |
| 3 `SlashingManager` slash-list & signature tests | **wrong** | the file has slash/jail/unstake cases and no signature-rejection case |
| 4(i) rejects a wrong `_slashingNonce` | **wrong** | no such test in `SlashingManager.test.js` |
| 4(ii) rejects a batch without 2/3+1 signatures | **wrong** | no such test |
| 4(iii) split into bounty, proposer share, remainder | **wrong** | the file never asserts the split (event counts only) |
| 5 `ValidatorShare` suite | verified | `test/units/staking/ValidatorShare.test.js` exists at both pins (`pos` adds `ValidatorSharePol.test.js` and a Forge suite) |
| 6 NFT / auction / dethrone | verified | `StakingNFT.test.js`; `dethrone` in `StakeManager.test.js` L1009; auction in `StakeManager.Staking.js` L269 |
| 7 `StakingInfo` Merkle-proof / account-state-root | **wrong** | no such test at either pin (one comment mentions `accountStateRoot`, `StakeManager.test.js` L1806) |
| 8 proxy-admin / registry-swap | unverifiable | `UpgradableProxy.test.js` and `GovernanceLockable.test.js` exist; no registry-swap case found |
| 9 `StateSender` sync + `topUpForFee`/`claimFee` | **wrong** (in part) | `topUpForFee`/`claimFee` tests exist in `StakeManager.test.js`; no `StateSender` test exists (only deployer helpers) |
| 10 OZ 0.5 unit tests | **wrong** | OZ tests are in neither repo |

Counts: 22 mappings (10 component, 12 test) — **8 verified, 12 wrong, 2
unverifiable**. The "wrong" and "unverifiable" entries are corrected in the
matrix rows above; none is evidence of a removed obligation. The golden fixture
and Go model (`evmroot/testdata/p1-reuse-matrix.json`, `p1matrix.go`) still carry
the earlier wording and are **not** changed by this documentation-only revision;
refresh them with `go run ./evmroot/cmd/p1matrix -update` when the model is next
touched.

## 4. Three options, compared on engineering merit

The earlier revision compared two options and eliminated one on a licence ground
that has been withdrawn (§2.1). With a GPL‑3.0 destination declared, **all three
of the reviewer's options are licence-permitted**, so the comparison is now on
engineering merit alone.

| Axis | (a) Focused port of `StakeManager`/`ValidatorShare` | (b) Selective reuse of compatible primitives | (c) Independent implementation of the profile's behaviours |
|---|---|---|---|
| Licence | **permitted** — GPL‑3.0 into a GPL‑3.0 destination | permitted under either destination licence | permitted |
| What it buys | real deployed-bytecode provenance | small, well-understood, low-risk building blocks | exactly the surface the profile needs |
| Toolchain | solc 0.5.17 → ≥0.8 is a rewrite (built-in overflow checks, `address payable`, ABI v2, constructor/visibility syntax) | same migration, far less code | targets the P2 toolchain directly |
| Unused surface | validator NFT, auctions, `dethrone`, delegation vouchers, Heimdall fee token, `StateSender`, upgradeable proxies, checkpoint Merkle plumbing — dead in self-bond, still on the audit surface | none | none |
| Storage coupling | the storage layout is entangled with those features; deleting them means keeping their assumptions | none | none |
| Upstream support | `matic-contracts` archived; `pos-contracts` tracks *deployed* bytecode, not this use | vendored `common/oz` tree, stable | n/a |
| Review inheritance | **forfeited in practice** — once most of the contract is deleted and the compiler moved, the artifact is no longer the audited one | none claimed | none claimed |

**Decision: (c) for the staking logic, with (b) available for primitives.**

The deciding argument is that (a)'s only real advantage is provenance, and the
work needed to fit these units to the self-bond profile — delete most of the
contract, keep its storage assumptions, move two compiler generations — destroys
exactly that advantage. The four behaviours actually reused (delayed unbond,
reward-per-weight accumulator, cap/bounty/remainder split, CEI claim pattern) are
small and must be rewritten against the D4/D5 certified lifecycle regardless,
which upstream does not have.

**(a) is not excluded.** It is rejected for *these* units on the surface,
storage-coupling and toolchain grounds above. A later unit with a closer surface
match — and the vendored `common/oz` primitives in particular — can revisit it,
and the matrix's licence gate will admit it under the declared destination.## 5. Explicit accounting replacements

Every duty a removed Polygon unit performed is re-homed. Full text and spec
references live in `evmroot/testdata/p1-reuse-matrix.json`
(`accounting_replacements`); summary:

| Key | Duty (Polygon) | Replacement | Spec |
|---|---|---|---|
| `root-certified-lifecycle` | reserve collateral to an assignment; hold it through extension / pending candidate / cancelled transition; release only on an authenticated "backs no successor" statement | D4 handoff state machine + D5 `Reservation`; election reserves, `AcknowledgeRetirement` records `R_ret`, withdrawal gated by `Δ_hold` / inbox cutoff / pending evidence; abort needs a root-certified abort + EVM ack | `governance.tex` §§ Stake Registry, Election, Trust Base Derivation, Economic Invariants 1–4; ADR 0006/0007 |
| `assigned-weight-reward` | per-checkpoint pool sizing + proposer bonus + validator/delegator split | closed-interval `R_ν(I)=min(ρ_e·\|I\|,Pool_free)·b_ν/W_e` over certified root-round progress; integer arithmetic, remainder stays in the source pot; idempotent bounded permissionless settlement; CEI claims; idle assigned validators paid (accepted limitation) | `governance.tex` §§ Rewards, Fees; roadmap T8, P7 |
| `objective-slashing-penalty` | Heimdall-signed slash batch: debit stake, credit reporter, jail | D5 `SlashableConflict` + S1/S2: charge attributable active/retiring collateral once, bounded bounty, remainder to treasury, duplicate-offence guard, jail excludes future elections; never mints/burns UCT | `governance.tex` §§ Slashing, "Slashed Stake"; ADR 0007; roadmap S1–S2 |
| `collateral-attribution-through-rotation` | keep bookkeeping attached across signer change / unbonding | D5 `InheritedProtectionUntil` (max protection across rotation/delegation change); historical bindings survive rotation & exit; slashing hits collateral + attributable unbonding shares | `governance.tex` §§ Stake Registry, Economic Invariants 4; ADR 0007; roadmap P3–P4 |
| `fee-accounting` | separate Heimdall fee-token escrow + claim | no separate fee token; T3 `FeeCollector` (protocol balance accounting, no contract call) + independent `Treasury`; permissionless split | `governance.tex` §§ Fees, Information Flows; roadmap T3 |
| `validator-identity-bookkeeping` | move bookkeeping on NFT transfer; auctions; dethrone refund | P3 stable non-transferable staking account, owner key, distinct roles, PoP, unique active bindings; no transfer, no auction | `governance.tex` §§ Stake Registry, Election; roadmap P3, P5 |

## 6. What P1 does not decide

- The contract toolchain (**P2**); the repository is `unicity-pos-contracts`.
- Any parameter value — `Δ_hold`, `ρ_e`, `N_max`, bounty caps, minimum
  self-bond, positive base-fee floor (release decisions; P7 for governance).
- The actual vendoring / writing of contract code (**P2** and later).
- Whether to accept a separately-housed GPL‑3.0 ported package, and the
  destination licence (**owner decisions**; see "Open for owner acceptance").
- A security audit. **Compiler modernization and a green upstream test suite
  are not a security audit** — the audit owner is the roadmap X-series (X2
  pre-TGE; X4/X5 PoS).
- Delegation (`ValidatorShare`) — deferred; its own ticket carries its own
  historical loss tests.

## 7. Reuse decision (normative)

> Independent implementation of a minimal self-bond set (not a clean-room process:
> provenance is documented, not certified). **No Polygon source is vendored or
> ported at this revision**: that is an engineering choice about these units
> (section 4), not a licence bar. Under the declared destination boundary a
> GPL‑3.0 port into the separate contract repository is licence-permitted, and the
> owner confirms the boundary. A short, named list of algorithm shapes — the
> delayed-unbond state machine, the reward-per-weight accumulator, the
> bounty/proposer-share/remainder penalty split, and the dormant delegation
> exchange-rate/commission formulas — is used as **reference only**. All M4S
> staking-contract code is written locally in `unicity-pos-contracts` (licence
> chosen by the owner; GPL‑3.0 proposed), against the frozen D4/D5 lifecycle.
> Checkpoint, bridge/state-sync, validator-NFT/auction, Heimdall-fee and
> upgradeable-proxy couplings are removed; each accounting duty they carried is
> re-homed per section 5.

## 8. Acceptance mapping

| P1 acceptance clause | Evidence |
|---|---|
| a reuse matrix identifies every retained dependency and removed test obligation | §3 table (mappings verified in §3.3) + `evmroot/testdata/p1-reuse-matrix.json`; `TestP1_ReuseMatrixValidates`, `TestP1_ReferenceRowsDropAnUpstreamTestAndReHomeIt` (every reference/port row has `removed_upstream_test` + `local_home`); retained deps = 0 live (`TestP1_NoUpstreamSourceIsPorted`), reference-only list named in §7 |
| checkpoint / bridge coupling deleted only after identifying accounting duties it carried | §3 rows 2, 3, 7, 9 + §5; `TestP1_EveryRemovalNamesItsAccountingDuty`, `TestP1_CheckpointAndBridgeCouplingIsRemoved` |
| root-certified lifecycle and assigned-weight rewards have explicit accounting replacements | §5 keys `root-certified-lifecycle`, `assigned-weight-reward`; `TestP1_RootCertifiedLifecycleAndRewardHaveReplacements` (both present, non-trivial, cite `governance.tex`) |
| neither compiler modernization nor upstream test success is treated as a security audit | §2, §4, §6; `Decision.UpstreamTestSuiteIsNotASecurityAudit` / `CompilerModernizationIsNotAnAudit` / `SecurityAuditOwner`; `TestP1_UpstreamTestSuccessIsNotAnAudit` |
| minimal self-bond compared with a port | §4 |
| pinned Polygon source revisions + licences | §2; `sources` in the fixture with 40-hex revisions + SPDX ids; `TestP1_NoUpstreamSourceIsPorted` |
| vendor only justified components | §4 and §7 — none justified for vendoring on engineering grounds (not a licence bar); `AnyVendored() == false`, `Decision.Vendored == false` |

## 9. Reproduce

```
go run ./evmroot/cmd/p1matrix            # print the assessment (validates first)
go run ./evmroot/cmd/p1matrix -update    # regenerate evmroot/testdata/p1-reuse-matrix.json
go test ./evmroot/... -run TestP1        # acceptance invariants + golden fixture

# Upstream facts (read 2026-09-06):
curl -s https://api.github.com/repos/maticnetwork/contracts   | jq '{archived,license:.license.spdx_id,default_branch}'
curl -s https://api.github.com/repos/0xPolygon/pos-contracts  | jq '{archived,license:.license.spdx_id,default_branch}'
curl -s https://api.github.com/repos/maticnetwork/contracts/branches/main | jq -r .commit.sha
```

## 10. Open for owner acceptance

P1 stays open for the owner. These decisions are the owner's; this assessment
records them and decides none (unresolved values stay symbolic):

1. **Accept P1's reviewed artifact/reuse boundary** (ADR 0011): independent
   implementation, nothing vendored, reference-only shapes.
2. **Confirm the licence boundary and select the contract licence**; decide
   whether a ported GPL package is ever in scope, and what a genesis package or
   node release carrying GPL bytecode must state.
3. **Resolve upstream licence scope** before any file is copied (GPLv3 `LICENSE`
   vs MIT `package.json`; no SPDX on `pos-contracts` `StakeManager.sol`; vendored
   OZ file notices).
4. **#85 economics:** bond/weight unit, election size and churn, penalties,
   bounties and repeat offences, protection periods, governance bounds and
   custody migration.
5. **Evidence protection and safe withdrawal with the I-track deferred**, and an
   enforceable real-time retirement floor/checkpoint policy (ADR 0012 open
   question 2).

Until these are answered, P2 starts no custody code on assumptions beyond this
document, and P-DESIGN #85 acceptance waits on items 4 and 5.
