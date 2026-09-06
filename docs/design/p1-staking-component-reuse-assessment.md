# P1 — Staking component reuse assessment

Issue: [#27 P1](https://github.com/ristik/bft-core/issues/27) · Milestone: M4S ·
Prereqs: [#6 D4](https://github.com/ristik/bft-core/issues/6),
[#7 D5](https://github.com/ristik/bft-core/issues/7) · Status: **proposed for acceptance**

P1 is an assessment ticket. It produces **a reviewed reuse decision**, not
contract code: which parts of the Polygon PoS staking contracts can serve the
enshrined-EVM PoS lifecycle, which are dropped, and what assumes each dropped
duty. The vendoring itself is [P2](https://github.com/ristik/bft-core/issues/30);
the contract repository and toolchain are chosen in P2; parameter values and any
security audit are separate.

Model: [`evmroot/p1reuse.go`](../../evmroot/p1reuse.go) (types + `Validate`),
[`evmroot/p1matrix.go`](../../evmroot/p1matrix.go) (`BuildP1ReuseMatrix`).
Fixture: [`evmroot/testdata/p1-reuse-matrix.json`](../../evmroot/testdata/p1-reuse-matrix.json).
Decision record: [ADR 0009](../adr/0009-staking-component-reuse.md).

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

## 2. Pinned upstream candidates and licences

Revisions read 2026-09-06 from the public GitHub API.

| Source | Repo | Revision | Licence | solc | State |
|---|---|---|---|---|---|
| `matic-contracts` | `github.com/maticnetwork/contracts` | `eef5359…` (`main`, 2024‑03‑01); tag `v0.3.11` = `9564ece3…` | **GPL‑3.0‑only** | 0.5.17 / ^0.5.2 | **archived** ~2024‑03; no upstream security stream |
| `pos-contracts` | `github.com/0xPolygon/pos-contracts` | `ffa83a7…` (`main`, 2026‑08‑05, "main mirrors deployed on‑chain bytecode") | **GPL‑3.0‑only** | 0.5.17 (staking set unchanged) | maintained; same `StakeManager` / `ValidatorShare` / `StakingInfo` units |

Both depend on `openzeppelin-solidity` 0.5.x (`SafeMath`, `ERC20`, `Ownable`,
`ReentrancyGuard`).

**Licence finding.** The entire Polygon PoS staking contract lineage is
**GPL‑3.0‑only** copyleft. `bft-core` is **Apache‑2.0**, and its custody
contracts are immutable. GPL‑3.0 → Apache‑2.0 relicensing is not permitted, so
**no upstream source can be copied or adapted into the Apache‑2.0 contract
set.** The roadmap's phrasing ("pin candidate Polygon source revisions and
licenses… vendor only the justified components") assumed a permissive upstream;
that assumption does not hold. A separately-housed GPL‑3.0 staking package built
by porting is theoretically possible, but that is an owner/governance decision
about a new distributable artifact and is **out of P1 scope** — this assessment
does not choose it and flags it for the owner.

## 3. Component reuse matrix

Dispositions: **clean-room-reference** (study the public algorithm, re-implement
locally under Apache‑2.0 — no upstream bytes), **remove** (drop; name any
accounting duty it carried and where that duty goes), **defer-not-applicable**
(out of scope for self-bond; kept as a reference for a later optional upgrade).
**vendor-port** is unavailable here — see §2.

| # | Upstream unit | Purpose | Disposition | Replacement / where the duty goes | Removed upstream test |
|---|---|---|---|---|---|
| 1 | `StakeManager.stakeFor/restake/unstake/unstakeClaim`; `WITHDRAWAL_DELAY = 2¹³` epochs | Bonding + fixed-delay unbond claim | clean-room-reference | D5 `Reservation` + `ProtectionParams`; delay is `Δ_hold` in **certified root rounds** with `Δ_hold > Δ_ev+Δ_incl+Δ_exec`, plus the forced-inbox position cutoff and the pending-evidence gate. Requesting retirement does not start the clock. Local home: **P2**. | `StakeManager` unstake/unstakeClaim dynasty & `WITHDRAWAL_DELAY` cases → D5 `TestD5_WithdrawalGates` |
| 2 | `StakeManager.checkSignatures/_increaseRewardAndAssertConsensus/rewardPerStake/CHECKPOINT_REWARD/_updateRewardsAndCommit`; proposer bonus + `combinedStakePower` split | Checkpoint-submission-driven reward accrual & consensus assertion | **remove** (checkpoint coupling) | Duty *(sizes a per-interval pool, applies a proposer bonus, splits by validator vs delegator stake power every checkpoint)* → accounting replacement **`assigned-weight-reward`**: `R_ν(I)=min(ρ_e·\|I\|,Pool_free)·b_ν/W_e` over certified root-round progress; no proposer bonus. | checkpoint reward / proposer-bonus / stake-power split cases |
| 3 | `StakeManager.slash` + `SlashingManager.updateSlashedAmounts` + `verifyConsensus` (Heimdall-checkpoint-signed batch) | Apply a slashing batch validated by Heimdall consensus signatures | **remove** (Heimdall/checkpoint path) | Duty *(debit offender validator+delegation stake, credit a reporter, update totals, jail)* → accounting replacement **`objective-slashing-penalty`**: D5 `SlashableConflict` + S1/S2; charge attributable collateral once, bounded bounty, remainder to treasury, duplicate-offence guard, jail excludes future elections. | `SlashingManager` slash-list & checkpoint-signature tests → D5 `TestD5_SlashableConflictDomain`, S1/S2 vectors |
| 4 | `SlashingManager` penalty arithmetic: amount cap, reporter bounty, remainder routing, per-offence dedupe | Penalty arithmetic + anti-double-charge | clean-room-reference | Re-implemented in **S2** against D5 collateral attribution; CEI on the bounty credit; dedupe keyed by the D5 conflict identity. Local home: **S2**. | `SlashingManager` slash-list & checkpoint-signature tests → S2 objective-slashing vectors |
| 5 | `ValidatorShare` — `exchangeRate`, `withdrawExchangeRate`, `buyVoucher`/`sellVoucher(_new)`, `commissionRate`, `_calculateReward`, `_calculateRewardPerShareWithRewards`, `EXCHANGE_RATE_PRECISION`, `getLiquidRewards` | Delegation share issuance, commission, per-delegator reward math | **defer-not-applicable** | Initial mode is self-bond only; delegation calls are rejected (roadmap P2). Deferred to a future delegation upgrade, which carries **its own** historical share/commission-loss tests through rotations and exits. Kept as an algorithm reference (exchange-rate accumulator; `reward.sub(validatorReward).mul(commissionRate).div(MAX_COMMISION_RATE)`). | entire `ValidatorShare` / voucher suite — out of scope for M4S self-bond; re-added only if delegation is enabled |
| 6 | `StakingNFT` (ERC‑721 validator ownership) + `validatorAuction` (`startAuction`/`confirmAuctionBid`/`dethroneAndStake`) | Transferable validator slots + slot auctions | **remove** | Duty *(move reward/stake bookkeeping on NFT transfer; auction escrow; dethrone refund)* → accounting replacement **`validator-identity-bookkeeping`**: P3 stable **non-transferable** staking account, owner key, distinct consensus/node roles, proof-of-possession, unique active bindings; membership changes only through the certified election. | NFT transfer/approval, auction, dethrone cases |
| 7 | `StakingInfo` — `getStakerDetails`, `getAccountStateRoot`, `verifyConsensus`, `updateNonce` (checkpoint Merkle account-root helpers + event logger) | Off-chain indexing events + checkpoint account-state-root verification | **remove** (checkpoint helpers) | Duty → accounting replacement **`root-certified-lifecycle`**: the root consumes the **certified contract output** and does not re-run the staking algorithm (`governance.tex` §"Trust Base Derivation" step 1). P5 emits the deterministic snapshot identity + candidate fields; P2 emits a minimal bonded/reserved/slashed event set. | `StakingInfo` Merkle-proof / account-state-root cases |
| 8 | `Registry` / `Governable` / `GovernanceLockable` / `UpgradableProxy` | Mutable contract address book + upgradeable proxies over custody logic | **remove** (carries no value accounting duty) | Address indirection + a proxy admin that can replace custody. `governance.tex` §"Upgrade and Delivery Boundaries": custody is **immutable**; stake custody & fixed slash/exit rules are separated from election policy; policy changes get bounded permissions + timelocks (roadmap P7). **No upgradeable proxy over custody.** | proxy-admin / registry-swap cases |
| 9 | `StateSender` / `IStateReceiver` (state-sync to Bor) + `topUpForFee` / `claimFee` (Heimdall fee token) | Cross-chain state sync + separate Heimdall fee balance | **remove** (bridge coupling) | State-sync unneeded in Setup 2 (each operator runs a paired reth node; the root feeds certified progress through the mandatory state feed). Duty *(Heimdall fee escrow)* → accounting replacement **`fee-accounting`**: T3 `FeeCollector` + independent `Treasury`; priority fees via protocol balance accounting without calling contract code. | `StateSender` sync + `topUpForFee`/`claimFee` cases |
| 10 | `openzeppelin-solidity` 0.5.x — `SafeMath`, `ERC20`, `Ownable`, `ReentrancyGuard`, `Math` | Checked arithmetic, access control, reentrancy guards at solc 0.5 | **remove** (library swap, no accounting change) | solc ≥ 0.8 built-in checked arithmetic + a current audited library (OpenZeppelin 5.x or Solady) pinned in **P2**; explicit `unchecked` only where proven safe. `SafeMath` 0.5 is obsolete. | OZ 0.5 `SafeMath`/`ReentrancyGuard` unit tests |

Disposition counts: 3 clean-room-reference, 6 remove, 1 defer-not-applicable, 0
vendor-port.

## 4. Self-bond vs port comparison

| Axis | Port the Polygon staking set | Minimal self-bond, clean-room |
|---|---|---|
| Licence | GPL‑3.0‑only into an Apache‑2.0 immutable-custody set — **not permitted** | Apache‑2.0, written locally |
| Compiler | solc 0.5.17 + OZ 0.5.x; a move to ≥ 0.8 is a rewrite (built-in overflow checks, `address payable`, ABI v2, constructor/visibility syntax) | targets the P2 toolchain directly |
| Upstream support | `maticnetwork/contracts` archived; `pos-contracts` tracks *deployed* bytecode, not this use | n/a |
| Unused surface imported | validator NFT + auctions + `dethrone`, delegation vouchers, Heimdall fee token, `StateSender`, upgradeable proxies, checkpoint Merkle plumbing — all dead in self-bond, all still on the audit surface | only what the D4/D5 lifecycle needs |
| Behaviour actually reused | delayed-unbond state machine; `rewardPerStake` accumulator pattern (accrual without per-account loops); cap/bounty/remainder penalty split; CEI claim pattern | same, re-implemented against root rounds and D5 collateral attribution |
| Review inheritance | none — a modernised rewrite is not the audited artifact | none claimed; audit is X-series |

**Conclusion.** Port is not on the table (licence), and even setting licence
aside it would be a modernising rewrite of mostly-unused code. The reused
behaviours are small and better expressed against the frozen D4/D5 lifecycle.
**Decision: clean-room minimal self-bond, no upstream source vendored**, with a
short named reference list (rows 1, 4, and the row 5 formulas kept dormant for a
future delegation upgrade).

## 5. Explicit accounting replacements

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

- The contract repository home and toolchain (**P2**).
- Any parameter value — `Δ_hold`, `ρ_e`, `N_max`, bounty caps, minimum
  self-bond, positive base-fee floor (release decisions; P7 for governance).
- The actual vendoring / writing of contract code (**P2** and later).
- Whether to accept a separately-housed GPL‑3.0 ported package (**owner /
  governance decision**; see §2).
- A security audit. **Compiler modernization and a green upstream test suite
  are not a security audit** — the audit owner is the roadmap X-series (X2
  pre-TGE; X4/X5 PoS).
- Delegation (`ValidatorShare`) — deferred; its own ticket carries its own
  historical loss tests.

## 7. Reuse decision (normative)

> Clean-room minimal self-bond. **No Polygon source is vendored or ported** into
> the contract set: every pinned Polygon staking revision is GPL‑3.0‑only and
> `bft-core` is Apache‑2.0 with immutable custody. A short, named list of
> algorithm shapes — the delayed-unbond state machine, the reward-per-weight
> accumulator, the cap/bounty/remainder penalty split, and the dormant
> delegation exchange-rate/commission formulas — is used as **reference only**.
> All M4S staking-contract code is written locally under Apache‑2.0 in the
> repository chosen by P2, against the frozen D4/D5 lifecycle. Checkpoint,
> bridge/state-sync, validator-NFT/auction, Heimdall-fee and upgradeable-proxy
> couplings are removed; each accounting duty they carried is re-homed per §5.

## 8. Acceptance mapping

| P1 acceptance clause | Evidence |
|---|---|
| a reuse matrix identifies every retained dependency and removed test obligation | §3 table + `evmroot/testdata/p1-reuse-matrix.json`; `TestP1_ReuseMatrixValidates`, `TestP1_ReferenceRowsDropAnUpstreamTestAndReHomeIt` (every reference/port row has `removed_upstream_test` + `local_home`); retained deps = 0 live (`TestP1_NoUpstreamSourceIsPorted`), reference-only list named in §7 |
| checkpoint / bridge coupling deleted only after identifying accounting duties it carried | §3 rows 2, 3, 7, 9 + §5; `TestP1_EveryRemovalNamesItsAccountingDuty`, `TestP1_CheckpointAndBridgeCouplingIsRemoved` |
| root-certified lifecycle and assigned-weight rewards have explicit accounting replacements | §5 keys `root-certified-lifecycle`, `assigned-weight-reward`; `TestP1_RootCertifiedLifecycleAndRewardHaveReplacements` (both present, non-trivial, cite `governance.tex`) |
| neither compiler modernization nor upstream test success is treated as a security audit | §2, §4, §6; `Decision.UpstreamTestSuiteIsNotASecurityAudit` / `CompilerModernizationIsNotAnAudit` / `SecurityAuditOwner`; `TestP1_UpstreamTestSuccessIsNotAnAudit` |
| minimal self-bond compared with a port | §4 |
| pinned Polygon source revisions + licences | §2; `sources` in the fixture with 40-hex revisions + SPDX ids; `TestP1_NoUpstreamSourceIsPorted` |
| vendor only justified components | §7 — none justified for vendoring (licence); `AnyVendored() == false`, `Decision.Vendored == false` |

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
