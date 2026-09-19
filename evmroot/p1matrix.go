package evmroot

// BuildP1ReuseMatrix is the P1 staking-component reuse assessment as data.
// It feeds both the golden fixture (evmroot/testdata/p1-reuse-matrix.json)
// and cmd/p1matrix. Every string here is normative and is mirrored in
// docs/design/p1-staking-component-reuse-assessment.md.
//
// Revisions were read on 2026-09-06 from the public GitHub API.

func p1Sources() []UpstreamSource {
	return []UpstreamSource{
		{
			Key:        "matic-contracts",
			Repo:       "github.com/maticnetwork/contracts",
			Revision:   "eef53596046eda70a53653a8e5ff79b1cbf0a4f9",
			RevisionAs: "main @ 2024-03-01 (last commit before archival); release tag v0.3.11 = 9564ece3a0647b0da18a1a2a51baffb5f661893f",
			License:    "root LICENSE is GNU GPL v3; package.json declares \"license\": \"MIT\"",
			SPDX:       "GPL-3.0-only",
			Archived:   true,
			SolcPragma: "0.5.17 / ^0.5.2",
			Deps:       "package.json pins openzeppelin-solidity 2.2.0 (verified). NOT 0.5.x -- 0.5.x is the Solidity pragma generation, a separate axis that an earlier revision of this matrix conflated with the dependency version.",
			Note:       "Original Matic/Polygon PoS staking set; archived by upstream ~2024-03, so no upstream security response stream. LICENCE LABELS CONFLICT AT THIS PIN: the root LICENSE is GPLv3 while package.json says MIT. That conflict is recorded, not resolved: it does not establish MIT permission, and it equally means the repository-level label is not by itself a complete per-file provenance analysis. Per-file notices and the licences of imported dependencies must be recorded before any file is copied.",
		},
		{
			Key:        "pos-contracts",
			Repo:       "github.com/0xPolygon/pos-contracts",
			Revision:   "ffa83a740dff3f4764277d855faf6c9388e06d90",
			RevisionAs: "main @ 2026-08-05 (\"main mirrors deployed on-chain bytecode\")",
			License:    "root LICENSE is GNU GPL v3; package.json declares \"license\": \"MIT\"",
			SPDX:       "GPL-3.0-only",
			Archived:   false,
			SolcPragma: "0.5.17",
			Deps:       "No openzeppelin-solidity dependency at all (verified): the OZ sources are VENDORED under contracts/common/oz and imported by relative path; the only OZ package present is @openzeppelin/test-helpers, a test dependency. The dependency layout therefore differs from matic-contracts and each vendored file needs its own licence notice recorded.",
			Note:       "Maintained successor carrying StakeManager / ValidatorShare / StakingInfo. Same licence-label conflict as the older pin. StakeManager.sol at this revision has NO SPDX header -- it begins directly with `pragma solidity 0.5.17;` (verified) -- so its per-file licence is inherited by argument from the repository, not stated in the file. NOTE ALSO: there is no SlashingManager at this pin; contracts/staking contains no slashing directory. SlashingManager exists only at the matic-contracts pin.",
		},
	}
}

func p1AccountingReplacements() []AccountingReplacement {
	return []AccountingReplacement{
		{
			Key:         "root-certified-lifecycle",
			Duty:        "Bind bonded collateral to an assignment, keep it reserved across epoch extension / pending candidate / cancelled transition, and release it only after an authenticated statement that the stake backs no active or prepared successor.",
			Replacement: "D4 epoch-handoff state machine + D5 reservation lifecycle. Election fixes effective weight and reserves the matching collateral (governance.tex \"Election\"). AcknowledgeRetirement records R_ret only when backsActiveOrPrepared is false; phases Bonded -> RetirementRequested -> Draining -> Released. Withdrawal needs now >= max(R_ret + Delta_hold, inheritedProtectionUntil), the forced-inbox position cutoff through LiabilityDeadlineRound, and no pending timely evidence. Cancellation/replacement of a prepared handoff needs a root-certified abort plus an EVM acknowledgement that releases the reservations. Root consumes the certified contract output; validators do not re-run the staking algorithm.",
			SpecRef:     "governance.tex \"Stake Registry\", \"Election\", \"Trust Base Derivation\" (steps 1-5), \"Economic Invariants\" (1-4); docs/adr/0006 (D4); docs/adr/0007 (D5); evmroot/d5retire.go.",
		},
		{
			Key:         "assigned-weight-reward",
			Duty:        "Size a per-interval reward pool, apply a proposer bonus, and split it by validator vs delegator stake power on every checkpoint (StakeManager rewardPerStake / CHECKPOINT_REWARD / _increaseRewardAndAssertConsensus).",
			Replacement: "governance.tex \"Rewards\": for a closed interval I wholly within one acknowledged assignment e, R_nu(I) = E(I) * b_nu / W_e with E(I) = min(rho_e * |I|, Pool_free); |I| counts certified root-round progress; no proposer bonus. Boundaries split I on assignment or rate change; a skipped root round is one interval and a retry never accrues it twice; idle assigned validators are still paid (explicit initial-policy limitation). Integer arithmetic, rounding remainder stays in its source pot; settlement is idempotent, bounded, permissionless, cannot process an unacknowledged future interval; claims use checks-effects-interactions; one failing claim never blocks another. Downtime / QC-omission is not an input.",
			SpecRef:     "governance.tex \"Rewards\", \"Fees\"; roadmap T8 (optional assignment rewards); roadmap P7 (economic integration).",
		},
		{
			Key:         "objective-slashing-penalty",
			Duty:        "Apply a slashing batch: debit the offender's validator + delegation stake, credit a reporter/proposer, update totals, and jail (StakeManager.slash / SlashingManager.updateSlashedAmounts, gated by Heimdall checkpoint signatures).",
			Replacement: "D5 SlashableConflict over (accountableKey, network, messageDomain, votingEpoch, votingRound) with the signed VoteInfo/LedgerCommitInfo binding; S1 consensus-signature primitive; S2 objective slashing. Accepted evidence charges the attributable active or retiring collateral once, credits a bounded submitter bounty, and transfers the remainder to treasury; a duplicate offence costs no extra principal; jailing excludes the validator from future elections while its consensus weight changes only at a committed handoff. Slashing transfers collateral and never creates or destroys native UCT.",
			SpecRef:     "governance.tex \"Slashing\", \"Slashed Stake\" rule; appendix-evm.tex \"Evidence\"; docs/adr/0007 (D5); roadmap S1-S2; evmroot/d5vote.go.",
		},
		{
			Key:         "collateral-attribution-through-rotation",
			Duty:        "Keep reward/stake bookkeeping attached to a validator across signer changes and unbonding (StakeManager.updateSigner, ValidatorShare unbond nonces).",
			Replacement: "D5 InheritedProtectionUntil carries the maximum applicable protection across key rotation and delegation changes; historical bindings survive rotation and exit for accountability; slashing applies to that collateral and its attributable unbonding shares, not merely the current free balance. Key rotation, delegation changes and queued withdrawals cannot remove liability for an earlier attributable offence. P3 registers stable staking identity with proof of possession and unique active bindings; rotation activates only through the committed assignment.",
			SpecRef:     "governance.tex \"Stake Registry\", \"Economic Invariants\" (4); docs/adr/0007 (D5); roadmap P3-P4.",
		},
		{
			Key:         "fee-accounting",
			Duty:        "Escrow a separate Heimdall fee-token balance per validator and let it be claimed (StakeManager.topUpForFee / claimFee).",
			Replacement: "No separate staking fee token. T3 FeeCollector receives priority fees through protocol balance accounting without calling its contract code; permissionless settlement splits attributable receipts between the reward pot and an independent Treasury; unexpected transfers are accounted separately; base-fee destruction is in the EVM native-currency supply accounting.",
			SpecRef:     "governance.tex \"Fees\", \"Information Flows\"; roadmap T3.",
		},
		{
			Key:         "validator-identity-bookkeeping",
			Duty:        "Move stake/reward bookkeeping when validator ownership transfers, and run slot auctions / dethrone refunds (StakingNFT ERC-721, validatorAuction startAuction/confirmAuctionBid/dethroneAndStake).",
			Replacement: "P3 identity, possession and historical key binding: a stable, non-transferable staking account with an owner key and distinct consensus / node roles, proof of possession, and unique active bindings. No transferable validator NFT and no slot auction in the initial profile; set membership changes only through the certified election and committed handoff.",
			SpecRef:     "governance.tex \"Stake Registry\", \"Election\"; roadmap P3, P5.",
		},
	}
}

func p1Components() []Component {
	return []Component{
		{
			UpstreamRef:         "matic-contracts",
			Unit:                "StakeManager.stakeFor / restake / unstake / unstakeClaim; WITHDRAWAL_DELAY = 2**13 epochs",
			Purpose:             "Validator bonding and a fixed-delay unbond claim.",
			Target:              "The D5 collateral-reservation lifecycle: reserve on election, protect after acknowledged retirement, release only past every gate.",
			Disposition:         DispositionIndependentImplementation,
			Replacement:         "evmroot/d5retire.go Reservation + ProtectionParams. Delay is Delta_hold in certified root rounds with Delta_hold > Delta_ev + Delta_incl + Delta_exec, plus the forced-inbox position cutoff and the pending-evidence gate; not a single fixed epoch count, and requesting retirement does not start the clock.",
			RemovedUpstreamTest: "StakeManager unstake / unstakeClaim dynasty and WITHDRAWAL_DELAY test cases.",
			LocalHome:           "P2 (immutable native stake custody), contract repo chosen in P2; gate model already in evmroot/d5retire.go and testdata/d5-vectors.json.",
			Note:                "Reference the state-machine shape only: request -> deactivation epoch -> claim after a delay. Re-implemented against root rounds, not Heimdall epochs.",
		},
		{
			UpstreamRef:     "matic-contracts",
			Unit:            "StakeManager.checkSignatures / _increaseRewardAndAssertConsensus / rewardPerStake / CHECKPOINT_REWARD / _updateRewardsAndCommit; proposer bonus and combinedStakePower split",
			Purpose:         "Checkpoint-submission-driven reward accrual and consensus assertion.",
			Target:          "Assigned-weight reward per certified root interval.",
			Disposition:     DispositionRemove,
			ReplacesDutyKey: "assigned-weight-reward",
			Replacement:     "Replaced by the governance.tex closed-interval reward formula; see accounting replacement \"assigned-weight-reward\".",
			Note:            "Checkpoint coupling: the whole accrual is driven by RootChain checkpoint submission and a per-checkpoint decreasing pool. The new reward is a function of certified root-round progress and effective weight only.",
		},
		{
			UpstreamRef:     "matic-contracts",
			Unit:            "StakeManager.slash + SlashingManager.updateSlashedAmounts + verifyConsensus (Heimdall-checkpoint-signed slashing batch)",
			Purpose:         "Apply a slashing batch validated by Heimdall consensus signatures over a checkpoint.",
			Target:          "Objective double-sign slashing over the D5 vote domain, submitted by anyone.",
			Disposition:     DispositionRemove,
			ReplacesDutyKey: "objective-slashing-penalty",
			Replacement:     "Replaced by D5 vote-domain + S1/S2; see accounting replacement \"objective-slashing-penalty\".",
			Note:            "The Heimdall/checkpoint signature path is removed entirely. Anyone may submit authenticated conflicting votes; the forced inbox preserves a timely commitment while execution is delayed.",
		},
		{
			UpstreamRef:         "matic-contracts",
			Unit:                "SlashingManager.updateSlashedAmounts: amount cap, reporter bounty and remainder routing",
			Purpose:             "Penalty arithmetic for an authenticated slashing batch.",
			Target:              "S2 objective-slashing arithmetic against D5 collateral attribution.",
			Disposition:         DispositionIndependentImplementation,
			Replacement:         "Re-implemented in S2: charge attributable active/retiring collateral once, bounded submitter bounty, remainder to treasury, checks-effects-interactions on the bounty credit.",
			RemovedUpstreamTest: "matic-contracts test/units/staking/SlashingManager.test.js at pin eef53596. Invariants it covers: (i) updateSlashedAmounts rejects a batch whose _slashingNonce is not exactly the stored nonce + 1; (ii) it rejects a batch without 2/3+1 consensus signatures; (iii) the slashed total is split into reporter bounty, proposer share and remainder. Local acceptance: (i) and (ii) are NOT retained -- the trigger is replaced entirely by D5 authenticated conflicting votes, so there is no batch and no nonce; (iii) is retained as an S2 arithmetic vector over D5 collateral attribution. New cases with no upstream counterpart are listed in the note below.",
			LocalHome:           "S2 (objective slashing and liability holds), contract repo chosen in P2.",
			Note:                "CORRECTION. An earlier revision of this row attributed PER-OFFENCE DE-DUPLICATION to upstream. It does not exist upstream. SlashingManager.updateSlashedAmounts (read at pin eef53596) does two things: `slashingNonce = slashingNonce.add(1); require(slashingNonce == _slashingNonce)`, a monotonically increasing BATCH nonce; and verifyConsensus over the batch payload. Neither derives a canonical offence identity, so the same offence appearing in two different batches would be charged twice. Nothing upstream prevents that. FURTHER: there is no SlashingManager at the pos-contracts pin at all -- contracts/staking has no slashing directory there -- so this unit is attributable only to matic-contracts, and only that pin. THE FOLLOWING ARE THEREFORE NEW UNICITY DESIGN AND NEW TESTS, with no upstream counterpart to reference or inherit review from: (1) objective evidence validation (authenticated conflicting votes rather than a consensus-signed batch); (2) canonical OFFENCE IDENTITY, i.e. D5 SlashableConflict over (accountableKey, network, messageDomain, votingEpoch, votingRound), and de-duplication keyed by it; (3) historical collateral attribution through key rotation, delegation change and queued withdrawal. Only the cap/bounty/remainder arithmetic shape is a reference.",
		},
		{
			UpstreamRef: "matic-contracts",
			Unit:        "ValidatorShare: exchangeRate / withdrawExchangeRate / buyVoucher / sellVoucher(_new) / commissionRate / _calculateReward / _calculateRewardPerShareWithRewards / EXCHANGE_RATE_PRECISION / getLiquidRewards",
			Purpose:     "Delegation share issuance, commission, and per-delegator reward math.",
			Target:      "None in the initial profile: self-bond only; delegation calls are rejected (roadmap P2).",
			Disposition: DispositionDeferNotApplicable,
			DeferredTo:  "A future delegation upgrade. governance.tex \"Stake Registry\" allows the first PoS deployment to disable delegation and use self-bond only; roadmap P2 says do not expose a partially implemented share API. That upgrade carries its own historical share / commission-loss tests through rotations and exits.",
			Note:        "Kept as an algorithm reference (exchange-rate accumulator; commission split reward.sub(validatorReward).mul(commissionRate).div(MAX_COMMISION_RATE)). Not on the initial audit surface; no voucher code is written for M4S.",
		},
		{
			UpstreamRef:     "matic-contracts",
			Unit:            "StakingNFT (ERC-721 validator ownership) + validatorAuction (startAuction / confirmAuctionBid / dethroneAndStake)",
			Purpose:         "Transferable validator slots and slot auctions.",
			Target:          "None: identity is a stable, non-transferable staking account (D5 / P3).",
			Disposition:     DispositionRemove,
			ReplacesDutyKey: "validator-identity-bookkeeping",
			Replacement:     "Replaced by P3 identity binding; see accounting replacement \"validator-identity-bookkeeping\".",
			Note:            "No transfer, no auction, no dethrone refund. Removes the NFT-transfer reward/stake carry, the auction escrow and the dethrone path from the surface.",
		},
		{
			UpstreamRef:     "matic-contracts",
			Unit:            "StakingInfo: getStakerDetails / getAccountStateRoot / verifyConsensus / updateNonce (checkpoint Merkle account-root helpers + event logger)",
			Purpose:         "Off-chain indexing events and checkpoint account-state-root verification for slashing/rewards.",
			Target:          "A minimal local event set; no checkpoint account-state-root.",
			Disposition:     DispositionRemove,
			ReplacesDutyKey: "root-certified-lifecycle",
			Replacement:     "The account-state-root / verifyConsensus helpers are dropped: the root consumes the certified contract output and does not re-run the staking algorithm (governance.tex \"Trust Base Derivation\" step 1). P5 emits the deterministic snapshot identity and candidate fields; P2 emits a minimal bonded / reserved / slashed event set.",
			Note:            "Event logging is re-created minimally where P2 / P5 need it; the Merkle-proof plumbing is not.",
		},
		{
			UpstreamRef:             "matic-contracts",
			Unit:                    "Registry / Governable / GovernanceLockable / UpgradableProxy (mutable address book + upgradeable proxies over the staking system)",
			Purpose:                 "A central mutable registry of contract addresses and upgradeable proxies for custody logic.",
			Target:                  "Immutable custody with policy / custody separation.",
			Disposition:             DispositionRemove,
			CarriesNoAccountingDuty: true,
			Note:                    "No value accounting of its own: it is address indirection plus a proxy admin that can replace custody logic. governance.tex \"Upgrade and Delivery Boundaries\" makes money custody, withdrawal accounting, allocation, wrapper and vault contracts immutable in the initial profile; stake custody and its fixed slash/exit rules are separated from election policy, and policy changes have bounded permissions and timelocks (roadmap P7). No upgradeable proxy sits over custody.",
		},
		{
			UpstreamRef:     "matic-contracts",
			Unit:            "StateSender / IStateReceiver (state-sync to Bor) + topUpForFee / claimFee (Heimdall fee token)",
			Purpose:         "Cross-chain state sync to the child chain and a separate Heimdall fee-token balance.",
			Target:          "None.",
			Disposition:     DispositionRemove,
			ReplacesDutyKey: "fee-accounting",
			Replacement:     "Bridge state-sync is not needed in Setup 2 (each operator runs a paired reth node; the root feeds certified progress through the mandatory state feed). Fee handling is replaced per accounting replacement \"fee-accounting\".",
			Note:            "Removes the StateSender coupling and the second fee token. This is the \"bridge coupling\" the ticket calls out; the accounting duty it carried (the Heimdall fee escrow) is re-homed to T3.",
		},
		{
			UpstreamRef:             "matic-contracts",
			Unit:                    "openzeppelin-solidity 0.5.x: SafeMath / ERC20 / Ownable / ReentrancyGuard / Math",
			Purpose:                 "Checked arithmetic, access control and reentrancy guards at solc 0.5.",
			Target:                  "Current audited primitives at the P2 toolchain.",
			Disposition:             DispositionRemove,
			CarriesNoAccountingDuty: true,
			Note:                    "SafeMath 0.5 is obsolete under solc >= 0.8 built-in checked arithmetic. Replaced by solc >= 0.8 semantics plus a current audited library (e.g. OpenZeppelin 5.x or Solady) pinned in P2, with explicit unchecked blocks only where proven safe. This is a library swap, not an accounting change.",
		},
	}
}

// BuildP1ReuseMatrix returns the populated, self-consistent assessment.
func BuildP1ReuseMatrix() ReuseMatrix {
	return ReuseMatrix{
		Ticket:                 "P1 — Staking component reuse assessment (issue #27)",
		BaseRevision:           "integration/enshrined-evm @ 28459b85 (D4 #6, D5 #7 merged)",
		Sources:                p1Sources(),
		Components:             p1Components(),
		AccountingReplacements: p1AccountingReplacements(),
		Destination: Destination{
			Repository:       "github.com/ristik/unicity-pos-contracts (separate from bft-core; created under P1 for exactly this reason)",
			SPDX:             "GPL-3.0-only",
			Boundary:         "The contracts are a SEPARATE ARTIFACT from the Apache-2.0 platform: separate repository, separate source tree, separate build, and no linking. The platform interacts with the deployed contracts only across the EVM ABI and the certified-input boundary -- it does not import, compile or link contract source. Nothing in the platform derives from contract source, and nothing in the contracts derives from platform source. That separation is what allows GPL-3.0 contracts and an Apache-2.0 platform to coexist; the earlier revision assumed the opposite without examining the boundary.",
			LegalReviewOwner: "Repository owner, before any upstream file is copied. This matrix narrows the engineering options and records the boundary; it does not make the licence determination and must not be read as legal advice.",
		},
		Decision: ReuseDecision{
			Choice:                               "INDEPENDENT IMPLEMENTATION of a minimal self-bond set, in a separate GPL-3.0-only repository, with a focused port kept open as a live option for specific units rather than excluded on licence grounds. No upstream source is copied at this revision; that is an engineering choice about which units are worth porting, NOT a licence prohibition.",
			Rationale:                            "The destination is a separate GPL-3.0-only repository, so a GPL-3.0 source port is LICENCE-PERMITTED. An earlier revision of this assessment concluded otherwise by assuming the contracts had to be Apache-2.0 because the platform is; that inference was wrong and is withdrawn. The three options were therefore compared on engineering merit. (a) FOCUSED PORT of StakeManager/ValidatorShare: licence-permitted, and it would carry real deployed-bytecode provenance, but the units are solc 0.5.17 built around auctions, a validator NFT, delegation vouchers, Heimdall fee tokens and checkpoint state-sync -- none of which the self-bond profile uses -- and their storage layout is entangled with those features. Porting means deleting most of the contract and keeping its storage assumptions, which forfeits the provenance that made the port attractive. (b) SELECTIVE REUSE OF COMPATIBLE PRIMITIVES: the vendored contracts/common/oz tree is small and well understood; taking those primitives is cheap and low-risk, and remains available under both destination licences. (c) INDEPENDENT IMPLEMENTATION of the four behaviours the profile actually needs (delayed unbond, reward-per-weight accumulator, cap/bounty/remainder split, CEI claim pattern): each is small, and each must be rewritten anyway against the D4/D5 certified lifecycle, which upstream does not have. (c) is chosen for the staking logic and (b) remains available for primitives. (a) is not excluded; it is rejected for THESE units on the surface/toolchain grounds above, and a later unit with a better surface match could revisit it.",
			Vendored:                             false,
			LicenceConstraint:                    "Both pinned sources are GPL-3.0-only at the repository level, and both package.json files declare \"license\": \"MIT\" (verified at each pin). That conflict is recorded and NOT resolved here: it does not establish MIT permission, and it equally means a repository-level label is not a per-file provenance analysis. The successor StakeManager.sol carries no SPDX header at all. Before any file is copied, per-file notices and the licences of every imported dependency must be recorded, and the owner must confirm the destination boundary in Destination.Boundary. A GPL-3.0-only destination can absorb GPL-3.0 and permissive sources; an Apache-2.0 destination could not absorb the GPL ones -- which is why the destination is declared as data rather than assumed.",
			UpstreamTestSuiteIsNotASecurityAudit: true,
			CompilerModernizationIsNotAnAudit:    true,
			SecurityAuditOwner:                   "roadmap X-series -- X2 (pre-TGE audit and remediation) and X4 / X5 (PoS shadow audit and integrated activation gate). Not upstream Polygon review, and not a green local test run. The Go validator in this package is SCHEMA validation of this assessment's own consistency: it checks that required fields are present, well-formed and mutually consistent. It establishes nothing about licence correctness, upstream provenance or accounting completeness.",
		},
	}
}
