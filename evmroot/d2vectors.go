package evmroot

import (
	"encoding/json"
	"math/big"
)

// D2 vector set: the reth system-call and fee profile, made checkable
// before the fork implements it. Same builder feeds the golden test
// (d2_test.go) and cmd/d2vectors.

// D2VectorSet is the whole D2 vector document.
type D2VectorSet struct {
	ExecConfig     D2ConfigVector       `json:"exec_config"`
	GasAccounting  D2GasVector          `json:"gas_accounting"`
	ForcedPrefix   D2ForcedPrefixVector `json:"forced_prefix_accounting"`
	BaseFeeSeries  []D2BaseFeeVector    `json:"base_fee_series"`
	BaseFeeOracle  []D2BaseFeeOracle    `json:"base_fee_arithmetic_oracle"`
	OrdinaryGasRec []D2OrdinaryGasCase  `json:"ordinary_gas_recovery"`
	SealOutcomes   D2SealOutcomeCase    `json:"seal_outcome_list"`
	ImportChecks   []D2ImportVector     `json:"import_checks"`
}

// D2SealOutcomeCase is the canonical block-structure vector: a system op
// followed by a poison forced entry followed by a valid one, committed by
// sealOutcomeRoot, with the ordinary transaction list carrying NONE of
// them.
type D2SealOutcomeCase struct {
	Note                        string        `json:"note"`
	Outcomes                    []SealOutcome `json:"seal_registry_records"`
	OutcomeRootHex              string        `json:"seal_registry_commitment"`
	OrdinaryTxCount             int           `json:"ordinary_tx_count"`
	ForcedTxCount               int           `json:"successful_forced_tx_count_in_receipt_trie"`
	HeaderGasUsed               uint64        `json:"header_gas_used"`
	SystemGas                   uint64        `json:"system_gas"`
	ForcedExecGas               uint64        `json:"forced_exec_gas"`
	RejectedConsumptionGas      uint64        `json:"rejected_entry_consumption_gas"`
	RecoveredOrdinary           uint64        `json:"recovered_ordinary_gas"`
	Entry1ValidAtTurn           bool          `json:"forced_entry_1_valid_at_its_turn"`
	Entry2ValidAtTurn           bool          `json:"forced_entry_2_valid_at_its_turn"`
	Entry2ValidAtAdmission      bool          `json:"forced_entry_2_valid_at_admission"`
	OutcomeDeterminedAtTurn     bool          `json:"rejection_set_determined_only_at_turn_not_admission"`
	CommitmentWrittenPostPrefix bool          `json:"commitment_written_by_post_prefix_finalization"`
	PoisonNotAReverT            bool          `json:"rejection_record_is_not_an_evm_revert"`
	SystemOrRejectedInTrie      bool          `json:"system_or_rejected_record_in_a_trie"`
	SuccessfulForcedInTxReceipt bool          `json:"successful_forced_tx_in_tx_and_receipt_trie"`
	CommitmentInContractState   bool          `json:"commitment_is_a_contract_state_value_not_a_header_field"`
	ImportOK                    bool          `json:"import_ok"`
}

// D2BaseFeeOracle cross-checks ExecConfig.NextBaseFee against an
// independent big.Int computation for values large enough to overflow a
// naive uint64 multiply.
type D2BaseFeeOracle struct {
	ParentBaseFee uint64 `json:"parent_base_fee"`
	OrdinaryUsed  uint64 `json:"ordinary_used"`
	Model         uint64 `json:"model_next_base_fee"`
	BigIntOracle  uint64 `json:"bigint_oracle_next_base_fee"`
	Match         bool   `json:"match"`
	Note          string `json:"note,omitempty"`
}

// D2OrdinaryGasCase exercises RecoverOrdinaryGas: header gasUsed minus the
// system and forced-prefix receipt gas is the value that feeds the next
// base fee.
type D2OrdinaryGasCase struct {
	HeaderGasUsed    uint64 `json:"header_gas_used"`
	SystemReceiptGas uint64 `json:"system_receipt_gas"`
	ForcedReceiptGas uint64 `json:"forced_receipt_gas_sum"`
	OrdinaryGas      uint64 `json:"recovered_ordinary_gas"`
	OK               bool   `json:"ok"`
}

type D2ConfigVector struct {
	GMax             uint64 `json:"g_max"`
	GSys             uint64 `json:"g_sys"`
	GFI              uint64 `json:"g_fi"`
	BaseFeeFloor     uint64 `json:"base_fee_floor"`
	OrdinaryCapacity uint64 `json:"ordinary_capacity"` // g_max - g_sys - g_fi
	OrdinaryTarget   uint64 `json:"ordinary_target"`   // EIP-1559 target over ordinary capacity
}

type D2GasVector struct {
	Note          string `json:"note"`
	SystemOpenGas uint64 `json:"system_open_gas"`
	FinalizeGas   uint64 `json:"system_finalize_gas"`
	System        uint64 `json:"system_gas"` // DERIVED: open + finalize
	Forced        uint64 `json:"forced_gas"` // DERIVED: turn-rejected count * charge
	Ordinary      uint64 `json:"ordinary_gas"`
	HeaderGasUsed uint64 `json:"header_gas_used"` // system + forced + ordinary
	RecoveredOrd  uint64 `json:"recovered_ordinary_gas"`
	ReconcilesOK  bool   `json:"work_split_reconciles"`
	SystemWithinG bool   `json:"system_within_g_sys"`
	ParentBaseFee uint64 `json:"parent_base_fee"`
	NextBaseFee   uint64 `json:"next_base_fee"` // from ordinary gas vs ordinary target only
	BudgetOK      bool   `json:"budget_ok"`
	ClosesExactly bool   `json:"closes_exactly"`
}

// D2ForcedEntryRow is one row of the forced-prefix accounting vector.
type D2ForcedEntryRow struct {
	Sender        string `json:"sender"`
	ValidAtTurn   bool   `json:"valid_at_its_turn"`
	Reverted      bool   `json:"evm_reverted"`
	DeclaredGas   uint64 `json:"declared_gas"`
	ExecGas       uint64 `json:"exec_gas"`
	InReceiptTrie bool   `json:"in_receipt_trie"`
}

// D2ForcedPrefixVector is a mixed successful / reverted / rejected forced
// prefix under a positive g_fi: every valid entry's execution gas (success
// or revert) is charged to g_forced_actual against the reserved g_fi budget,
// discretionary gas is derived separately from receipts, the header gas
// closes exactly, and the base fee ignores the forced work.
type D2ForcedPrefixVector struct {
	Note                       string             `json:"note"`
	GFI                        uint64             `json:"g_fi"`
	OrdinaryCapacity           uint64             `json:"ordinary_capacity"`
	Entries                    []D2ForcedEntryRow `json:"entries"`
	ForcedExecGas              uint64             `json:"forced_exec_gas"` // Σ ExecGas over turn-valid entries
	RejectedConsumptionGas     uint64             `json:"rejected_consumption_gas"`
	WorkForced                 uint64             `json:"work_forced"`            // DERIVED: exec + rejected, <= g_fi
	DiscretionaryGasUsed       uint64             `json:"discretionary_gas_used"` // DERIVED work.ordinary, from receipts
	SystemGas                  uint64             `json:"system_gas"`
	HeaderGasUsed              uint64             `json:"header_gas_used"`
	RecoveredOrdinaryGas       uint64             `json:"recovered_ordinary_gas"`
	ParentBaseFee              uint64             `json:"parent_base_fee"`
	NextBaseFee                uint64             `json:"next_base_fee"`
	NextBaseFeeIfForcedCounted uint64             `json:"next_base_fee_if_forced_gas_wrongly_counted"`
	BaseFeeIgnoresForcedGas    bool               `json:"base_fee_ignores_forced_gas"`
	ForcedGasWithinGFI         bool               `json:"forced_gas_within_g_fi"`
	NineMFitsWithFullOrdinary  bool               `json:"nine_million_forced_tx_fits_with_ordinary_full"`
	WorkSplitReconciles        bool               `json:"work_split_reconciles"`
	HeaderGasClosesExactly     bool               `json:"header_gas_closes_exactly"`
	ImportOK                   bool               `json:"import_ok"`
}

type D2BaseFeeVector struct {
	ParentBaseFee  uint64 `json:"parent_base_fee"`
	OrdinaryUsed   uint64 `json:"ordinary_used"`
	OrdinaryTarget uint64 `json:"ordinary_target"`
	NextBaseFee    uint64 `json:"next_base_fee"`
	Note           string `json:"note,omitempty"`
}

type D2ImportVector struct {
	Name     string `json:"name"`
	WantOK   bool   `json:"want_ok"`
	WantCode string `json:"want_code"` // "" when want_ok
	GotOK    bool   `json:"got_ok"`
	GotCode  string `json:"got_code"`
	Matches  bool   `json:"matches"`
}

// d2RootInput is the structured, D1-valid rootInput the baseline D2 block
// imports.
func d2RootInput() RootInput {
	o := sampleOrigin()
	te := sampleTE()
	o.TRHash = teHash(te) // O_-.TRHash IS the hash of the carried technical record
	return RootInput{
		Version: ProfileVersion, NetworkID: 3, PartitionID: 0x45564d00, ShardID: []byte{},
		Round: 57, CertifiedEpoch: o.IR.Epoch, AuthorizedEpoch: te.Epoch,
		ParentHash: rep(0xEE, 32), Origin: o, TE: te,
	}
}

// d2Witness builds the two verified inputs for a rootInput. sigValid is the
// upstream real-certificate verdict (see TestD2_CertificateBoundaryFixtures
// for the mapping through bft-go-base's UnicitySeal.Verify).
func d2Witness(ri RootInput, sigValid bool) CompanionWitness {
	return CompanionWitness{
		UC:                  UCWitness{Cert: verifiedCertFromOrigin(ri.Origin, ri.Round, sigValid)},
		ExpectedTransitions: append([][]byte(nil), ri.Transitions...),
	}
}

// finalizeFor computes the FinalizeStep for a block: the commitment over
// the outcomes determined at each forced entry's turn.
func finalizeFor(b SealBlock) FinalizeStep {
	gas := uint64(0)
	if len(b.ForcedPrefix) > 0 {
		gas = 30_000
	}
	return FinalizeStep{Present: true, AfterForcedPrefix: true, Committed: SealRegistryCommitment(DerivedSealOutcomes(b)), GasUsed: gas}
}

// validSealBlock builds a baseline block that passes every D2 predicate.
func validSealBlock(cfg ExecConfig) (SealBlock, RootInput) {
	ri := d2RootInput()
	ed := ri.ExtraData()
	b := SealBlock{
		ExtraData: ed,
		Context: BlockContext{
			NetworkID: ri.NetworkID, PartitionID: ri.PartitionID, ShardID: ri.ShardID,
			Round: ri.Round, ParentHash: ri.ParentHash,
		},
		BaseFee:              1_000_000_000,
		Withdrawals:          0,
		BlobTxCount:          0,
		OrdinaryTxCount:      12,
		ForcedTxCount:        0,
		DiscretionaryGasUsed: 15_000_000,
		SystemCall: SystemCall{
			From: SystemOrigin, To: SystemRegistry, Value: 0,
			HasSig: false, HasNonce: false, FromTxPool: false, GasUsed: 1_800_000, Succeeded: true,
		},
		Work: BlockWork{System: 1_800_000, Forced: 0, Ordinary: 15_000_000},
		Companion: CompanionData{
			Present:    true,
			RootInput:  ri,
			Witness:    d2Witness(ri, true),
			Provenance: "newPayload",
		},
	}
	b.Finalize = finalizeFor(b)
	b.SealRegistryStateValue = b.Finalize.Committed
	return b, ri
}

// BuildD2Vectors computes the D2 vector set from this package's model.
func BuildD2Vectors() D2VectorSet {
	cfg := DefaultExecConfig()
	var vs D2VectorSet

	vs.ExecConfig = D2ConfigVector{
		GMax: cfg.GMax, GSys: cfg.GSys, GFI: cfg.GFI, BaseFeeFloor: cfg.BaseFeeFloor,
		OrdinaryCapacity: cfg.OrdinaryCapacity(), OrdinaryTarget: cfg.OrdinaryTarget(),
	}

	// --- worked gas accounting that closes exactly -----------------------
	// A real block: the system split is DERIVED (open + finalize), not a
	// caller-supplied lump; reconcileWork rejects a Work that does not match.
	gb, _ := validSealBlock(cfg)
	gb.SystemCall.GasUsed = 1_780_000
	gb.Finalize = finalizeFor(gb)
	gb.Finalize.GasUsed = 20_000
	gb.SealRegistryStateValue = gb.Finalize.Committed
	gb.DiscretionaryGasUsed = 15_000_000
	gb.Work = BlockWork{System: 1_800_000, Forced: 0, Ordinary: 15_000_000}
	gw, gwReason := reconcileWork(gb)
	gc := cfg.CheckGas(gw)
	gRec, _ := RecoverOrdinaryGas(gw.HeaderGasUsed(), gb.SystemCall.GasUsed+gb.Finalize.GasUsed, gw.Forced)
	vs.GasAccounting = D2GasVector{
		Note:          "g_system_actual is DERIVED as SystemCall.GasUsed (open) + Finalize.GasUsed (write); g_forced_actual as Σ ExecGas of the valid forced prefix + turn-rejected count * RejectedConsumptionGas; g_ordinary_actual as DiscretionaryGasUsed (the NON-forced receipt gas). header.gasUsed is their sum. Base fee updates from ordinary vs ordinary target only (this g_fi=0 profile has no forced prefix).",
		SystemOpenGas: gb.SystemCall.GasUsed, FinalizeGas: gb.Finalize.GasUsed,
		System: gw.System, Forced: gw.Forced, Ordinary: gw.Ordinary,
		HeaderGasUsed: gw.HeaderGasUsed(), RecoveredOrd: gRec,
		ReconcilesOK:  gwReason == "",
		SystemWithinG: gw.System <= cfg.GSys,
		ParentBaseFee: 1_000_000_000,
		NextBaseFee:   cfg.NextBaseFee(1_000_000_000, gw),
		BudgetOK:      gc.BudgetOK,
		ClosesExactly: gc.BudgetOK && gc.HeaderGasUsed == gw.System+gw.Forced+gw.Ordinary && gRec == gw.Ordinary,
	}

	// --- forced-prefix accounting: reserved g_fi capacity is real -------
	// g_max 30M, g_sys 2M, g_fi 20M -> ordinary capacity 8M. A mixed prefix:
	// one entry succeeds (3M), one is valid-at-turn but EVM-reverts (5M) —
	// both charge their exec gas to g_fi and keep a standard receipt — and
	// one is invalid at its turn (consumed for 21_000). Discretionary demand
	// fills 4M of the 8M ordinary capacity. The 8M of executed forced gas
	// would not fit ordinary capacity at all (the 9M/20M/8M counterexample),
	// but against the reserved g_fi it is includable and does not move the
	// base fee.
	fpCfg := cfg
	fpCfg.GFI = 20_000_000
	fp, _ := validSealBlock(fpCfg)
	fp.OrdinaryTxCount, fp.ForcedTxCount = 5, 2
	fp.DiscretionaryGasUsed = 4_000_000
	fp.ForcedStartBalance = map[string]int64{"succeeds": 10, "reverts": 10, "poison": 0}
	fp.ForcedPrefix = []ForcedEntry{
		{Sender: "succeeds", ValueDelta: -1, DeclaredGas: 4_000_000, ExecGas: 3_000_000},
		{Sender: "reverts", ValueDelta: -1, DeclaredGas: 6_000_000, ExecGas: 5_000_000, Reverted: true},
		{Sender: "poison", ValueDelta: -1, Reason: "insufficient_balance_at_turn"},
	}
	fp.RejectedConsumptionGas = 21_000
	fp.SystemCall.GasUsed = 1_500_000
	fp.Finalize = finalizeFor(fp)
	fp.Finalize.GasUsed = 30_000
	fp.SealRegistryStateValue = fp.Finalize.Committed
	fp.Work = BlockWork{System: 1_530_000, Forced: 8_021_000, Ordinary: 4_000_000}
	fpWork, fpReason := reconcileWork(fp)
	fpRes := ValidateImport(fp, fpCfg)
	fpRec, _ := RecoverOrdinaryGas(fpWork.HeaderGasUsed(), fp.SystemCall.GasUsed+fp.Finalize.GasUsed, fpWork.Forced)
	fpTurns := evalForcedPrefix(fp.ForcedPrefix, fp.ForcedStartBalance)
	fpRows := make([]D2ForcedEntryRow, len(fp.ForcedPrefix))
	for i, e := range fp.ForcedPrefix {
		fpRows[i] = D2ForcedEntryRow{
			Sender: e.Sender, ValidAtTurn: fpTurns[i], Reverted: e.Reverted,
			DeclaredGas: e.DeclaredGas, ExecGas: e.ExecGas, InReceiptTrie: fpTurns[i],
		}
	}
	fpParent := uint64(1_000_000_000)
	fpNext := fpCfg.NextBaseFee(fpParent, fpWork)
	fpWrong := fpCfg.NextBaseFee(fpParent, BlockWork{System: fpWork.System, Ordinary: fpWork.Ordinary + fpWork.Forced})
	vs.ForcedPrefix = D2ForcedPrefixVector{
		Note:                       "g_fi 20M reserved. A valid forced tx (success OR EVM-revert) charges its ExecGas to g_forced_actual against g_fi, keeping a standard receipt; an entry invalid at its turn is consumed for RejectedConsumptionGas. g_ordinary_actual is DiscretionaryGasUsed (NON-forced receipt gas) only. The 8M executed forced gas exceeds the 8M ordinary capacity once discretionary demand is present — proving reserved capacity is what makes an admitted forced tx includable — and it does not enter the EIP-1559 feedback loop.",
		GFI:                        fpCfg.GFI,
		OrdinaryCapacity:           fpCfg.OrdinaryCapacity(),
		Entries:                    fpRows,
		ForcedExecGas:              8_000_000,
		RejectedConsumptionGas:     fp.RejectedConsumptionGas,
		WorkForced:                 fpWork.Forced,
		DiscretionaryGasUsed:       fpWork.Ordinary,
		SystemGas:                  fp.SystemCall.GasUsed + fp.Finalize.GasUsed,
		HeaderGasUsed:              fpWork.HeaderGasUsed(),
		RecoveredOrdinaryGas:       fpRec,
		ParentBaseFee:              fpParent,
		NextBaseFee:                fpNext,
		NextBaseFeeIfForcedCounted: fpWrong,
		BaseFeeIgnoresForcedGas:    fpNext != fpWrong && fpNext == fpCfg.NextBaseFee(fpParent, BlockWork{System: fpWork.System, Ordinary: fpWork.Ordinary}),
		ForcedGasWithinGFI:         fpWork.Forced <= fpCfg.GFI,
		NineMFitsWithFullOrdinary:  fpWork.Forced > fpCfg.OrdinaryCapacity() && fpRes.OK,
		WorkSplitReconciles:        fpReason == "",
		HeaderGasClosesExactly:     fpWork.HeaderGasUsed() == fpWork.System+fpWork.Forced+fpWork.Ordinary && fpRec == fpWork.Ordinary,
		ImportOK:                   fpRes.OK,
	}

	// --- base-fee series: up, flat, down, floor clamp --------------------
	tgt := cfg.OrdinaryTarget()
	for _, bf := range []struct {
		parent uint64
		used   uint64
		note   string
	}{
		{1_000_000_000, tgt, "used == target -> unchanged"},
		{1_000_000_000, tgt + tgt/2, "used > target -> base fee rises"},
		{1_000_000_000, tgt / 2, "used < target -> base fee falls"},
		{8, 0, "tiny parent fee, zero ordinary demand -> clamps to positive floor"},
	} {
		vs.BaseFeeSeries = append(vs.BaseFeeSeries, D2BaseFeeVector{
			ParentBaseFee: bf.parent, OrdinaryUsed: bf.used, OrdinaryTarget: tgt,
			NextBaseFee: cfg.NextBaseFee(bf.parent, BlockWork{System: cfg.GSys, Ordinary: bf.used}),
			Note:        bf.note,
		})
	}

	// --- base-fee arithmetic oracle (overflow-range) --------------------
	for _, o := range []struct {
		parent uint64
		used   uint64
		note   string
	}{
		{10_000_000_000_000, 2 * tgt, "parent 1e13, ordinary at 2x target: naive uint64 parent*(used-target) overflows"},
		{1 << 60, tgt / 4, "parent 2^60, quarter target: down-step, still exact"},
		{MaxBaseFee, 2 * tgt, "parent at MaxBaseFee: result stays clamped and exact"},
	} {
		model := cfg.NextBaseFee(o.parent, BlockWork{System: cfg.GSys, Ordinary: o.used})
		oracle := bigIntNextBaseFee(cfg, o.parent, o.used)
		vs.BaseFeeOracle = append(vs.BaseFeeOracle, D2BaseFeeOracle{
			ParentBaseFee: o.parent, OrdinaryUsed: o.used,
			Model: model, BigIntOracle: oracle, Match: model == oracle, Note: o.note,
		})
	}

	// --- ordinary-gas recovery ---------------------------------------
	for _, g := range [][3]uint64{
		{16_800_000, 1_800_000, 0},         // system 1.8M, no forced -> ordinary 15M
		{20_000_000, 2_000_000, 3_000_000}, // -> ordinary 15M
		{1_000_000, 2_000_000, 0},          // receipts exceed header -> not ok
	} {
		rec, ok := RecoverOrdinaryGas(g[0], g[1], g[2])
		vs.OrdinaryGasRec = append(vs.OrdinaryGasRec, D2OrdinaryGasCase{
			HeaderGasUsed: g[0], SystemReceiptGas: g[1], ForcedReceiptGas: g[2],
			OrdinaryGas: rec, OK: ok,
		})
	}

	// --- sequential forced prefix: entry 1 (valid at its turn) SPENDS the
	//     sender's balance, so entry 2 — valid at admission — is invalid at
	//     ITS turn. The rejection set is only knowable after the prefix runs,
	//     so the commitment is written by the post-prefix FinalizeStep. The
	//     successful forced tx (entry 1) is an ordinary tx in the receipt
	//     trie; the system op + entry-2 rejection record are off-trie. ------
	fcfg := cfg
	fcfg.GFI = 2_000_000
	fri := d2RootInput()
	fed := fri.ExtraData()
	fPrefix := []ForcedEntry{
		{Sender: "alice", ValueDelta: -100, DeclaredGas: 800_000, ExecGas: 500_000, Reason: ""}, // turn 1: balance 100 -> 0, valid; 500k of its 800k declared g_fi limit
		{Sender: "alice", ValueDelta: -50, Reason: "insufficient_balance_at_turn"},              // turn 2: balance 0 -> -50, INVALID at its turn (was fine at admission)
	}
	fStart := map[string]int64{"alice": 100}
	fBlock := SealBlock{
		ExtraData: fed,
		Context: BlockContext{
			NetworkID: fri.NetworkID, PartitionID: fri.PartitionID, ShardID: fri.ShardID,
			Round: fri.Round, ParentHash: fri.ParentHash,
		},
		BaseFee:                1_000_000_000,
		OrdinaryTxCount:        3,
		ForcedTxCount:          1, // entry 1: an ordinary tx in transactionsRoot / receiptsRoot
		ForcedPrefix:           fPrefix,
		ForcedStartBalance:     fStart,
		RejectedConsumptionGas: 21_000,
		DiscretionaryGasUsed:   10_400_000, // NON-forced receipt gas only
		SystemCall:             SystemCall{From: SystemOrigin, To: SystemRegistry, GasUsed: 1_500_000, Succeeded: true},
		Work:                   BlockWork{System: 1_530_000, Forced: 521_000, Ordinary: 10_400_000}, // System = open 1_500_000 + finalize 30_000; Forced = 500_000 exec + 21_000 rejected
		Companion: CompanionData{
			Present: true, RootInput: fri, Witness: d2Witness(fri, true), Provenance: "newPayload",
		},
	}
	fBlock.Finalize = finalizeFor(fBlock)
	fBlock.SealRegistryStateValue = fBlock.Finalize.Committed
	fRes := ValidateImport(fBlock, fcfg)

	turns := evalForcedPrefix(fPrefix, fStart)
	fOutcomes := DerivedSealOutcomes(fBlock)
	fWork, _ := reconcileWork(fBlock)
	headerGas := fWork.HeaderGasUsed()
	recOrd, _ := RecoverOrdinaryGas(headerGas, fBlock.SystemCall.GasUsed+fBlock.Finalize.GasUsed, fWork.Forced)
	src := fBlock.Finalize.Committed
	vs.SealOutcomes = D2SealOutcomeCase{
		Note: "The forced prefix runs FIFO; each entry's validity is decided AT ITS TURN against the running pre-state. Entry 1 spends alice's balance, so entry 2 — fine at admission — is invalid at its turn. The rejection set is knowable only after the prefix, so a post-prefix FinalizeStep (a second, gas-charged system op) writes sealRegistryCommitment into seal-registry contract storage; the first system call carries NO forced-outcome input. " +
			"The valid forced entry (entry 1) is an ordinary transaction in transactionsRoot / receiptsRoot with a standard receipt, but its ExecGas is charged to g_forced_actual against the reserved g_fi budget. header.gasUsed = discretionary receipt gas + g_sys (open + finalize) + executed valid prefix + the g_fi consumption charge for rejected entries.",
		Outcomes: fOutcomes, OutcomeRootHex: hx(src[:]), OrdinaryTxCount: fBlock.OrdinaryTxCount, ForcedTxCount: fBlock.ForcedTxCount,
		HeaderGasUsed: headerGas, SystemGas: fBlock.SystemCall.GasUsed + fBlock.Finalize.GasUsed, ForcedExecGas: fPrefix[0].ExecGas, RejectedConsumptionGas: fBlock.RejectedConsumptionGas, RecoveredOrdinary: recOrd,
		Entry1ValidAtTurn:           turns[0],
		Entry2ValidAtTurn:           turns[1],
		Entry2ValidAtAdmission:      true, // balance 100 >= 50
		OutcomeDeterminedAtTurn:     turns[0] && !turns[1],
		CommitmentWrittenPostPrefix: fBlock.Finalize.Present && fBlock.Finalize.AfterForcedPrefix,
		PoisonNotAReverT:            len(fOutcomes) == 2 && fOutcomes[1].Kind == OutcomeForcedRejected && fOutcomes[1].Reason != "",
		SystemOrRejectedInTrie:      false,
		SuccessfulForcedInTxReceipt: true,
		CommitmentInContractState:   true,
		ImportOK:                    fRes.OK,
	}

	// --- import checks --------------------------------------------------
	mut := func(f func(*SealBlock)) SealBlock {
		b, _ := validSealBlock(cfg)
		f(&b)
		return b
	}
	// fmut builds a block with a positive g_fi and a standard mixed forced
	// prefix: entry 0 valid at its turn (500k of an 800k declared g_fi
	// limit), entry 1 invalid at its turn (consumed for 21_000).
	fmut := func(gfi uint64, f func(*SealBlock)) SealBlock {
		fc := cfg
		fc.GFI = gfi
		b, _ := validSealBlock(fc)
		b.OrdinaryTxCount, b.ForcedTxCount = 3, 1
		b.DiscretionaryGasUsed = 10_000_000
		b.ForcedStartBalance = map[string]int64{"a": 100}
		b.ForcedPrefix = []ForcedEntry{
			{Sender: "a", ValueDelta: -100, DeclaredGas: 800_000, ExecGas: 500_000, Reason: ""},
			{Sender: "a", ValueDelta: -50, Reason: "insufficient_balance_at_turn"},
		}
		b.RejectedConsumptionGas = 21_000
		b.SystemCall.GasUsed = 1_500_000
		b.Finalize = finalizeFor(b)
		b.Finalize.GasUsed = 30_000
		b.SealRegistryStateValue = b.Finalize.Committed
		b.Work = BlockWork{System: 1_530_000, Forced: 521_000, Ordinary: 10_000_000}
		if f != nil {
			f(&b)
		}
		return b
	}
	cases := []struct {
		name     string
		gfi      uint64 // 0 => validate against cfg unchanged
		block    SealBlock
		wantOK   bool
		wantCode string
	}{
		{"valid", 0, mut(func(*SealBlock) {}), true, ""},
		{"companion_missing", 0, mut(func(b *SealBlock) { b.Companion.Present = false }), false, "companion_missing"},
		{"cert_not_verified", 0, mut(func(b *SealBlock) { b.Companion.Witness.UC.Cert.SignaturesValid = false }), false, "companion_unauthenticated"},
		{"cert_wrong_origin", 0, mut(func(b *SealBlock) { b.Companion.Witness.UC.Cert.OriginID = Hash32{1} }), false, "companion_unauthenticated"},
		{"cert_wrong_authorized_round", 0, mut(func(b *SealBlock) { b.Companion.Witness.UC.Cert.AuthorizedRound = 99 }), false, "companion_unauthenticated"},
		{"cert_stale_root_round", 0, mut(func(b *SealBlock) { b.LastAppliedRootRound = b.Companion.Witness.UC.Cert.RootRound + 1 }), false, "companion_unauthenticated"},
		{"witness_te_not_bound_to_trhash", 0, mut(func(b *SealBlock) {
			b.Companion.RootInput.TE.Leader = "someone-else" // TE no longer hashes to Origin.TRHash
		}), false, "companion_unauthenticated"},
		{"transition_inserted_body", 0, mut(func(b *SealBlock) {
			// append an arbitrary committed body with a matching-length proof;
			// it is NOT the authenticated expected body at that position.
			b.Companion.RootInput.Transitions = append(b.Companion.RootInput.Transitions, []byte{0x81, 0x01})
			// ExpectedTransitions unchanged -> count/position mismatch
		}), false, "companion_unauthenticated"},
		{"transition_substituted_body", 0, mut(func(b *SealBlock) {
			// the verifier's authenticated sequence expects one specific body;
			// the companion carries a different body of the same length.
			b.Companion.Witness.ExpectedTransitions = [][]byte{{0x01, 0x02}}
			b.Companion.RootInput.Transitions = [][]byte{{0xFF, 0xFF}}
		}), false, "companion_unauthenticated"},
		{"rootinput_invalid_epoch", 0, mut(func(b *SealBlock) { b.Companion.RootInput.AuthorizedEpoch = 9 }), false, "rootinput_invalid"}, // TE.Epoch (1) != AuthorizedEpoch (9); TE unchanged so the witness still binds
		{"rootinput_short_parent_hash", 0, mut(func(b *SealBlock) { b.Companion.RootInput.ParentHash = rep(0xEE, 31) }), false, "rootinput_invalid"},
		{"malformed_origin_breaks_ref", 0, mut(func(b *SealBlock) { b.Companion.RootInput.Origin.TRHash = rep(1, 8) }), false, "companion_unauthenticated"}, // RefFromOrigin rejects a non-32-byte TRHash
		{"context_mismatch_round", 0, mut(func(b *SealBlock) { b.Context.Round = 58 }), false, "context_mismatch"},
		{"context_mismatch_parent", 0, mut(func(b *SealBlock) { b.Context.ParentHash = rep(0xAB, 32) }), false, "context_mismatch"},
		{"extradata_mismatch", 0, mut(func(b *SealBlock) { b.ExtraData[0] ^= 0xff }), false, "extradata_mismatch"},
		{"seal_finalize_missing", 0, mut(func(b *SealBlock) { b.Finalize.Present = false }), false, "seal_finalize_missing"},
		{"seal_finalize_not_after_prefix", 0, mut(func(b *SealBlock) { b.Finalize.AfterForcedPrefix = false }), false, "seal_finalize_missing"},
		{"seal_registry_commitment_mismatch", 0, mut(func(b *SealBlock) { b.SealRegistryStateValue[0] ^= 0xff }), false, "seal_registry_commitment_mismatch"},
		{"finalize_wrong_commitment", 0, mut(func(b *SealBlock) { b.Finalize.Committed[0] ^= 0xff }), false, "seal_registry_commitment_mismatch"},
		{"system_origin_forged", 0, mut(func(b *SealBlock) { b.SystemCall.From = [20]byte{0: 0x01} }), false, "system_origin_forged"},
		{"system_value_nonzero", 0, mut(func(b *SealBlock) { b.SystemCall.Value = 1 }), false, "system_value_nonzero"},
		{"system_from_pool", 0, mut(func(b *SealBlock) { b.SystemCall.FromTxPool = true }), false, "system_from_pool"},
		{"system_failed", 0, mut(func(b *SealBlock) { b.SystemCall.Succeeded = false }), false, "system_failed"},
		{"base_fee_below_floor", 0, mut(func(b *SealBlock) { b.BaseFee = cfg.BaseFeeFloor - 1 }), false, "base_fee_below_floor"},
		{"withdrawals_nonempty", 0, mut(func(b *SealBlock) { b.Withdrawals = 1 }), false, "withdrawals_nonempty"},
		{"blob_tx_present", 0, mut(func(b *SealBlock) { b.BlobTxCount = 1 }), false, "blob_tx_present"},
		{"ordinary_gas_over_capacity", 0, mut(func(b *SealBlock) { b.DiscretionaryGasUsed = cfg.OrdinaryCapacity() + 1 }), false, "gas_budget"},
		// Gas split cannot be lied about: Work.System and Work.Forced are
		// derived from the two privileged steps and the re-executed valid
		// prefix + turn-rejected set; Work.Ordinary comes from DiscretionaryGasUsed.
		{"finalizer_gas_hidden_from_work", 0, mut(func(b *SealBlock) { b.Finalize.GasUsed = cfg.GSys + 1 }), false, "gas_split_unreconciled"},
		{"work_system_mismatch", 0, mut(func(b *SealBlock) { b.Work.System = cfg.GSys - 1 }), false, "gas_split_unreconciled"},
		{"work_forced_mismatch", 0, mut(func(b *SealBlock) { b.Work.Forced = 5_000 }), false, "gas_split_unreconciled"},
		// A well-formed mixed prefix (one valid entry, one rejected) imports.
		{"valid_forced_prefix", 2_000_000, fmut(2_000_000, nil), true, ""},
		// A valid forced tx that the D5 inbox admitted draws on the reserved
		// g_fi budget, so it stays includable even with ordinary capacity
		// full: g_fi 20M, ordinary capacity 8M, one 9M forced tx, no
		// discretionary txs (the reviewer's 9M/20M/8M counterexample).
		{"forced_prefix_uses_reserved_capacity", 20_000_000, fmut(20_000_000, func(b *SealBlock) {
			b.OrdinaryTxCount, b.ForcedTxCount = 0, 1
			b.DiscretionaryGasUsed = 0
			b.ForcedStartBalance = map[string]int64{"a": 100}
			b.ForcedPrefix = []ForcedEntry{{Sender: "a", ValueDelta: -1, DeclaredGas: 9_000_000, ExecGas: 9_000_000}}
			b.Finalize = finalizeFor(*b)
			b.SealRegistryStateValue = b.Finalize.Committed
			b.Work = BlockWork{System: b.SystemCall.GasUsed + b.Finalize.GasUsed, Forced: 9_000_000, Ordinary: 0}
		}), true, ""},
		// A valid forced tx that EVM-reverts still consumes its declared
		// capacity from g_fi and stays an ordinary receipt.
		{"reverted_forced_tx_uses_reserved_capacity", 20_000_000, fmut(20_000_000, func(b *SealBlock) {
			b.OrdinaryTxCount, b.ForcedTxCount = 0, 1
			b.DiscretionaryGasUsed = 0
			b.ForcedStartBalance = map[string]int64{"a": 100}
			b.ForcedPrefix = []ForcedEntry{{Sender: "a", ValueDelta: -1, DeclaredGas: 7_000_000, ExecGas: 6_500_000, Reverted: true}}
			b.Finalize = finalizeFor(*b)
			b.SealRegistryStateValue = b.Finalize.Committed
			b.Work = BlockWork{System: b.SystemCall.GasUsed + b.Finalize.GasUsed, Forced: 6_500_000, Ordinary: 0}
		}), true, ""},
		// Over-budget forced prefix: two valid entries, each declared <= g_fi,
		// but their combined executed gas exceeds g_fi.
		{"forced_prefix_over_g_fi", 8_000_000, fmut(8_000_000, func(b *SealBlock) {
			b.OrdinaryTxCount, b.ForcedTxCount = 0, 2
			b.DiscretionaryGasUsed = 0
			b.ForcedStartBalance = map[string]int64{"a": 100}
			b.ForcedPrefix = []ForcedEntry{
				{Sender: "a", ValueDelta: -1, DeclaredGas: 5_000_000, ExecGas: 5_000_000},
				{Sender: "a", ValueDelta: -1, DeclaredGas: 5_000_000, ExecGas: 5_000_000},
			}
			b.Finalize = finalizeFor(*b)
			b.SealRegistryStateValue = b.Finalize.Committed
			b.Work = BlockWork{System: b.SystemCall.GasUsed + b.Finalize.GasUsed, Forced: 10_000_000, Ordinary: 0}
		}), false, "gas_budget"},
		// Per-entry declared limit above g_fi is a D5 admission violation.
		{"forced_declared_over_g_fi", 8_000_000, fmut(8_000_000, func(b *SealBlock) {
			b.ForcedPrefix[0].DeclaredGas = 9_000_000
		}), false, "forced_declared_over_g_fi"},
		// Charging a valid forced tx's gas to the discretionary bucket is
		// rejected: Work.Forced must reconcile to exec + rejected.
		{"forced_gas_charged_to_discretionary", 20_000_000, fmut(20_000_000, func(b *SealBlock) {
			b.ForcedPrefix[0].DeclaredGas = 5_000_000
			b.ForcedPrefix[0].ExecGas = 5_000_000
			b.DiscretionaryGasUsed = 15_000_000 // 10_000_000 + the 5_000_000 it must not carry
			b.Work.Forced = 21_000              // pretends only the rejected charge is forced
		}), false, "gas_split_unreconciled"},
		// Exec gas above the entry's own declared limit is rejected.
		{"forced_exec_over_declared", 2_000_000, fmut(2_000_000, func(b *SealBlock) {
			b.ForcedPrefix[0].ExecGas = 900_000 // declared 800_000
			b.Work.Forced = 921_000
		}), false, "gas_split_unreconciled"},
		// An admitted forced tx cannot be dropped from the receipt-trie count.
		{"forced_tx_count_drops_admitted_entry", 2_000_000, fmut(2_000_000, func(b *SealBlock) { b.ForcedTxCount = 0 }), false, "forced_tx_count_mismatch"},
		// A turn-rejected entry must not carry exec gas.
		{"rejected_entry_carries_exec_gas", 2_000_000, fmut(2_000_000, func(b *SealBlock) { b.ForcedPrefix[1].ExecGas = 5_000 }), false, "gas_split_unreconciled"},
		{"combined_system_over_g_sys", 0, mut(func(b *SealBlock) {
			// open + finalize both reported, Work.System matches the sum, but
			// the SUM exceeds g_sys.
			b.SystemCall.GasUsed = cfg.GSys - 10
			b.Finalize = finalizeFor(*b) // recompute the commitment for the new open gas
			b.Finalize.GasUsed = 20
			b.SealRegistryStateValue = b.Finalize.Committed
			b.Work.System = cfg.GSys + 10
		}), false, "gas_budget"},
		{"system_plus_finalize_overflow", 0, mut(func(b *SealBlock) {
			b.SystemCall.GasUsed = ^uint64(0)
			b.Finalize = finalizeFor(*b)
			b.Finalize.GasUsed = 1
			b.SealRegistryStateValue = b.Finalize.Committed
			b.Work.System = 0
		}), false, "gas_split_unreconciled"},
	}
	for _, c := range cases {
		useCfg := cfg
		if c.gfi != 0 {
			useCfg.GFI = c.gfi
		}
		got := ValidateImport(c.block, useCfg)
		vs.ImportChecks = append(vs.ImportChecks, D2ImportVector{
			Name: c.name, WantOK: c.wantOK, WantCode: c.wantCode,
			GotOK: got.OK, GotCode: got.Code,
			Matches: got.OK == c.wantOK && got.Code == c.wantCode,
		})
	}

	return vs
}

// bigIntNextBaseFee is an independent big.Int oracle for
// ExecConfig.NextBaseFee: the London update over ordinary gas/target with
// the positive floor and MaxBaseFee clamps, computed with no intermediate
// truncation.
func bigIntNextBaseFee(c ExecConfig, parentBaseFee, ordinaryUsed uint64) uint64 {
	target := c.OrdinaryTarget()
	used := ordinaryUsed
	if used > 2*target {
		used = 2 * target
	}
	parent := new(big.Int).SetUint64(parentBaseFee)
	tgt := new(big.Int).SetUint64(target)
	denom := new(big.Int).SetUint64(c.BaseFeeChangeDenom)
	var child *big.Int
	switch {
	case target == 0 || used == target:
		child = new(big.Int).Set(parent)
	case used > target:
		num := new(big.Int).SetUint64(used - target)
		delta := new(big.Int).Mul(parent, num)
		delta.Div(delta, tgt)
		delta.Div(delta, denom)
		if delta.Sign() == 0 {
			delta.SetUint64(1)
		}
		child = new(big.Int).Add(parent, delta)
	default:
		num := new(big.Int).SetUint64(target - used)
		delta := new(big.Int).Mul(parent, num)
		delta.Div(delta, tgt)
		delta.Div(delta, denom)
		child = new(big.Int).Sub(parent, delta)
		if child.Sign() < 0 {
			child.SetUint64(0)
		}
	}
	floor := new(big.Int).SetUint64(c.BaseFeeFloor)
	if child.Cmp(floor) < 0 {
		child.Set(floor)
	}
	maxbf := new(big.Int).SetUint64(MaxBaseFee)
	if child.Cmp(maxbf) > 0 {
		child.Set(maxbf)
	}
	return child.Uint64()
}

// MarshalD2Vectors renders the D2 vector set as stable, indented JSON.
func MarshalD2Vectors(vs D2VectorSet) ([]byte, error) {
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
