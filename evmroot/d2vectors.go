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
	ExecConfig     D2ConfigVector      `json:"exec_config"`
	GasAccounting  D2GasVector         `json:"gas_accounting"`
	BaseFeeSeries  []D2BaseFeeVector   `json:"base_fee_series"`
	BaseFeeOracle  []D2BaseFeeOracle   `json:"base_fee_arithmetic_oracle"`
	OrdinaryGasRec []D2OrdinaryGasCase `json:"ordinary_gas_recovery"`
	SealOutcomes   D2SealOutcomeCase   `json:"seal_outcome_list"`
	ImportChecks   []D2ImportVector    `json:"import_checks"`
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
	System        uint64 `json:"system_gas"`
	Forced        uint64 `json:"forced_gas"`
	Ordinary      uint64 `json:"ordinary_gas"`
	HeaderGasUsed uint64 `json:"header_gas_used"` // system + forced + ordinary
	ParentBaseFee uint64 `json:"parent_base_fee"`
	NextBaseFee   uint64 `json:"next_base_fee"` // from ordinary gas vs ordinary target only
	BudgetOK      bool   `json:"budget_ok"`
	ClosesExactly bool   `json:"closes_exactly"` // header_gas_used == system+forced+ordinary and each within budget
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
		BaseFee:         1_000_000_000,
		Withdrawals:     0,
		BlobTxCount:     0,
		OrdinaryTxCount: 12,
		ForcedTxCount:   0,
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
	w := BlockWork{System: 1_800_000, Forced: 0, Ordinary: 15_000_000}
	gc := cfg.CheckGas(w)
	vs.GasAccounting = D2GasVector{
		Note:   "System runs under g_sys, ordinary under g_max-g_sys-g_fi; header gasUsed is the sum; base fee updates from ordinary vs ordinary target only.",
		System: w.System, Forced: w.Forced, Ordinary: w.Ordinary,
		HeaderGasUsed: w.HeaderGasUsed(),
		ParentBaseFee: 1_000_000_000,
		NextBaseFee:   cfg.NextBaseFee(1_000_000_000, w),
		BudgetOK:      gc.BudgetOK,
		ClosesExactly: gc.BudgetOK && gc.HeaderGasUsed == w.System+w.Forced+w.Ordinary,
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
		{Sender: "alice", ValueDelta: -100, Reason: ""},                            // turn 1: balance 100 -> 0, valid
		{Sender: "alice", ValueDelta: -50, Reason: "insufficient_balance_at_turn"}, // turn 2: balance 0 -> -50, INVALID at its turn (was fine at admission)
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
		SystemCall:             SystemCall{From: SystemOrigin, To: SystemRegistry, GasUsed: 1_500_000, Succeeded: true},
		Work:                   BlockWork{System: 1_530_000, Forced: 21_000, Ordinary: 10_400_000}, // System = open 1_500_000 + finalize 30_000
		Companion: CompanionData{
			Present: true, RootInput: fri, Witness: d2Witness(fri, true), Provenance: "newPayload",
		},
	}
	fBlock.Finalize = finalizeFor(fBlock)
	fBlock.SealRegistryStateValue = fBlock.Finalize.Committed
	fRes := ValidateImport(fBlock, fcfg)

	turns := evalForcedPrefix(fPrefix, fStart)
	fOutcomes := DerivedSealOutcomes(fBlock)
	headerGas := fBlock.Work.HeaderGasUsed()
	recOrd, _ := RecoverOrdinaryGas(headerGas, fBlock.SystemCall.GasUsed+fBlock.Finalize.GasUsed, fBlock.RejectedConsumptionGas)
	src := fBlock.Finalize.Committed
	vs.SealOutcomes = D2SealOutcomeCase{
		Note: "The forced prefix runs FIFO; each entry's validity is decided AT ITS TURN against the running pre-state. Entry 1 spends alice's balance, so entry 2 — fine at admission — is invalid at its turn. The rejection set is knowable only after the prefix, so a post-prefix FinalizeStep (a second, gas-charged system op) writes sealRegistryCommitment into seal-registry contract storage; the first system call carries NO forced-outcome input. " +
			"The successful forced entry (entry 1) is an ordinary transaction in transactionsRoot / receiptsRoot with a standard receipt. header.gasUsed = ordinary cumulative + g_sys (open + finalize) + the g_fi consumption charge for rejected entries.",
		Outcomes: fOutcomes, OutcomeRootHex: hx(src[:]), OrdinaryTxCount: fBlock.OrdinaryTxCount, ForcedTxCount: fBlock.ForcedTxCount,
		HeaderGasUsed: headerGas, SystemGas: fBlock.SystemCall.GasUsed + fBlock.Finalize.GasUsed, RejectedConsumptionGas: fBlock.RejectedConsumptionGas, RecoveredOrdinary: recOrd,
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
	cases := []struct {
		name     string
		block    SealBlock
		wantOK   bool
		wantCode string
	}{
		{"valid", mut(func(*SealBlock) {}), true, ""},
		{"companion_missing", mut(func(b *SealBlock) { b.Companion.Present = false }), false, "companion_missing"},
		{"cert_not_verified", mut(func(b *SealBlock) { b.Companion.Witness.UC.Cert.SignaturesValid = false }), false, "companion_unauthenticated"},
		{"cert_wrong_origin", mut(func(b *SealBlock) { b.Companion.Witness.UC.Cert.OriginID = Hash32{1} }), false, "companion_unauthenticated"},
		{"cert_wrong_authorized_round", mut(func(b *SealBlock) { b.Companion.Witness.UC.Cert.AuthorizedRound = 99 }), false, "companion_unauthenticated"},
		{"cert_stale_root_round", mut(func(b *SealBlock) { b.LastAppliedRootRound = b.Companion.Witness.UC.Cert.RootRound + 1 }), false, "companion_unauthenticated"},
		{"witness_te_not_bound_to_trhash", mut(func(b *SealBlock) {
			b.Companion.RootInput.TE.Leader = "someone-else" // TE no longer hashes to Origin.TRHash
		}), false, "companion_unauthenticated"},
		{"transition_inserted_body", mut(func(b *SealBlock) {
			// append an arbitrary committed body with a matching-length proof;
			// it is NOT the authenticated expected body at that position.
			b.Companion.RootInput.Transitions = append(b.Companion.RootInput.Transitions, []byte{0x81, 0x01})
			// ExpectedTransitions unchanged -> count/position mismatch
		}), false, "companion_unauthenticated"},
		{"transition_substituted_body", mut(func(b *SealBlock) {
			// the verifier's authenticated sequence expects one specific body;
			// the companion carries a different body of the same length.
			b.Companion.Witness.ExpectedTransitions = [][]byte{{0x01, 0x02}}
			b.Companion.RootInput.Transitions = [][]byte{{0xFF, 0xFF}}
		}), false, "companion_unauthenticated"},
		{"rootinput_invalid_epoch", mut(func(b *SealBlock) { b.Companion.RootInput.AuthorizedEpoch = 9 }), false, "rootinput_invalid"}, // TE.Epoch (1) != AuthorizedEpoch (9); TE unchanged so the witness still binds
		{"rootinput_short_parent_hash", mut(func(b *SealBlock) { b.Companion.RootInput.ParentHash = rep(0xEE, 31) }), false, "rootinput_invalid"},
		{"malformed_origin_breaks_ref", mut(func(b *SealBlock) { b.Companion.RootInput.Origin.TRHash = rep(1, 8) }), false, "companion_unauthenticated"}, // RefFromOrigin rejects a non-32-byte TRHash
		{"context_mismatch_round", mut(func(b *SealBlock) { b.Context.Round = 58 }), false, "context_mismatch"},
		{"context_mismatch_parent", mut(func(b *SealBlock) { b.Context.ParentHash = rep(0xAB, 32) }), false, "context_mismatch"},
		{"extradata_mismatch", mut(func(b *SealBlock) { b.ExtraData[0] ^= 0xff }), false, "extradata_mismatch"},
		{"seal_finalize_missing", mut(func(b *SealBlock) { b.Finalize.Present = false }), false, "seal_finalize_missing"},
		{"seal_finalize_not_after_prefix", mut(func(b *SealBlock) { b.Finalize.AfterForcedPrefix = false }), false, "seal_finalize_missing"},
		{"seal_registry_commitment_mismatch", mut(func(b *SealBlock) { b.SealRegistryStateValue[0] ^= 0xff }), false, "seal_registry_commitment_mismatch"},
		{"finalize_wrong_commitment", mut(func(b *SealBlock) { b.Finalize.Committed[0] ^= 0xff }), false, "seal_registry_commitment_mismatch"},
		{"system_origin_forged", mut(func(b *SealBlock) { b.SystemCall.From = [20]byte{0: 0x01} }), false, "system_origin_forged"},
		{"system_value_nonzero", mut(func(b *SealBlock) { b.SystemCall.Value = 1 }), false, "system_value_nonzero"},
		{"system_from_pool", mut(func(b *SealBlock) { b.SystemCall.FromTxPool = true }), false, "system_from_pool"},
		{"system_failed", mut(func(b *SealBlock) { b.SystemCall.Succeeded = false }), false, "system_failed"},
		{"base_fee_below_floor", mut(func(b *SealBlock) { b.BaseFee = cfg.BaseFeeFloor - 1 }), false, "base_fee_below_floor"},
		{"withdrawals_nonempty", mut(func(b *SealBlock) { b.Withdrawals = 1 }), false, "withdrawals_nonempty"},
		{"blob_tx_present", mut(func(b *SealBlock) { b.BlobTxCount = 1 }), false, "blob_tx_present"},
		{"system_gas_over_budget", mut(func(b *SealBlock) { b.Work.System = cfg.GSys + 1 }), false, "gas_budget"},
		{"ordinary_gas_over_capacity", mut(func(b *SealBlock) { b.Work.Ordinary = cfg.OrdinaryCapacity() + 1 }), false, "gas_budget"},
	}
	for _, c := range cases {
		got := ValidateImport(c.block, cfg)
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
