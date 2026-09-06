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
	Note              string        `json:"note"`
	Outcomes          []SealOutcome `json:"outcomes"`
	OutcomeRootHex    string        `json:"seal_outcome_root"`
	OrdinaryTxCount   int           `json:"ordinary_tx_count"`
	HeaderGasUsed     uint64        `json:"header_gas_used"`
	SystemGas         uint64        `json:"system_gas"`
	ForcedGasSum      uint64        `json:"forced_gas_sum"`
	RecoveredOrdinary uint64        `json:"recovered_ordinary_gas"`
	PoisonNotAReverT  bool          `json:"poison_entry_is_a_rejection_record_not_an_evm_revert"`
	SystemInTxList    bool          `json:"system_or_forced_in_ordinary_tx_list"`
	ImportOK          bool          `json:"import_ok"`
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
	return RootInput{
		Version: ProfileVersion, NetworkID: 3, PartitionID: 0x45564d00, ShardID: []byte{},
		Round: 57, CertifiedEpoch: o.IR.Epoch, AuthorizedEpoch: sampleTE().Epoch,
		ParentHash: rep(0xEE, 32), Origin: o, TE: sampleTE(),
	}
}

// d2TrustBase is the importer's trust-base view: a 5-member unequal-weight
// assignment (10/6/5/2/1, W=24) and its recomputed quorum threshold (17).
func d2TrustBase() (SignerAssignment, uint64) {
	a := SignerAssignment{"root-a": 10, "root-b": 6, "root-c": 5, "root-d": 2, "root-e": 1}
	return a, a.RootQuorumThreshold()
}

// d2SealSigners is a signer subset whose weight clears the threshold.
func d2SealSigners() []string { return []string{"root-a", "root-b", "root-c"} } // 10+6+5 = 21 >= 17

// validSealBlock builds a baseline block that passes every D2 predicate.
func validSealBlock(cfg ExecConfig) (SealBlock, RootInput) {
	ri := d2RootInput()
	tb, thr := d2TrustBase()
	ed := ri.ExtraData()
	outcomes := []SealOutcome{
		{Kind: OutcomeSystem, GasUsed: 1_800_000, Status: 1, Digest: ed[:]},
	}
	return SealBlock{
		ExtraData: ed,
		Context: BlockContext{
			NetworkID: ri.NetworkID, PartitionID: ri.PartitionID, ShardID: ri.ShardID,
			Round: ri.Round, ParentHash: ri.ParentHash, SealOutcomeRoot: SealOutcomeRoot(outcomes),
		},
		BaseFee:         1_000_000_000,
		Withdrawals:     0,
		BlobTxCount:     0,
		OrdinaryTxCount: 12,
		SystemCall: SystemCall{
			From: SystemOrigin, To: SystemRegistry, Value: 0,
			HasSig: false, HasNonce: false, FromTxPool: false, Succeeded: true,
		},
		Work: BlockWork{System: 1_800_000, Forced: 0, Ordinary: 15_000_000},
		Companion: CompanionData{
			Present:   true,
			RootInput: ri,
			Witness: CompanionWitness{
				UC: UCWitness{OriginID: ri.Origin.Identity(), SealSigners: d2SealSigners()},
			},
			SealOutcomes: outcomes,
			Provenance:   "newPayload",
		},
		TrustBase:          tb,
		TrustBaseThreshold: thr,
	}, ri
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

	// --- seal-outcome list: system + poison + valid forced --------------
	fcfg := cfg
	fcfg.GFI = 2_000_000 // enable the forced inbox for this vector
	fri := d2RootInput()
	fed := fri.ExtraData()
	fOutcomes := []SealOutcome{
		{Kind: OutcomeSystem, GasUsed: 1_500_000, Status: 1, Digest: fed[:]},
		{Kind: OutcomeForcedRejected, GasUsed: 0, Status: 0, Reason: "nonce_already_used", Digest: rep(0xF0, 32)},
		{Kind: OutcomeForced, GasUsed: 400_000, Status: 1, Digest: rep(0xF1, 32)},
	}
	tb2, thr2 := d2TrustBase()
	fBlock := SealBlock{
		ExtraData: fed,
		Context: BlockContext{
			NetworkID: fri.NetworkID, PartitionID: fri.PartitionID, ShardID: fri.ShardID,
			Round: fri.Round, ParentHash: fri.ParentHash, SealOutcomeRoot: SealOutcomeRoot(fOutcomes),
		},
		BaseFee: 1_000_000_000, OrdinaryTxCount: 3,
		SystemCall: SystemCall{From: SystemOrigin, To: SystemRegistry, Succeeded: true},
		Work:       BlockWork{System: 1_500_000, Forced: 400_000, Ordinary: 10_000_000},
		Companion: CompanionData{
			Present: true, RootInput: fri,
			Witness:      CompanionWitness{UC: UCWitness{OriginID: fri.Origin.Identity(), SealSigners: d2SealSigners()}},
			SealOutcomes: fOutcomes, Provenance: "newPayload",
		},
		TrustBase: tb2, TrustBaseThreshold: thr2,
	}
	fRes := ValidateImport(fBlock, fcfg)
	headerGas := fBlock.Work.HeaderGasUsed()
	forcedSum := fOutcomes[1].GasUsed + fOutcomes[2].GasUsed
	recOrd, _ := RecoverOrdinaryGas(headerGas, fOutcomes[0].GasUsed, forcedSum)
	sor := SealOutcomeRoot(fOutcomes)
	vs.SealOutcomes = D2SealOutcomeCase{
		Note: "System op + forced entries live in the seal-outcome list committed by sealOutcomeRoot, NOT in the Ethereum transaction list. " +
			"A poison entry is a rejection record (Kind=forced_rejected, an authenticated reason), never an EVM revert. " +
			"transactionsRoot/receiptsRoot keep standard semantics over the ordinary txs only.",
		Outcomes: fOutcomes, OutcomeRootHex: hx(sor[:]), OrdinaryTxCount: fBlock.OrdinaryTxCount,
		HeaderGasUsed: headerGas, SystemGas: fOutcomes[0].GasUsed, ForcedGasSum: forcedSum, RecoveredOrdinary: recOrd,
		PoisonNotAReverT: fOutcomes[1].Kind == OutcomeForcedRejected && fOutcomes[1].Reason != "",
		SystemInTxList:   false, // by construction: the tx list count excludes them
		ImportOK:         fRes.OK,
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
		{"witness_wrong_origin", mut(func(b *SealBlock) { b.Companion.Witness.UC.OriginID = Hash32{1} }), false, "companion_unauthenticated"},
		{"witness_below_threshold", mut(func(b *SealBlock) { b.Companion.Witness.UC.SealSigners = []string{"root-d", "root-e"} }), false, "companion_unauthenticated"}, // 2+1 = 3 < 17
		{"witness_unknown_signer", mut(func(b *SealBlock) { b.Companion.Witness.UC.SealSigners = []string{"root-a", "ghost"} }), false, "companion_unauthenticated"},
		{"witness_transition_proof_count", mut(func(b *SealBlock) {
			b.Companion.RootInput.Transitions = [][]byte{rep(0xB0, 8)}
			// extraData + outcome root now stale, but the witness count check fires first
		}), false, "companion_unauthenticated"},
		{"rootinput_invalid_epoch", mut(func(b *SealBlock) { b.Companion.RootInput.AuthorizedEpoch = 9; b.Companion.RootInput.TE.Epoch = 9 }), false, "rootinput_invalid"},
		{"rootinput_short_parent_hash", mut(func(b *SealBlock) { b.Companion.RootInput.ParentHash = rep(0xEE, 31) }), false, "rootinput_invalid"},
		{"malformed_origin_breaks_witness", mut(func(b *SealBlock) { b.Companion.RootInput.Origin.TRHash = rep(1, 8) }), false, "companion_unauthenticated"}, // a malformed O_- cannot carry a matching witness
		{"context_mismatch_round", mut(func(b *SealBlock) { b.Context.Round = 58 }), false, "context_mismatch"},
		{"context_mismatch_parent", mut(func(b *SealBlock) { b.Context.ParentHash = rep(0xAB, 32) }), false, "context_mismatch"},
		{"extradata_mismatch", mut(func(b *SealBlock) { b.ExtraData[0] ^= 0xff }), false, "extradata_mismatch"},
		{"seal_outcomes_empty", mut(func(b *SealBlock) { b.Companion.SealOutcomes = nil }), false, "seal_outcomes_shape"},
		{"system_not_first_outcome", mut(func(b *SealBlock) {
			b.Companion.SealOutcomes = []SealOutcome{{Kind: OutcomeForced, GasUsed: 1, Status: 1}, {Kind: OutcomeSystem, GasUsed: 1_800_000, Status: 1}}
			b.Context.SealOutcomeRoot = SealOutcomeRoot(b.Companion.SealOutcomes)
		}), false, "seal_outcomes_shape"},
		{"seal_outcome_root_mismatch", mut(func(b *SealBlock) { b.Context.SealOutcomeRoot[0] ^= 0xff }), false, "seal_outcome_root_mismatch"},
		{"system_outcome_status_zero", mut(func(b *SealBlock) {
			b.Companion.SealOutcomes[0].Status = 0
			b.Context.SealOutcomeRoot = SealOutcomeRoot(b.Companion.SealOutcomes)
		}), false, "system_failed"},
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
