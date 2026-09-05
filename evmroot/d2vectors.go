package evmroot

import (
	"crypto/sha256"
	"encoding/json"
)

// D2 vector set: the reth system-call and fee profile, made checkable
// before the fork implements it. Same builder feeds the golden test
// (d2_test.go) and cmd/d2vectors.

// D2VectorSet is the whole D2 vector document.
type D2VectorSet struct {
	ExecConfig    D2ConfigVector    `json:"exec_config"`
	GasAccounting D2GasVector       `json:"gas_accounting"`
	BaseFeeSeries []D2BaseFeeVector `json:"base_fee_series"`
	ImportChecks  []D2ImportVector  `json:"import_checks"`
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

// validSealBlock builds a baseline block that passes every D2 predicate,
// with a header extraData that actually commits its companion rootInput.
func validSealBlock(cfg ExecConfig) (SealBlock, []byte) {
	ri := RootInput{
		Version: ProfileVersion, NetworkID: 3, PartitionID: 0x45564d00, ShardID: []byte{},
		Round: 57, Epoch: 1, ParentHash: rep(0xEE, 32), Origin: sampleOrigin(), TE: sampleTE(),
	}
	riBytes := ri.Encode()
	return SealBlock{
		ExtraData:   sha256.Sum256(riBytes),
		BaseFee:     1_000_000_000,
		Withdrawals: 0,
		BlobTxCount: 0,
		SystemCall: SystemCall{
			From: SystemOrigin, To: SystemRegistry, Value: 0,
			HasSig: false, HasNonce: false, FromTxPool: false, Succeeded: true,
		},
		Work:      BlockWork{System: 1_800_000, Forced: 0, Ordinary: 15_000_000},
		Companion: CompanionData{Present: true, RootInput: riBytes, Witnesses: [][]byte{rep(0xC0, 40)}},
	}, riBytes
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
		{"companion_missing", mut(func(b *SealBlock) { b.Companion.Present = false; b.Companion.RootInput = nil }), false, "companion_missing"},
		{"extradata_mismatch", mut(func(b *SealBlock) { b.ExtraData[0] ^= 0xff }), false, "extradata_mismatch"},
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

// MarshalD2Vectors renders the D2 vector set as stable, indented JSON.
func MarshalD2Vectors(vs D2VectorSet) ([]byte, error) {
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
