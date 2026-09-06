package evmroot

import (
	"bytes"
	"os"
	"testing"
)

func TestD2_GasBudgetInvariant(t *testing.T) {
	cfg := DefaultExecConfig()
	// g_sys + g_fi + ordinary_capacity == g_max, exactly.
	if cfg.GSys+cfg.GFI+cfg.OrdinaryCapacity() != cfg.GMax {
		t.Fatalf("budget split does not close: %d + %d + %d != %d",
			cfg.GSys, cfg.GFI, cfg.OrdinaryCapacity(), cfg.GMax)
	}
}

func TestD2_HeaderGasUsedIsTheSum(t *testing.T) {
	w := BlockWork{System: 1_800_000, Forced: 500_000, Ordinary: 12_000_000}
	if w.HeaderGasUsed() != 14_300_000 {
		t.Fatalf("HeaderGasUsed = %d, want 14300000", w.HeaderGasUsed())
	}
}

func TestD2_BaseFeeUpdateExcludesSystemAndForcedGas(t *testing.T) {
	cfg := DefaultExecConfig()
	tgt := cfg.OrdinaryTarget()
	// Two blocks with identical ordinary gas (== target) but very
	// different system/forced gas must yield the same next base fee:
	// system and forced gas are outside the feedback loop.
	a := cfg.NextBaseFee(1_000_000_000, BlockWork{System: 100_000, Forced: 0, Ordinary: tgt})
	b := cfg.NextBaseFee(1_000_000_000, BlockWork{System: cfg.GSys, Forced: 0, Ordinary: tgt})
	if a != b || a != 1_000_000_000 {
		t.Fatalf("base fee depends on system/forced gas: a=%d b=%d", a, b)
	}
}

func TestD2_BaseFeeClampsToPositiveFloor(t *testing.T) {
	cfg := DefaultExecConfig()
	got := cfg.NextBaseFee(8, BlockWork{System: cfg.GSys, Ordinary: 0})
	if got < cfg.BaseFeeFloor {
		t.Fatalf("base fee %d dropped below floor %d", got, cfg.BaseFeeFloor)
	}
}

func TestD2_BaseFeeRisesWhenOrdinaryDemandExceedsTarget(t *testing.T) {
	cfg := DefaultExecConfig()
	tgt := cfg.OrdinaryTarget()
	got := cfg.NextBaseFee(1_000_000_000, BlockWork{System: cfg.GSys, Ordinary: tgt + tgt/2})
	if got <= 1_000_000_000 {
		t.Fatalf("base fee did not rise on over-target ordinary demand: %d", got)
	}
}

func TestD2_ImportValidation(t *testing.T) {
	for _, v := range BuildD2Vectors().ImportChecks {
		if !v.Matches {
			t.Errorf("%s: got (ok=%v code=%q), want (ok=%v code=%q)", v.Name, v.GotOK, v.GotCode, v.WantOK, v.WantCode)
		}
	}
}

func TestD2_SystemCallMustBeFirstAndValid(t *testing.T) {
	cfg := DefaultExecConfig()
	b, _ := validSealBlock(cfg)
	if r := ValidateImport(b, cfg); !r.OK {
		t.Fatalf("baseline block rejected: %s (%s)", r.Code, r.Reason)
	}
	// A forged ordinary sender for the privileged op is rejected before
	// the payload's own execution result is considered.
	b.SystemCall.From = [20]byte{0: 0x01}
	if r := ValidateImport(b, cfg); r.OK || r.Code != "system_origin_forged" {
		t.Fatalf("forged system sender not rejected as expected: %+v", r)
	}
}

func TestD2_MissingCompanionDataIsFatal(t *testing.T) {
	cfg := DefaultExecConfig()
	b, _ := validSealBlock(cfg)
	b.Companion.Present = false
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_missing" {
		t.Fatalf("a block whose payload executes but has no companion data must be rejected: %+v", r)
	}
}

func TestD2_UnauthenticatedOrInvalidRootInputRejected(t *testing.T) {
	cfg := DefaultExecConfig()

	// Present but not authenticated.
	b, _ := validSealBlock(cfg)
	b.Companion.Authenticated = false
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("unauthenticated companion accepted: %+v", r)
	}

	// Authenticated but the decoded rootInput is structurally invalid.
	b, _ = validSealBlock(cfg)
	b.Companion.RootInput.AuthorizedEpoch = 9 // 2 epochs from certified -> invalid boundary
	b.Companion.RootInput.TE.Epoch = 9
	if r := ValidateImport(b, cfg); r.OK || r.Code != "rootinput_invalid" {
		t.Fatalf("structurally invalid rootInput accepted: %+v", r)
	}

	// A syntactically fine rootInput for a DIFFERENT block, spliced in with
	// the original header context: rejected on context, and even past that
	// the extraData would not match.
	b, _ = validSealBlock(cfg)
	other := d2RootInput()
	other.Round, other.TE.Round, other.Origin.IR.Round = 99, 99, 99
	b.Companion.RootInput = other
	if r := ValidateImport(b, cfg); r.OK {
		t.Fatal("a rootInput for a different block was accepted")
	}
}

func TestD2_NextBaseFeeNoOverflow(t *testing.T) {
	cfg := DefaultExecConfig()
	// The reviewer's case: parent 1e13, ordinary at 2x target -> +parent/8.
	tgt := cfg.OrdinaryTarget()
	got := cfg.NextBaseFee(10_000_000_000_000, BlockWork{System: cfg.GSys, Ordinary: 2 * tgt})
	if got != 11_250_000_000_000 {
		t.Fatalf("NextBaseFee overflowed or is wrong: got %d, want 11250000000000", got)
	}
	// Cross-check the whole oracle table.
	for _, o := range BuildD2Vectors().BaseFeeOracle {
		if !o.Match {
			t.Errorf("base-fee oracle mismatch: parent=%d used=%d model=%d oracle=%d",
				o.ParentBaseFee, o.OrdinaryUsed, o.Model, o.BigIntOracle)
		}
	}
}

func TestD2_ConfigValidation(t *testing.T) {
	if err := DefaultExecConfig().Valid(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	for _, bad := range []ExecConfig{
		{GMax: 30_000_000, GSys: 2_000_000, BaseFeeFloor: 7, ElasticityDenom: 0, BaseFeeChangeDenom: 8},
		{GMax: 30_000_000, GSys: 2_000_000, BaseFeeFloor: 7, ElasticityDenom: 2, BaseFeeChangeDenom: 0},
		{GMax: 30_000_000, GSys: 2_000_000, BaseFeeFloor: 0, ElasticityDenom: 2, BaseFeeChangeDenom: 8},
		{GMax: 30_000_000, GSys: 30_000_000, BaseFeeFloor: 7, ElasticityDenom: 2, BaseFeeChangeDenom: 8},
	} {
		if bad.Valid() == nil {
			t.Errorf("invalid config accepted: %+v", bad)
		}
		if r := ValidateImport(SealBlock{}, bad); r.OK || r.Code != "bad_config" {
			t.Errorf("ValidateImport did not reject bad config: %+v", r)
		}
	}
}

func TestD2_RecoverOrdinaryGas(t *testing.T) {
	if g, ok := RecoverOrdinaryGas(20_000_000, 2_000_000, 3_000_000); !ok || g != 15_000_000 {
		t.Fatalf("recovered %d, ok=%v; want 15000000,true", g, ok)
	}
	if _, ok := RecoverOrdinaryGas(1_000_000, 2_000_000, 0); ok {
		t.Fatal("receipts exceeding the header total were accepted")
	}
}

func TestD2_VectorsMatchGolden(t *testing.T) {
	const path = "testdata/d2-vectors.json"
	got, err := MarshalD2Vectors(BuildD2Vectors())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run: go run ./evmroot/cmd/d2vectors -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale — regenerate with: go run ./evmroot/cmd/d2vectors -update", path)
	}
}
