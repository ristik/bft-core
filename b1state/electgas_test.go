package b1state

import (
	"errors"
	"math"
	"testing"
)

func TestElectGasIsTheMeasurementWithAQuarterRoundedUp(t *testing.T) {
	for _, tc := range []struct{ measured, want uint64 }{
		{4, 5}, {5, 7}, {8, 10}, {1, 2}, {4_987_664, 6_234_580}, {5_000_000, 6_250_000}, {46_180_946, 57_726_183},
	} {
		got, err := PinElectGas(tc.measured)
		if err != nil || got != tc.want {
			t.Fatalf("PinElectGas(%d) = %d, %v; want %d", tc.measured, got, err, tc.want)
		}
		if got < tc.measured+tc.measured/4 {
			t.Fatal("the margin is at least a quarter")
		}
	}
	if _, err := PinElectGas(0); !errors.Is(err, ErrElectMeasurement) {
		t.Fatal("zero is no measurement", err)
	}
	if _, err := PinElectGas(math.MaxUint64); !errors.Is(err, ErrOverflow) {
		t.Fatal("overflow is refused", err)
	}
	if _, err := PinElectGas(math.MaxUint64 - 1); !errors.Is(err, ErrOverflow) {
		t.Fatal("overflow is refused near the top", err)
	}
}

func TestAMeasurementIsWithinTheProfileCeilings(t *testing.T) {
	ok := ElectMeasurement{V: 16, L: 2, C: 8, Gas: 5_000_000}
	if err := ok.Valid(); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]ElectMeasurement{
		"no identities":     {V: 0, L: 2, C: 8, Gas: 1},
		"too many":          {V: ElectMaxIdentities + 1, L: 2, C: 8, Gas: 1},
		"no lots":           {V: 16, L: 0, C: 8, Gas: 1},
		"too many lots":     {V: 16, L: ElectMaxLots + 1, C: 8, Gas: 1},
		"no committee":      {V: 16, L: 2, C: 0, Gas: 1},
		"committee too big": {V: 64, L: 2, C: ElectMaxCommittee + 1, Gas: 1},
		"committee above V": {V: 8, L: 2, C: 9, Gas: 1},
		"no gas":            {V: 16, L: 2, C: 8, Gas: 0},
	} {
		if err := m.Valid(); !errors.Is(err, ErrElectMeasurement) {
			t.Fatal(name, err)
		}
	}
}

func electProfile(t *testing.T, m ElectMeasurement) Profile {
	t.Helper()
	p := fixtureProfile(2)
	p.RecordsCustody, p.HRecords, p.HookRecordGas = [20]byte{0xc1}, 3, 2_000_000
	p.ElectionContract = [20]byte{0xe1}
	var err error
	if p.ElectGas, err = ElectGasFor(m); err != nil {
		t.Fatal(err)
	}
	p.SystemGas, _ = p.RequiredSystemGas()
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTheGenesisCheckRefusesAPriceBelowAFreshMeasurement(t *testing.T) {
	rec := ElectMeasurement{V: 16, L: 2, C: 8, Gas: 4_987_664}
	p := electProfile(t, rec)
	if err := CheckElectGas(p, rec, rec); err != nil {
		t.Fatal("the measurement the price was pinned from passes", err)
	}
	// a fresh measurement within the margin passes (the contracts changed a little)
	if err := CheckElectGas(p, rec, ElectMeasurement{V: 16, L: 2, C: 8, Gas: 5_500_000}); err != nil {
		t.Fatal("within the margin", err)
	}
	for name, tc := range map[string]struct {
		profile Profile
		rec     ElectMeasurement
		fresh   ElectMeasurement
	}{
		"fresh above the price":             {p, rec, ElectMeasurement{V: 16, L: 2, C: 8, Gas: p.ElectGas + 1}},
		"a hand-typed price":                {func() Profile { x := p; x.ElectGas++; return x }(), rec, rec},
		"a price below its own measurement": {func() Profile { x := p; x.ElectGas = rec.Gas; return x }(), rec, rec},
		"fresh of a larger profile":         {p, rec, ElectMeasurement{V: 32, L: 2, C: 8, Gas: 1}},
		"fresh with more lots":              {p, rec, ElectMeasurement{V: 16, L: 4, C: 8, Gas: 1}},
		"fresh with a larger committee":     {p, rec, ElectMeasurement{V: 16, L: 2, C: 10, Gas: 1}},
		"invalid fresh":                     {p, rec, ElectMeasurement{}},
		"invalid recorded":                  {p, ElectMeasurement{}, rec},
		"no election hook":                  {func() Profile { x := p; x.ElectionContract, x.ElectGas = [20]byte{}, 0; return x }(), rec, rec},
	} {
		if err := CheckElectGas(tc.profile, tc.rec, tc.fresh); err == nil {
			t.Fatal(name, "must be refused")
		}
	}
	if err := CheckElectGas(func() Profile { x := p; x.ElectGas++; return x }(), rec, rec); !errors.Is(err, ErrElectGas) {
		t.Fatal("a price that is not the pinned measurement carries ErrElectGas", err)
	}
	if err := CheckElectGas(p, rec, ElectMeasurement{V: 16, L: 2, C: 8, Gas: p.ElectGas + 1}); !errors.Is(err, ErrElectGas) {
		t.Fatal("below a fresh measurement carries ErrElectGas", err)
	}
}
