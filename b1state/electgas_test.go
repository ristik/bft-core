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
		"no identities":        {V: 0, L: 2, C: 8, Gas: 1},
		"V below the floor":    {V: ElectMinIdentities - 1, L: 2, C: 4, Gas: 1},
		"L not a power of two": {V: 16, L: 3, C: 8, Gas: 1},
		"C below the floor":    {V: 16, L: 2, C: ElectMinCommittee - 1, Gas: 1},
		"too many":             {V: ElectMaxIdentities + 1, L: 2, C: 8, Gas: 1},
		"no lots":              {V: 16, L: 0, C: 8, Gas: 1},
		"too many lots":        {V: 16, L: ElectMaxLots + 1, C: 8, Gas: 1},
		"no committee":         {V: 16, L: 2, C: 0, Gas: 1},
		"committee too big":    {V: 64, L: 2, C: ElectMaxCommittee + 1, Gas: 1},
		"committee above V":    {V: 8, L: 2, C: 9, Gas: 1},
		"no gas":               {V: 16, L: 2, C: 8, Gas: 0},
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

var devnetCaps = ElectCaps{VMax: 16, LMax: 2, NMax: 8}

func TestTheGenesisCheckRefusesAPriceBelowAFreshMeasurement(t *testing.T) {
	rec := ElectMeasurement{V: 16, L: 2, C: 8, Gas: 4_987_664}
	p := electProfile(t, rec)
	if err := CheckElectGas(p, devnetCaps, rec, rec); err != nil {
		t.Fatal("the measurement the price was pinned from passes", err)
	}
	// a fresh measurement within the margin passes (the contracts changed a little)
	if err := CheckElectGas(p, devnetCaps, rec, ElectMeasurement{V: 16, L: 2, C: 8, Gas: 5_500_000}); err != nil {
		t.Fatal("within the margin", err)
	}
	with := func(f func(*Profile)) Profile { x := p; f(&x); return x }
	for name, tc := range map[string]struct {
		profile Profile
		caps    ElectCaps
		rec     ElectMeasurement
		fresh   ElectMeasurement
	}{
		"fresh above the price":             {p, devnetCaps, rec, ElectMeasurement{V: 16, L: 2, C: 8, Gas: p.ElectGas + 1}},
		"a hand-typed price":                {with(func(x *Profile) { x.ElectGas++ }), devnetCaps, rec, rec},
		"a price below its own measurement": {with(func(x *Profile) { x.ElectGas = rec.Gas }), devnetCaps, rec, rec},
		"no election hook":                  {with(func(x *Profile) { x.ElectionContract, x.ElectGas = [20]byte{}, 0 }), devnetCaps, rec, rec},
		"invalid fresh":                     {p, devnetCaps, rec, ElectMeasurement{}},
		"invalid recorded":                  {p, devnetCaps, ElectMeasurement{}, rec},
		"invalid caps":                      {p, ElectCaps{}, rec, rec},
	} {
		if err := CheckElectGas(tc.profile, tc.caps, tc.rec, tc.fresh); err == nil {
			t.Fatal(name, "must be refused")
		}
	}
	if err := CheckElectGas(with(func(x *Profile) { x.ElectGas++ }), devnetCaps, rec, rec); !errors.Is(err, ErrElectGas) {
		t.Fatal("a price that is not the pinned measurement carries ErrElectGas", err)
	}
	if err := CheckElectGas(p, devnetCaps, rec, ElectMeasurement{V: 16, L: 2, C: 8, Gas: p.ElectGas + 1}); !errors.Is(err, ErrElectGas) {
		t.Fatal("below a fresh measurement carries ErrElectGas", err)
	}
}

// The measurement must be taken at exactly the deployed caps, in either direction, and a fresh measurement must be at the same caps: a
// smaller fresh run is cheaper than the worst case and would pass any price.
func TestTheMeasurementIsTiedToTheDeployedCapsInBothDirections(t *testing.T) {
	rec := ElectMeasurement{V: 16, L: 2, C: 8, Gas: 4_987_664}
	p := electProfile(t, rec)
	cheaper := func(v, l, c uint32) ElectMeasurement { return ElectMeasurement{V: v, L: l, C: c, Gas: 1} }
	for name, fresh := range map[string]ElectMeasurement{
		"fresh with a smaller V":         cheaper(8, 2, 8),
		"fresh with fewer lots":          cheaper(16, 1, 8),
		"fresh with a smaller committee": cheaper(16, 2, 4),
		"fresh with a larger V":          cheaper(32, 2, 8),
		"fresh with more lots":           cheaper(16, 4, 8),
		"fresh with a larger committee":  cheaper(16, 2, 10),
	} {
		err := CheckElectGas(p, devnetCaps, rec, fresh)
		if !errors.Is(err, ErrElectGas) || errors.Is(err, ErrElectMeasurement) {
			t.Fatal(name, "is refused for the caps, not as an invalid measurement:", err)
		}
	}
	for name, caps := range map[string]ElectCaps{
		"deployed V above the measured":         {VMax: 128, LMax: 2, NMax: 8},
		"deployed lots above the measured":      {VMax: 16, LMax: 8, NMax: 8},
		"deployed committee above measured":     {VMax: 16, LMax: 2, NMax: 16},
		"deployed V below the measured":         {VMax: 8, LMax: 2, NMax: 8},
		"deployed lots below the measured":      {VMax: 16, LMax: 1, NMax: 8},
		"deployed committee below the measured": {VMax: 16, LMax: 2, NMax: 4},
	} {
		err := CheckElectGas(p, caps, rec, rec)
		if !errors.Is(err, ErrElectGas) || errors.Is(err, ErrElectMeasurement) {
			t.Fatal(name, "is refused for the caps:", err)
		}
	}
}

func TestCapsAreWithinTheMeasurementDomain(t *testing.T) {
	if err := devnetCaps.Valid(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]ElectCaps{
		"V below the floor": {VMax: 4, LMax: 2, NMax: 4}, "L not a power of two": {VMax: 16, LMax: 3, NMax: 8},
		"committee below the floor": {VMax: 16, LMax: 2, NMax: 3}, "committee above V": {VMax: 8, LMax: 2, NMax: 9},
		"V above the ceiling": {VMax: 129, LMax: 2, NMax: 8}, "zero": {},
	} {
		if err := c.Valid(); !errors.Is(err, ErrElectMeasurement) {
			t.Fatal(name, err)
		}
	}
}
