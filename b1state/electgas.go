package b1state

import (
	"errors"
	"math"
)

// The election hook's price is never a hand-typed constant. It is derived from a measurement of the worst-case election for the profile's
// chosen (V, L, C) (unicity-pos-contracts `script/measure-elect.sh V L C`), pinned with a fixed margin, recorded with its measurement in
// the genesis artifact, and checked again against a fresh measurement: a profile whose pinned ElectGas is below what the election now costs
// is refused. A price below the true cost would invalidate every threshold block, which the chain could never recover from, so there is no
// runtime truncation to fall back on.

const (
	// ElectMarginNumerator / ElectMarginDenominator are the margin over the measured worst case: 5/4, rounded up.
	ElectMarginNumerator   uint64 = 5
	ElectMarginDenominator uint64 = 4
	// Profile ceilings of the measurement (design v5 section 6: V_max 128, L_max 8, N_max 32).
	ElectMaxIdentities = 128
	ElectMaxLots       = 8
	ElectMaxCommittee  = 32
)

var (
	// ErrElectMeasurement reports a measurement that cannot be a worst-case election of a profile.
	ErrElectMeasurement = errors.New("b1state: invalid election measurement")
	// ErrElectGas reports a pinned ElectGas that is not derived from, or is below, the measurement.
	ErrElectGas = errors.New("b1state: the election price does not cover the measured worst case")
)

// ElectMeasurement is one measurement of the worst-case election: V identities of L lots each, a committed committee of C, every outsider
// ranked above the weakest incumbent. Gas is the gross gas of the one elect call.
type ElectMeasurement struct {
	V   uint32 `json:"v"`
	L   uint32 `json:"l"`
	C   uint32 `json:"c"`
	Gas uint64 `json:"gas"`
}

// Valid checks the measurement is within the profile ceilings.
func (m ElectMeasurement) Valid() error {
	if m.V == 0 || m.V > ElectMaxIdentities || m.L == 0 || m.L > ElectMaxLots || m.C == 0 || m.C > ElectMaxCommittee || m.C > m.V || m.Gas == 0 {
		return ErrElectMeasurement
	}
	return nil
}

// PinElectGas is the price pinned for a measured worst case: the measurement plus a quarter, rounded up.
func PinElectGas(measured uint64) (uint64, error) {
	if measured == 0 {
		return 0, ErrElectMeasurement
	}
	hi := measured / ElectMarginDenominator
	rem := measured % ElectMarginDenominator
	// measured*5/4 = measured + measured/4 (+1 when the quarter has a remainder)
	pinned := measured
	if hi > math.MaxUint64-pinned {
		return 0, ErrOverflow
	}
	pinned += hi
	if rem != 0 {
		if pinned == math.MaxUint64 {
			return 0, ErrOverflow
		}
		pinned++
	}
	return pinned, nil
}

// ElectGasFor is the price a measurement pins, after checking the measurement.
func ElectGasFor(m ElectMeasurement) (uint64, error) {
	if err := m.Valid(); err != nil {
		return 0, err
	}
	return PinElectGas(m.Gas)
}

// CheckElectGas is the genesis check: the profile carries the election hook, the recorded measurement is valid and the price is exactly the
// one it pins, and the price still covers a fresh measurement of the same (V, L, C) or a larger one is refused.
func CheckElectGas(p Profile, recorded, fresh ElectMeasurement) error {
	if !p.ElectionEnabled() {
		return ErrElectGas
	}
	pinned, err := ElectGasFor(recorded)
	if err != nil {
		return err
	}
	if p.ElectGas != pinned {
		return errors.Join(ErrElectGas, errors.New("the price is not the recorded measurement pinned with the margin"))
	}
	if err := fresh.Valid(); err != nil {
		return err
	}
	if fresh.V > recorded.V || fresh.L > recorded.L || fresh.C > recorded.C {
		return errors.Join(ErrElectGas, errors.New("the fresh measurement is of a larger profile than the recorded one"))
	}
	if p.ElectGas < fresh.Gas {
		return errors.Join(ErrElectGas, errors.New("the pinned price is below a fresh measurement"))
	}
	return nil
}
