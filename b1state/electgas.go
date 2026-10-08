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
	// Floors of the measurement script's domain.
	ElectMinIdentities = 5
	ElectMinCommittee  = 4
)

var (
	// ErrElectMeasurement reports a measurement that cannot be a worst-case election of a profile.
	ErrElectMeasurement = errors.New("b1state: invalid election measurement")
	// ErrElectGas reports a pinned ElectGas that is not derived from, or is below, the measurement.
	ErrElectGas = errors.New("b1state: the election price does not cover the measured worst case")
)

// ElectCaps are the deployed contracts' ceilings the measurement is taken at: the manifest's limits.vMax (live index), limits.lMax (lots
// per identity) and the election profile's nMax (committee). The measurement is the worst case only if it is taken at exactly these
// caps: a smaller one prices a chain whose registrations can grow past it (every threshold block would then be invalid), a larger one
// prices something the deployment cannot reach. The genesis tooling sets the manifest to the profile's values and the check refuses any
// difference, in either direction.
type ElectCaps struct {
	VMax uint32 `json:"vMax"`
	LMax uint32 `json:"lMax"`
	NMax uint32 `json:"nMax"`
}

// Valid checks the caps are within the profile ceilings the measurement script accepts.
func (c ElectCaps) Valid() error {
	if (ElectMeasurement{V: c.VMax, L: c.LMax, C: c.NMax, Gas: 1}).Valid() != nil {
		return ErrElectMeasurement
	}
	return nil
}

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
	// The domain of unicity-pos-contracts script/measure-elect.sh: V >= 5, C >= 4, L a power of two up to 8.
	if m.V < ElectMinIdentities || m.V > ElectMaxIdentities || (m.L != 1 && m.L != 2 && m.L != 4 && m.L != 8) ||
		m.C < ElectMinCommittee || m.C > ElectMaxCommittee || m.C > m.V || m.Gas == 0 {
		return ErrElectMeasurement
	}
	return nil
}

// AtCaps reports whether the measurement was taken at exactly the deployment's caps.
func (m ElectMeasurement) AtCaps(c ElectCaps) bool {
	return m.V == c.VMax && m.L == c.LMax && m.C == c.NMax
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

// CheckElectGas is the genesis check: the profile carries the election hook; the recorded measurement is valid, was taken at exactly the
// deployment's caps, and the price is exactly the one it pins; and the price still covers a fresh measurement of the same worst case.
// A fresh measurement of a smaller (V, L, C) proves nothing about the deployed contracts, so it is refused, not accepted.
func CheckElectGas(p Profile, caps ElectCaps, recorded, fresh ElectMeasurement) error {
	if !p.ElectionEnabled() {
		return ErrElectGas
	}
	if err := caps.Valid(); err != nil {
		return err
	}
	pinned, err := ElectGasFor(recorded)
	if err != nil {
		return err
	}
	if !recorded.AtCaps(caps) {
		return errors.Join(ErrElectGas, errors.New("the recorded measurement is not at the deployed caps (vMax, lMax, nMax)"))
	}
	if p.ElectGas != pinned {
		return errors.Join(ErrElectGas, errors.New("the price is not the recorded measurement pinned with the margin"))
	}
	if err := fresh.Valid(); err != nil {
		return err
	}
	if !fresh.AtCaps(caps) {
		return errors.Join(ErrElectGas, errors.New("the fresh measurement is not at the deployed caps"))
	}
	if p.ElectGas < fresh.Gas {
		return errors.Join(ErrElectGas, errors.New("the pinned price is below a fresh measurement"))
	}
	return nil
}
