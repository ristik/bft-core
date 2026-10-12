package b1state

import "errors"

// The records hook's per-record reservation is not a hand-typed number either. The largest record the hook applies is the RecoveryAck that
// also applies a pending closure (it derives K, an exposure per incumbent member, and closes J): its cost grows with the committee (nMax members
// of lMax lots), so a reservation that covers a small committee does not cover the committee the caps admit, and a block whose hook cannot apply
// its record within the reservation is invalid (the shard halts: P85 contracts#32). The reservation is therefore checked against a COLD
// measurement of the worst committee the deployment's caps admit (unicity-pos-contracts `script/measure-hook-gas.sh V L C`), with the margin
// the election's price carries, at profile generation (`b1-profile --hook-measurement`) and again against a fresh measurement
// (`check-hook-gas`).

var (
	// ErrHookMeasurement reports a measurement that cannot be a worst-case record of a profile.
	ErrHookMeasurement = errors.New("b1state: invalid hook-gas measurement")
	// ErrHookGas reports a pinned HookRecordGas below the measured worst case with the margin.
	ErrHookGas = errors.New("b1state: the per-record hook gas does not cover the measured worst case")
)

// HookMeasurement is the largest COLD gas of one applied record (ack, the staging of J's closure, the closure of an Active J, the RecoveryAck
// with a pending closure) for the worst committee of the caps: V identities, committees of C members of L lots each. Kind names the record it is.
type HookMeasurement struct {
	V    uint32 `json:"v"`
	L    uint32 `json:"l"`
	C    uint32 `json:"c"`
	Gas  uint64 `json:"gas"`
	Kind string `json:"kind"`
}

// Valid checks the measurement is within the profile ceilings the measurement script accepts.
func (m HookMeasurement) Valid() error {
	if (ElectMeasurement{V: m.V, L: m.L, C: m.C, Gas: m.Gas}).Valid() != nil || m.Kind == "" {
		return ErrHookMeasurement
	}
	return nil
}

// AtCaps reports whether the measurement was taken at exactly the deployment's caps.
func (m HookMeasurement) AtCaps(c ElectCaps) bool {
	return ElectMeasurement{V: m.V, L: m.L, C: m.C}.AtCaps(c)
}

// MinHookRecordGas is the lowest per-record reservation a measurement admits: the measured worst case plus a quarter, rounded up (the
// election's margin).
func MinHookRecordGas(m HookMeasurement) (uint64, error) {
	if err := m.Valid(); err != nil {
		return 0, err
	}
	return PinElectGas(m.Gas)
}

// CheckHookRecordGas is the profile check: the measurement is valid and taken at exactly the deployed caps, and the profile's per-record
// reservation is at least the measured worst case with the margin.
func CheckHookRecordGas(p Profile, caps ElectCaps, m HookMeasurement) error {
	if !p.HookEnabled() {
		return ErrHookGas
	}
	if err := caps.Valid(); err != nil {
		return err
	}
	min, err := MinHookRecordGas(m)
	if err != nil {
		return err
	}
	if !m.AtCaps(caps) {
		return errors.Join(ErrHookGas, errors.New("the measurement is not at the deployed caps (vMax, lMax, nMax)"))
	}
	if p.HookRecordGas < min {
		return errors.Join(ErrHookGas, errors.New("the reservation is below the measured worst case with the margin"))
	}
	return nil
}

// CheckHookGas is the genesis re-check: the recorded measurement passes CheckHookRecordGas, and so does a fresh measurement of the same caps.
// A fresh measurement of other caps proves nothing about the deployed contracts and is refused.
func CheckHookGas(p Profile, caps ElectCaps, recorded, fresh HookMeasurement) error {
	if err := CheckHookRecordGas(p, caps, recorded); err != nil {
		return err
	}
	return CheckHookRecordGas(p, caps, fresh)
}
