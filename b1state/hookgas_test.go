package b1state

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func hookProfile(gas uint64) Profile {
	return Profile{RecordsCustody: [20]byte{0xc1}, HRecords: 2, HookRecordGas: gas}
}

// The reservation is the measured worst record plus a quarter, rounded up, at exactly the deployed caps.
func TestTheHookRecordGasMustCoverTheMeasuredWorstRecordWithTheMargin(t *testing.T) {
	caps := ElectCaps{VMax: 16, LMax: 2, NMax: 8}
	m := HookMeasurement{V: 16, L: 2, C: 8, Gas: 3_629_888, Kind: "recovery"}
	min, err := MinHookRecordGas(m)
	require.NoError(t, err)
	require.EqualValues(t, 4_537_360, min, "ceil(3,629,888 x 1.25)")
	require.NoError(t, CheckHookRecordGas(hookProfile(min), caps, m))
	require.ErrorIs(t, CheckHookRecordGas(hookProfile(min-1), caps, m), ErrHookGas)
	require.ErrorIs(t, CheckHookRecordGas(hookProfile(3_000_000), caps, m), ErrHookGas, "the reservation merged before the guard")

	require.ErrorIs(t, CheckHookRecordGas(hookProfile(min), ElectCaps{VMax: 16, LMax: 2, NMax: 7}, m), ErrHookGas, "not at the deployed caps")
	require.ErrorIs(t, CheckHookRecordGas(hookProfile(min), ElectCaps{VMax: 32, LMax: 2, NMax: 8}, m), ErrHookGas)
	require.ErrorIs(t, CheckHookRecordGas(Profile{HookRecordGas: min}, caps, m), ErrHookGas, "no records hook")
	for name, bad := range map[string]HookMeasurement{
		"no gas":           {V: 16, L: 2, C: 8, Kind: "recovery"},
		"no kind":          {V: 16, L: 2, C: 8, Gas: 1},
		"lots off domain":  {V: 16, L: 3, C: 8, Gas: 1, Kind: "recovery"},
		"committee > V":    {V: 16, L: 2, C: 32, Gas: 1, Kind: "recovery"},
		"committee floor":  {V: 16, L: 2, C: 3, Gas: 1, Kind: "recovery"},
		"identities floor": {V: 4, L: 2, C: 4, Gas: 1, Kind: "recovery"},
	} {
		_, err := MinHookRecordGas(bad)
		require.ErrorIs(t, err, ErrHookMeasurement, name)
	}
}

func TestCheckHookGasHoldsTheFreshMeasurementToTheSameRule(t *testing.T) {
	caps := ElectCaps{VMax: 16, LMax: 1, NMax: 6}
	recorded := HookMeasurement{V: 16, L: 1, C: 6, Gas: 2_281_165, Kind: "recovery"}
	p := hookProfile(3_000_000)
	require.NoError(t, CheckHookGas(p, caps, recorded, recorded))
	require.NoError(t, CheckHookGas(p, caps, recorded, HookMeasurement{V: 16, L: 1, C: 6, Gas: 2_400_000, Kind: "recovery"}), "exactly 3,000,000 with the margin")
	require.ErrorIs(t, CheckHookGas(p, caps, recorded, HookMeasurement{V: 16, L: 1, C: 6, Gas: 2_400_001, Kind: "recovery"}), ErrHookGas, "the contracts grew past the margin")
	require.ErrorIs(t, CheckHookGas(p, caps, recorded, HookMeasurement{V: 16, L: 2, C: 6, Gas: 1, Kind: "recovery"}), ErrHookGas, "a fresh measurement of other caps proves nothing")
	require.ErrorIs(t, CheckHookGas(p, caps, HookMeasurement{V: 16, L: 1, C: 6, Gas: 2_500_000, Kind: "recovery"}, recorded), ErrHookGas, "the recorded one is checked too")
}
