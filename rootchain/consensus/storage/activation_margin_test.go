package storage

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// The margin between a record and the activation round it must still commit before is one named number, used by the Prepare floor and by
// the leader's Commit adjustment. It used to be the literal 8 in both places (audit note on handoff_operator.go), so editing one would have
// silently broken the assumption that a Freeze ordered at the end of the lapse window still commits before the activation the Prepare chose.
func TestTheActivationMarginIsOneNumberForThePrepareFloorAndTheCommitAdjustment(t *testing.T) {
	require.EqualValues(t, PrepareFreezeLapseRounds+HandoffActivationMarginRounds, PrepareActivationFloorRounds)

	t.Run("a nearer activation is moved out to the margin", func(t *testing.T) {
		got, ok := CommitActivationRound(5, 100)
		require.True(t, ok)
		require.EqualValues(t, 100+HandoffActivationMarginRounds, got)
		got, ok = CommitActivationRound(100+HandoffActivationMarginRounds-1, 100)
		require.True(t, ok)
		require.EqualValues(t, 100+HandoffActivationMarginRounds, got, "one round short of the margin is still moved")
	})
	t.Run("an activation that already leaves the margin is kept", func(t *testing.T) {
		got, ok := CommitActivationRound(100+HandoffActivationMarginRounds, 100)
		require.True(t, ok)
		require.EqualValues(t, 100+HandoffActivationMarginRounds, got)
		got, ok = CommitActivationRound(1000, 100)
		require.True(t, ok)
		require.EqualValues(t, 1000, got)
	})
	t.Run("the Prepare floor and the Commit adjustment agree at the end of the lapse window", func(t *testing.T) {
		const prepared = 1000
		activation := uint64(prepared + PrepareActivationFloorRounds) // the nearest activation a Prepare may ask for
		lastFreeze := uint64(prepared + PrepareFreezeLapseRounds)     // a Freeze ordered as late as the window allows
		got, ok := CommitActivationRound(activation, lastFreeze)
		require.True(t, ok)
		require.Equal(t, activation, got, "the floor already leaves the margin after the last Freeze, so the Commit does not move it")
		got, ok = CommitActivationRound(activation, lastFreeze+1)
		require.True(t, ok)
		require.Equal(t, activation+1, got, "one round later it would, by exactly the margin")
	})
	t.Run("the margin cannot overflow the round", func(t *testing.T) {
		_, ok := CommitActivationRound(0, math.MaxUint64)
		require.False(t, ok)
		_, ok = CommitActivationRound(0, math.MaxUint64-HandoffActivationMarginRounds+1)
		require.False(t, ok)
		got, ok := CommitActivationRound(0, math.MaxUint64-HandoffActivationMarginRounds)
		require.True(t, ok)
		require.EqualValues(t, uint64(math.MaxUint64), got)
	})
}
