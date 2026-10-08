package trustbase

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLeaderPolicyIsAPropertyOfTheEpoch(t *testing.T) {
	s := threeEpochStore(t)
	// nothing is activated: every installed epoch is legacy, and nothing in production installs an activation
	for epoch := uint64(1); epoch <= 3; epoch++ {
		p, err := s.LeaderPolicy(epoch)
		require.NoError(t, err)
		require.Equal(t, LeaderPolicyLegacy, p)
	}
	require.NoError(t, s.ActivateLeaderPolicy(2, LeaderPolicyWeightedV1))
	p, err := s.LeaderPolicy(1)
	require.NoError(t, err)
	require.Equal(t, LeaderPolicyLegacy, p, "before the boundary")
	for _, epoch := range []uint64{2, 3} {
		p, err = s.LeaderPolicy(epoch)
		require.NoError(t, err)
		require.Equal(t, LeaderPolicyWeightedV1, p, "epoch %d", epoch)
	}
	// the activation record is idempotent
	require.NoError(t, s.ActivateLeaderPolicy(2, LeaderPolicyWeightedV1))
	// it is independent of the signing scheme history
	c, err := s.SigningConfig(2)
	require.NoError(t, err)
	require.EqualValues(t, 1, c.Scheme)
}

func TestLeaderPolicyRefusals(t *testing.T) {
	s := threeEpochStore(t)

	_, err := s.LeaderPolicy(9)
	require.ErrorIs(t, err, ErrLeaderPolicyHistory, "missing history is not an implicit legacy choice")
	require.ErrorIs(t, s.ActivateLeaderPolicy(9, LeaderPolicyWeightedV1), ErrLeaderPolicyHistory, "no trust base for the epoch")
	require.ErrorIs(t, s.ActivateLeaderPolicy(2, "root-wrr-v2"), ErrLeaderPolicyHistory, "unknown policy")
	require.ErrorIs(t, s.ActivateLeaderPolicy(2, LeaderPolicyLegacy), ErrLeaderPolicyHistory, "legacy is the absence of an activation")
	require.ErrorIs(t, s.ActivateLeaderPolicy(2, ""), ErrLeaderPolicyHistory)

	require.NoError(t, s.ActivateLeaderPolicy(3, LeaderPolicyWeightedV1))
	require.ErrorIs(t, s.ActivateLeaderPolicy(2, LeaderPolicyWeightedV1), ErrLeaderPolicyHistory, "the policy never goes back below a recorded activation")
	// the refusals recorded nothing
	p, err := s.LeaderPolicy(2)
	require.NoError(t, err)
	require.Equal(t, LeaderPolicyLegacy, p)
}

// a record cannot be replaced by a different one for the same epoch; the registry has a single activatable policy, so the
// conflict is exercised on the stored value directly
func TestLeaderPolicyConflictingRecordForTheSameEpochIsRefused(t *testing.T) {
	s := threeEpochStore(t)
	require.NoError(t, s.ActivateLeaderPolicy(2, LeaderPolicyWeightedV1))
	s.leaderPolicy.byEpoch[2] = "other"
	require.ErrorIs(t, s.ActivateLeaderPolicy(2, LeaderPolicyWeightedV1), ErrLeaderPolicyHistory)
}

// the latest activation at or below the epoch decides; the registry holds one activatable policy today, so the lookup is
// exercised with distinct stored values
func TestLeaderPolicyTakesTheLatestActivationAtOrBelowTheEpoch(t *testing.T) {
	s := threeEpochStore(t)
	s.leaderPolicy.byEpoch = map[uint64]string{1: "a", 3: "c", 2: "b"}
	for epoch, want := range map[uint64]string{1: "a", 2: "b", 3: "c"} {
		p, err := s.LeaderPolicy(epoch)
		require.NoError(t, err)
		require.Equal(t, want, p, "epoch %d", epoch)
	}
}

// A store bound to the verified history takes every epoch's leader policy from the same committed tuple as the signing
// configuration: the activation is the history's, not a call, and an epoch the history does not hold is an error.
func TestABoundStoreTakesTheLeaderPolicyFromTheHistory(t *testing.T) {
	s := threeEpochStore(t)
	require.NoError(t, s.BindSigningAuthority(historyOf{1: legacy(), 2: cfg2()}))

	p, err := s.LeaderPolicy(1)
	require.NoError(t, err)
	require.Equal(t, LeaderPolicyLegacy, p)
	p, err = s.LeaderPolicy(2)
	require.NoError(t, err)
	require.Equal(t, LeaderPolicyWeightedV1, p)

	// epoch 3 has a trust base but the history does not hold it: never an implicit legacy
	_, err = s.LeaderPolicy(3)
	require.ErrorIs(t, err, ErrLeaderPolicyHistory)
	require.ErrorIs(t, err, errNotHeld)
	// and no trust base is an error whatever the history says
	_, err = s.LeaderPolicy(4)
	require.ErrorIs(t, err, ErrLeaderPolicyHistory)

	require.ErrorIs(t, s.ActivateLeaderPolicy(2, LeaderPolicyWeightedV1), ErrLeaderPolicyHistory, "a second source would disagree")
}

// The in-memory activation seam and the bound history never both answer: an activation recorded before the bind is not consulted.
func TestABoundStoreIgnoresARecordedInMemoryPolicy(t *testing.T) {
	s := threeEpochStore(t)
	require.NoError(t, s.ActivateLeaderPolicy(2, LeaderPolicyWeightedV1))
	require.NoError(t, s.BindSigningAuthority(historyOf{1: legacy(), 2: legacy(), 3: legacy()}))
	p, err := s.LeaderPolicy(2)
	require.NoError(t, err)
	require.Equal(t, LeaderPolicyLegacy, p, "the history is the only source once bound")
}
