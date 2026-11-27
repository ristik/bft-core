package b1state

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
)

// The generic EVM assignment limit is a native resource bound (256, owner §49) and no longer follows the B1 registry; a B1-enabled deployment
// guards its own, equal to the registry's member ceiling (a gas bound that stays 16).
func TestTheB1GuardIsTheRegistryCeiling(t *testing.T) {
	require.Equal(t, MaxMembers, evmassign.B1MaxValidators)
	require.Greater(t, evmassign.MaxValidators, MaxMembers)
	require.LessOrEqual(t, ElectMaxCommittee, MaxMembers)
}
