package b1state

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
)

// A root epoch's validator set becomes a B1 registry entry (rootinput.Derive); a set above the entry's member ceiling would make admission
// refuse the epoch. The upstream caps must not exceed it.
func TestUpstreamCommitteeCapsFitTheB1MemberCeiling(t *testing.T) {
	require.LessOrEqual(t, evmassign.MaxValidators, MaxMembers)
	require.LessOrEqual(t, ElectMaxCommittee, MaxMembers)
}
