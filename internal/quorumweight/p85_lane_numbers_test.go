package quorumweight

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The quorums scripts/p85-recovery-steps.sh states for its committees (K: four unit weights; J = K plus the joiner: five). The EVM request quorum is a
// majority, the root quorum is two thirds plus one: they differ for five (3 and 4), and the lane's J-stall and activation checks depend on which is which.
func TestTheP85LaneQuorumNumbers(t *testing.T) {
	for _, c := range []struct{ total, evm, root uint64 }{{4, 3, 3}, {5, 3, 4}} {
		evm, err := MajorityThreshold(c.total)
		require.NoError(t, err)
		require.Equal(t, c.evm, evm, "EVM request quorum of %d unit validators", c.total)
		root, err := Threshold(c.total)
		require.NoError(t, err)
		require.Equal(t, c.root, root, "root quorum of %d unit roots", c.total)
	}
}
