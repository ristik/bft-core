//go:build !vrdev

package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
)

// A production build (no vrdev tag) ignores the development staging variables: no flag or environment variable adds a staged peer.
func TestAProductionBuildIgnoresTheDevelopmentStagingVariables(t *testing.T) {
	t.Setenv("UBFT_VR_DEV_STAGE_EXTRA_ROOTS", "root-x,root-y")
	t.Setenv("UBFT_VR_DEV_STAGE_EXTRA_EVM", "evm-x")
	ids, roots := devStagedExtras([]evmassign.Identity{{EVMNodeID: "e1"}}, []evmroot.Member{{NodeID: "r1"}})
	require.Len(t, ids, 1)
	require.Len(t, roots, 1)
}
