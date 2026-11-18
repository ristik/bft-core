//go:build vrdev

package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
)

// The vrdev build (the VR lane's) adds the named extras, at most maxDevExtras of each.
func TestTheDevBuildAddsABoundedNumberOfExtraStagedPeers(t *testing.T) {
	t.Setenv("UBFT_VR_DEV_STAGE_EXTRA_ROOTS", "a,b,c,d,e,f,g")
	t.Setenv("UBFT_VR_DEV_STAGE_EXTRA_EVM", "x")
	ids, roots := devStagedExtras([]evmassign.Identity{{EVMNodeID: "e1"}}, []evmroot.Member{{NodeID: "r1"}})
	require.Len(t, ids, 2)
	require.Len(t, roots, 1+maxDevExtras)
}
