package consensus

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// §49: the frontier trust base carries up to 256 roots and 256 trust signatures (a native resource bound; quorum and signature validity are
// untouched), and 257 of either is refused.
func TestFrontierTrustBoundsAre256(t *testing.T) {
	tb := func(roots, sigs int) *types.RootTrustBaseV1 {
		out := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 1, Signatures: map[string]hex.Bytes{}}
		for i := 0; i < roots; i++ {
			out.RootNodes = append(out.RootNodes, &types.NodeInfo{NodeID: fmt.Sprintf("root%03d", i), SigKey: make([]byte, 33), Stake: 1})
		}
		for i := 0; i < sigs; i++ {
			out.Signatures[fmt.Sprintf("root%03d", i)] = make([]byte, 65)
		}
		return out
	}
	require.Equal(t, 256, maxFrontierRoots)
	require.NoError(t, validateFrontierTrustBounds(tb(256, 256)))
	require.Error(t, validateFrontierTrustBounds(tb(257, 0)), "257 roots")
	require.Error(t, validateFrontierTrustBounds(tb(256, 257)), "257 trust signatures")
	require.Error(t, validateFrontierTrustBounds(tb(0, 0)), "no roots")
	require.Error(t, validateFrontierTrustBounds(nil))
}
