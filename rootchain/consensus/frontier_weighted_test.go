package consensus

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

func weightedFrontierTrust(t *testing.T) *types.RootTrustBaseV1 {
	t.Helper()
	trust := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 2, EpochStart: 7, QuorumThreshold: 7}
	for _, n := range []struct {
		id    string
		stake uint64
	}{{"a-heavy", 6}, {"b", 1}, {"c", 1}, {"d", 1}} {
		node := testutils.NewTestNode(t)
		v, err := node.Signer.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		trust.RootNodes = append(trust.RootNodes, &types.NodeInfo{NodeID: n.id, SigKey: bytes.Clone(key), Stake: n.stake})
	}
	return trust
}

// The frontier sampler serves a weighted committee only when the epoch is a verified Q3 activation's and the threshold is the exact
// weighted one; the unit profile still refuses every weight.
func TestFrontierProfileAdmitsAWeightedCommitteeOnlyExplicitly(t *testing.T) {
	trust := weightedFrontierTrust(t)
	require.NoError(t, ValidateFrontierProfileMode(trust, weightvalidation.ModeWeighted), "acceptance control")
	require.ErrorIs(t, ValidateFrontierProfile(trust), ErrFrontierProfile, "the default is the unit profile")
	require.ErrorIs(t, ValidateFrontierProfileMode(trust, weightvalidation.ModeUnit), ErrFrontierProfile)
	for name, change := range map[string]func(*types.RootTrustBaseV1){
		"a threshold below the exact one": func(tb *types.RootTrustBaseV1) { tb.QuorumThreshold = 6 },
		"a threshold above the exact one": func(tb *types.RootTrustBaseV1) { tb.QuorumThreshold = 8 },
		"a zero weight":                   func(tb *types.RootTrustBaseV1) { tb.RootNodes[1].Stake = 0 },
		"a weight above the member cap":   func(tb *types.RootTrustBaseV1) { tb.RootNodes[0].Stake = 1<<40 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			tb := weightedFrontierTrust(t)
			change(tb)
			require.ErrorIs(t, ValidateFrontierProfileMode(tb, weightvalidation.ModeWeighted), ErrFrontierProfile)
		})
	}
}
