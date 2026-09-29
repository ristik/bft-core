package consensus

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	testutils "github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestBootstrapLeaderRetainsCanonicalOrderAfterQCUpdates(t *testing.T) {
	nodes := make([]*types.NodeInfo, 4)
	ids := make([]string, 4)
	for i := range nodes {
		n := testutils.NewTestNode(t)
		ids[i] = n.PeerConf.ID.String()
		nodes[i] = &types.NodeInfo{NodeID: ids[i]}
	}
	sort.Strings(ids)
	base := constLeader{leader: testutils.NewTestNode(t).PeerConf.ID}
	selector, err := newBootstrapLeader(base, 100, nodes)
	require.NoError(t, err)
	for round := uint64(100); round < 120; round++ {
		require.NoError(t, selector.Update(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round, ParentRoundNumber: round - 1}}, round,
			func(uint64) (*storage.ExecutedBlock, error) {
				return &storage.ExecutedBlock{BlockData: &rctypes.BlockData{Author: ids[0]}}, nil
			}))
		got, err := selector.GetLeaderForRound(round)
		require.NoError(t, err)
		require.Equal(t, ids[(round-100)%4], got.String())
	}
}
