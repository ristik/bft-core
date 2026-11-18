package consensus

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testobs "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #1113 (astra on #1183, round 2): a leader the selector could not name for lack of committed history is asked again in the same round,
// so a recovery that supplies the history gives it the protected share without a round change.
func TestProposerPriorityRefreshesWhenHistoryAppearsInSameRound(t *testing.T) {
	nodes := make([]*types.NodeInfo, 5)
	for i, id := range testpeer.GeneratePeerIDs(t, 5) {
		nodes[i] = &types.NodeInfo{NodeID: id.String(), Stake: 1}
	}
	genesis := bytes.Repeat([]byte{7}, 32)
	head := leader.LeaderHead{Round: 99}
	selector, err := leader.NewEpochReputation(genesis, 2, 100, 4, nodes, func() (leader.LeaderHead, error) { return head, nil })
	require.NoError(t, err)
	pm, err := NewPacemaker(time.Second, 10*time.Second, testobs.Default(t))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer pm.Stop()
	pm.Reset(ctx, 123, nil, nil) // round 124 is beyond the bootstrap run; its cutoff is 100
	cm := &ConsensusManager{pacemaker: pm, leaderSelector: selector}
	_, err = selector.GetLeaderForRound(124)
	require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable)
	cm.refreshProposers()

	ring, err := rctypes.NewLeaderState(genesis, 2, 100, 5, 100)
	require.NoError(t, err)
	ring, err = ring.Next(122, []byte{0x1f})
	require.NoError(t, err)
	head = leader.LeaderHead{Round: 122, State: ring}
	// A recovered chain with high QC 123 resets the pacemaker to the same round.
	// The real selector now sees the newly available committed history.
	pm.Reset(ctx, 123, nil, nil)
	current, err := selector.GetLeaderForRound(124)
	require.NoError(t, err)
	next, err := selector.GetLeaderForRound(125)
	require.NoError(t, err)
	require.EqualValues(t, 124, pm.GetCurrentRound())
	cm.refreshProposers() // the loop's refresh after recovery
	require.True(t, cm.EligibleProposer(current), "the now-known current leader has the protected share")
	require.True(t, cm.EligibleProposer(next), "the now-known next leader has the protected share")
}
