package consensus

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// utbRecoveryRoot is a restarted root whose block stores bind certificates by the UTB rule of every epoch (the authenticated configuration is the seam).
func utbRecoveryRoot(t *testing.T, c *anchorCluster) *ConsensusManager {
	root := latchProbe(t, c)
	root.utbPrevious = func(uint64) (*types.RootTrustBaseV2, error) { return nil, errors.New("no finalized entry") }
	root.utbConfig = func(uint64) (votesig.Config, error) { return votesig.Config{UTB: true}, nil }
	return root
}

// In a UTB epoch the replacement store of a recovery carries the binding, and recovering from a peer's state still works end to end through
// onStateResponse. (In this cluster every pending QC is already at or below the head's commit QC, so ProcessQc skips them as stale before the binding;
// the case rev2 found, a QC above the store's high QC that commits a pruned round, is pinned at the store in storage.TestProcessQcInAUTBEpochLeavesAPrunedCommitToTheCommit.)
func TestRecoveryInAUTBEpochReplaysAStateWhoseFirstQCCommitsNothingTheTreeHolds(t *testing.T) {
	c := newAnchorCluster(t)
	for i := 0; i < 6 && !(c.state().CommittedHead.Anchor == nil && c.state().CommittedHead.Block.Anchor == nil); i++ {
		c.advance()
	}
	state := c.state()
	require.True(t, hasQCThatCommitsNothing(state), "premise: the state right after the anchor, whose first QCs commit the anchor or nothing")

	root := utbRecoveryRoot(t, c)
	previous := root.blockStore
	require.NoError(t, recoverTo(t, root, state), "the same state recovers in a legacy epoch (TestRolledRootsRejoinFromStatesWithQCsThatCommitNothing)")
	require.NotSame(t, previous, root.blockStore, "the replacement store was installed")
	require.False(t, root.frontier.faulted.Load())
	adopted, err := root.blockStore.GetState()
	require.NoError(t, err)
	require.Equal(t, len(state.Pending), len(adopted.Pending), "every pending block was replayed, and every certificate inserted")
	var last uint64
	for _, b := range state.Pending {
		if b.Qc != nil {
			last = max(last, b.Qc.GetRound())
		}
	}
	require.GreaterOrEqual(t, root.blockStore.GetHighQc().GetRound(), last, "the last pending certificate was inserted")
}
