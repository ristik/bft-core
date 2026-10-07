package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

// advance delivers the latest proposal to every replica, then lets the next leader collect the votes and propose again.
func (c *q3Cluster) advance(proposals *[]*abdrc.ProposalMsg) {
	c.t.Helper()
	ctx := context.Background()
	last := (*proposals)[len(*proposals)-1]
	for _, r := range c.replicas {
		r.net.ResetSentMessages(network.ProtocolRootVote)
		require.NoError(c.t, r.manager.onProposalMsg(ctx, last))
	}
	next, err := c.replicas[0].manager.leaderSelector.GetLeaderForRound(last.Block.Round + 1)
	require.NoError(c.t, err)
	collector := c.byID(next)
	collector.manager.pacemaker.setState(ctx, pmsRoundMatured)
	for _, r := range c.replicas {
		if collector.manager.pacemaker.GetCurrentRound() > last.Block.Round {
			break
		}
		votes := r.net.SentMessages(network.ProtocolRootVote)
		require.Len(c.t, votes, 1)
		require.NoError(c.t, collector.manager.onVoteMsg(ctx, votes[0].Message.(*abdrc.VoteMsg)))
	}
	*proposals = append(*proposals, collector.net.WaitRootProposal(c.t))
}

// A root restarted into an activated epoch while its peers are already in it recovers from a peer's state: the manager verifies the
// state's certificates under the verified history (the epoch's own weights and scheme), and installs no V2 handoff authority for the
// activated epoch, whose lineage is not a V2 body.
func TestARestartedRootRecoversInAnActivatedEpochFromAPeersState(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	anchor := c.activateAll()
	first := c.firstProposal(anchor.Slot)
	_ = first
	proposals := []*abdrc.ProposalMsg{c.proposal}
	var state *abdrc.StateMsg
	for i := 0; i < 8; i++ {
		leader, err := c.replicas[0].manager.leaderSelector.GetLeaderForRound(proposals[len(proposals)-1].Block.Round)
		require.NoError(t, err)
		st, err := c.byID(leader).manager.blockStore.GetState()
		require.NoError(t, err)
		if st.CommittedHead.Anchor == nil && st.CommittedHead.Block.Anchor == nil {
			state = st
			break
		}
		c.advance(&proposals)
	}
	require.NotNil(t, state, "premise: the committed head moved past the first successor of the anchor")

	t.Run("the restarted root adopts the peers' committed head", func(t *testing.T) {
		root := c.replicas[3] // the lightest member, restarted
		root.close()
		root.mustOpen(true)
		require.NoError(t, root.rt.Recover(context.Background()))
		require.NoError(t, recoverTo(t, root.manager, state))
		require.False(t, root.manager.recovery.InRecovery())
		adopted, err := root.manager.blockStore.GetState()
		require.NoError(t, err)
		require.Equal(t, state.CommittedHead.Block.Round, adopted.CommittedHead.Block.Round)
	})
	t.Run("a binary without the verified history cannot recover in the activated epoch", func(t *testing.T) {
		root := c.replicas[2]
		root.close()
		root.mustOpen(true)
		require.NoError(t, root.rt.Recover(context.Background()))
		root.manager.q3 = nil // the manager does not know the history
		err := recoverTo(t, root.manager, state)
		require.ErrorIs(t, err, trusthistorystore.ErrNotFound, "the V1/V2 recovery history holds no body for the activated epoch")
		require.True(t, root.manager.recovery.InRecovery(), "nothing was adopted")
	})
}

// The lineage a StateMsg is verified against is the verified history's view when the binary knows Q3, and the V1/V2 recovery history
// alone otherwise: only the first can answer for an activated epoch.
func TestTheStateHistoryOfAnActivatedEpochIsTheVerifiedLineage(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	c.activateAll()
	m := c.heavy().manager

	rec, err := m.stateHistory().ByEpoch(2)
	require.NoError(t, err)
	require.NotNil(t, rec.Verified)
	require.EqualValues(t, 7, rec.Verified.QuorumThreshold)
	genesis, err := m.stateHistory().ByEpoch(1)
	require.NoError(t, err)
	require.NotNil(t, genesis.V1, "the genesis epoch is the recovery history's record")

	m.q3 = nil
	_, err = m.stateHistory().ByEpoch(2)
	require.ErrorIs(t, err, trusthistorystore.ErrNotFound, "the V1/V2 history holds no body of the activated epoch")
}
