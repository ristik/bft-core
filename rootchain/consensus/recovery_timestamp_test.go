package consensus

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

func TestRecoveryAuthenticatesTimestampBeforeInstallingParent(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	for _, committed := range []bool{false, true} {
		name := "pending high QC parent"
		if committed {
			name = "committed head"
		}
		t.Run(name, func(t *testing.T) {
			root := latchProbe(t, c)
			bad := *state
			if committed {
				head := *state.CommittedHead
				block := *head.Block
				block.Timestamp = math.MaxUint64
				head.Block = &block
				bad.CommittedHead = &head
			} else {
				bad.Pending = append([]*rctypes.BlockData(nil), state.Pending...)
				found := false
				for i, b := range bad.Pending {
					if b.Round == state.CommittedHead.CommitQc.GetRound() {
						copy := *b
						copy.Timestamp = math.MaxUint64
						bad.Pending[i] = &copy
						found = true
					}
				}
				require.True(t, found, "reviewer's certified pending-parent premise")
			}
			previous := root.blockStore
			err := recoverTo(t, root, &bad)
			require.ErrorIs(t, err, abdrc.ErrRecoveryTimestamp)
			require.Same(t, previous, root.blockStore)
			require.False(t, root.frontier.faulted.Load())
			root.recovery.Clear()
			require.NoError(t, recoverTo(t, root, state), "original signed history remains replayable")
			parent, err := root.blockStore.Block(root.blockStore.GetHighQc().GetRound())
			require.NoError(t, err)
			_, err = proposalTimestamp(basetypes.NewTimestamp(), parent.BlockData.Timestamp)
			require.NoError(t, err)
		})
	}
}

func TestRecoveryLiveTimeRefusalDoesNotLatchPersistenceFault(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	proposal := *c.proposals[len(c.proposals)-1]
	block := *proposal.Block
	proposal.Block = &block
	now := basetypes.NewTimestamp()
	block.Timestamp = now + 60
	leaderID, err := firstReplica(c.replicas).manager.leaderSelector.GetLeaderForRound(block.Round)
	require.NoError(t, err)
	leader := c.replicas[leaderID]
	require.NoError(t, proposal.Sign(leader.manager.safety.signer))
	root := latchProbe(t, c)
	root.frontier.eligible.Store(true)
	root.safety.now = func() uint64 { return now }
	_, err = root.recovery.Set(&proposal)
	require.NoError(t, err)
	err = root.onStateResponse(context.Background(), state)
	require.ErrorIs(t, err, ErrTimestampTooFarAhead)
	require.False(t, root.recovery.InRecovery())
	require.False(t, root.frontier.faulted.Load(), "successful replay plus a live refusal is not persistence uncertainty")
	require.True(t, root.frontier.eligible.Load())
	// The same genuinely leader-signed proposal becomes eligible once time catches up.
	root.safety.now = func() uint64 { return now + 60 }
	require.NoError(t, root.safety.validateVoteTimestamp(&block))
	require.NoError(t, root.onProposalMsg(context.Background(), &proposal))
	require.False(t, root.frontier.faulted.Load())
	require.True(t, root.frontier.eligible.Load())
}

func TestScheme2RecoveryAuthenticatesPendingAndCommittedTime(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	anchor := c.activateAll()
	c.firstProposal(anchor.Slot)
	proposals := []*abdrc.ProposalMsg{c.proposal}
	var state *abdrc.StateMsg
	for i := 0; i < 8; i++ {
		id, err := c.replicas[0].manager.leaderSelector.GetLeaderForRound(proposals[len(proposals)-1].Block.Round)
		require.NoError(t, err)
		st, err := c.byID(id).manager.blockStore.GetState()
		require.NoError(t, err)
		if st.CommittedHead.Anchor == nil && st.CommittedHead.Block.Anchor == nil {
			state = st
			break
		}
		c.advance(&proposals)
	}
	require.NotNil(t, state)
	raw, err := basetypes.Cbor.Marshal(state)
	require.NoError(t, err)
	var wire abdrc.StateMsg
	require.NoError(t, basetypes.Cbor.Unmarshal(raw, &wire))
	require.EqualValues(t, 2, wire.CommittedHead.CommitQc.Scheme)
	require.NotZero(t, wire.CommittedHead.CommitQc.VoteInfo.Timestamp)
	r := c.replicas[3]
	r.close()
	r.mustOpen(true)
	require.NoError(t, r.rt.Recover(context.Background()))
	for _, head := range []bool{false, true} {
		bad := wire
		if head {
			copy := *wire.CommittedHead
			block := *copy.Block
			block.Timestamp = math.MaxUint64
			copy.Block = &block
			bad.CommittedHead = &copy
		} else {
			bad.Pending = append([]*rctypes.BlockData(nil), wire.Pending...)
			found := false
			for i, b := range bad.Pending {
				if b.Round == wire.CommittedHead.CommitQc.GetRound() {
					copy := *b
					copy.Timestamp = math.MaxUint64
					bad.Pending[i] = &copy
					found = true
				}
			}
			require.True(t, found)
		}
		before := r.manager.blockStore
		require.ErrorIs(t, recoverTo(t, r.manager, &bad), abdrc.ErrRecoveryTimestamp)
		require.Same(t, before, r.manager.blockStore)
		r.manager.recovery.Clear()
	}
	require.NoError(t, recoverTo(t, r.manager, &wire))
}

// An uncertified leaf can be replayed, but cannot become a live parent until its
// timestamp agrees with the subsequently received, genuinely signed QC.
func TestRecoveredLeafTimestampAuthenticatedBeforeLiveUse(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	leaf := *c.proposals[len(c.proposals)-1].Block
	leaf.Timestamp = math.MaxUint64
	bad := *state
	bad.Pending = append(append([]*rctypes.BlockData(nil), state.Pending...), &leaf)
	trigger := c.advance()
	root := latchProbe(t, c)
	_, err := root.recovery.Set(trigger)
	require.NoError(t, err)
	err = root.onStateResponse(context.Background(), &bad)
	require.ErrorIs(t, err, rctypes.ErrTimestampProof)
	require.False(t, root.frontier.faulted.Load())
}

func TestLiveQCAuthenticatesExecutedParentTimestamp(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	root := latchProbe(t, c)
	require.NoError(t, recoverTo(t, root, state))
	qc := root.blockStore.GetHighQc()
	parent, err := root.blockStore.Block(qc.GetRound())
	require.NoError(t, err)
	parent.BlockData.Timestamp++
	require.ErrorIs(t, root.checkRecoveryNeeded(qc), rctypes.ErrTimestampProof)
	require.False(t, root.recovery.InRecovery())
	root.processQC(context.Background(), qc)
	require.True(t, root.recovery.InRecovery(), "mismatched QC must trigger recovery before promotion")
}
