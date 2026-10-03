package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The epoch guard on the live vote and timeout handlers, driven with authenticated messages of the old epoch through the
// real onVoteMsg/onTimeoutMsg: the old committee keeps running the suffix after the activation round A* until the
// successor is installed (D4), and only then is an old-epoch message refused.
func TestOldEpochVotesAndTimeoutsThroughTheLiveHandlers(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 9)
	var source *anchorReplica
	for id, r := range replicas {
		if r.oldSigners[id.String()] != nil {
			source = r
			break
		}
	}
	require.NotNil(t, source)
	ctx := context.Background()
	round := source.proof.CommitQC.GetRound() + 1
	require.Greater(t, round, source.proof.Record.ActivationRound, "the message is in the suffix beyond A*")

	author := source.manager.id.String()
	vote := NewDummyVote(t, author, round, []byte{1})
	vote.HighQc = source.proof.CommitQC
	require.NoError(t, vote.Sign(source.oldSigners[author]))
	timeout := abdrc.NewTimeoutMsg(&rctypes.Timeout{Round: round, Epoch: 1, HighQc: source.proof.CommitQC}, author, nil)
	require.NoError(t, timeout.Sign(source.oldSigners[author]))

	t.Run("before the successor is installed the old committee still takes them", func(t *testing.T) {
		cm := stoppedHandoffReplica(t, source)
		t.Cleanup(cm.pacemaker.Stop)
		cm.pacemaker.Reset(ctx, round-2, nil, nil)
		cm.updateTrustBase()
		require.EqualValues(t, 1, cm.trustBase.Load().Epoch)
		require.Nil(t, cm.epochAnchor)
		require.NoError(t, vote.Verify(cm.trustBaseStore))
		require.NoError(t, cm.onVoteMsg(ctx, vote))
		require.Contains(t, cm.voteBuffer, author)
		require.NoError(t, timeout.Verify(cm.trustBaseStore))
		err := cm.onTimeoutMsg(ctx, timeout)
		require.NotErrorIs(t, err, ErrVoteEpoch)
		if err != nil {
			require.ErrorContains(t, err, "timeout vote triggers recovery")
		}
	})

	t.Run("after the successor is installed they are authentic but refused", func(t *testing.T) {
		require.EqualValues(t, 2, source.manager.trustBase.Load().Epoch)
		require.Greater(t, round, anchor.Slot)
		require.NoError(t, vote.Verify(source.store), "the vote still authenticates under its own epoch")
		require.ErrorIs(t, source.manager.onVoteMsg(ctx, vote), ErrVoteEpoch)
		require.NotContains(t, source.manager.voteBuffer, author)
		require.NoError(t, timeout.Verify(source.store))
		require.ErrorIs(t, source.manager.onTimeoutMsg(ctx, timeout), ErrVoteEpoch)
	})

	t.Run("a member whose weight changed across epochs is never weighed with the new epoch's weight", func(t *testing.T) {
		// the author weighs 6 in the installed epoch and 1 under the epoch that authenticated the vote
		setStakes(source.manager, 7, map[string]uint64{author: 6})
		before := len(source.manager.voteBuffer)
		require.ErrorIs(t, source.manager.onVoteMsg(ctx, vote), ErrVoteEpoch)
		require.Len(t, source.manager.voteBuffer, before, "the refused vote is not buffered, so it cannot count with weight 6")
		w, err := source.manager.bufferedWeight()
		require.NoError(t, err)
		require.Zero(t, w)
	})
}
