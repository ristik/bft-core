package shardnode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
)

func TestQ3TrustStoreServesAV3EpochOnlyOnceTheJournalCompletedItAndFollowsTheHistory(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	base, err := NewHistoricalTrustBaseStore(ctx, memorydb.New(), f.Old, [32]byte{1}, true)
	require.NoError(t, err)
	s := NewQ3TrustStore(base, rt)

	epoch := f.Claim.Epoch
	tb, err := s.GetByEpoch(ctx, 1)
	require.NoError(t, err, "the pinned genesis epoch")
	require.EqualValues(t, 1, tb.Epoch)
	_, err = s.GetByEpoch(ctx, epoch)
	require.Error(t, err, "an epoch the verified history does not hold is refused")
	require.False(t, s.IsV2Epoch(epoch))
	current, ok := s.CurrentRootEpoch()
	require.True(t, ok)
	require.EqualValues(t, 1, current)

	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Activate(ctx, p.Bundle()))

	got, err := s.GetByEpoch(ctx, epoch)
	require.NoError(t, err)
	var total uint64
	for _, n := range got.RootNodes {
		total += n.Stake
	}
	require.EqualValues(t, 9, total, "the verified history's exact weights")
	require.EqualValues(t, 7, got.QuorumThreshold)
	require.True(t, s.IsV2Epoch(epoch), "a V3 epoch keeps the proof-aware admission gate closed like a V2 one")
	id, err := s.BodyID(epoch)
	require.NoError(t, err)
	require.Equal(t, f.Claim.BodyID, id)

	// the current root epoch moves only when the follower says everything the activation needs is installed, one epoch at a time
	current, _ = s.CurrentRootEpoch()
	require.EqualValues(t, 1, current, "installed by the journal, not yet by the shard")
	require.ErrorIs(t, s.ActivateQ3(epoch+1), ErrQ3Epoch, "skipping an epoch")
	require.NoError(t, s.ActivateQ3(epoch))
	current, _ = s.CurrentRootEpoch()
	require.Equal(t, epoch, current)
	require.NoError(t, s.ActivateQ3(epoch), "idempotent")
	require.ErrorIs(t, s.ActivateQ3(epoch+1), ErrQ3Epoch, "an epoch the history does not activate")

	require.True(t, s.Guarded().BoundTo(rt))
}
