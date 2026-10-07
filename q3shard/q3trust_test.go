package q3shard

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func TestQ3TrustStoreServesAV3EpochOnlyOnceTheJournalCompletedItAndFollowsTheHistory(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	base, err := shardnode.NewHistoricalTrustBaseStore(ctx, memorydb.New(), f.Old, [32]byte{1}, true)
	require.NoError(t, err)
	s := NewQ3TrustStore(base, rt)

	epoch := f.Claim.Epoch
	tb, err := s.GetByEpoch(ctx, 1)
	require.NoError(t, err, "the pinned genesis epoch")
	require.EqualValues(t, 1, tb.Epoch)
	_, err = s.GetByEpoch(ctx, epoch)
	require.ErrorIs(t, err, q3format.ErrUnknownEpoch, "an epoch the verified history does not hold is refused")
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

// While an installation is still running (the root step, before the journal's completion marker), the install can verify the epoch it
// replaces from the history, though the node does not yet serve the new epoch to anything else.
func TestTheInstallVerifiesFromTheHistoryBeforeTheJournalAdmitsTheEpoch(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	base, err := shardnode.NewHistoricalTrustBaseStore(ctx, memorydb.New(), f.Old, [32]byte{1}, true)
	require.NoError(t, err)
	s := NewQ3TrustStore(base, rt)
	epoch := f.Claim.Epoch

	var during, served error
	p.Root.OnInstall = func(e q3format.Entry) {
		_, during = s.Verified().GetByEpoch(ctx, e.Epoch())
		_, served = s.GetByEpoch(ctx, e.Epoch())
	}
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Activate(ctx, p.Bundle()))
	require.NoError(t, during, "the install reads the verified history")
	require.ErrorIs(t, served, q3active.ErrNotActive, "but the node does not serve an epoch the journal has not completed")
	got, err := s.GetByEpoch(ctx, epoch)
	require.NoError(t, err, "served once complete")
	require.EqualValues(t, epoch, got.Epoch)

	genesis, err := s.Verified().GetByEpoch(ctx, 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, genesis.Epoch)
	_, err = s.Verified().GetByEpoch(ctx, epoch+1)
	require.ErrorIs(t, err, q3format.ErrUnknownEpoch, "an epoch the history does not hold")
}
