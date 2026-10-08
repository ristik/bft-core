package q3active_test

import (
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A coupled first activation followed by two root-only activations: every shard's history runs through all of them. The unchanged
// aggregators (three partitions) hold anchor, continuation, continuation, continuation, each under its own root identity and linked to
// the one before; the designated EVM shard holds anchor, its real assignment, then continuations of that assignment.
func TestRequestHistoryRunsThroughLaterRootOnlyEpochs(t *testing.T) {
	ctx := context.Background()
	first := q3fixture.New(t, q3fixture.Options{Assignment: true})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	third := q3fixture.New(t, q3fixture.Options{After: second})
	p := newProcess(t, first)
	rt := p.start()
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Activate(ctx, p.bundle()))
	for _, f := range []*q3fixture.Fixture{second, third} {
		l, c := evidenceOf(f)
		b, err := rt.BundleFor(l, f.Snapshot, c)
		require.NoError(t, err)
		require.NoError(t, rt.Activate(ctx, b))
	}
	require.EqualValues(t, 4, rt.History().Tip().Epoch())

	firstID := first.Body.Identity()
	hist, err := rt.RequestHistory(q3active.RequestHistoryConfig{Candidates: retainedCandidates{string(firstID[:]): first.Candidate},
		HashAlg: crypto.SHA256, Network: q3fixture.Network, Version: 1, Anchor: anchorOf(first.ShardConf)})
	require.NoError(t, err)

	bodies := make([][]byte, 0, 3)
	for epoch := uint64(2); epoch <= 4; epoch++ {
		e, err := rt.History().ForEpoch(epoch)
		require.NoError(t, err)
		id := e.BodyID()
		bodies = append(bodies, id[:])
	}

	for _, partition := range []types.PartitionID{q3fixture.PartitionID + 1, q3fixture.PartitionID + 2, q3fixture.PartitionID + 3} {
		chain, err := hist.Chain(partition, types.ShardID{})
		require.NoError(t, err, "partition %d", partition)
		require.Len(t, chain, 4, "partition %d: the anchor and a continuation per root epoch", partition)
		for i, a := range chain[1:] {
			require.Equal(t, bodies[i], a.RootBody(), "partition %d, epoch %d", partition, i+2)
			require.Equal(t, chain[0].PDRHash(), a.PDRHash(), "an unchanged shard keeps its configuration")
		}
	}

	designated, err := hist.Chain(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err)
	require.Len(t, designated, 4)
	require.Equal(t, bodies[0], designated[1].RootBody(), "the real assignment, under the coupled activation's identity")
	require.NotEqual(t, designated[0].PDRHash(), designated[1].PDRHash(), "the activation installs another configuration")
	for i := 2; i < 4; i++ {
		require.Equal(t, bodies[i-1], designated[i].RootBody())
		require.Equal(t, designated[1].PDRHash(), designated[i].PDRHash(), "root-only epochs keep the installed assignment")
	}

	t.Run("a root-only epoch needs no retained candidate, the coupled one does", func(t *testing.T) {
		none, err := rt.RequestHistory(q3active.RequestHistoryConfig{Candidates: retainedCandidates{}, HashAlg: crypto.SHA256, Network: q3fixture.Network,
			Version: 1, Anchor: anchorOf(first.ShardConf)})
		require.NoError(t, err)
		_, err = none.Chain(q3fixture.PartitionID+1, types.ShardID{})
		require.ErrorIs(t, err, q3active.ErrRequestHistory, "epoch 2 is coupled: its candidate is the evidence")
	})
}
