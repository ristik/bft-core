package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// restart is the process restart a successive activation starts from: the second handoff is installed by a stopped manager that
// recovers its journal and rebuilds the verified history from the genesis and the retained first activation.
func (r *q3Replica) restart() {
	r.t.Helper()
	r.close()
	r.mustOpen(true)
	require.NoError(r.t, r.rt.Recover(context.Background()))
}

func secondBundle(f *q3fixture.Fixture) q3active.Bundle {
	return q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot}
}

// The second activation is committed by the first activation's weighted scheme 2 committee: the manager verifies the old commit
// under that epoch's own scheme, keys and threshold (heavy plus one light is weight 7 of 9), installs epoch 3 and anchors it.
func TestSecondHandoffIsVerifiedUnderSchemeTwo(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	c.activateAll()
	second := q3fixture.New(t, q3fixture.Options{After: c.f, Weights: []uint64{1, 1, 6, 1}})
	retained := c.replicas[:3]
	ctx := context.Background()

	t.Run("a commit below the epoch's weighted threshold installs nothing", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			signedBy int
		}{{"the heavy member alone is weight 6 of 7", 1}} {
			bad := q3fixture.New(t, q3fixture.Options{After: c.f, SignedBy: tc.signedBy})
			r := retained[1]
			r.restart()
			err := r.rt.Activate(ctx, secondBundle(bad))
			require.ErrorIs(t, err, q3format.ErrActivation, tc.name)
			require.ErrorIs(t, err, handoff.ErrProof, tc.name)
			_, err = r.trust.GetByEpoch(3)
			require.Error(t, err, "no epoch 3 trust base was stored")
			_, ok := r.rt.Activated(3)
			require.False(t, ok, "the history does not hold the refused epoch")
		}
	})

	for _, r := range retained {
		r.restart()
		require.NoError(t, r.rt.Activate(ctx, secondBundle(second)))
		r.startConsensus()
	}
	anchor := retained[0].manager.epochAnchor
	require.EqualValues(t, 14, anchor.Slot, "the second successor is anchored at (3, A*-1)")
	for _, r := range retained {
		tb := r.manager.trustBase.Load()
		require.EqualValues(t, 3, tb.Epoch)
		require.EqualValues(t, 15, tb.EpochStart)
		require.EqualValues(t, 7, tb.QuorumThreshold)
		weights := map[string]uint64{}
		for _, n := range tb.RootNodes {
			weights[n.NodeID] = n.Stake
		}
		require.EqualValues(t, 6, weights[second.NewNodes[2].PeerConf.ID.String()], "the new weights are the second body's")
		for epoch, scheme := range map[uint64]uint64{1: votesig.SchemeLegacy, 2: votesig.SchemeDomainBound, 3: votesig.SchemeDomainBound} {
			cfg, err := r.trust.SigningConfig(epoch)
			require.NoError(t, err)
			require.Equal(t, scheme, cfg.Scheme, "epoch %d keeps its own scheme", epoch)
		}
		require.NoError(t, r.rt.Admit(3))
		require.NoError(t, r.rt.Gate(ctx, second.Claim))
		require.EqualValues(t, 3, r.rt.Snapshot().Epoch())
		require.Equal(t, anchor, r.manager.epochAnchor)
	}
}
