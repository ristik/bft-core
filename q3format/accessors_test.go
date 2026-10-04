package q3format

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// The values an installer takes from a verified entry are copies, derived from the verified activation and nothing else.
func TestEntryHandsOutTheVerifiedActivationAsCopies(t *testing.T) {
	w := newWorld(t, 0)
	l := w.link(spec{})
	h, err := w.h.WithV3(l)
	require.NoError(t, err)
	e := h.Tip()
	p, err := decodeProof(l.Proof)
	require.NoError(t, err)

	t.Run("the projection is the activated committee with its exact weights", func(t *testing.T) {
		tb := e.Projection()
		require.EqualValues(t, 2, tb.Epoch)
		require.EqualValues(t, 25, tb.EpochStart, "A*")
		require.EqualValues(t, 7, tb.QuorumThreshold)
		require.Equal(t, l.Body.StateSummary, []byte(tb.StateHash))
		require.Equal(t, l.Body.ChangeRecordHash, []byte(tb.ChangeRecordHash))
		weights := map[string]uint64{}
		for _, n := range tb.RootNodes {
			weights[n.NodeID] = n.Stake
		}
		require.Equal(t, map[string]uint64{"n1": 6, "n2": 1, "n3": 1, "n4": 1}, weights)

		tb.RootNodes[0].Stake = 99
		tb.QuorumThreshold = 1
		tb.StateHash[0] ^= 0xFF
		again := e.Projection()
		require.EqualValues(t, 7, again.QuorumThreshold, "the entry is not changed through a returned projection")
		require.NotEqual(t, uint64(99), again.RootNodes[0].Stake)
		require.Equal(t, l.Body.StateSummary, []byte(again.StateHash))
	})

	t.Run("the handoff is what the old committee's commit derived", func(t *testing.T) {
		v, g, ok := e.Handoff()
		require.True(t, ok)
		body := l.Body.Identity()
		require.Equal(t, p.Record.ID(), v.RecordID)
		require.Equal(t, []byte(p.CommitQC.LedgerCommitInfo.Hash), v.Root)
		require.Equal(t, p.Control.Digest(), v.ControlDigest)
		require.EqualValues(t, 1, v.Epoch)
		require.Equal(t, p.Record, v.Record)
		require.Equal(t, body[:], g.NextBodyID)
		require.EqualValues(t, 2, g.Epoch)
		require.EqualValues(t, 25, g.Start)
		require.Equal(t, e.AnchorID(), [32]byte(g.ID()), "the epoch genesis is the entry's anchor")

		v.RecordID[0] ^= 0xFF
		v.Root[0] ^= 0xFF
		g.NextBodyID[0] ^= 0xFF
		g.RecordID[0] ^= 0xFF
		g.SuccessorTRHash[0] ^= 0xFF
		v2, g2, ok := e.Handoff()
		require.True(t, ok)
		require.Equal(t, p.Record.ID(), v2.RecordID, "the entry is not changed through the returned handoff")
		require.Equal(t, body[:], g2.NextBodyID)
		require.Equal(t, e.AnchorID(), [32]byte(g2.ID()))
	})

	t.Run("a legacy or zero entry has no activation", func(t *testing.T) {
		genesis, err := h.ForEpoch(1)
		require.NoError(t, err)
		for name, entry := range map[string]Entry{"genesis": genesis, "zero": {}} {
			_, _, ok := entry.Handoff()
			require.False(t, ok, name)
			_, ok = entry.Config()
			require.False(t, ok, name)
		}
	})

	t.Run("A_min is the body's lower bound, A* the committed boundary", func(t *testing.T) {
		require.EqualValues(t, 20, e.EarliestActivation())
		require.EqualValues(t, 25, e.Start())
		genesis, err := h.ForEpoch(1)
		require.NoError(t, err)
		require.Zero(t, genesis.EarliestActivation())
	})
}

func TestHistorySigningIsExplicitPerEpoch(t *testing.T) {
	w := newWorld(t, 0)
	h := w.append(spec{})
	legacy, err := h.Signing(1)
	require.NoError(t, err)
	require.Equal(t, votesig.Config{Scheme: votesig.SchemeLegacy, Network: testNetwork}, legacy)
	cfg, err := h.Signing(2)
	require.NoError(t, err)
	require.Equal(t, votesig.Config{Scheme: votesig.SchemeDomainBound, Network: testNetwork, Genesis: h.Genesis()}, cfg)
	require.NoError(t, cfg.Validate())
	for _, epoch := range []uint64{0, 3, 99} {
		_, err := h.Signing(epoch)
		require.ErrorIs(t, err, ErrUnknownEpoch, "an epoch the history does not hold is never scheme 1: %d", epoch)
	}
}
