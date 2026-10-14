package q3format_test

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
)

func TestB1AuthenticatedPrefixPreservesNativeBodiesWeightsAndActualStarts(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	s := q3fixture.New(t, q3fixture.Options{After: f})
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(s.Envelope)
	require.NoError(t, err)
	entries, err := h.B1Entries(15)
	require.NoError(t, err)
	require.Len(t, entries, 3)
	require.EqualValues(t, 7, entries[1].Start)
	require.EqualValues(t, 15, entries[2].Start)
	require.Equal(t, f.Body.Identity(), entries[1].BodyID)
	require.Equal(t, f.Claim.CommitID, entries[1].ActivationCommitID)
	require.Equal(t, f.Body.Config.Identity(), entries[1].SigningConfigHash)
	require.EqualValues(t, 3, entries[1].BodyKind)
	require.EqualValues(t, 2, entries[1].SigningScheme)
	total, err := entries[1].TotalWeight()
	require.NoError(t, err)
	require.EqualValues(t, 9, total)
	older, err := h.B1Entries(6)
	require.NoError(t, err)
	require.Len(t, older, 1)
	require.Nil(t, older[0].End)
	// The registry keeps every epoch: both supersession epochs are authenticated and both are installed; nothing survives or is dropped by age.
	require.NoError(t, b1state.ValidateHistory(entries))
	require.EqualValues(t, 3, entries[len(entries)-1].Epoch)
	entries[1].Members[0].Weight++
	again, err := h.B1Entries(15)
	require.NoError(t, err)
	require.NotEqual(t, entries[1].Members[0].Weight, again[1].Members[0].Weight)
	// A separately signed genesis with a positive start has no authority at round zero.
	positive := *f.Old
	positive.EpochStart = 1
	positive.Signatures = maps.Clone(f.Old.Signatures)
	clear(positive.Signatures)
	for _, node := range f.OldNodes {
		require.NoError(t, positive.Sign(node.PeerConf.ID.String(), node.Signer))
	}
	laterGenesis, err := q3format.NewHistory(&positive)
	require.NoError(t, err)
	_, err = laterGenesis.B1Entries(0)
	require.ErrorIs(t, err, q3format.ErrUnknownEpoch)
	var missing *q3format.History
	_, err = missing.B1Entries(15)
	require.ErrorIs(t, err, q3format.ErrHistory)
}
