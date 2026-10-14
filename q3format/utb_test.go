package q3format_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/utb"
)

// The unsigned UTB chain of a real Q3 history is the same whether it is derived from the projection every installer holds or from the activated
// bodies' own facts (the root V2/V3 path), and each entry links to its predecessor's EntryID.
func TestUTBChainOfAQ3HistoryIsOneCanonicalDerivation(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	s := q3fixture.New(t, q3fixture.Options{After: f})
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(s.Envelope)
	require.NoError(t, err)

	chain, err := h.UTBUnsigned()
	require.NoError(t, err)
	require.Len(t, chain, 3)
	require.True(t, chain[0].IsGenesis())
	for i := 1; i < len(chain); i++ {
		id, err := chain[i-1].EntryID()
		require.NoError(t, err)
		require.Equal(t, id[:], []byte(chain[i].PreviousEntryID))
		require.EqualValues(t, i+1, chain[i].Epoch)
	}

	// the independent derivation: the activated body's members and thresholds with the committed record's actual activation round
	for i := 1; i < len(chain); i++ {
		e, err := h.ForEpoch(uint64(i + 1))
		require.NoError(t, err)
		body, err := q3format.DecodeBody(e.BodyEncoding())
		require.NoError(t, err)
		viaBody, err := utb.BuildUnsigned(chain[i-1], utb.FromWeightSet(body.Network, body.Epoch, e.Start(), body.Members, body.RootThreshold, body.StateSummary, body.ChangeRecordHash))
		require.NoError(t, err)
		want, _ := viaBody.SigBytes()
		got, _ := chain[i].SigBytes()
		require.Equal(t, want, got, "epoch %d", i+1)
		require.Equal(t, e.Start(), chain[i].EpochStart, "the actual activation, not the earliest")
	}
	// deterministic
	again, err := h.UTBUnsigned()
	require.NoError(t, err)
	for i := range chain {
		a, _ := chain[i].EntryID()
		b, _ := again[i].EntryID()
		require.Equal(t, a, b)
	}
}
