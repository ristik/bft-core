package q3fixture

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3format"
)

func TestFixtureIsAVerifiedActivation(t *testing.T) {
	f := New(t, Options{})
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	env, err := q3format.DecodeEnvelope(f.EnvelopeBytes)
	require.NoError(t, err)
	next, err := h.VerifyEnvelope(env)
	require.NoError(t, err)
	require.Equal(t, f.Claim, next.Tip().Claim())
	require.EqualValues(t, 7, next.Tip().Start())
	tb := next.Tip().Projection()
	require.EqualValues(t, 7, tb.QuorumThreshold, "W=9, Q=7")
}

func TestCoupledFixtureCarriesAWeightedCandidateTheBodyBinds(t *testing.T) {
	f := New(t, Options{Assignment: true})
	require.NotEmpty(t, f.Candidate)
	require.NotNil(t, f.Successor)
	var total uint64
	for _, v := range f.Successor.Validators {
		total += v.Stake
	}
	require.EqualValues(t, 9, total, "the EVM set mirrors the root weights")
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	_, err = h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
}
