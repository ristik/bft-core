package vradmit

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The executor's fields of the root state (VT-05a part 2): the acknowledged result, the Prepare's UC time and the staged Boundary round
// trip canonically; a staged bitmap or commitment without a staged body and result is refused; GENESIS_RESULT is acknowledged at genesis;
// the Prepare's UC time goes with the attempt.
func TestRootStateExecutorFields(t *testing.T) {
	w := newWorld(t)
	g := GenesisRootState(5, 4)
	require.Equal(t, vrschema.GenesisResult, g.Acknowledged)
	s := g
	s.PrepareUCTime = 77
	s.StagedBody, s.StagedResult, s.StagedBitmap = [32]byte{1}, w.r, 0b101
	var err error
	s.StagedSupport, err = s.StagedSupport.Add(w.commitment(w.j[3], vrschema.RuleID("a")))
	require.NoError(t, err)
	raw, err := s.Encode()
	require.NoError(t, err)
	back, err := DecodeRootState(raw)
	require.NoError(t, err)
	require.Equal(t, s.StagedBody, back.StagedBody)
	require.Equal(t, s.StagedResult, back.StagedResult)
	require.Equal(t, s.StagedBitmap, back.StagedBitmap)
	require.Equal(t, s.StagedSupport, back.StagedSupport)
	require.EqualValues(t, 77, back.PrepareUCTime)
	gd, err := g.Digest()
	require.NoError(t, err)
	sd, err := s.Digest()
	require.NoError(t, err)
	require.NotEqual(t, gd, sd, "every field is committed")

	bad := g
	bad.StagedBitmap = 1
	_, err = bad.Encode()
	require.ErrorIs(t, err, ErrRootState)
	bad = g
	bad.StagedBody = [32]byte{1}
	_, err = bad.Encode()
	require.ErrorIs(t, err, ErrRootState, "a staged body without its result")

	p, err := g.ApplyPrepare(5, 0, 1234)
	require.NoError(t, err)
	require.EqualValues(t, 1234, p.PrepareUCTime)
	_, err = g.ApplyPrepare(5, 1, 1234)
	require.Error(t, err, "a Prepare of an attempt the state has not opened")
	next, err := p.EndBlock(5, 100, vrschema.ControlState{Kind: vrschema.CtlAborted, Attempt: 0}, 4)
	require.NoError(t, err)
	require.EqualValues(t, 1, next.Backoff.Attempt)
	require.Zero(t, next.PrepareUCTime, "reset with the attempt")
}
