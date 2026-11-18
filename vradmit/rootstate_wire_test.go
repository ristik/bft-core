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

// The Open step records the block that opened the stored attempt (VT-05b): an abort, a cooldown crossing or a new epoch's first block sets
// AttemptOpenRound and AttemptOpenUCTime to that block's; a block that opens nothing keeps them; they round-trip in the encoding.
func TestTheOpenStepRecordsTheAttemptsOpening(t *testing.T) {
	g := GenesisRootState(5, 4)
	require.Zero(t, g.AttemptOpenRound, "no block opened the genesis attempt")
	same, err := g.EndBlockAt(5, 50, 777, vrschema.ControlState{Kind: vrschema.CtlIdle}, 4)
	require.NoError(t, err)
	require.Zero(t, same.AttemptOpenRound, "an idle block of the genesis attempt opens nothing")
	aborted, err := g.EndBlockAt(5, 60, 888, vrschema.ControlState{Kind: vrschema.CtlAborted, Attempt: 0}, 4)
	require.NoError(t, err)
	require.EqualValues(t, 1, aborted.Backoff.Attempt)
	require.EqualValues(t, 60, aborted.AttemptOpenRound)
	require.EqualValues(t, 888, aborted.AttemptOpenUCTime)
	later, err := aborted.EndBlockAt(5, 61, 889, vrschema.ControlState{Kind: vrschema.CtlAborted, Attempt: 0}, 4)
	require.NoError(t, err)
	require.EqualValues(t, 60, later.AttemptOpenRound, "the same identity re-observed keeps its opening")
	cooled, err := aborted.EndBlockAt(5, 160, 999, vrschema.ControlState{Kind: vrschema.CtlPrepared, Attempt: 1, OrderedRound: 100}, 4)
	require.NoError(t, err)
	require.EqualValues(t, 2, cooled.Backoff.Attempt, "the cooldown crossing opens attempt 2")
	require.EqualValues(t, 160, cooled.AttemptOpenRound)
	epoch, err := cooled.EndBlockAt(6, 300, 1500, vrschema.ControlState{Kind: vrschema.CtlIdle}, 4)
	require.NoError(t, err)
	require.EqualValues(t, 6, epoch.Backoff.Epoch)
	require.EqualValues(t, 300, epoch.AttemptOpenRound, "a new epoch's attempt 0 opens at its first block")
	raw, err := epoch.Encode()
	require.NoError(t, err)
	back, err := DecodeRootState(raw)
	require.NoError(t, err)
	require.EqualValues(t, 300, back.AttemptOpenRound)
	require.EqualValues(t, 1500, back.AttemptOpenUCTime)
	again, err := back.Encode()
	require.NoError(t, err)
	require.Equal(t, raw, again)
}
