package rootrecords

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustBlock(t *testing.T, s State, e, r uint64) State {
	t.Helper()
	n, err := s.Block(e, r)
	require.NoError(t, err)
	return n
}

func mustCommit(t *testing.T, s State, h, next, first uint64, assignment bool) State {
	t.Helper()
	n, err := s.Commit(h, next, first, assignment, id32(byte(next)))
	require.NoError(t, err)
	return n
}

func prog(t *testing.T, s State, round uint64) uint64 {
	t.Helper()
	p, err := s.Progress(round)
	require.NoError(t, err)
	return p
}

func TestStateProgressAndFreeze(t *testing.T) {
	s := NewState(1, 1)
	require.Zero(t, prog(t, s, 1))
	require.EqualValues(t, 49, prog(t, s, 50))
	s = mustCommit(t, s, 100, 2, 101, true)
	require.EqualValues(t, 99, prog(t, s, 100), "frozen at the endpoint p(1,100)")
	before := s.Digest()
	s = mustBlock(t, s, 1, 130) // an old-epoch suffix block moves nothing
	require.EqualValues(t, 99, prog(t, s, 130))
	s = mustBlock(t, s, 2, 100) // a successor block before its first round
	require.EqualValues(t, 99, prog(t, s, 100))
	require.Equal(t, before, s.Digest(), "blocks that are not ordinary progress leave the committed digest alone")
	s = mustBlock(t, s, 2, 105)
	require.False(t, s.Frozen)
	require.EqualValues(t, 104, prog(t, s, 105), "offset 100 + (105 - 101)")
	require.NotEqual(t, before, s.Digest())
	// an ordinary block of the current epoch does not change the digest either
	after := s.Digest()
	s = mustBlock(t, s, 2, 106)
	require.Equal(t, after, s.Digest())
}

func TestStateRefusals(t *testing.T) {
	s := NewState(1, 5)
	_, err := s.Block(1, 4) // before the epoch's first round
	require.ErrorIs(t, err, ErrProgress)
	_, err = s.Block(2, 10) // another epoch before any H
	require.ErrorIs(t, err, ErrProgress)
	for name, c := range map[string]struct{ h, next, first uint64 }{
		"successor epoch not later":  {9, 1, 20},
		"no first round":             {9, 2, 0},
		"activation not after H":     {9, 2, 9},
		"H before the epoch started": {3, 2, 20},
	} {
		_, err := s.Commit(c.h, c.next, c.first, true, id32(1))
		require.ErrorIs(t, err, ErrProgress, name)
	}
	f := mustCommit(t, s, 9, 2, 20, true)
	_, err = f.Commit(9, 3, 30, true, id32(1))
	require.ErrorIs(t, err, ErrProgress, "H twice")
	// a refused step leaves the value unchanged
	before := s.Bytes()
	_, _ = s.Commit(3, 2, 20, true, id32(1))
	require.Equal(t, before, s.Bytes())
}

func TestStateAckReadsTheOffsetsFixedAtCommit(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	s = mustBlock(t, s, 2, 140) // the EVM acknowledges later, in a successor block
	n, r, err := s.Ack(140, 1_100, id32(1), id32(2), 1)
	require.NoError(t, err)
	require.Equal(t, KindAck, r.Kind)
	require.EqualValues(t, 100, payloadWord(r, 1), "H round")
	require.EqualValues(t, 100, payloadWord(r, 2), "offset p(1,100)+1")
	require.EqualValues(t, 101, payloadWord(r, 3), "first round")
	require.EqualValues(t, 139, r.Progress, "anchored at the progress of the acknowledging block")
	require.EqualValues(t, 1_100, r.UCTime)
	require.Empty(t, n.Pending)
	require.EqualValues(t, 1, n.Count)
	require.Equal(t, r.ID, n.Tip)
	require.NoError(t, Verify([]Record{r}))
	_, _, err = n.Ack(141, 1_101, id32(1), id32(2), 1)
	require.ErrorIs(t, err, ErrNoPending)
}

func TestStateAckInTheFrozenWindowAnchorsAtTheEndpoint(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	_, r, err := s.Ack(100, 1_050, id32(1), id32(2), 1)
	require.NoError(t, err)
	require.EqualValues(t, 99, r.Progress)
}

func TestStateRecoveryAckDerivesBothOffsets(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true) // J
	s = mustBlock(t, s, 2, 120)
	s = mustCommit(t, s, 130, 3, 131, true) // K, ordered in J's epoch
	s = mustBlock(t, s, 3, 135)
	_, r, err := s.Ack(135, 1_100, id32(1), id32(2), 2)
	require.NoError(t, err)
	require.Equal(t, KindRecoveryAck, r.Kind)
	want := []uint64{0, 0, 100, 101, 130, 130, 131, 3, 2}
	for i := 2; i < 9; i++ {
		require.EqualValues(t, want[i], payloadWord(r, i), "word %d", i)
	}
	require.Equal(t, id32(2), [32]byte(r.Data[32:64]))
	require.EqualValues(t, 134, r.Progress)
}

func TestStatePendingNamesTheRetainedCandidates(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	s = mustBlock(t, s, 2, 120)
	s = mustCommit(t, s, 130, 3, 131, true)
	require.Equal(t, []PendingH{
		{Epoch: 1, HRound: 100, Offset: 100, First: 101, RootEpoch: 2, BodyID: id32(2)},
		{Epoch: 2, HRound: 130, Offset: 130, First: 131, RootEpoch: 3, BodyID: id32(3)},
	}, s.Pending)
}

func TestStateRootOnlyHandoffAdvancesProgressWithoutAPendingAck(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, false)
	require.Empty(t, s.Pending)
	s = mustBlock(t, s, 2, 105)
	require.EqualValues(t, 104, prog(t, s, 105))
	_, _, err := s.Ack(105, 1_020, id32(1), id32(2), 1)
	require.ErrorIs(t, err, ErrNoPending)
}

func TestStateAtMostAPrimaryAndItsRecoveryArePending(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	s = mustBlock(t, s, 2, 120)
	s = mustCommit(t, s, 130, 3, 131, true)
	s = mustBlock(t, s, 3, 140)
	_, err := s.Commit(150, 4, 151, true, id32(4))
	require.ErrorIs(t, err, ErrProgress)
}

func TestStateRecordsLinkAndKeepAnchorsMonotone(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	s = mustBlock(t, s, 2, 110)
	s1, r1, err := s.Ack(110, 1_100, id32(1), id32(2), 1)
	require.NoError(t, err)
	s1 = mustCommit(t, mustBlock(t, s1, 2, 120), 150, 3, 151, true)
	s1 = mustBlock(t, s1, 3, 155)
	s2, r2, err := s1.Ack(155, 1_200, id32(3), id32(4), 2)
	require.NoError(t, err)
	require.Equal(t, r1.ID, r2.Predecessor)
	require.EqualValues(t, 1, r2.Index)
	require.NoError(t, Verify([]Record{r1, r2}))
	require.Equal(t, r2.ID, s2.Tip)
	// a UC time below the last record's is refused, not rewritten
	late := mustCommit(t, mustBlock(t, s2, 3, 160), 170, 4, 171, true)
	_, _, err = late.Ack(171, 900, id32(5), id32(6), 3)
	require.ErrorIs(t, err, ErrMonotonic)
	// a progress below the last record's is refused
	low := s2
	low.LastProgress = 1 << 40
	low.Pending = []PendingH{{Epoch: 3, HRound: 1, Offset: 1, First: 2, RootEpoch: 4}}
	_, _, err = low.Ack(180, 1_300, id32(5), id32(6), 3)
	require.ErrorIs(t, err, ErrMonotonic)
	// a record before any UC time cannot be anchored
	zero := NewState(1, 1)
	zero.Pending = []PendingH{{Epoch: 1, HRound: 2, Offset: 3, First: 4, RootEpoch: 2}}
	_, _, err = zero.Ack(5, 0, id32(1), id32(2), 1)
	require.ErrorIs(t, err, ErrNoUCTime)
}

func TestStateEncodingRoundTripsAndIsCanonical(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	s = mustBlock(t, s, 2, 110)
	s, _, err := s.Ack(110, 1_100, id32(1), id32(2), 1)
	require.NoError(t, err)
	s = mustCommit(t, s, 150, 3, 151, true)
	for _, st := range []State{NewState(7, 3), s} {
		got, err := DecodeState(st.Bytes())
		require.NoError(t, err)
		require.Equal(t, st.Bytes(), got.Bytes())
		require.Equal(t, st.Digest(), got.Digest())
	}
	require.NotEqual(t, NewState(1, 1).Digest(), s.Digest())
}

func TestDecodeStateRefusals(t *testing.T) {
	good := NewState(1, 1)
	bad := map[string]State{
		"first round zero":                 {Epoch: 1},
		"frozen without successor":         {Epoch: 1, First: 1, Frozen: true},
		"successor without H":              {Epoch: 1, First: 1, NextEpoch: 2},
		"offset not endpoint plus 1":       {Epoch: 1, First: 1, Frozen: true, Endpoint: 5, NextEpoch: 2, NextOffset: 9, NextFirst: 3},
		"three pending":                    {Epoch: 1, First: 1, Pending: make([]PendingH, 3)},
		"count without a tip":              {Epoch: 1, First: 1, Count: 2},
		"pending beyond the current epoch": {Epoch: 1, First: 1, Pending: []PendingH{{Epoch: 1, HRound: 3, Offset: 3, First: 9, RootEpoch: 5, BodyID: id32(1)}}},
		"tip without a count":              {Epoch: 1, First: 1, Tip: id32(1)},
	}
	for name, st := range bad {
		_, err := DecodeState(st.Bytes())
		require.ErrorIs(t, err, ErrState, name)
	}
	enc := good.Bytes()
	for name, data := range map[string][]byte{"trailing": append(append([]byte(nil), enc...), 0), "truncated": enc[:len(enc)-1], "empty": nil} {
		_, err := DecodeState(data)
		require.ErrorIs(t, err, ErrState, name)
	}
}

// The root's State and the registry-side Tracker are two implementations of one rule: every valid event sequence must give them the
// same progress at every ordinary round.
func TestStateAgreesWithTheTrackerOnRandomEventSequences(t *testing.T) {
	for seed := int64(1); seed <= 300; seed++ {
		rng := rand.New(rand.NewSource(seed))
		first := uint64(1 + rng.Intn(5))
		s, tr := NewState(1, first), NewGenesis(1, first)
		epoch, round := uint64(1), first
		for step := 0; step < 40; step++ {
			switch {
			case s.Frozen:
				// a suffix block of the old epoch first, half the time: no progress
				if rng.Intn(2) == 0 {
					ns, err := s.Block(epoch, round+uint64(rng.Intn(3)))
					require.NoError(t, err)
					s = ns
				}
				epoch, round = s.NextEpoch, s.NextFirst+uint64(rng.Intn(4))
				ns, err := s.Block(epoch, round)
				require.NoError(t, err)
				require.NoError(t, tr.Observe(epoch, round))
				s = ns
			case rng.Intn(5) == 0:
				h := round + uint64(rng.Intn(3))
				nextFirst := h + 1 + uint64(rng.Intn(5))
				ns, err := s.Commit(h, epoch+1, nextFirst, false, [32]byte{})
				require.NoError(t, err)
				_, err = tr.OrderH(h, epoch+1, nextFirst)
				require.NoError(t, err)
				s = ns
				round = h
			default:
				round += uint64(1 + rng.Intn(4))
				ns, err := s.Block(epoch, round)
				require.NoError(t, err)
				require.NoError(t, tr.Observe(epoch, round))
				s = ns
			}
			got, err := s.Progress(round)
			require.NoError(t, err)
			require.Equal(t, tr.Progress(), got, "seed %d step %d", seed, step)
		}
	}
}

func TestStateProgressOverflowIsRefusedAndLeavesTheValue(t *testing.T) {
	const max = ^uint64(0)
	s := NewState(1, 1)
	s.Offset = max - 1
	before := s.Bytes()
	_, err := s.Block(1, 3) // offset + 2 wraps
	require.ErrorIs(t, err, ErrProgress)
	_, err = s.Progress(3)
	require.ErrorIs(t, err, ErrProgress)
	_, err = s.Commit(3, 2, 10, true, id32(1)) // p(1,3) = max+1 wraps
	require.ErrorIs(t, err, ErrProgress)
	require.Equal(t, before, s.Bytes())
	// p(e,h) = max leaves no successor offset
	_, err = s.Commit(2, 2, 10, true, id32(1))
	require.ErrorIs(t, err, ErrProgress)
	// the last representable progress is fine
	ok, err := s.Block(1, 2)
	require.NoError(t, err)
	require.EqualValues(t, max, prog(t, ok, 2))
	// a successor whose offset leaves no room
	f := NewState(1, 1)
	f.Frozen, f.Endpoint, f.NextEpoch, f.NextOffset, f.NextFirst = true, max-1, 2, max, 5
	_, err = f.Block(2, 6)
	require.ErrorIs(t, err, ErrProgress)
	g, err := f.Block(2, 5)
	require.NoError(t, err)
	require.EqualValues(t, max, prog(t, g, 5))
}

func TestDecodeStateRefusesANonShortestInteger(t *testing.T) {
	enc := NewState(1, 1).Bytes()
	// the version 1 follows the text string; write it as 18 01
	i := bytes.Index(enc, []byte(stateDomain)) + len(stateDomain)
	require.Equal(t, byte(0x01), enc[i])
	bad := append(append(append([]byte(nil), enc[:i]...), 0x18, 0x01), enc[i+1:]...)
	_, err := DecodeState(bad)
	require.ErrorIs(t, err, ErrState)
	_, err = DecodeState(enc)
	require.NoError(t, err)
}

func closureData(epoch uint64) []byte {
	a, h, r, e, k := id32(1), id32(2), id32(3), id32(4), id32(5)
	return concat(a[:], word(100), h[:], r[:], e[:], k[:])
}

func TestStateAwaitsTheClosureOfAnEpochAnAssignmentHandoffEnded(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	require.Empty(t, s.Awaiting, "H alone ends nothing: the epoch's last block may still be ordered")
	s = mustBlock(t, s, 1, 130) // suffix block
	require.Empty(t, s.Awaiting)
	s = mustBlock(t, s, 2, 105) // the first successor block
	require.Equal(t, []Awaiting{{Epoch: 1, HRound: 100}}, s.Awaiting)
	again := mustBlock(t, s, 2, 106)
	require.Equal(t, s.Bytes(), again.Bytes())

	// a root-only handoff ends an epoch whose assignment continues: nothing awaits
	r := mustCommit(t, NewState(1, 1), 100, 2, 101, false)
	r = mustBlock(t, r, 2, 105)
	require.Empty(t, r.Awaiting)

	// a primary and its recovery each end an epoch
	k := mustCommit(t, s, 150, 3, 151, true)
	k = mustBlock(t, k, 3, 155)
	require.Equal(t, []Awaiting{{Epoch: 1, HRound: 100}, {Epoch: 2, HRound: 150}}, k.Awaiting)
	round, ok := k.HRoundAwaiting(2)
	require.True(t, ok)
	require.EqualValues(t, 150, round)
	_, ok = k.HRoundAwaiting(3)
	require.False(t, ok)
}

func TestStateCloseProjectsOnceAtTheCarryingBlock(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	s = mustBlock(t, s, 2, 105)
	n, r, err := s.Close(1, closureData(1), 105, 1_500)
	require.NoError(t, err)
	require.Equal(t, KindClosure, r.Kind)
	require.EqualValues(t, 104, r.Progress, "p_close: the progress of the block that carries the closure")
	require.EqualValues(t, 1_500, r.UCTime)
	require.Empty(t, n.Awaiting)
	require.EqualValues(t, 1, n.Count)
	require.NoError(t, Verify([]Record{r}))
	_, _, err = n.Close(1, closureData(1), 106, 1_501)
	require.ErrorIs(t, err, ErrNotAwaiting, "a repeat is no second record")
	_, _, err = s.Close(2, closureData(2), 105, 1_500)
	require.ErrorIs(t, err, ErrNotAwaiting, "an epoch no handoff ended")
	_, _, err = s.Close(1, closureData(1)[:191], 105, 1_500)
	require.ErrorIs(t, err, ErrPayload)
	_, _, err = s.Close(1, closureData(1), 105, 0)
	require.ErrorIs(t, err, ErrNoUCTime)
}

func TestStateAwaitingEncodingAndRefusals(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	s = mustBlock(t, s, 2, 105)
	got, err := DecodeState(s.Bytes())
	require.NoError(t, err)
	require.Equal(t, s.Awaiting, got.Awaiting)
	_, err = DecodeState(State{Epoch: 3, First: 1, Awaiting: []Awaiting{{Epoch: 2, HRound: 5}, {Epoch: 1, HRound: 4}}}.Bytes())
	require.ErrorIs(t, err, ErrState, "descending")
	_, err = DecodeState(State{Epoch: 3, First: 1, Awaiting: []Awaiting{{Epoch: 1, HRound: 5}, {Epoch: 1, HRound: 4}}}.Bytes())
	require.ErrorIs(t, err, ErrState, "duplicate")
}
