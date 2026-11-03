package types

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func testLeaderState(t *testing.T, members, start, first uint64) *LeaderState {
	t.Helper()
	s, err := NewLeaderState(bytes.Repeat([]byte{7}, 32), 2, start, members, first)
	require.NoError(t, err)
	return s
}

func TestLeaderLag(t *testing.T) {
	d, err := LeaderLag(5)
	require.NoError(t, err)
	require.EqualValues(t, 24, d)
	_, err = LeaderLag(0)
	require.ErrorIs(t, err, ErrLeaderState)
	_, err = LeaderLag(math.MaxUint64)
	require.ErrorIs(t, err, ErrLeaderState)
}

func TestNewLeaderStateIsIndependentOfTheFirstChildRound(t *testing.T) {
	a, b := testLeaderState(t, 4, 100, 100), testLeaderState(t, 4, 100, 137)
	for _, s := range []*LeaderState{a, b} {
		require.Len(t, s.Records, 2)
		require.EqualValues(t, 99, s.Records[0].Round, "the floor is the anchor slot")
		require.Empty(t, s.Records[0].Voters)
		require.Empty(t, s.Records[1].Voters, "the first ordinary block has no ordinary QC")
	}
	for _, bad := range []func() error{
		func() error { _, err := NewLeaderState(make([]byte, 31), 2, 100, 4, 100); return err },
		func() error { _, err := NewLeaderState(make([]byte, 32), 2, 0, 4, 100); return err },
		func() error { _, err := NewLeaderState(make([]byte, 32), 2, 100, 4, 99); return err },
		func() error { _, err := NewLeaderState(make([]byte, 32), 2, 100, 0, 100); return err },
	} {
		require.ErrorIs(t, bad(), ErrLeaderState)
	}
}

func TestLeaderStateNextEvictsByRoundAndLeavesTheParent(t *testing.T) {
	s := testLeaderState(t, 4, 100, 100) // D = 20
	parent := s.Clone()
	child, err := s.Next(101, []byte{0b0111})
	require.NoError(t, err)
	require.Equal(t, parent, s, "the parent's ring is what forks and the frozen suffix read")
	require.Len(t, child.Records, 3)

	// gaps in numeric rounds need no entries: a jump keeps the newest record at or below head-D and every newer one
	far, err := child.Next(130, []byte{0b1011}) // 130-20 = 110: 101 is the newest at or below it
	require.NoError(t, err)
	require.Equal(t, []uint64{101, 130}, recordRounds(far))

	exact, err := far.Next(150, []byte{0b1101}) // 150-20 = 130: exactly the record at 130 is the floor
	require.NoError(t, err)
	require.Equal(t, []uint64{130, 150}, recordRounds(exact))

	_, err = exact.Next(150, []byte{1})
	require.ErrorIs(t, err, ErrLeaderState, "a round not above the last")
	_, err = exact.Next(151, []byte{0b10000})
	require.ErrorIs(t, err, ErrLeaderState, "a bit above the committee")
	_, err = exact.Next(151, []byte{1, 0})
	require.ErrorIs(t, err, ErrLeaderState, "a bitmap of the wrong length")
}

func recordRounds(s *LeaderState) (out []uint64) {
	for _, r := range s.Records {
		out = append(out, r.Round)
	}
	return out
}

func TestLeaderStateCapacityIsDPlusTwo(t *testing.T) {
	s := testLeaderState(t, 4, 100, 100)
	max := 0
	var err error
	for round := uint64(101); round < 300; round++ {
		s, err = s.Next(round, []byte{0b0111})
		require.NoError(t, err)
		require.NoError(t, s.Valid())
		max = len(s.Records)
		require.LessOrEqual(t, uint64(max), s.Lag+2)
	}
	require.EqualValues(t, s.Lag+1, max, "one record per round above head-D, and the newest at or below it")
}

func TestLeaderStateValidRefusals(t *testing.T) {
	cases := map[string]func(*LeaderState){
		"genesis":    func(s *LeaderState) { s.Genesis = s.Genesis[:31] },
		"start":      func(s *LeaderState) { s.Start = 0 },
		"lag":        func(s *LeaderState) { s.Lag++ },
		"no records": func(s *LeaderState) { s.Records = nil },
		"order":      func(s *LeaderState) { s.Records[1].Round = s.Records[0].Round },
		"bitmap":     func(s *LeaderState) { s.Records[1].Voters = []byte{0xFF} },
		"too long": func(s *LeaderState) {
			s.Records = nil
			for r := uint64(0); r < s.Lag+3; r++ {
				s.Records = append(s.Records, LeaderRecord{Round: r})
			}
		},
	}
	for name, mutate := range cases {
		s := testLeaderState(t, 4, 100, 100)
		mutate(s)
		require.ErrorIs(t, s.Valid(), ErrLeaderState, name)
		_, err := s.Digest()
		require.ErrorIs(t, err, ErrLeaderState, name)
		_, err = s.Next(1000, nil)
		require.ErrorIs(t, err, ErrLeaderState, name)
	}
	var none *LeaderState
	require.ErrorIs(t, none.Valid(), ErrLeaderState)
}

func TestLeaderStateSelect(t *testing.T) {
	s := testLeaderState(t, 4, 100, 100) // records 99, 100, no samples
	s, err := s.Next(105, []byte{0b0111})
	require.NoError(t, err)
	s, err = s.Next(108, []byte{0b1011})
	require.NoError(t, err)

	got, err := s.Select(99, 108, false)
	require.NoError(t, err)
	require.Nil(t, got, "a covered prefix with no sample: the full committee")
	got, err = s.Select(104, 108, false)
	require.NoError(t, err)
	require.Nil(t, got)
	got, err = s.Select(105, 108, false)
	require.NoError(t, err)
	require.Equal(t, []byte{0b0111}, got)
	got, err = s.Select(107, 108, false)
	require.NoError(t, err)
	require.Equal(t, []byte{0b0111}, got, "the newest record at or before the cutoff")
	got, err = s.Select(108, 108, false)
	require.NoError(t, err, "a committed head at the cutoff is enough, no later successor is needed")
	require.Equal(t, []byte{0b1011}, got)

	_, err = s.Select(109, 108, false)
	require.ErrorIs(t, err, ErrHistoryUnavailable, "above the head is unavailable, not covered empty")
	require.NotErrorIs(t, err, ErrHistoryRefused)
	_, err = s.Select(98, 108, false)
	require.ErrorIs(t, err, ErrHistoryRefused)
	require.NotErrorIs(t, err, ErrHistoryUnavailable)

	// sealed at 108: the terminal state proves no further sample, whatever later suffix header the head has
	_, err = s.Select(100, 109, false)
	require.ErrorIs(t, err, ErrLeaderState, "an unsealed head is its ring's last record")

	got, err = s.Select(5000, 108, true)
	require.NoError(t, err)
	require.Equal(t, []byte{0b1011}, got)
	got, err = s.Select(107, 4000, true)
	require.NoError(t, err)
	require.Equal(t, []byte{0b0111}, got, "below the seal the frozen ring answers as it did")
	_, err = s.Select(98, 4000, true)
	require.ErrorIs(t, err, ErrHistoryRefused)
}

func TestLeaderStateDigestBindsEveryField(t *testing.T) {
	base := func() *LeaderState {
		s, err := testLeaderState(t, 4, 100, 100).Next(105, []byte{0b0111})
		require.NoError(t, err)
		return s
	}
	want, err := base().Digest()
	require.NoError(t, err)
	for name, mutate := range map[string]func(*LeaderState){
		"genesis": func(s *LeaderState) { s.Genesis[0] ^= 1 },
		"epoch":   func(s *LeaderState) { s.Epoch++ },
		"start":   func(s *LeaderState) { s.Start++ },
		"round":   func(s *LeaderState) { s.Records[2].Round++ },
		"voters":  func(s *LeaderState) { s.Records[2].Voters = []byte{0b1011} },
		"floor":   func(s *LeaderState) { s.Records = s.Records[1:] },
	} {
		s := base()
		mutate(s)
		got, err := s.Digest()
		require.NoError(t, err, name)
		require.NotEqual(t, want, got, name)
	}
}

// Two children of one parent, as a fork executes them: neither shares a record or a bitmap with the other or with the parent, with spare
// capacity and across an eviction.
func TestLeaderStateSiblingsShareNothing(t *testing.T) {
	parent := testLeaderState(t, 4, 100, 100)
	parent, err := parent.Next(105, []byte{0b0111})
	require.NoError(t, err)
	snapshot := parent.Clone()
	for _, rounds := range [][2]uint64{{106, 107}, {300, 301}} { // the second pair evicts
		a, err := parent.Next(rounds[0], []byte{0b0111})
		require.NoError(t, err)
		b, err := parent.Next(rounds[1], []byte{0b1011})
		require.NoError(t, err)
		require.Equal(t, rounds[0], a.Records[len(a.Records)-1].Round, "the sibling's append did not overwrite it")
		require.Equal(t, []byte{0b0111}, a.Records[len(a.Records)-1].Voters)
		a.Records[0].Round = 1
		for i := range a.Records {
			if len(a.Records[i].Voters) != 0 {
				a.Records[i].Voters[0] = 0
			}
		}
		require.Equal(t, snapshot, parent)
		require.NotEqual(t, uint64(1), b.Records[0].Round)
		require.Equal(t, []byte{0b1011}, b.Records[len(b.Records)-1].Voters)
	}
	clone := parent.Clone()
	clone.Genesis[0] ^= 1
	clone.Records[1].Round = 1
	clone.Records[2].Voters[0] = 0
	require.Equal(t, snapshot, parent)
}

// The leaf's encoding is consensus: this vector changes only with a new policy. It covers the domain, field order and an absent bitmap, nil
// and empty being one encoding.
func TestLeaderStateDigestVector(t *testing.T) {
	s, err := testLeaderState(t, 4, 100, 100).Next(105, []byte{0b0111})
	require.NoError(t, err)
	got, err := s.Digest()
	require.NoError(t, err)
	require.Equal(t, "e6e9182784431d92fa3b6522bf96fb3cf9c13ebf3377f465bbb73bed7b9f9afa", hex.EncodeToString(got))
	empty := s.Clone()
	empty.Records[0].Voters = []byte{}
	require.ErrorIs(t, empty.Valid(), ErrLeaderState, "a record without a sample has one encoding")
	_, err = s.Next(106, []byte{})
	require.ErrorIs(t, err, ErrLeaderState)
	raw, err := types.Cbor.Marshal(s)
	require.NoError(t, err)
	var decoded LeaderState
	require.NoError(t, types.Cbor.Unmarshal(raw, &decoded))
	require.NoError(t, decoded.Valid(), "the codec keeps a record without a sample nil")
	again, err := decoded.Digest()
	require.NoError(t, err)
	require.Equal(t, got, again)
}

func TestLeaderBitmap(t *testing.T) {
	committee := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
	got, err := LeaderBitmap(committee, []string{"i", "a", "c"})
	require.NoError(t, err)
	require.Equal(t, []byte{0b101, 1}, got, "independent of the signers' order")
	_, err = LeaderBitmap(committee, []string{"a", "z"})
	require.ErrorIs(t, err, ErrLeaderState)
	_, err = LeaderBitmap([]string{"a", "c", "b", "d"}, []string{"a"})
	require.ErrorIs(t, err, ErrLeaderState, "the search finds this signer in an unsorted committee: only the order check refuses it")
	_, err = LeaderBitmap(committee, nil)
	require.ErrorIs(t, err, ErrLeaderState)
}
