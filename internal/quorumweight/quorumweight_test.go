package quorumweight

import (
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

func TestThreshold(t *testing.T) {
	for total, want := range map[uint64]uint64{1: 1, 2: 2, 3: 3, 4: 3, 9: 7, 10: 7, 100: 67} {
		got, err := Threshold(total)
		require.NoError(t, err)
		require.Equal(t, want, got, "total %d", total)
	}
	_, err := Threshold(0)
	require.ErrorIs(t, err, ErrZeroWeight)
	_, err = Threshold(math.MaxUint64/2 + 1)
	require.ErrorIs(t, err, ErrWeightOverflow)
	got, err := Threshold(math.MaxUint64 / 2)
	require.NoError(t, err)
	require.Equal(t, uint64(math.MaxUint64/2)*2/3+1, got)
}

func TestFaultyBound(t *testing.T) {
	f, err := FaultyBound(9)
	require.NoError(t, err)
	require.EqualValues(t, 2, f)
	f, err = FaultyBound(1)
	require.NoError(t, err)
	require.EqualValues(t, 0, f)
	_, err = FaultyBound(0)
	require.ErrorIs(t, err, ErrZeroWeight)
}

func TestTallyRefusesDuplicateAndOverflowAndStaysUnchanged(t *testing.T) {
	var tally Tally
	require.NoError(t, tally.Add("a", math.MaxUint64-1))
	require.ErrorIs(t, tally.Add("a", 1), ErrDuplicateSigner)
	require.ErrorIs(t, tally.Add("b", 2), ErrWeightOverflow)
	require.EqualValues(t, uint64(math.MaxUint64-1), tally.Weight())
	require.NoError(t, tally.Add("b", 1), "the refused signer was not recorded")
	require.EqualValues(t, uint64(math.MaxUint64), tally.Weight())
}

func TestReachedZeroThreshold(t *testing.T) {
	require.False(t, Reached(5, 0))
	require.True(t, Reached(5, 5))
	require.False(t, Reached(4, 5))
}

func TestTotalWeight(t *testing.T) {
	total, err := TotalWeight([]*types.NodeInfo{{NodeID: "a", Stake: 6}, {NodeID: "b", Stake: 1}})
	require.NoError(t, err)
	require.EqualValues(t, 7, total)
	_, err = TotalWeight([]*types.NodeInfo{{NodeID: "a", Stake: 1}, {NodeID: "a", Stake: 1}})
	require.ErrorIs(t, err, ErrDuplicateSigner)
	_, err = TotalWeight([]*types.NodeInfo{{NodeID: "a", Stake: math.MaxUint64}, {NodeID: "b", Stake: 1}})
	require.ErrorIs(t, err, ErrWeightOverflow)
	_, err = TotalWeight(nil)
	require.ErrorIs(t, err, ErrZeroWeight)
	_, err = TotalWeight([]*types.NodeInfo{nil})
	require.ErrorIs(t, err, ErrUnknownSigner)
}

type fakeTB struct {
	stake     map[string]uint64
	bad       map[string]bool
	threshold uint64
	calls     int
}

func (f *fakeTB) GetQuorumThreshold() uint64 { return f.threshold }
func (f *fakeTB) GetRootNodes() []*types.NodeInfo {
	var out []*types.NodeInfo
	for id, s := range f.stake {
		out = append(out, &types.NodeInfo{NodeID: id, Stake: s})
	}
	return out
}
func (f *fakeTB) VerifySignature(_ []byte, _ []byte, id string) (uint64, error) {
	f.calls++
	s, ok := f.stake[id]
	if !ok {
		return 0, errors.New("not in trust base")
	}
	if f.bad[id] {
		return 0, errors.New("bad signature")
	}
	return s, nil
}

func sigs(ids ...string) map[string]hex.Bytes {
	m := map[string]hex.Bytes{}
	for _, id := range ids {
		m[id] = []byte{1}
	}
	return m
}

func TestVerifySigned(t *testing.T) {
	tb := &fakeTB{stake: map[string]uint64{"heavy": 6, "l1": 1, "l2": 1, "l3": 1}, bad: map[string]bool{}, threshold: 7}

	w, err := VerifySigned(tb, nil, sigs("heavy", "l1"))
	require.NoError(t, err)
	require.EqualValues(t, 7, w)

	_, err = VerifySigned(tb, nil, sigs("l1", "l2", "l3"))
	require.ErrorIs(t, err, ErrQuorumNotReached)
	require.EqualError(t, err, "quorum not reached, signed_votes=3 quorum_threshold=7")

	_, err = VerifySigned(tb, nil, sigs("heavy", "l1", "nobody"))
	require.ErrorIs(t, err, ErrUnknownSigner)

	tb.bad["l2"] = true
	_, err = VerifySigned(tb, nil, sigs("heavy", "l1", "l2"))
	require.ErrorIs(t, err, ErrInvalidSignature)
	require.NotErrorIs(t, err, ErrUnknownSigner)

	_, err = VerifySigned(tb, nil, nil)
	require.ErrorIs(t, err, ErrQuorumNotReached)

	tb.threshold = 0
	_, err = VerifySigned(tb, nil, sigs("heavy"))
	require.ErrorIs(t, err, ErrZeroWeight)
}

func TestVerifySignedRefusesOverflow(t *testing.T) {
	tb := &fakeTB{stake: map[string]uint64{"a": math.MaxUint64, "b": 1}, bad: map[string]bool{}, threshold: 2}
	_, err := VerifySigned(tb, nil, sigs("a", "b"))
	require.ErrorIs(t, err, ErrWeightOverflow)
}
