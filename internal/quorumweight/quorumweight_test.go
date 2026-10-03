package quorumweight

import (
	"crypto"
	"errors"
	"math"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
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
	for total := uint64(1); total <= 64; total++ { // the bound is total - threshold and never wraps
		f, err = FaultyBound(total)
		require.NoError(t, err)
		th, _ := Threshold(total)
		require.Equal(t, total-th, f)
	}
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

	// D3 / v1 legacy acceptance: an invalid signature of a KNOWN member is skipped and counts for nothing
	tb.bad["l2"] = true
	w, err = VerifySigned(tb, nil, sigs("heavy", "l1", "l2"))
	require.NoError(t, err)
	require.EqualValues(t, 7, w)
	_, err = VerifySigned(tb, nil, sigs("heavy", "l2"))
	require.ErrorIs(t, err, ErrQuorumNotReached, "the skipped signature carries no weight")

	_, err = VerifySigned(tb, nil, nil)
	require.ErrorIs(t, err, ErrQuorumNotReached)

	tb.threshold = 0
	_, err = VerifySigned(tb, nil, sigs("heavy"))
	require.ErrorIs(t, err, ErrZeroWeight)
}

func TestVerifySignedStrict(t *testing.T) {
	tb := &fakeTB{stake: map[string]uint64{"heavy": 6, "l1": 1, "l2": 1, "l3": 1}, bad: map[string]bool{}, threshold: 7}
	_, err := VerifySignedStrict(tb, nil, sigs("heavy", "l1"))
	require.NoError(t, err)
	_, err = VerifySignedStrict(tb, nil, sigs("heavy", "l1", "nobody"))
	require.ErrorIs(t, err, ErrUnknownSigner)

	tb.bad["l2"] = true
	_, err = VerifySignedStrict(tb, nil, sigs("heavy", "l1", "l2"))
	require.ErrorIs(t, err, ErrInvalidSignature)
	require.NotErrorIs(t, err, ErrUnknownSigner)
}

func TestVerifySignedRefusesOverflow(t *testing.T) {
	tb := &fakeTB{stake: map[string]uint64{"a": math.MaxUint64, "b": 1}, bad: map[string]bool{}, threshold: 2}
	_, err := VerifySigned(tb, nil, sigs("a", "b"))
	require.ErrorIs(t, err, ErrWeightOverflow)
}

func TestVerifySignedWithoutMemberListClassifiesFailureAsInvalid(t *testing.T) {
	tb := &fakeTB{stake: map[string]uint64{}, bad: map[string]bool{}, threshold: 1}
	_, err := VerifySignedStrict(tb, nil, sigs("x"))
	require.ErrorIs(t, err, ErrInvalidSignature, "with no member list a failed lookup cannot be called unknown")
	require.NotErrorIs(t, err, ErrUnknownSigner)
	_, err = VerifySigned(tb, nil, sigs("x"))
	require.ErrorIs(t, err, ErrQuorumNotReached, "legacy acceptance: skipped, then the quorum is not reached")
}

// realTrust is a v1 trust base of real secp256k1 members with the given stakes and the threshold 2W/3+1.
func realTrust(t *testing.T, stakes map[string]uint64, threshold uint64) (*types.RootTrustBaseV1, map[string]abcrypto.Signer) {
	t.Helper()
	signers := map[string]abcrypto.Signer{}
	var nodes []*types.NodeInfo
	for id, stake := range stakes {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		signers[id] = s
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: stake})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	return &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 1, RootNodes: nodes, QuorumThreshold: threshold}, signers
}

func sealSignedBy(t *testing.T, signers map[string]abcrypto.Signer, ids ...string) *types.UnicitySeal {
	t.Helper()
	seal := &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 3, Epoch: 1, Timestamp: types.GenesisTime + 1, Hash: []byte{1}}
	for _, id := range ids {
		require.NoError(t, seal.Sign(id, signers[id]))
	}
	return seal
}

func TestCheckedRoutesGoBaseSealVerificationThroughTheCheckedSum(t *testing.T) {
	tb, signers := realTrust(t, map[string]uint64{"heavy": 6, "l1": 1, "l2": 1, "l3": 1}, 7)
	stranger, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	signers["stranger"] = stranger

	good := sealSignedBy(t, signers, "heavy", "l1")
	require.NoError(t, good.Verify(Checked(tb)), "heavy plus one light node is a weight quorum")
	require.ErrorIs(t, sealSignedBy(t, signers, "l1", "l2", "l3").Verify(Checked(tb)), ErrQuorumNotReached)

	// go-base skips a signature of a non-member; the wrapper refuses the whole seal
	withStranger := sealSignedBy(t, signers, "heavy", "l1", "stranger")
	require.NoError(t, withStranger.Verify(tb), "unwrapped go-base verifier silently ignores the stranger")
	require.ErrorIs(t, withStranger.Verify(Checked(tb)), ErrUnknownSigner)

	// v1 legacy acceptance is kept: a known member's invalid signature is skipped
	bad := sealSignedBy(t, signers, "heavy", "l1", "l2")
	bad.Signatures["l2"] = []byte{1, 2, 3}
	require.NoError(t, bad.Verify(Checked(tb)))

	// a test double (anything but the production *RootTrustBaseV1) is passed through
	d := testDouble{}
	require.Equal(t, types.RootTrustBase(d), Checked(d))
}

func TestCheckedRefusesWeightOverflowThatGoBaseWraps(t *testing.T) {
	tb, signers := realTrust(t, map[string]uint64{"a": math.MaxUint64 - 1, "b": math.MaxUint64 - 1}, 5)
	seal := sealSignedBy(t, signers, "a", "b")
	require.NoError(t, seal.Verify(tb), "go-base wraps the sum around and still reaches the threshold")
	require.ErrorIs(t, seal.Verify(Checked(tb)), ErrWeightOverflow)
}

func TestVerifyTrustBaseLineage(t *testing.T) {
	prev, signers := realTrust(t, map[string]uint64{"heavy": 6, "l1": 1, "l2": 1, "l3": 1}, 7)
	stranger, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	signers["stranger"] = stranger
	sign := func(tb *types.RootTrustBaseV1, ids ...string) *types.RootTrustBaseV1 {
		bs, err := tb.SigBytes()
		require.NoError(t, err)
		tb.Signatures = map[string]hex.Bytes{}
		for _, id := range ids {
			sig, err := signers[id].SignBytes(bs)
			require.NoError(t, err)
			tb.Signatures[id] = sig
		}
		return tb
	}

	// genesis epoch: self-signed by its own members
	require.NoError(t, VerifyTrustBase(sign(prev, "heavy", "l1"), nil))
	require.ErrorIs(t, VerifyTrustBase(sign(prev, "l1", "l2", "l3"), nil), ErrQuorumNotReached)
	require.NoError(t, sign(prev, "heavy", "l1", "stranger").Verify(nil), "go-base ignores the stranger")
	require.ErrorIs(t, VerifyTrustBase(sign(prev, "heavy", "l1", "stranger"), nil), ErrUnknownSigner)

	// successor: signed by the previous epoch's validators
	sign(prev, "heavy", "l1")
	prevHash, err := prev.Hash(crypto.SHA256)
	require.NoError(t, err)
	next := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 2, EpochStart: 10, RootNodes: prev.RootNodes,
		QuorumThreshold: 7, PreviousEntryHash: prevHash}
	require.NoError(t, VerifyTrustBase(sign(next, "heavy", "l2"), prev))
	require.ErrorIs(t, VerifyTrustBase(sign(next, "l1", "l2"), prev), ErrQuorumNotReached)
	require.ErrorIs(t, VerifyTrustBase(sign(next, "heavy", "l2", "stranger"), prev), ErrUnknownSigner)
	require.Error(t, VerifyTrustBase(sign(next, "heavy", "l2"), nil), "a successor needs its predecessor")
	next.EpochStart = prev.EpochStart // structural check of go-base IsValid still applies
	require.Error(t, VerifyTrustBase(sign(next, "heavy", "l2"), prev))
}

type testDouble struct{ types.RootTrustBase }
