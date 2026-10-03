package consensus

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// skewed committee: "heavy" weighs 6, three light nodes weigh 1 each. Total 9, threshold 7. heavy+1 light is a minority
// by count (2 of 4) and a quorum by weight; the three light nodes are a majority by count and are not a quorum.
func skewedCommittee() weightedQuorum {
	return weightedQuorum{members: []*types.NodeInfo{{NodeID: "heavy", Stake: 6}, {NodeID: "l1", Stake: 1}, {NodeID: "l2", Stake: 1}, {NodeID: "l3", Stake: 1}}}
}

type skewedInfo struct{ weightedQuorum }

func (skewedInfo) GetQuorumThreshold() uint64 { return 7 }

func skewed() QuorumInfo { return profile2QuorumInfo{QuorumInfo: skewedInfo{skewedCommittee()}} }

type hugeInfo struct{ weightedQuorum }

func (hugeInfo) GetQuorumThreshold() uint64 { return math.MaxUint64 }

// two members whose weights do not add up in a uint64
func hugeCommittee() QuorumInfo {
	return profile2QuorumInfo{QuorumInfo: hugeInfo{weightedQuorum{members: []*types.NodeInfo{{NodeID: "a", Stake: math.MaxUint64 - 1}, {NodeID: "b", Stake: 2}}}}}
}

func TestVoteRegisterQCIsWeightedNotCounted(t *testing.T) {
	q := skewed()
	r := NewVoteRegister()
	for _, a := range []string{"l1", "l2", "l3"} {
		qc, err := r.InsertVote(NewDummyVote(t, a, 7, []byte{1}), q)
		require.NoError(t, err)
		require.Nil(t, qc, "3 of 4 votes by count carry 3 of 9 by weight")
	}
	qc, err := r.InsertVote(NewDummyVote(t, "heavy", 7, []byte{1}), q)
	require.NoError(t, err)
	require.NotNil(t, qc)

	r = NewVoteRegister()
	_, err = r.InsertVote(NewDummyVote(t, "l1", 7, []byte{1}), q)
	require.NoError(t, err)
	qc, err = r.InsertVote(NewDummyVote(t, "heavy", 7, []byte{1}), q)
	require.NoError(t, err)
	require.NotNil(t, qc, "2 of 4 votes by count carry 7 of 9 by weight")
}

func TestVoteRegisterTCIsWeightedNotCounted(t *testing.T) {
	q := skewed()
	r := NewVoteRegister()
	for i, a := range []string{"l1", "l2", "l3"} {
		tc, w, err := r.InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, a), q)
		require.NoError(t, err)
		require.Nil(t, tc)
		require.EqualValues(t, i+1, w)
	}
	tc, w, err := r.InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, "heavy"), q)
	require.NoError(t, err)
	require.NotNil(t, tc)
	require.EqualValues(t, 9, w)
}

func TestMaxFaultyWeightIsWeighted(t *testing.T) {
	// f = total - threshold = 9 - 7 = 2, not len-threshold
	require.EqualValues(t, 2, maxFaultyWeight(skewed()))
}

func TestVoteRegisterRefusesUnknownAuthorAndOverflow(t *testing.T) {
	_, err := NewVoteRegister().InsertVote(NewDummyVote(t, "stranger", 7, []byte{1}), skewed())
	require.ErrorIs(t, err, quorumweight.ErrUnknownSigner)
	_, _, err = NewVoteRegister().InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, "stranger"), skewed())
	require.ErrorIs(t, err, quorumweight.ErrUnknownSigner)

	r := NewVoteRegister()
	qc, err := r.InsertVote(NewDummyVote(t, "a", 7, []byte{1}), hugeCommittee())
	require.NoError(t, err)
	require.Nil(t, qc)
	_, err = r.InsertVote(NewDummyVote(t, "b", 7, []byte{1}), hugeCommittee())
	require.ErrorIs(t, err, quorumweight.ErrWeightOverflow)

	tr := NewVoteRegister()
	_, _, err = tr.InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, "a"), hugeCommittee())
	require.NoError(t, err)
	_, _, err = tr.InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, "b"), hugeCommittee())
	require.ErrorIs(t, err, quorumweight.ErrWeightOverflow)
}

func TestSignedWeightRefusesOverflowAndMaxFaultyOverflowNeverAmplifies(t *testing.T) {
	huge := hugeCommittee()
	votes := map[string]*abdrc.VoteMsg{"a": nil, "b": nil}
	_, err := bufferedVoteWeight(votes, huge)
	require.ErrorIs(t, err, quorumweight.ErrWeightOverflow)
	require.EqualValues(t, uint64(math.MaxUint64), maxFaultyWeight(huge), "a committee whose total overflows can never amplify")
}

func TestBufferedWeightUsesProfileWeights(t *testing.T) {
	trust := &types.RootTrustBaseV1{Version: 1, Epoch: 1, QuorumThreshold: 7,
		RootNodes: []*types.NodeInfo{{NodeID: "heavy", Stake: 6}, {NodeID: "l1", Stake: 1}, {NodeID: "l2", Stake: 1}, {NodeID: "l3", Stake: 1}}}
	m := &ConsensusManager{params: &Parameters{NetworkProfileVersion: storage.ProfileHandoff},
		voteBuffer: map[string]*abdrc.VoteMsg{"heavy": nil, "l1": nil}}
	m.trustBase.Store(trust)
	w, err := m.bufferedWeight()
	require.NoError(t, err)
	require.EqualValues(t, 7, w, "recovery trigger weighs the buffered votes by stake, not by count")
	require.True(t, reached(w, m.voteQuorumInfo()))

	m.voteBuffer = map[string]*abdrc.VoteMsg{"l1": nil, "l2": nil, "l3": nil}
	w, err = m.bufferedWeight()
	require.NoError(t, err)
	require.EqualValues(t, 3, w)
	require.False(t, reached(w, m.voteQuorumInfo()), "three light votes are a count majority but not a weight quorum")
}

func TestCheckWeightEpochRefusesOtherEpoch(t *testing.T) {
	m := &ConsensusManager{params: &Parameters{}}
	m.trustBase.Store(&types.RootTrustBaseV1{Version: 1, Epoch: 2})
	require.NoError(t, m.checkWeightEpoch(2))
	require.ErrorIs(t, m.checkWeightEpoch(1), ErrVoteEpoch)
}

func TestVoteRegisterTCFormsFromHeavyPlusOneLightMinorityByCount(t *testing.T) {
	// 2 of 4 timeout votes by count, 7 of 9 by weight; both arrival orders, with the heavy vote last and first
	for _, order := range [][]string{{"l1", "heavy"}, {"heavy", "l1"}} {
		r := NewVoteRegister()
		tc, w, err := r.InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, order[0]), skewed())
		require.NoError(t, err)
		require.Nil(t, tc, "%s alone is below the threshold", order[0])
		tc, w, err = r.InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, order[1]), skewed())
		require.NoError(t, err)
		require.NotNil(t, tc, "order %v", order)
		require.EqualValues(t, 7, w)
	}
}

func TestPacemakerTimeoutAmplificationIsByWeight(t *testing.T) {
	newPM := func(t *testing.T) *Pacemaker {
		pm, err := NewPacemaker(8*time.Second, 10*time.Second, observability.Default(t))
		require.NoError(t, err)
		t.Cleanup(pm.Stop)
		pm.Reset(context.Background(), 6, nil, nil)
		return pm
	}
	inTimeout := func(pm *Pacemaker) bool { return pm.status.Load() == uint32(pmsRoundTimeout) }

	// f = total - threshold = 2: two light timeout votes (2 of 4 by count) weigh 2, which is not more than f
	pm := newPM(t)
	for _, a := range []string{"l1", "l2"} {
		tc, err := pm.RegisterTimeoutVote(context.Background(), NewDummyTimeoutVote(nil, 7, a), skewed())
		require.NoError(t, err)
		require.Nil(t, tc)
		require.False(t, inTimeout(pm), "weight at most f must not move the pacemaker to the timeout state")
	}
	tc, err := pm.RegisterTimeoutVote(context.Background(), NewDummyTimeoutVote(nil, 7, "l3"), skewed())
	require.NoError(t, err)
	require.Nil(t, tc)
	require.True(t, inTimeout(pm), "three light votes weigh 3 > f: the quorum is no longer possible, jump to timeout")

	// a single heavy vote (1 of 4 by count, which a count rule would call at most f=1) weighs 6 > f
	pm = newPM(t)
	tc, err = pm.RegisterTimeoutVote(context.Background(), NewDummyTimeoutVote(nil, 7, "heavy"), skewed())
	require.NoError(t, err)
	require.Nil(t, tc)
	require.True(t, inTimeout(pm))

	// a committee whose total overflows never amplifies
	pm = newPM(t)
	_, err = pm.RegisterTimeoutVote(context.Background(), NewDummyTimeoutVote(nil, 7, "a"), hugeCommittee())
	require.NoError(t, err)
	require.False(t, inTimeout(pm))
}

func TestVoteRegisterDuplicateRefusalsAreSentinels(t *testing.T) {
	r := NewVoteRegister()
	_, err := r.InsertVote(NewDummyVote(t, "l1", 7, []byte{1}), skewed())
	require.NoError(t, err)
	_, err = r.InsertVote(NewDummyVote(t, "l1", 7, []byte{1}), skewed())
	require.ErrorIs(t, err, quorumweight.ErrDuplicateSigner)

	_, _, err = r.InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, "l1"), skewed())
	require.NoError(t, err)
	_, _, err = r.InsertTimeoutVote(NewDummyTimeoutVote(nil, 7, "l1"), skewed())
	require.ErrorIs(t, err, quorumweight.ErrDuplicateSigner)
}
