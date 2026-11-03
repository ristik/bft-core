package leader

import (
	"bytes"
	"math"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	test "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

var erGenesis = bytes.Repeat([]byte{7}, 32)

func erNodes(t *testing.T, weights ...uint64) []*types.NodeInfo {
	t.Helper()
	ids := test.GeneratePeerIDs(t, len(weights))
	nodes := make([]*types.NodeInfo, len(weights))
	for i := range weights {
		nodes[i] = &types.NodeInfo{NodeID: ids[i].String(), Stake: weights[i]}
	}
	return nodes
}

func erSelector(t *testing.T, nodes []*types.NodeInfo, start, quorum uint64, head *LeaderHead) *EpochReputation {
	t.Helper()
	e, err := NewEpochReputation(erGenesis, 2, start, quorum, nodes, func() (LeaderHead, error) { return *head, nil })
	require.NoError(t, err)
	return e
}

func erRing(t *testing.T, n, start uint64, records ...rctypes.LeaderRecord) *rctypes.LeaderState {
	t.Helper()
	s, err := rctypes.NewLeaderState(erGenesis, 2, start, n, start)
	require.NoError(t, err)
	for _, r := range records {
		s, err = s.Next(r.Round, r.Voters)
		require.NoError(t, err)
	}
	return s
}

func TestEpochReputationBootstrapIsTheFullCommittee(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1)
	head := LeaderHead{Round: 99}
	e := erSelector(t, nodes, 100, 4, &head)
	full, err := NewWeighted(100, nodes)
	require.NoError(t, err)
	for r := uint64(100); r < 100+24; r++ { // D = 24 for five members: timed-out rounds count, no history is read
		got, err := e.GetLeaderForRound(r)
		require.NoError(t, err, r)
		want, err := full.GetLeaderForRound(r)
		require.NoError(t, err)
		require.Equal(t, want, got, r)
	}
	_, err = e.GetLeaderForRound(99)
	require.ErrorIs(t, err, ErrBeforeStart)
	_, err = e.GetLeaderForRound(124)
	require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable, "the first round after the bootstrap is normal and reads history")
}

func TestEpochReputationRecoveryRunsAreDistributed(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1)
	head := LeaderHead{Round: 99}
	e := erSelector(t, nodes, 100, 4, &head)
	first := uint64(100 + 24)
	var runs []peer.ID
	for period := uint64(0); period < 6; period++ {
		base := first + period*RecoverySpacing
		// the period's normal rounds read history; with none it is unavailable, never a member
		for _, r := range []uint64{base, base + RecoverySpacing - RecoveryRun - 1} {
			_, err := e.GetLeaderForRound(r)
			require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable, "round %d", r)
		}
		runStart := base + RecoverySpacing - RecoveryRun
		l, err := e.GetLeaderForRound(runStart)
		require.NoError(t, err, "a recovery run needs no history")
		for i := uint64(1); i < RecoveryRun; i++ {
			got, err := e.GetLeaderForRound(runStart + i)
			require.NoError(t, err)
			require.Equal(t, l, got, "four consecutive rounds of one member")
		}
		runs = append(runs, l)
	}
	require.Equal(t, runs[0], runs[5], "n*S covers every member and repeats")
	seen := map[peer.ID]bool{}
	for _, l := range runs[:5] {
		seen[l] = true
	}
	require.Len(t, seen, 5, "every member has a run")
	for i, n := range sortedIDs(t, nodes) {
		require.Equal(t, n, runs[i], "in canonical order")
	}
}

func sortedIDs(t *testing.T, nodes []*types.NodeInfo) []peer.ID {
	t.Helper()
	w, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	return w.members
}

func TestEpochReputationRecoveryLeadershipIgnoresHistory(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1)
	start := uint64(100)
	run := start + 24 + RecoverySpacing - RecoveryRun
	head := LeaderHead{Round: 99}
	e := erSelector(t, nodes, start, 4, &head)
	without, err := e.GetLeaderForRound(run)
	require.NoError(t, err)
	head = LeaderHead{Round: run - 1, State: erRing(t, 5, start, rctypes.LeaderRecord{Round: run - 24 - 1, Voters: []byte{0b01111}})}
	with, err := e.GetLeaderForRound(run)
	require.NoError(t, err)
	require.Equal(t, without, with, "local availability must not change a leader")
}

func TestEpochReputationNormalRoundsUseTheCutoffSample(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1)
	ids := sortedIDs(t, nodes)
	start := uint64(100)
	bitmap := byte(0b01111) // everyone but ids[4]
	head := LeaderHead{Round: 200, State: erRing(t, 5, start,
		rctypes.LeaderRecord{Round: 150, Voters: []byte{0b11111}},
		rctypes.LeaderRecord{Round: 180, Voters: []byte{bitmap}},
		rctypes.LeaderRecord{Round: 200, Voters: []byte{bitmap}})}
	e := erSelector(t, nodes, start, 4, &head)
	active := make([]*types.NodeInfo, 0, 4)
	for _, n := range nodes {
		if n.NodeID != ids[4].String() {
			active = append(active, n)
		}
	}
	want, err := NewWeighted(start, active)
	require.NoError(t, err)
	for r := uint64(180 + 24); r <= 200+24; r++ {
		got, err := e.GetLeaderForRound(r)
		require.NoError(t, err, r)
		require.NotEqual(t, ids[4], got, "an absent member outside its run: round %d", r)
		wantLeader, err := want.GetLeaderForRound(r)
		require.NoError(t, err)
		require.Equal(t, wantLeader, got, "a table from zero priorities at A at numeric round %d: nothing carries across bitmaps", r)
	}
	full, err := NewWeighted(start, nodes)
	require.NoError(t, err)
	got, err := e.GetLeaderForRound(179 + 24) // the cutoff's sample is the full committee
	require.NoError(t, err)
	wantFull, err := full.GetLeaderForRound(179 + 24)
	require.NoError(t, err)
	require.Equal(t, wantFull, got)

	_, err = e.GetLeaderForRound(201 + 24)
	require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable, "a cutoff above the head")
}

func TestEpochReputationCoveredEmptyPrefixDiffersFromUnavailable(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1)
	head := LeaderHead{Round: 130, State: erRing(t, 5, 100)} // committed through 130, no carrier after the first child
	head.State.Records = append(head.State.Records, rctypes.LeaderRecord{Round: 130})
	e := erSelector(t, nodes, 100, 4, &head)
	full, err := NewWeighted(100, nodes)
	require.NoError(t, err)
	got, err := e.GetLeaderForRound(125) // cutoff 101
	require.NoError(t, err)
	want, err := full.GetLeaderForRound(125)
	require.NoError(t, err)
	require.Equal(t, want, got)
	_, err = e.GetLeaderForRound(131 + 24)
	require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable)
}

func TestEpochReputationARingOfAnotherEpochIsNotHistory(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1)
	start := uint64(100)
	other, err := rctypes.NewLeaderState(bytes.Repeat([]byte{9}, 32), 1, 50, 5, 50)
	require.NoError(t, err)
	other, err = other.Next(99, []byte{0b01111})
	require.NoError(t, err)
	sameEpoch, err := rctypes.NewLeaderState(bytes.Repeat([]byte{9}, 32), 2, 50, 5, 50)
	require.NoError(t, err)
	sameEpoch, err = sameEpoch.Next(99, []byte{0b01111})
	require.NoError(t, err)
	for name, ring := range map[string]*rctypes.LeaderState{"other epoch": other, "same epoch, other genesis": sameEpoch} {
		// the installed anchor: its committed head keeps the outgoing root, ring and terminal control state; no child is committed
		head := LeaderHead{Round: 99, State: ring, Sealed: true}
		e := erSelector(t, nodes, start, 4, &head)
		_, err := e.GetLeaderForRound(start + 24)
		require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable, name)
	}
	head := LeaderHead{Round: 99}
	e := erSelector(t, nodes, start, 4, &head)
	_, err = e.GetLeaderForRound(start + 24)
	require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable, "no ring at all")
}

func TestEpochReputationSealedRingAnswersAboveItsHead(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1)
	head := LeaderHead{Round: 5000, Sealed: true, State: erRing(t, 5, 100, rctypes.LeaderRecord{Round: 200, Voters: []byte{0b01111}})}
	e := erSelector(t, nodes, 100, 4, &head)
	_, err := e.GetLeaderForRound(5000 + 10000)
	require.NoError(t, err, "no further sample can exist: the closing block's is the last")
	unsealed := LeaderHead{Round: 200, State: head.State}
	e = erSelector(t, nodes, 100, 4, &unsealed)
	_, err = e.GetLeaderForRound(201 + 24)
	require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable)
}

func TestEpochReputationNonQuorateSampleIsInvalid(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1)
	head := LeaderHead{Round: 200, State: erRing(t, 5, 100, rctypes.LeaderRecord{Round: 200, Voters: []byte{0b00111}})}
	e := erSelector(t, nodes, 100, 4, &head)
	_, err := e.GetLeaderForRound(200 + 24)
	require.ErrorIs(t, err, ErrInvalidSample)
	head.State.Members = 6
	head.State.Lag = 28
	_, err = e.GetLeaderForRound(200 + 24)
	require.ErrorIs(t, err, ErrInvalidSample, "a ring of another committee size")
}

func TestEpochReputationWeightedActiveSetKeepsOriginalWeights(t *testing.T) {
	nodes := erNodes(t, 3, 2, 2, 2, 2)
	ids := sortedIDs(t, nodes)
	heavy := -1
	for i, id := range ids {
		for _, n := range nodes {
			if n.NodeID == id.String() && n.Stake == 3 {
				heavy = i
			}
		}
	}
	bitmap := byte(0b11111) &^ (1 << heavy)
	head := LeaderHead{Round: 200, State: erRing(t, 5, 100, rctypes.LeaderRecord{Round: 200, Voters: []byte{bitmap}})}
	e := erSelector(t, nodes, 100, 8, &head)
	got, err := e.GetLeaderForRound(200 + 24)
	require.NoError(t, err, "weight 8 of 11 is a responsive quorum")
	require.NotEqual(t, ids[heavy], got)
}

func TestEpochReputationCacheNeverChangesAnAnswer(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1, 1, 1, 1)
	start := uint64(100)
	bitmaps := []byte{}
	for b := 0; b < 128; b++ {
		if popcount(byte(b)) >= 5 {
			bitmaps = append(bitmaps, byte(b))
		}
	}
	require.Greater(t, len(bitmaps), activeTableCache, "more active sets than the cache holds")
	head := LeaderHead{Round: 200}
	e := erSelector(t, nodes, start, 5, &head)
	answer := func(b byte, r uint64) peer.ID {
		head.State = erRing(t, 7, start, rctypes.LeaderRecord{Round: 200, Voters: []byte{b}})
		l, err := e.GetLeaderForRound(r)
		require.NoError(t, err)
		return l
	}
	r := uint64(200 + 32)
	// the answer of each active set comes from its own NewWeighted over exactly its members: a cache that collapsed two sets into one
	// table could only be seen against a reference that shares nothing with it
	want := make(map[byte]peer.ID)
	distinct := map[peer.ID]bool{}
	for _, b := range bitmaps {
		var active []*types.NodeInfo
		for i, id := range sortedIDs(t, nodes) {
			if b&(1<<i) != 0 {
				for _, n := range nodes {
					if n.NodeID == id.String() {
						active = append(active, n)
					}
				}
			}
		}
		table, err := NewWeighted(start, active)
		require.NoError(t, err)
		want[b], err = table.GetLeaderForRound(r)
		require.NoError(t, err)
		distinct[want[b]] = true
	}
	require.Greater(t, len(distinct), 1, "the sets must disagree at this round, or a shared table would pass")
	for _, b := range bitmaps {
		require.Equal(t, want[b], answer(b, r), "bitmap %07b", b)
	}
	require.LessOrEqual(t, len(e.active), activeTableCache)
	for i := len(bitmaps) - 1; i >= 0; i-- { // the opposite order, the far-evicted ones rebuilt
		require.Equal(t, want[bitmaps[i]], answer(bitmaps[i], r), "bitmap %07b", bitmaps[i])
	}
}

func popcount(b byte) (n int) {
	for ; b != 0; b &= b - 1 {
		n++
	}
	return n
}

func TestEpochReputationUpdateIsBenign(t *testing.T) {
	head := LeaderHead{Round: 99}
	e := erSelector(t, erNodes(t, 1, 1, 1, 1), 100, 3, &head)
	require.NoError(t, e.Update(nil, 5000, nil), "missing history belongs to the lookup, never to Update")
	require.NoError(t, e.UpdateWithTrustBase(nil, 5000))
}

func TestEpochReputationConstructionRefusals(t *testing.T) {
	nodes := erNodes(t, 1, 1, 1, 1)
	head := func() (LeaderHead, error) { return LeaderHead{}, nil }
	_, err := NewEpochReputation(erGenesis, 2, 100, 3, nodes, nil)
	require.ErrorIs(t, err, ErrInvalidSample)
	_, err = NewEpochReputation(erGenesis, 2, 100, 0, nodes, head)
	require.ErrorIs(t, err, ErrInvalidSample)
	_, err = NewEpochReputation(erGenesis, 2, 0, 3, nodes, head)
	require.ErrorIs(t, err, ErrInvalidStart)
	_, err = NewEpochReputation(erGenesis, 2, 100, 3, nil, head)
	require.ErrorIs(t, err, ErrNoMembers)
	_, err = NewEpochReputation(erGenesis, 2, math.MaxUint64-1, 3, nodes, head)
	require.ErrorIs(t, err, ErrInvalidStart, "start + D overflows")
}
