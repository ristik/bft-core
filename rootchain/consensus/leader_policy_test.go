package consensus

import (
	"errors"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	test "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

type fakePolicies struct {
	policy string
	err    error
	asked  []uint64
}

func (f *fakePolicies) LeaderPolicy(epoch uint64) (string, error) {
	f.asked = append(f.asked, epoch)
	return f.policy, f.err
}

func policyCommittee(t *testing.T, weights ...uint64) []*types.NodeInfo {
	t.Helper()
	ids := test.GeneratePeerIDs(t, len(weights))
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = id.String()
	}
	sort.Strings(names)
	nodes := make([]*types.NodeInfo, len(weights))
	for i := range weights {
		nodes[i] = &types.NodeInfo{NodeID: names[i], Stake: weights[i]}
	}
	return nodes
}

// Nothing is active: the legacy selector is built, once, for the epoch that was asked for.
func TestEpochLeaderLegacyPolicyKeepsTheLegacySelector(t *testing.T) {
	nodes := policyCommittee(t, 1, 1, 1, 1)
	built := 0
	want, err := newBootstrapLeader(&bootstrapLeader{}, 5, nodes)
	require.NoError(t, err)
	policies := &fakePolicies{policy: trustbase.LeaderPolicyLegacy}
	got, err := newEpochLeader(policies, 3, 5, nodes, func() (Leader, error) { built++; return want, nil })
	require.NoError(t, err)
	require.Same(t, want, got)
	require.Equal(t, 1, built)
	require.Equal(t, []uint64{3}, policies.asked)
}

// Unit weights under root-wrr-v1 reproduce today's handoff schedule exactly: the golden sequence is the rotation members
// 0,1,2,3,... from the start round, the same leaders newBootstrapLeader returns for every round of the epoch.
func TestEpochLeaderUnitWeightsReproduceTheLegacyHandoffSchedule(t *testing.T) {
	nodes := policyCommittee(t, 1, 1, 1, 1)
	const start = 40
	legacy, err := newBootstrapLeader(&bootstrapLeader{}, start, nodes)
	require.NoError(t, err)
	got, err := newEpochLeader(&fakePolicies{policy: trustbase.LeaderPolicyWeightedV1}, 2, start, nodes,
		func() (Leader, error) {
			t.Fatal("the legacy selector is not built for an activated epoch")
			return nil, nil
		})
	require.NoError(t, err)
	require.IsType(t, &leader.Weighted{}, got)
	for r := uint64(start); r < start+101; r++ {
		a, err := legacy.GetLeaderForRound(r)
		require.NoError(t, err)
		b, err := got.GetLeaderForRound(r)
		require.NoError(t, err)
		require.Equal(t, a, b, "round %d", r)
	}
	// golden: the canonical order, repeated
	for i := uint64(0); i < 12; i++ {
		id, err := got.GetLeaderForRound(start + i)
		require.NoError(t, err)
		require.Equal(t, nodes[i%4].NodeID, id.String())
	}
}

// A restart (or a second construction from the same authenticated inputs) yields the same schedule whatever the first
// instance was asked, and the heavy committee differs from the legacy rotation, so the dispatch is not a no-op.
func TestEpochLeaderRestartReplaysTheSameSchedule(t *testing.T) {
	nodes := policyCommittee(t, 6, 1, 1, 1)
	policies := &fakePolicies{policy: trustbase.LeaderPolicyWeightedV1}
	build := func() Leader {
		l, err := newEpochLeader(policies, 4, 17, nodes, func() (Leader, error) { return nil, errors.New("legacy") })
		require.NoError(t, err)
		return l
	}
	live := build()
	for r := uint64(17); r < 17+60; r += 7 { // a live node sees an uneven sample of rounds
		_, err := live.GetLeaderForRound(r)
		require.NoError(t, err)
	}
	restarted := build()
	legacy, err := newBootstrapLeader(&bootstrapLeader{}, 17, nodes)
	require.NoError(t, err)
	differs := false
	for r := uint64(17 + 80); r >= 17; r-- {
		a, err := live.GetLeaderForRound(r)
		require.NoError(t, err)
		b, err := restarted.GetLeaderForRound(r)
		require.NoError(t, err)
		require.Equal(t, a, b, "round %d", r)
		if l, _ := legacy.GetLeaderForRound(r); l != a {
			differs = true
		}
	}
	require.True(t, differs, "the weighted schedule is not the unit rotation")
}

func TestEpochLeaderRefusesWithoutFallback(t *testing.T) {
	nodes := policyCommittee(t, 1, 1, 1)
	legacy := func() (Leader, error) { t.Fatal("no fallback to the legacy selector"); return nil, nil }

	sentinel := errors.New("no history")
	_, err := newEpochLeader(&fakePolicies{err: sentinel}, 2, 5, nodes, legacy)
	require.ErrorIs(t, err, sentinel, "missing policy history")

	_, err = newEpochLeader(&fakePolicies{policy: "root-wrr-v9"}, 2, 5, nodes, legacy)
	require.ErrorIs(t, err, ErrLeaderPolicy, "unknown policy")

	weighted := &fakePolicies{policy: trustbase.LeaderPolicyWeightedV1}
	_, err = newEpochLeader(weighted, 2, 0, nodes, legacy)
	require.ErrorIs(t, err, leader.ErrInvalidStart)
	_, err = newEpochLeader(weighted, 2, 5, nil, legacy)
	require.ErrorIs(t, err, leader.ErrNoMembers)
	zero := policyCommittee(t, 1, 0, 1)
	_, err = newEpochLeader(weighted, 2, 5, zero, legacy)
	require.ErrorIs(t, err, leader.ErrInvalidWeight)
}
