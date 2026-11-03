package consensus

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	test "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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
	got, err := newEpochLeader(policies, 3, 5, nodes, func() (Leader, error) { built++; return want, nil }, nil)
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
		}, nil)
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
		l, err := newEpochLeader(policies, 4, 17, nodes, func() (Leader, error) { return nil, errors.New("legacy") }, nil)
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
	_, err := newEpochLeader(&fakePolicies{err: sentinel}, 2, 5, nodes, legacy, nil)
	require.ErrorIs(t, err, sentinel, "missing policy history")

	_, err = newEpochLeader(&fakePolicies{policy: "root-wrr-v9"}, 2, 5, nodes, legacy, nil)
	require.ErrorIs(t, err, ErrLeaderPolicy, "unknown policy")

	weighted := &fakePolicies{policy: trustbase.LeaderPolicyWeightedV1}
	_, err = newEpochLeader(weighted, 2, 0, nodes, legacy, nil)
	require.ErrorIs(t, err, leader.ErrInvalidStart)
	_, err = newEpochLeader(weighted, 2, 5, nil, legacy, nil)
	require.ErrorIs(t, err, leader.ErrNoMembers)
	zero := policyCommittee(t, 1, 0, 1)
	_, err = newEpochLeader(weighted, 2, 5, zero, legacy, nil)
	require.ErrorIs(t, err, leader.ErrInvalidWeight)
}

type fakeSigning struct {
	cfg votesig.Config
	err error
}

func (f fakeSigning) SigningConfig(uint64) (votesig.Config, error) { return f.cfg, f.err }

// The policy's one constructor, and rev's conditions on it: only under the handoff profile, where votes are weighed by stake, with an
// anchor's genesis to bind the ring to, and only under scheme 2, where a QC's signature keys are verified voters.
func TestEpochLeaderReputationConditions(t *testing.T) {
	nodes := policyCommittee(t, 3, 2, 2, 2, 2)
	trust := &types.RootTrustBaseV1{RootNodes: nodes, QuorumThreshold: 8}
	anchor := &rctypes.EpochAnchor{GenesisID: make([]byte, 32), Epoch: 2, Slot: 39, StateRoot: make([]byte, 32)}
	store := func() *storage.BlockStore { return nil }
	scheme2 := fakeSigning{cfg: votesig.Config{Scheme: votesig.SchemeDomainBound}}
	policies := &fakePolicies{policy: trustbase.LeaderPolicyReputationV1}
	build := func(profile uint64, a *rctypes.EpochAnchor, signing signingConfigs) func() (Leader, error) {
		return func() (Leader, error) { return reputationLeader(profile, a, trust, signing, store) }
	}
	got, err := newEpochLeader(policies, 2, 40, nodes, nil, build(storage.ProfileHandoff, anchor, scheme2))
	require.NoError(t, err)
	require.IsType(t, &leader.EpochReputation{}, got)

	_, err = newEpochLeader(policies, 2, 40, nodes, nil, build(storage.ProfileLegacy, anchor, scheme2))
	require.ErrorIs(t, err, ErrReputationProfile, "votes count one each outside the handoff profile")
	_, err = newEpochLeader(policies, 1, 1, nodes, nil, build(storage.ProfileHandoff, nil, scheme2))
	require.ErrorIs(t, err, ErrReputationProfile, "the genesis epoch has no anchor")
	_, err = newEpochLeader(policies, 2, 40, nodes, nil, build(storage.ProfileHandoff, anchor, fakeSigning{cfg: votesig.Config{Scheme: votesig.SchemeLegacy}}))
	require.ErrorIs(t, err, ErrReputationScheme, "scheme 1 QCs can carry unverified signature keys")
	sentinel := errors.New("no history")
	_, err = newEpochLeader(policies, 2, 40, nodes, nil, build(storage.ProfileHandoff, anchor, fakeSigning{err: sentinel}))
	require.ErrorIs(t, err, sentinel, "an unknown scheme is not assumed")
}

func TestTrustLeaderInputs(t *testing.T) {
	nodes := policyCommittee(t, 1, 1, 1, 1)
	for name, tc := range map[string]struct {
		policy string
		want   bool
	}{"reputation": {trustbase.LeaderPolicyReputationV1, true}, "weighted": {trustbase.LeaderPolicyWeightedV1, false}, "legacy": {trustbase.LeaderPolicyLegacy, false}} {
		committee, reputation, err := trustLeaderInputs{store: &fakeInputStore{fakePolicies: fakePolicies{policy: tc.policy}, nodes: nodes}}.LeaderCommittee(2)
		require.NoError(t, err, name)
		require.Equal(t, tc.want, reputation, name)
		if tc.want {
			require.True(t, slices.IsSorted(committee), "canonical order, whatever the trust base's")
			require.Len(t, committee, 4)
		} else {
			require.Empty(t, committee, name)
		}
	}
	sentinel := errors.New("no history")
	_, _, err := trustLeaderInputs{store: &fakeInputStore{fakePolicies: fakePolicies{err: sentinel}}}.LeaderCommittee(2)
	require.ErrorIs(t, err, sentinel)
}

type fakeInputStore struct {
	fakePolicies
	nodes []*types.NodeInfo
}

func (f *fakeInputStore) GetByEpoch(uint64) (*types.RootTrustBaseV1, error) {
	reversed := slices.Clone(f.nodes)
	slices.SortFunc(reversed, func(a, b *types.NodeInfo) int { return strings.Compare(b.NodeID, a.NodeID) })
	return &types.RootTrustBaseV1{RootNodes: reversed}, nil
}
