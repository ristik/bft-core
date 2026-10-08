package consensus

import (
	"context"
	"math/big"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// Q4 #399: the weighted epoch's committed ProtocolConfig selects root-wrr-v1 as part of the one Q3 activation. These tests run the
// real activation, journal and restart paths of the Q3 harness; no test seam records a policy.

// referenceSchedule is an independent statement of the root-wrr-v1 rule: priorities zero before the start round, each round every
// priority grows by its weight, the greatest leads (ties: the smallest node ID) and loses the total.
func referenceSchedule(nodes []*types.NodeInfo, start uint64, rounds int) []string {
	ids := make([]string, len(nodes))
	weight := map[string]*big.Int{}
	total := new(big.Int)
	for i, n := range nodes {
		ids[i] = n.NodeID
		weight[n.NodeID] = new(big.Int).SetUint64(n.Stake)
		total.Add(total, weight[n.NodeID])
	}
	sort.Strings(ids)
	prio := map[string]*big.Int{}
	for _, id := range ids {
		prio[id] = new(big.Int)
	}
	out := make([]string, 0, rounds)
	for i := 0; i < rounds; i++ {
		best := ids[0]
		for _, id := range ids {
			prio[id].Add(prio[id], weight[id])
		}
		for _, id := range ids {
			if prio[id].Cmp(prio[best]) > 0 {
				best = id
			}
		}
		prio[best].Sub(prio[best], total)
		out = append(out, best)
	}
	return out
}

func scheduleOf(t *testing.T, l Leader, from uint64, rounds int) []string {
	t.Helper()
	out := make([]string, 0, rounds)
	for r := from; r < from+uint64(rounds); r++ {
		id, err := l.GetLeaderForRound(r)
		require.NoError(t, err, "round %d", r)
		out = append(out, id.String())
	}
	return out
}

// requireWeightedEpoch is the activation premise for one replica: the installed epoch's selector is the weighted one, started at
// A* with zero priorities, and its schedule is the reference one for the epoch's committed weights.
func requireWeightedEpoch(t *testing.T, r *q3Replica, epoch, start uint64) {
	t.Helper()
	tb := r.manager.trustBase.Load()
	require.EqualValues(t, epoch, tb.Epoch)
	require.IsType(t, &leader.Weighted{}, r.manager.leaderSelector, "the committed tuple selects root-wrr-v1")
	policy, err := r.trust.LeaderPolicy(epoch)
	require.NoError(t, err)
	require.Equal(t, tbstore.LeaderPolicyWeightedV1, policy)
	const rounds = 54
	require.Equal(t, referenceSchedule(tb.RootNodes, start, rounds), scheduleOf(t, r.manager.leaderSelector, start, rounds))
	_, err = r.manager.leaderSelector.GetLeaderForRound(start - 1)
	require.ErrorIs(t, err, leader.ErrBeforeStart, "the schedule has no position before A*")
}

func TestPolicyNamesOfTheTupleAndTheStoreAreOne(t *testing.T) {
	require.Equal(t, q3format.LeaderPolicyWeightedV1, tbstore.LeaderPolicyWeightedV1)
	require.Equal(t, q3format.LeaderPolicyLegacy, tbstore.LeaderPolicyLegacy)
	require.Equal(t, tbstore.LeaderPolicyWeightedV1, q3format.Q3Config(5, [32]byte{1}).LeaderPolicy)
}

// The activation of the weighted epoch selects the weighted selector at A* on every replica, from the committed tuple alone, and the
// heavy member leads its weight's share of each nine rounds.
func TestQ3ActivationSelectsTheWeightedLeader(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	anchor := c.activateAll()
	start := anchor.Slot + 1
	require.EqualValues(t, 7, start)

	var first []string
	for _, r := range c.replicas {
		requireWeightedEpoch(t, r, 2, start)
		got := scheduleOf(t, r.manager.leaderSelector, start, 18)
		if first == nil {
			first = got
		}
		require.Equal(t, first, got, "every replica derives the same schedule")
	}
	heavy := c.heavy().id().String()
	for cycle := 0; cycle < 2; cycle++ {
		n := 0
		for _, id := range first[cycle*9 : cycle*9+9] {
			if id == heavy {
				n++
			}
		}
		require.Equal(t, 6, n, "the 6,1,1,1 heavy member leads six of every nine rounds")
	}
	// the genesis epoch keeps its history: legacy, and it is not the activated selector's
	old, err := c.heavy().trust.LeaderPolicy(1)
	require.NoError(t, err)
	require.Equal(t, tbstore.LeaderPolicyLegacy, old)
	_, err = c.heavy().trust.LeaderPolicy(3)
	require.ErrorIs(t, err, tbstore.ErrLeaderPolicyHistory, "an epoch the history does not hold has no policy, not a legacy one")
	require.ErrorIs(t, c.heavy().trust.ActivateLeaderPolicy(2, tbstore.LeaderPolicyWeightedV1), tbstore.ErrLeaderPolicyHistory,
		"the store takes the policy from the history, not from a call")
}

// Restarted startup rebuilds the same selector from the retained verified context and A*, never from the restored round: the
// priorities are zero at A* however far the chain has moved, and a node that restarts late agrees with one that did not.
func TestQ3ActivationRestartRebuildsTheScheduleFromAStar(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	anchor := c.activateAll()
	start := anchor.Slot + 1
	live := c.firstProposal(anchor.Slot)
	_ = live
	proposals := []*abdrc.ProposalMsg{c.proposal}
	for i := 0; i < 3; i++ {
		c.advance(&proposals)
	}
	want := scheduleOf(t, c.heavy().manager.leaderSelector, start, 40)

	for _, r := range c.replicas {
		r.restart()
		requireWeightedEpoch(t, r, 2, start)
		require.Equal(t, want, scheduleOf(t, r.manager.leaderSelector, start, 40), "a restart agrees with a node that did not restart")
	}
	// a first query far from A* on a cold selector replays from A*, not from the restored round
	r := c.replicas[1]
	r.restart()
	far, err := r.manager.leaderSelector.GetLeaderForRound(start + 35)
	require.NoError(t, err)
	require.Equal(t, want[35], far.String())
	near, err := r.manager.leaderSelector.GetLeaderForRound(start)
	require.NoError(t, err)
	require.Equal(t, want[0], near.String(), "an earlier round is the zero-priority one")
}

// A successor with changed weights resets: its schedule is the reference one for its own weights from its own A*, not a
// continuation of the previous epoch's priorities, and the policy of the earlier epochs stays what their entries committed.
func TestQ3ChangedWeightSuccessorResetsTheSchedule(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	c.activateAll()
	epoch2 := referenceSchedule(c.heavy().manager.trustBase.Load().RootNodes, 7, 9)
	second := q3fixture.New(t, q3fixture.Options{After: c.f, Weights: []uint64{1, 1, 6, 1}})
	ctx := context.Background()
	retained := c.replicas[:3]
	for _, r := range retained {
		r.restart()
		require.NoError(t, r.rt.Activate(ctx, secondBundle(second)))
		r.startConsensus()
	}
	start := retained[0].manager.epochAnchor.Slot + 1
	require.EqualValues(t, 15, start)
	for _, r := range retained {
		requireWeightedEpoch(t, r, 3, start)
		for epoch, want := range map[uint64]string{1: tbstore.LeaderPolicyLegacy, 2: tbstore.LeaderPolicyWeightedV1, 3: tbstore.LeaderPolicyWeightedV1} {
			got, err := r.trust.LeaderPolicy(epoch)
			require.NoError(t, err)
			require.Equal(t, want, got, "epoch %d keeps the policy its entry committed", epoch)
		}
	}
	// old-epoch suffix evidence cannot be taken by the successor's selector: the proposal is refused on its epoch before any lookup,
	// whatever its round (the epoch-2 rounds from A* on are the old suffix); the old epoch's own policy is kept in the history
	probe := &leaderProbe{Leader: retained[0].manager.leaderSelector}
	retained[0].manager.leaderSelector = probe
	for _, round := range []uint64{start - 1, start, start + 20} {
		err := retained[0].manager.validateProposalParent(&drctypes.BlockData{Epoch: 2, Round: round})
		require.ErrorContains(t, err, "outside installed epoch", "round %d", round)
	}
	require.Empty(t, probe.asked)
	retained[0].manager.leaderSelector = probe.Leader
	got := scheduleOf(t, retained[0].manager.leaderSelector, start, 9)
	require.NotEqual(t, epoch2, got, "the new weights are not a continuation of epoch 2")
	newHeavy := second.NewNodes[2].PeerConf.ID.String()
	n := 0
	for _, id := range got {
		if id == newHeavy {
			n++
		}
	}
	require.Equal(t, 6, n, "the new heavy member leads six of nine from A*")
}

// leaderProbe records the rounds the selector is asked for.
type leaderProbe struct {
	Leader
	mu    sync.Mutex
	asked []uint64
}

func (p *leaderProbe) GetLeaderForRound(round uint64) (peer.ID, error) {
	p.mu.Lock()
	p.asked = append(p.asked, round)
	p.mu.Unlock()
	return p.Leader.GetLeaderForRound(round)
}

func (p *leaderProbe) reset() {
	p.mu.Lock()
	p.asked = nil
	p.mu.Unlock()
}

func (p *leaderProbe) maxAsked() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Max(append([]uint64{0}, p.asked...))
}

// The weighted selector costs work proportional to the distance to the round it is asked for. A round that arrives in a message
// is therefore looked up only after the message's own round evidence is verified, on every path: a proposal's round must follow its
// certificate (checked before signature and lookup), a vote or timeout for a future round is buffered or answered from its
// certificates without asking the selector for the message's round.
func TestMessageRoundsAreEvidencedBeforeTheSelectorIsAsked(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	anchor := c.activateAll()
	c.firstProposal(anchor.Slot)
	proposals := []*abdrc.ProposalMsg{c.proposal}
	// the lightest-ordered member is the one that stays behind
	lights := slices.Clone(c.lights())
	sort.Slice(lights, func(i, j int) bool { return lights[i].id().String() < lights[j].id().String() })
	lag := lights[len(lights)-1]
	online := slices.DeleteFunc(slices.Clone(c.replicas), func(r *q3Replica) bool { return r == lag })
	all := c.replicas
	c.replicas = online
	for i := 0; i < 3; i++ {
		c.advance(&proposals)
	}
	c.replicas = all
	probe := &leaderProbe{Leader: lag.manager.leaderSelector}
	lag.manager.leaderSelector = probe
	ctx := context.Background()
	current := lag.manager.pacemaker.GetCurrentRound()
	latest := proposals[len(proposals)-1]
	require.Greater(t, latest.Block.Round, current+1, "premise: the member is several rounds behind")

	t.Run("a proposal whose round does not follow its certificate never reaches the selector", func(t *testing.T) {
		probe.reset()
		for _, round := range []uint64{latest.Block.Round + 1, 1 << 40, ^uint64(0)} {
			bad := *latest
			block := *latest.Block
			block.Round = round
			bad.Block = &block
			require.ErrorIs(t, lag.manager.onProposalMsg(ctx, &bad), abdrc.ErrRoundEvidence, "round %d", round)
		}
		require.Empty(t, probe.asked, "no leader lookup for an unjustified round")
	})

	t.Run("a certified proposal ahead of the member triggers recovery before any lookup of its round", func(t *testing.T) {
		probe.reset()
		require.Error(t, lag.manager.onProposalMsg(ctx, latest))
		require.True(t, lag.manager.recovery.InRecovery())
		require.Less(t, probe.maxAsked(), latest.Block.Round, "the selector was not asked for the message's round")
	})

	t.Run("a vote for a future round is buffered without a lookup", func(t *testing.T) {
		probe.reset()
		var future *abdrc.VoteMsg
		for _, r := range online {
			for _, m := range r.net.SentMessages(network.ProtocolRootVote) {
				if v := m.Message.(*abdrc.VoteMsg); v.VoteInfo.RoundNumber > current+1 {
					future = v
				}
			}
		}
		require.NotNil(t, future, "premise: a validly signed vote for a round past the member's")
		require.NoError(t, lag.manager.onVoteMsg(ctx, future))
		require.Contains(t, lag.manager.voteBuffer, future.Author, "the future vote is buffered")
		require.Less(t, probe.maxAsked(), future.VoteInfo.RoundNumber, "the selector was not asked for the vote's round")
	})

	t.Run("a timeout for a future round is answered from its certificates without a lookup of its round", func(t *testing.T) {
		probe.reset()
		ahead := online[0]
		ahead.net.ResetSentMessages(network.ProtocolRootTimeout)
		ahead.manager.onLocalTimeout(ctx)
		sent := ahead.net.SentMessages(network.ProtocolRootTimeout)
		require.NotEmpty(t, sent, "premise: a signed timeout vote of a round past the member's")
		timeout := sent[0].Message.(*abdrc.TimeoutMsg)
		require.Greater(t, timeout.Timeout.Round, lag.manager.pacemaker.GetCurrentRound()+1)
		require.Error(t, lag.manager.onTimeoutMsg(ctx, timeout), "the member is behind: recovery, not an election")
		require.Less(t, probe.maxAsked(), timeout.Timeout.Round, "the selector was not asked for the timeout's round")
	})
}
