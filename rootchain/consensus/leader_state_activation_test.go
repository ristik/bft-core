package consensus

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// phaseLockBlockRate with the fixture's T2 of 2.5 s makes T2 12 root rounds (2500/227 + 1), a multiple of the four-round cycle of #886.
const phaseLockBlockRate = 454 * time.Millisecond

// newPhaseLockLive is four real managers on a real epoch 2 of four equal members. Equal weights make root-wrr-v1 the plain rotation of
// the sorted committee (TestEpochLeaderUnitWeightsReproduceTheLegacyHandoffSchedule). No node runs until started.
func newPhaseLockLive(t *testing.T, timeout time.Duration) *q4bLive {
	t.Helper()
	return newEqualLive(t, timeout, "H", "a", "b", "c")
}

// newEqualLive is real managers, one per name, on a real epoch 2 of equal members. No node runs until started.
func newEqualLive(t *testing.T, timeout time.Duration, names ...string) *q4bLive {
	t.Helper()
	weights := make([]uint64, len(names))
	for i := range weights {
		weights[i] = 1
	}
	f := q3fixture.New(t, q3fixture.Options{Assignment: true, Weights: weights})
	c := newQ4BBase(t, 2, f)
	tune := func(p *Parameters) { p.BlockRate, p.LocalTimeout = phaseLockBlockRate, timeout }
	for i, name := range names {
		r := newQ3Replica(t, f, f.NewNodes[i])
		r.tune = tune
		n := &q4bNode{name: name, weight: f.Members[i].Weight, r: r}
		c.nodes = append(c.nodes, n)
		c.attach(i, n)
		r.mustOpen(true)
		t.Cleanup(r.close)
		selectRuntimeRequestHistory(t, r)
	}
	ctx := context.Background()
	for _, n := range c.nodes {
		require.NoError(t, n.r.rt.Recover(ctx))
		require.NoError(t, n.r.rt.Activate(ctx, n.r.bundle()))
	}
	for _, n := range c.nodes {
		n.r.close()
		n.r.mustOpen(true)
		require.NoError(t, n.r.rt.Recover(ctx))
		selectRuntimeRequestHistory(t, n.r)
	}
	return c
}

type reputationInputs struct {
	committee  []string
	reputation bool
}

func (r reputationInputs) LeaderCommittee(uint64) ([]string, bool, error) {
	return r.committee, r.reputation, nil
}

// On a real activation: the anchor keeps the outgoing root and has no ring of the new epoch, and the epoch's first executed ordinary block
// starts one from the anchor's genesis, whatever round it is proposed at. Under any other policy no leaf appears and the root is unchanged.
func TestLeaderRingStartsAtTheAnchorChild(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	anchor := c.activateAll()
	committee := make([]string, 0, len(c.f.NewNodes))
	for _, n := range c.f.NewNodes {
		committee = append(committee, n.PeerConf.ID.String())
	}
	child := func(round uint64) *rctypes.BlockData {
		return &rctypes.BlockData{Version: 3, Epoch: anchor.Epoch, Round: round, Anchor: anchor, Payload: &rctypes.Payload{Version: 3}}
	}
	store := c.replicas[0].manager.blockStore
	_, ring, sealed := store.LeaderHead()
	require.Nil(t, ring, "the installed anchor holds no ring of the new epoch")
	require.True(t, sealed, "and keeps the outgoing terminal control state")

	store.SetLeaderInputs(reputationInputs{committee: committee})
	_, err := store.Add(child(anchor.Slot+1), c.replicas[0].manager.irReqVerifier)
	require.NoError(t, err)
	plain, err := store.Block(anchor.Slot + 1)
	require.NoError(t, err)
	require.Nil(t, plain.ShardState.Leader, "another policy has no leaf")

	other := c.replicas[1].manager.blockStore
	other.SetLeaderInputs(reputationInputs{committee: committee, reputation: true})
	_, err = other.Add(child(anchor.Slot+1), c.replicas[1].manager.irReqVerifier)
	require.NoError(t, err)
	early, err := other.Block(anchor.Slot + 1)
	require.NoError(t, err)
	require.NotEqual(t, plain.RootHash, early.RootHash, "the state root binds the leaf")
	require.Equal(t, anchor.GenesisID, early.ShardState.Leader.Genesis)
	require.Equal(t, anchor.Epoch, early.ShardState.Leader.Epoch)
	require.EqualValues(t, anchor.Slot+1, early.ShardState.Leader.Start)
	require.EqualValues(t, 20, early.ShardState.Leader.Lag, "4n+4 of the committee")
	require.Equal(t, []rctypes.LeaderRecord{{Round: anchor.Slot}, {Round: anchor.Slot + 1}}, early.ShardState.Leader.Records)

	third := c.replicas[2].manager.blockStore
	third.SetLeaderInputs(reputationInputs{committee: committee, reputation: true})
	_, err = third.Add(child(anchor.Slot+40), c.replicas[2].manager.irReqVerifier)
	require.NoError(t, err)
	late, err := third.Block(anchor.Slot + 40)
	require.NoError(t, err)
	require.EqualValues(t, anchor.Slot+1, late.ShardState.Leader.Start, "a first child well after A: the start is still A")
	require.Equal(t, []rctypes.LeaderRecord{{Round: anchor.Slot}, {Round: anchor.Slot + 40}}, late.ShardState.Leader.Records)
}

// #886 B1 and B2 on real managers with durable stores: a quorum with no new commit, no proposal and no vote getting through. Once every
// cutoff is above the committed head the leader is unknown, and each round ends at certificate speed rather than one local timeout later,
// every advance on a real TC, with no state recovery and with the node's serving APIs usable throughout.
func TestUnknownLeaderRoundsAdvanceAtCertificateSpeed(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	const timeout = 2 * time.Second
	c := newPhaseLockLive(t, timeout)
	var drop atomic.Bool
	base := c.net.filter
	var sendsMu sync.Mutex
	sends := map[[2]string]map[uint64]int{} // sender and receiver: timeout votes per round
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if drop.Load() {
			switch m := msg.(type) {
			case *abdrc.ProposalMsg, *abdrc.VoteMsg:
				return true
			case *abdrc.TimeoutMsg:
				sendsMu.Lock()
				defer sendsMu.Unlock()
				k := [2]string{from.String(), to.String()}
				if sends[k] == nil {
					sends[k] = map[uint64]int{}
				}
				sends[k][m.Timeout.Round]++
			}
		}
		return base(from, to, msg)
	}
	c.start(c.all()...)
	c.warm(3, c.all()...)
	drop.Store(true)
	head := func() uint64 {
		round, _, _ := c.nodes[0].r.manager.blockStore.LeaderHead()
		return round
	}
	lag := uint64(4*len(c.nodes) + 4)
	require.Eventually(t, func() bool { return c.state("H").Round > head()+lag+1 }, 3*time.Minute, 20*time.Millisecond, "the covered rounds time out")
	frozenHead := head()
	const stretch = 60
	from, began := c.state("H").Round, time.Now()
	require.Eventually(t, func() bool { return c.state("H").Round >= from+stretch }, 2*stretch*timeout, 5*time.Millisecond, "the rounds advance")
	elapsed := time.Since(began)
	t.Logf("tau: %d unknown rounds in %s, %s a round (durable stores, %d roots on one machine)", stretch, elapsed, elapsed/stretch, len(c.nodes))
	// without the immediate timeout each of these rounds costs T plus this same work: faster than T alone is what tells them apart, on any machine
	require.Less(t, elapsed, stretch*timeout, "certificate speed, not a local timeout per round")

	require.EqualValues(t, frozenHead, head(), "no commit: every advance was a TC")
	// the action fires once per round: a retransmission is the ordinary timer's, not one per loop event
	sendsMu.Lock()
	var rounds, total int
	for _, perRound := range sends {
		for round, n := range perRound {
			if round >= from {
				rounds++
				total += n
			}
		}
	}
	sendsMu.Unlock()
	require.NotZero(t, rounds)
	require.Less(t, total, 2*rounds, "%d timeout sends over %d sender, receiver and round combinations", total, rounds)
	for _, n := range c.nodes {
		require.False(t, n.r.manager.recovery.InRecovery(), "%s: unknown history is not state recovery", n.name)
		require.True(t, n.r.manager.frontier == nil || !n.r.manager.frontier.faulted.Load(), "%s: nor a frontier fault", n.name)
		_, err := n.r.manager.ShardInfo(q3fixture.PartitionID, types.ShardID{})
		require.NoError(t, err, "%s still serves its shard info", n.name)
		_, enabled, err := n.r.manager.RequestView(q3fixture.PartitionID, types.ShardID{})
		require.NoError(t, err, "%s still serves its request view", n.name)
		require.True(t, enabled)
	}
	// and takes a certification request: retained through the stretch, not refused and not lost for want of a known next leader
	hash := bytes.Repeat([]byte{0x81}, 32)
	for _, n := range c.nodes {
		proof := phaseLockProof(t, c, n.r, hash)
		require.NotNil(t, proof, "%s", n.name)
		require.NoError(t, n.r.manager.RequestCertification(context.Background(), *proof), "%s still takes certification requests", n.name)
	}
}

// A state recovery replaces the block store, and the replacement must still name the epoch's committee to execution: a node that recovers
// into a ring has to go on executing blocks. X joins an epoch whose head has one, by recovery, and commits with the others.
func TestStateRecoveryKeepsTheLeaderInputs(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	first := c.except("c")
	c.start(first...)
	c.warm(4, first...)
	c.start("c")
	m := c.nodes[c.idx("c")].r.manager
	require.Eventually(t, func() bool {
		_, ring, _ := m.blockStore.LeaderHead()
		return ring != nil && len(ring.Records) > 3
	}, 2*time.Minute, 50*time.Millisecond, "the recovered node goes on executing and committing blocks with a ring")
	require.NotNil(t, m.blockStore.LeaderInputs())

	// and its selector reads the store the recovery put in place: beyond the bootstrap, at a cutoff no store before the recovery could
	// answer, it names a peer's leader. The head compared is the recovered node's own, which every live peer has reached.
	peerSelector := c.nodes[c.idx(first[0])].r.manager
	lag := uint64(4*len(c.nodes) + 4)
	start := m.epochAnchor.Slot + 1
	require.Eventually(t, func() bool {
		head, _, _ := m.blockStore.LeaderHead()
		round := head + lag
		if head < start || round < start+lag {
			return false
		}
		mine, err := m.leaderSelector.GetLeaderForRound(round)
		if err != nil {
			return false
		}
		theirs, err := peerSelector.leaderSelector.GetLeaderForRound(round)
		return err == nil && mine == theirs
	}, 2*time.Minute, 50*time.Millisecond, "a recovered node's selector follows the replaced store and agrees with a peer")
}

// recoveryRunLeader is a selector whose every round is led by one member; start says which rounds begin a recovery run.
type recoveryRunLeader struct {
	constLeader
	start func(round uint64) bool
}

func (l recoveryRunLeader) RecoveryRunStart(round uint64) bool { return l.start(round) }

// Rev's binding note 2: a stall has burned past T2, so slot s of a recovery run would otherwise time out every shard, and a retained request
// reaching the leader for s+1 would lose to that pending change. Only that proposal leaves them out.
func TestRecoveryRunFirstProposalCarriesNoTimeouts(t *testing.T) {
	_, infos := testutils.CreateTestNodes(t, 2)
	for name, tc := range map[string]struct {
		start bool
		want  int
	}{"the first slot of a run": {true, 0}, "any other round": {false, 1}} {
		t.Run(name, func(t *testing.T) {
			cms, net := createConsensusManagers(t, 2, infos)
			m := cms[0]
			proposals := make(chan *abdrc.ProposalMsg, 8)
			net.SetFirewall(func(from, to peer.ID, msg any) bool {
				if p, ok := msg.(*abdrc.ProposalMsg); ok && from == m.id {
					select {
					case proposals <- p:
					default:
					}
				}
				return true
			})
			m.leaderSelector = recoveryRunLeader{constLeader: constLeader{leader: m.id, nodes: m.Validators()}, start: func(uint64) bool { return tc.start }}
			ctx := context.Background()
			high := m.blockStore.GetHighQc().GetRound()
			m.pacemaker.startNewRound(ctx, high+1000) // far past every shard's T2, as after a stall
			tcert := &rctypes.TimeoutCert{Timeout: rctypes.NewTimeout(high+999, m.trustBase.Load().Epoch, m.blockStore.GetHighQc())}
			m.pacemaker.lastRoundTC = tcert
			m.processNewRoundEvent(ctx)
			select {
			case p := <-proposals:
				require.Len(t, p.Block.Payload.Requests, tc.want)
			case <-time.After(5 * time.Second):
				t.Fatal("no proposal")
			}
		})
	}
}

// Design gate 4: a node that signed and recorded its timeout for a round whose leader is unknown, and died before sending it, says the same
// thing byte for byte after the restart: the B1 path goes through the same durable signing as a local timeout, and the stalled round then advances.
func TestRestartInAnUnknownLeaderRoundResendsTheRecordedTimeout(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	var drop atomic.Bool
	base := c.net.filter
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if drop.Load() {
			switch msg.(type) {
			case *abdrc.ProposalMsg, *abdrc.VoteMsg:
				return true
			}
		}
		return base(from, to, msg)
	}
	c.start(c.all()...)
	c.warm(3, c.all()...)
	drop.Store(true)
	h := c.nodes[c.idx("H")]
	lag := uint64(4*len(c.nodes) + 4)
	head := func() uint64 {
		round, _, _ := h.r.manager.blockStore.LeaderHead()
		return round
	}
	require.Eventually(t, func() bool { return c.state("H").Round > head()+lag+1 }, 3*time.Minute, 20*time.Millisecond, "the covered rounds run out")

	// c leaves first and one round passes, so no timeout of c is left for the cut round: a and b are below the quorum, and the round can only
	// advance with H's statement. Stopped after the cut, c's timeout could already be delivered, and the round advanced before H had resent anything.
	stopped := c.state("a").Round
	c.stop("c")
	require.Eventually(t, func() bool { return c.state("a").Round > stopped+1 }, q4bDeadline, 20*time.Millisecond, "H, a and b time the rounds out")
	h.crash.arm(q4bCutSpec{Point: cutBeforeSend, Kind: storage.DecisionTimeout})
	select {
	case <-h.crash.fired:
	case <-time.After(q4bDeadline):
		require.FailNow(t, "the timeout was never signed")
	}
	c.stop("H")
	h.crash.mu.Lock()
	epoch, round, wantStatement, wantMessage := h.crash.epoch, h.crash.round, h.crash.statement, h.crash.msg
	h.crash.mu.Unlock()
	require.NotNil(t, wantMessage)
	require.Greater(t, round, head()+lag, "the cut round's leader is unknown")
	_, err := h.r.manager.leaderSelector.GetLeaderForRound(round)
	require.ErrorIs(t, err, rctypes.ErrHistoryUnavailable)

	c.restart("H")
	require.Eventually(t, func() bool { return c.state("a").Round > round }, 2*time.Minute, 20*time.Millisecond, "the round advances with the recorded timeout")
	drop.Store(false)
	tr := c.finish()
	author, sent := h.r.id().String(), 0
	for _, ev := range tr {
		if ev.Kind == "attempt" && ev.Msg.Class == q4Timeout && ev.Msg.Author == author && ev.Msg.Epoch == epoch && ev.Msg.Round == round {
			require.Equal(t, wantStatement, ev.Msg.Statement, "the only statement of the author for the cut round is the recorded one")
			if bytes.Equal(ev.Msg.Raw, wantMessage) {
				sent++
			}
		}
	}
	require.Positive(t, sent, "the recorded timeout goes out after the restart, byte for byte")
}
