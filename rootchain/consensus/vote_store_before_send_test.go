package consensus

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

// voteFailStore is a root's database whose last-vote write can be made to fail. Everything else, the scheme 2 decision record
// included, is the real store.
type voteFailStore struct {
	storage.BoltDB
	fail   *atomic.Bool
	writes *atomic.Int64
}

var errVoteStore = errors.New("injected: the last vote cannot be stored")

func (s voteFailStore) WriteVote(vote any) error {
	if s.fail.Load() {
		return errVoteStore
	}
	s.writes.Add(1)
	return s.BoltDB.WriteVote(vote)
}

func sentVotes(net *testnetwork.MockNet) int { return len(net.SentMessages(network.ProtocolRootVote)) }
func sentTimeouts(net *testnetwork.MockNet) int {
	return len(net.SentMessages(network.ProtocolRootTimeout))
}

// A vote is stored before it leaves the node. When the store fails, nothing is sent and nothing is remembered as sent: a vote on the
// wire with no stored copy could be followed, after a restart or a recovery, by a different one for the same round (bft-core#585).
// Scheme 2: the epoch-2 cluster with domain-bound signing.
func TestAVoteThatCannotBeStoredIsNotSent_Scheme2(t *testing.T) {
	fail, writes := &atomic.Bool{}, &atomic.Int64{}
	c, heavy := skewedAnchorClusterWith(t, anchorOptions{weights: skewedStakes, syncDB: true,
		store: func(db storage.BoltDB) PersistentStore { return voteFailStore{BoltDB: db, fail: fail, writes: writes} }})
	for i := 0; i < 2; i++ {
		c.advance()
	}
	var r *anchorReplica
	for id, replica := range c.replicas {
		if id.String() == heavy {
			r = replica
		}
	}
	ctx := context.Background()
	last := c.proposals[len(c.proposals)-1]
	cfg, err := r.manager.safety.config(last.Block.Epoch)
	require.NoError(t, err)
	require.EqualValues(t, votesig.SchemeDomainBound, cfg.Scheme, "premise: a scheme 2 epoch")
	require.Positive(t, writes.Load(), "premise: the votes of the earlier rounds were stored through this store")
	r.net.ResetSentMessages(network.ProtocolRootVote)

	// the proposal vote
	fail.Store(true)
	err = r.manager.onProposalMsg(ctx, last)
	require.ErrorIs(t, err, errVoteStore, "the failed store is reported")
	require.Zero(t, sentVotes(r.net), "and the vote is not sent")
	require.Nil(t, r.manager.pacemaker.GetVoted(), "nor remembered as sent")
	_, recorded, derr := r.db.SignedDecision(storage.DecisionVote, last.Block.Epoch, last.Block.Round)
	require.NoError(t, derr)
	require.NotEmpty(t, recorded, "(the scheme 2 decision itself was recorded: the node cannot sign another statement for the round)")

	// the timeout vote of the same round
	r.net.ResetSentMessages(network.ProtocolRootTimeout)
	r.manager.onLocalTimeout(ctx)
	require.Zero(t, sentTimeouts(r.net), "a timeout vote that cannot be stored is not sent")
	require.Nil(t, r.manager.pacemaker.GetTimeoutVote())

	// with the store working again the next local timeout stores and sends
	fail.Store(false)
	before := writes.Load()
	r.manager.onLocalTimeout(ctx)
	sent := r.net.SentMessages(network.ProtocolRootTimeout)
	require.Len(t, sent, len(c.replicas), "stored, then sent: one copy to each root of the committee")
	require.Equal(t, before+1, writes.Load())
	stored, err := r.manager.blockStore.ReadLastVote()
	require.NoError(t, err)
	require.Equal(t, timeoutMessageID(sent[0].Message.(*abdrc.TimeoutMsg)), timeoutMessageID(stored.(*abdrc.TimeoutMsg)), "what was sent is what is stored")
}

// The same in a legacy (scheme 1) epoch, on a single root that leads every round.
func TestAVoteThatCannotBeStoredIsNotSent_Legacy(t *testing.T) {
	newRoot := func(t *testing.T) (*ConsensusManager, *testnetwork.MockNet, *atomic.Bool, *atomic.Int64) {
		fail, writes := &atomic.Bool{}, &atomic.Int64{}
		mockNet := testnetwork.NewRootMockNetwork()
		cm, _, _ := initConsensusManagerOver(t, mockNet, func(db storage.BoltDB) PersistentStore {
			return voteFailStore{BoltDB: db, fail: fail, writes: writes}
		})
		cm.pacemaker.Reset(context.Background(), cm.blockStore.GetHighQc().GetRound(), nil, nil)
		t.Cleanup(cm.pacemaker.Stop)
		return cm, mockNet, fail, writes
	}
	ctx := context.Background()
	// the root proposes round 2 to itself; the proposal is what it would vote for
	propose := func(t *testing.T, cm *ConsensusManager, mockNet *testnetwork.MockNet) *abdrc.ProposalMsg {
		t.Helper()
		cm.pacemaker.setState(ctx, pmsRoundMatured)
		cm.processNewRoundEvent(ctx)
		sent := mockNet.SentMessages(network.ProtocolRootProposal)
		require.Len(t, sent, 1, "premise: the single root proposes")
		return sent[0].Message.(*abdrc.ProposalMsg)
	}

	t.Run("control: with the store working the vote is stored and sent", func(t *testing.T) {
		cm, mockNet, _, writes := newRoot(t)
		require.NoError(t, cm.onProposalMsg(ctx, propose(t, cm, mockNet)))
		require.Equal(t, 1, sentVotes(mockNet))
		require.EqualValues(t, 1, writes.Load())
		require.NotNil(t, cm.pacemaker.GetVoted())
	})

	t.Run("a proposal vote that cannot be stored is not sent", func(t *testing.T) {
		cm, mockNet, fail, _ := newRoot(t)
		proposal := propose(t, cm, mockNet)
		fail.Store(true)
		require.ErrorIs(t, cm.onProposalMsg(ctx, proposal), errVoteStore)
		require.Zero(t, sentVotes(mockNet))
		require.Nil(t, cm.pacemaker.GetVoted())
		stored, err := cm.blockStore.ReadLastVote()
		require.NoError(t, err)
		require.Nil(t, stored)
	})

	t.Run("a timeout vote that cannot be stored is not sent; the next one, stored, is", func(t *testing.T) {
		cm, mockNet, fail, writes := newRoot(t)
		fail.Store(true)
		cm.onLocalTimeout(ctx)
		require.Zero(t, sentTimeouts(mockNet))
		require.Nil(t, cm.pacemaker.GetTimeoutVote(), "not remembered: the pacemaker would otherwise resend it without storing it")
		cm.onLocalTimeout(ctx)
		require.Zero(t, sentTimeouts(mockNet), "still failing, still nothing")

		fail.Store(false)
		cm.onLocalTimeout(ctx)
		sent := mockNet.SentMessages(network.ProtocolRootTimeout)
		require.Len(t, sent, 1)
		require.EqualValues(t, 1, writes.Load())
		stored, err := cm.blockStore.ReadLastVote()
		require.NoError(t, err)
		require.Equal(t, timeoutMessageID(sent[0].Message.(*abdrc.TimeoutMsg)), timeoutMessageID(stored.(*abdrc.TimeoutMsg)))
		// the remembered vote is resent without another store, as before
		cm.onLocalTimeout(ctx)
		require.Len(t, mockNet.SentMessages(network.ProtocolRootTimeout), 2)
		require.EqualValues(t, 1, writes.Load())
	})
}

// voteFailPersistent is voteFailStore over the store interface, for the harnesses that hand one over.
type voteFailPersistent struct {
	PersistentStore
	fail *atomic.Bool
}

func (s voteFailPersistent) WriteVote(vote any) error {
	if s.fail.Load() {
		return errVoteStore
	}
	return s.PersistentStore.WriteVote(vote)
}

// countingVoteNet counts the votes a root sends.
type countingVoteNet struct {
	RootNet
	votes atomic.Int64
}

func (n *countingVoteNet) Send(ctx context.Context, msg any, receivers ...peer.ID) error {
	if _, ok := msg.(*abdrc.VoteMsg); ok {
		n.votes.Add(1)
	}
	return n.RootNet.Send(ctx, msg, receivers...)
}

// A root that joins late recovers from its peers and then votes for the proposal that triggered the recovery, and for the live
// proposals after it. That first vote used not to be stored at all. With its store refusing votes the root sends none, through the
// recovery and after it; when the store works again it votes.
func TestALateRootWhoseVoteStoreFailsSendsNoVoteThroughRecovery(t *testing.T) {
	fail := &atomic.Bool{}
	stores := 0
	cms, rootNet := createConsensusManagersWithOptions(t, 4, nil, func(*types.RootTrustBaseV1) []Option { return nil },
		func(store PersistentStore) PersistentStore {
			stores++
			if stores == 4 { // the late root's
				return voteFailPersistent{PersistentStore: store, fail: fail}
			}
			return store
		})
	for _, cm := range cms {
		cm.leaderSelector = constLeader{leader: cms[0].id, nodes: cms[0].Validators()}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var running atomic.Int32
	run := func(cm *ConsensusManager) {
		running.Add(1)
		go func() { defer running.Add(-1); _ = cm.Run(ctx) }()
	}
	for _, cm := range cms[:3] {
		run(cm)
	}
	t.Cleanup(func() {
		cancel()
		require.Eventually(t, func() bool { return running.Load() == 0 }, 3*time.Second, 20*time.Millisecond)
	})
	require.Eventually(t, func() bool { return cms[0].pacemaker.GetCurrentRound() >= 6 }, 5*time.Second, 20*time.Millisecond)

	late := cms[3]
	counted := &countingVoteNet{RootNet: late.net}
	late.net = counted
	fail.Store(true)
	// hold the state response back until the late root is in recovery, so that the recovery, not luck, is what it goes through
	rootNet.SetFirewall(func(from, to peer.ID, msg any) bool {
		_, state := msg.(*abdrc.StateMsg)
		return state && to == late.id
	})
	run(late)
	require.Eventually(t, late.recovery.InRecovery, 2*time.Second, 10*time.Millisecond)
	rootNet.SetFirewall(func(from, to peer.ID, msg any) bool { return false })
	require.Eventually(t, func() bool { return !late.recovery.InRecovery() }, 5*time.Second, 10*time.Millisecond, "premise: the late root completes its recovery")
	// the committee goes on for several rounds with the late root following
	from := cms[0].pacemaker.GetCurrentRound()
	require.Eventually(t, func() bool { return cms[0].pacemaker.GetCurrentRound() >= from+4 }, 10*time.Second, 20*time.Millisecond)
	require.Zero(t, counted.votes.Load(), "no vote left the root whose store refuses votes: not the one after the recovery, not a live one")

	fail.Store(false)
	require.Eventually(t, func() bool { return counted.votes.Load() > 0 }, 10*time.Second, 20*time.Millisecond, "with the store working again it votes")
}
