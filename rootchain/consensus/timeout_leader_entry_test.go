package consensus

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// tcFailStore is a replica's store whose write of the timeout certificate can be made to fail.
type tcFailStore struct {
	storage.BoltDB
	fail *atomic.Bool
}

func (s tcFailStore) WriteTC(tc *drctypes.TimeoutCert) error {
	if s.fail.Load() {
		return errors.New("tc write failed")
	}
	return s.BoltDB.WriteTC(tc)
}

// #1210: a leader that enters its round by a timeout certificate which it could not store does not propose: a restart forgets the round
// entry, and the certificate entering the round again would sign another proposal for the same round. The round is entered all the same.
func TestLeaderDoesNotProposeOnARoundEnteredByAnUnstoredTC(t *testing.T) {
	setup := func(t *testing.T) (leader, collector *anchorReplica, votes []*abdrc.TimeoutMsg, round uint64, fail *atomic.Bool) {
		fail = &atomic.Bool{}
		replicas, votes, round, _, _ := realQCTimeoutsFull(t, false, false, anchorOptions{
			store: func(db storage.BoltDB) PersistentStore { return tcFailStore{BoltDB: db, fail: fail} }})
		id, err := replicas[0].manager.leaderSelector.GetLeaderForRound(round + 1)
		require.NoError(t, err)
		for _, r := range replicas {
			if r.manager.id == id {
				leader = r
			} else if collector == nil {
				collector = r
			}
		}
		require.NotNil(t, leader)
		require.NotNil(t, collector)
		return leader, collector, votes, round, fail
	}
	ctx := context.Background()

	t.Run("a certificate carried by a timeout vote", func(t *testing.T) {
		leader, collector, votes, round, fail := setup(t)
		for _, v := range votes {
			if v.Author != collector.manager.id.String() {
				require.NoError(t, collector.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)))
			}
		}
		collector.net.ResetSentMessages(network.ProtocolRootTimeout)
		collector.manager.onLocalTimeout(ctx)
		next := collector.net.SentMessages(network.ProtocolRootTimeout)[0].Message.(*abdrc.TimeoutMsg)
		require.NotNil(t, next.LastTC)

		fail.Store(true)
		leader.net.ResetSentMessages(network.ProtocolRootProposal)
		require.NoError(t, leader.manager.onTimeoutMsg(ctx, next))
		require.Equal(t, round+1, leader.manager.pacemaker.GetCurrentRound(), "the round is entered")
		require.Empty(t, leader.net.SentMessages(network.ProtocolRootProposal), "but nothing is signed on it")
	})

	t.Run("a certificate the leader collected", func(t *testing.T) {
		leader, _, votes, round, fail := setup(t)
		fail.Store(true)
		leader.net.ResetSentMessages(network.ProtocolRootProposal)
		for _, v := range votes {
			if v.Author != leader.manager.id.String() {
				_ = leader.manager.onTimeoutMsg(ctx, recodeTimeout(t, v))
			}
		}
		require.Equal(t, round+1, leader.manager.pacemaker.GetCurrentRound(), "the round is entered")
		require.Empty(t, leader.net.SentMessages(network.ProtocolRootProposal), "but nothing is signed on it")
	})
}

// laggingLeader: the leader of the round after the timeout round has not seen the blocks the timeout votes' high QC certifies, and the
// certificate reaches it in the timeout vote of a root that collected it.
type laggingLeader struct {
	leader, sender, follower *anchorReplica
	next                     *abdrc.TimeoutMsg
	round                    uint64
	missed                   []*abdrc.ProposalMsg
}

func newLaggingLeader(t *testing.T) *laggingLeader {
	replicas, votes, round, lagger, missed := realQCTimeoutsFull(t, true, true, anchorOptions{})
	ctx := context.Background()
	sender, follower := replicas[len(replicas)-1], replicas[0]
	for _, v := range votes {
		require.NoError(t, sender.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)))
	}
	require.Equal(t, round+1, sender.manager.pacemaker.GetCurrentRound(), "the sender collected the certificate")
	sender.net.ResetSentMessages(network.ProtocolRootTimeout)
	sender.manager.onLocalTimeout(ctx)
	next := sender.net.SentMessages(network.ProtocolRootTimeout)[0].Message.(*abdrc.TimeoutMsg)
	require.NotNil(t, next.LastTC)
	lagger.net.ResetSentMessages(network.ProtocolRootProposal)
	return &laggingLeader{leader: lagger, sender: sender, follower: follower, next: next, round: round, missed: missed}
}

// A leader which lacks the block the certificate's high QC certifies does not use the certificate: it neither enters the round nor
// proposes on an older parent. With the blocks it proposes, extends the high QC of the certificate, and a follower votes for it (#1210).
func TestLeaderProposesOnTheHighQCOfTheCarriedTC(t *testing.T) {
	s := newLaggingLeader(t)
	ctx := context.Background()
	before := s.leader.manager.pacemaker.GetCurrentRound()
	require.Error(t, s.leader.manager.onTimeoutMsg(ctx, s.next), "the certificate's high QC needs the missing blocks")
	require.Empty(t, s.leader.net.SentMessages(network.ProtocolRootProposal), "no proposal on an older parent")
	require.Equal(t, before, s.leader.manager.pacemaker.GetCurrentRound(), "the leader has not moved on")

	for _, p := range s.missed {
		require.NoError(t, s.leader.manager.onProposalMsg(ctx, p))
	}
	require.NoError(t, s.leader.manager.onTimeoutMsg(ctx, recodeTimeout(t, s.next)))
	require.Equal(t, s.round+1, s.leader.manager.pacemaker.GetCurrentRound())
	sent := s.leader.net.SentMessages(network.ProtocolRootProposal)
	require.NotEmpty(t, sent, "the leader proposes")
	prop := sent[0].Message.(*abdrc.ProposalMsg)
	high := s.next.LastTC.Timeout.HighQc.GetRound()
	require.GreaterOrEqual(t, prop.Block.Qc.GetRound(), high, "it extends the high QC of the certificate")
	require.Equal(t, s.round, prop.LastRoundTc.GetRound())

	s.follower.net.ResetSentMessages(network.ProtocolRootVote)
	require.NoError(t, s.follower.manager.onProposalMsg(ctx, prop), "a follower accepts it")
	require.NotEmpty(t, s.follower.net.SentMessages(network.ProtocolRootVote), "and votes for it")
}

// A leader that fell behind recovers on the timeout vote carrying the certificate, and after the recovery proposes in the round the
// certificate ended: a retransmission would carry a stale certificate (#1210).
func TestLaggingLeaderProposesAfterRecovery(t *testing.T) {
	s := newLaggingLeader(t)
	ctx := context.Background()
	s.leader.net.ResetSentMessages(network.ProtocolRootStateReq)
	err := s.leader.manager.onTimeoutMsg(ctx, s.next)
	require.Error(t, err)
	require.True(t, s.leader.manager.recovery.InRecovery(), "the leader started a recovery")
	require.NotEmpty(t, s.leader.net.SentMessages(network.ProtocolRootStateReq))

	s.sender.net.ResetSentMessages(network.ProtocolRootStateResp)
	require.NoError(t, s.sender.manager.onStateReq(ctx, &abdrc.StateRequestMsg{NodeId: s.leader.manager.id.String()}))
	resp := s.sender.net.SentMessages(network.ProtocolRootStateResp)
	require.NotEmpty(t, resp)
	require.NoError(t, s.leader.manager.onStateResponse(ctx, resp[0].Message.(*abdrc.StateMsg)))
	require.False(t, s.leader.manager.recovery.InRecovery())

	require.Equal(t, s.round+1, s.leader.manager.pacemaker.GetCurrentRound(), "the certificate took it into the next round")
	sent := s.leader.net.SentMessages(network.ProtocolRootProposal)
	require.NotEmpty(t, sent, "and as its leader it proposed")
	prop := sent[0].Message.(*abdrc.ProposalMsg)
	require.GreaterOrEqual(t, prop.Block.Qc.GetRound(), s.next.LastTC.Timeout.HighQc.GetRound())
	s.follower.net.ResetSentMessages(network.ProtocolRootVote)
	require.NoError(t, s.follower.manager.onProposalMsg(ctx, prop))
	require.NotEmpty(t, s.follower.net.SentMessages(network.ProtocolRootVote))
}
