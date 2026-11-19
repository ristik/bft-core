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
	"github.com/unicitynetwork/bft-go-base/types"
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

// The high QC of a carried certificate: one not newer than the high QC is not looked at (its block may be pruned), a newer one whose block
// is missing starts no recovery and leaves the root without a parent for a proposal, a newer one whose block is present is processed.
func TestAdmitTheParentOfACarriedTC(t *testing.T) {
	s := newLaggingLeader(t)
	m := s.leader.manager
	qc1 := s.missed[1].Block.Qc // the high QC of the timeout votes, carried by the second proposal
	require.NotNil(t, qc1)
	ctx := context.Background()
	tcOf := func(qc *drctypes.QuorumCert) *drctypes.TimeoutCert {
		return &drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Epoch: qc.VoteInfo.Epoch, Round: s.round, HighQc: qc}}
	}
	high := m.blockStore().GetHighQc().GetRound()

	known, err := m.admitTCParent(ctx, tcOf(qc1))
	require.NoError(t, err, "no failure and no recovery for a missing block")
	require.False(t, known, "the newer QC has no block here: no parent to propose on")
	require.False(t, m.recovery.InRecovery(), "and none is started for it")
	require.Equal(t, high, m.blockStore().GetHighQc().GetRound())

	known, err = m.admitTCParent(ctx, nil)
	require.NoError(t, err)
	require.True(t, known)

	require.NoError(t, m.onProposalMsg(ctx, s.missed[0])) // the block qc1 certifies
	known, err = m.admitTCParent(ctx, tcOf(qc1))
	require.NoError(t, err)
	require.True(t, known, "the block is here: the QC is processed")
	require.Equal(t, qc1.GetRound(), m.blockStore().GetHighQc().GetRound())

	// a QC older than the high QC is not looked at: its block is not here (pruned, or never seen)
	old := &drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{RoundNumber: 1}}
	_, err = m.blockStore().Block(old.GetRound())
	require.Error(t, err, "premise: no block of that round")
	known, err = m.admitTCParent(ctx, tcOf(old))
	require.NoError(t, err)
	require.True(t, known)
	require.False(t, m.recovery.InRecovery())
}

// A root signs one proposal for a round as long as the process lives: when a recovery or the like lowers the round and the certificate
// ends it again, no second proposal for that round is signed (#1210).
func TestNoSecondProposalForARoundAlreadySigned(t *testing.T) {
	s := newLaggingLeader(t)
	ctx := context.Background()
	for _, p := range s.missed {
		require.NoError(t, s.leader.manager.onProposalMsg(ctx, p))
	}
	require.NoError(t, s.leader.manager.onTimeoutMsg(ctx, s.next))
	sent := len(s.leader.net.SentMessages(network.ProtocolRootProposal))
	require.NotZero(t, sent, "the leader proposed in the round after the certificate")

	// a request arrives after the first proposal: a suppressed duplicate must not take it out of the buffer
	psID := types.PartitionShardID{PartitionID: partitionID, ShardID: shardID.Key()}
	buf := s.leader.manager.irReqBuffer
	buf.irChgReqBuffer[psID] = &irChange{Req: &drctypes.IRChangeReq{Partition: partitionID, Shard: shardID, CertReason: drctypes.Quorum}}
	require.True(t, buf.IsChangeInBuffer(partitionID, shardID))

	// the round is lowered (what a recovery's reset does) and the certificate is processed again
	s.leader.manager.pacemaker.Reset(ctx, s.round-1, nil, nil)
	require.Equal(t, s.round, s.leader.manager.pacemaker.GetCurrentRound())
	_ = s.leader.manager.onTimeoutMsg(ctx, recodeTimeout(t, s.next))
	require.Equal(t, s.round+1, s.leader.manager.pacemaker.GetCurrentRound(), "premise: the certificate advanced the round again")
	require.Len(t, s.leader.net.SentMessages(network.ProtocolRootProposal), sent, "but no second proposal")
	require.True(t, s.leader.manager.irReqBuffer.IsChangeInBuffer(partitionID, shardID), "and the request is still buffered for the next one")
}

// The guard is scoped to the epoch: a successor epoch's first leader that signed an overlapping round of the old epoch (the suffix rounds
// of the old epoch overlap the first rounds of the successor) still proposes in the successor.
func TestGuardIsScopedToTheEpoch(t *testing.T) {
	s := newLaggingLeader(t)
	ctx := context.Background()
	for _, p := range s.missed {
		require.NoError(t, s.leader.manager.onProposalMsg(ctx, p))
	}
	m := s.leader.manager
	m.lastProposedEpoch.Store(m.trustBase.Load().Epoch - 1)
	m.lastProposedRound.Store(s.round + 10) // an old-epoch round above the successor's first rounds
	require.NoError(t, m.onTimeoutMsg(ctx, s.next))
	require.NotEmpty(t, s.leader.net.SentMessages(network.ProtocolRootProposal), "the successor's leader proposes")
	require.Equal(t, m.trustBase.Load().Epoch, m.lastProposedEpoch.Load())
	require.Equal(t, s.round+1, m.lastProposedRound.Load())
}

// Timeouts at the start of an epoch carry no high QC at all, nor does the certificate: the carried certificate takes the leader into its
// round and it proposes on the epoch anchor, with no panic.
func TestTimeoutWithoutAHighQCCarryingATC(t *testing.T) {
	byID, anchor, _ := newAnchorReplicas(t, 4)
	ctx := context.Background()
	leaderID, err := firstReplica(byID).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 2)
	require.NoError(t, err)
	var leader, collector *anchorReplica
	var votes []*abdrc.TimeoutMsg
	for id, r := range byID {
		r.manager.onLocalTimeout(ctx)
		votes = append(votes, r.net.SentMessages(network.ProtocolRootTimeout)[0].Message.(*abdrc.TimeoutMsg))
		require.Nil(t, votes[len(votes)-1].Timeout.HighQc, "premise: no high QC at the epoch start")
		if id == leaderID {
			leader = r
		} else {
			collector = r
		}
	}
	for _, v := range votes {
		_ = collector.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)) // the vote after the quorum is stale
	}
	require.Equal(t, anchor.Slot+2, collector.manager.pacemaker.GetCurrentRound(), "the collector formed the certificate")
	collector.net.ResetSentMessages(network.ProtocolRootTimeout)
	collector.manager.onLocalTimeout(ctx)
	next := collector.net.SentMessages(network.ProtocolRootTimeout)[0].Message.(*abdrc.TimeoutMsg)
	require.NotNil(t, next.LastTC)

	leader.net.ResetSentMessages(network.ProtocolRootProposal)
	require.NotPanics(t, func() { require.NoError(t, leader.manager.onTimeoutMsg(ctx, next)) })
	require.Equal(t, anchor.Slot+2, leader.manager.pacemaker.GetCurrentRound())
	require.NotEmpty(t, leader.net.SentMessages(network.ProtocolRootProposal))
}
