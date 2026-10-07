package consensus

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Regressions of the review of #398: a restart between recording a timeout decision and sending the timeout must not cost the
// quorum its weight, and the timeouts the safety module signs must assemble into a certificate that verifies.

// pairedQC is a scheme 2 QC of epoch 2 for the round, formed by three of the four members.
func pairedQC(t *testing.T, c *pairedCommittee, round uint64) *drctypes.QuorumCert {
	t.Helper()
	tb, err := c.store.GetByEpoch(2)
	require.NoError(t, err)
	register := NewVoteRegister()
	var qc *drctypes.QuorumCert
	for _, id := range c.ids[:3] {
		v := c.vote(t, id, nil)
		v.VoteInfo.RoundNumber, v.VoteInfo.ParentRoundNumber = round, round-1
		vh, err := c.cfg.VoteInfoHash(votesig.VoteInfo{Epoch: 2, Round: round, Parent: round - 1, Exec: [32]byte(v.VoteInfo.CurrentRootHash), Timestamp: v.VoteInfo.Timestamp})
		require.NoError(t, err)
		v.LedgerCommitInfo.PreviousHash = vh[:]
		require.NoError(t, v.SignDomainBound(c.signers[id], c.cfg))
		qc, err = register.InsertVote(v, tb)
		require.NoError(t, err)
	}
	require.NotNil(t, qc)
	require.NoError(t, qc.VerifyWith(c.store))
	return qc
}

// precedingTC is an authentic scheme 2 TC for the round, the antecedent of a timeout of the next round whose HighQC is older.
func precedingTC(t *testing.T, c *pairedCommittee, round uint64, hqc *drctypes.QuorumCert) *drctypes.TimeoutCert {
	t.Helper()
	tc := &drctypes.TimeoutCert{Scheme: votesig.SchemeDomainBound, Timeout: drctypes.NewTimeout(round, 2, hqc), Signatures: map[string]*drctypes.TimeoutVote{}}
	for _, id := range c.ids[:3] {
		msg := abdrc.NewTimeoutMsg(drctypes.NewTimeout(round, 2, hqc), id, nil)
		require.NoError(t, msg.SignDomainBound(c.signers[id], c.cfg))
		require.NoError(t, tc.Add(id, msg.Timeout, msg.Signature))
	}
	require.NoError(t, tc.Verify(c.store))
	return tc
}

func (c *pairedCommittee) module(t *testing.T, id string, store SafetyStorage) *SafetyModule {
	t.Helper()
	m, err := NewSafetyModule(types.NetworkID(c.cfg.Network), id, c.signers[id], store, WithDomainBoundSigning(c.store, nil))
	require.NoError(t, err)
	return m
}

// Review's scenario: four nodes online, two of them crashed after their round-14 timeout decision was recorded and before the
// timeout left the node, and they come back with a HighQC that advanced from 12 to 13. Before the fix the recorded decision
// held PT only, a new timeout from the advanced HighQC was a different statement refused with ErrDecisionConflict, and only the
// two other signatures were left for the quorum of three. Now the complete signed message is recorded with the decision, the
// restarted nodes send that message again, and the certificate forms.
func TestTwoRestartedNodesStillFormATCWithAllFourNodesOnline(t *testing.T) {
	c := newPairedCommittee(t)
	oldQC, newQC := pairedQC(t, c, 12), pairedQC(t, c, 13)
	tb, err := c.store.GetByEpoch(2)
	require.NoError(t, err)
	previous := precedingTC(t, c, 13, oldQC)

	var replayed []*abdrc.TimeoutMsg
	for _, id := range c.ids[:2] {
		path := filepath.Join(t.TempDir(), "rc.db")
		db, err := storage.NewBoltStorage(path, storage.WithNoSync())
		require.NoError(t, err)
		// the crash: the decision and the signed timeout are recorded, the message is never returned
		m := c.module(t, id, &crashingStorage{BoltDB: db, failVoted: true})
		first := abdrc.NewTimeoutMsg(drctypes.NewTimeout(14, 2, oldQC), id, previous)
		require.ErrorIs(t, m.SignTimeout(first, previous), errCrash)
		require.NoError(t, db.Close())

		db, err = storage.NewBoltStorage(path, storage.WithNoSync())
		require.NoError(t, err)
		restarted := c.module(t, id, db)
		// building a new timeout from the advanced HighQC is still refused: nothing is signed with changed content
		changed := abdrc.NewTimeoutMsg(drctypes.NewTimeout(14, 2, newQC), id, previous)
		require.ErrorIs(t, restarted.SignTimeout(changed, previous), storage.ErrDecisionConflict)
		require.Empty(t, changed.Signature)
		// the recorded message is sent again
		msg, err := restarted.RecordedTimeout(2, 14)
		require.NoError(t, err)
		require.NotNil(t, msg)
		require.EqualValues(t, 12, msg.Timeout.GetHqcRound(), "with the HighQC it was signed with")
		require.NoError(t, msg.Verify(c.store))
		replayed = append(replayed, msg)
		require.NoError(t, db.Close())
	}

	var fresh []*abdrc.TimeoutMsg
	for _, id := range c.ids[2:] {
		db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "rc.db"), storage.WithNoSync())
		require.NoError(t, err)
		msg := abdrc.NewTimeoutMsg(drctypes.NewTimeout(14, 2, newQC), id, previous)
		require.NoError(t, c.module(t, id, db).SignTimeout(msg, previous))
		require.NoError(t, msg.Verify(c.store))
		fresh = append(fresh, msg)
		require.NoError(t, db.Close())
	}

	// the two fresh signatures alone are below the quorum of three: the restarted nodes' messages are what completes it
	register := NewVoteRegister()
	for _, msg := range fresh {
		tc, weight, err := register.InsertTimeoutVote(msg, tb)
		require.NoError(t, err)
		require.Nil(t, tc)
		require.LessOrEqual(t, weight, uint64(2))
	}
	var tc *drctypes.TimeoutCert
	for _, msg := range replayed {
		tc, _, err = register.InsertTimeoutVote(msg, tb)
		require.NoError(t, err)
	}
	require.NotNil(t, tc, "four nodes online form the TC")
	require.EqualValues(t, votesig.SchemeDomainBound, tc.Scheme)
	require.Len(t, tc.Signatures, 4)
	require.EqualValues(t, 13, tc.Timeout.GetHqcRound(), "the certificate carries the highest HighQC of its signers")
	require.NoError(t, tc.Verify(c.store), "with signers whose HighQC rounds are 12 and 13")
}

// The timeouts the safety module signs assemble into a scheme 2 certificate that verifies, and a vote of the other scheme is
// never mixed into it.
func TestSafetyModuleTimeoutsAssembleIntoAVerifiableScheme2TC(t *testing.T) {
	c := newPairedCommittee(t)
	qc := pairedQC(t, c, 12)
	tb, err := c.store.GetByEpoch(2)
	require.NoError(t, err)

	var msgs []*abdrc.TimeoutMsg
	for _, id := range c.ids[:3] {
		db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "rc.db"), storage.WithNoSync())
		require.NoError(t, err)
		msg := abdrc.NewTimeoutMsg(drctypes.NewTimeout(13, 2, qc), id, nil)
		require.NoError(t, c.module(t, id, db).SignTimeout(msg, nil))
		require.NoError(t, msg.Verify(c.store))
		msgs = append(msgs, msg)
		require.NoError(t, db.Close())
	}

	t.Run("three scheme 2 timeouts form a TC that verifies", func(t *testing.T) {
		register := NewVoteRegister()
		var tc *drctypes.TimeoutCert
		for _, msg := range msgs {
			tc, _, err = register.InsertTimeoutVote(msg, tb)
			require.NoError(t, err)
		}
		require.NotNil(t, tc)
		require.EqualValues(t, votesig.SchemeDomainBound, tc.Scheme)
		require.NoError(t, tc.Verify(c.store))
	})

	t.Run("a legacy-form timeout is refused by the scheme-2 certificate being formed", func(t *testing.T) {
		register := NewVoteRegister()
		_, _, err := register.InsertTimeoutVote(msgs[0], tb)
		require.NoError(t, err)
		legacy := abdrc.NewTimeoutMsg(drctypes.NewTimeout(13, 2, qc), c.ids[3], nil)
		require.NoError(t, legacy.Sign(c.signers[c.ids[3]]))
		_, _, err = register.InsertTimeoutVote(legacy, tb)
		require.ErrorIs(t, err, votesig.ErrScheme)
	})

	t.Run("a scheme 2 timeout is refused by the legacy certificate being formed", func(t *testing.T) {
		register := NewVoteRegister()
		legacy := abdrc.NewTimeoutMsg(drctypes.NewTimeout(13, 2, qc), c.ids[3], nil)
		require.NoError(t, legacy.Sign(c.signers[c.ids[3]]))
		_, _, err := register.InsertTimeoutVote(legacy, tb)
		require.NoError(t, err)
		_, _, err = register.InsertTimeoutVote(msgs[0], tb)
		require.ErrorIs(t, err, votesig.ErrScheme)
	})
}

// The manager side: a node that restarted after recording its timeout decision (the pacemaker holds no timeout vote any more)
// sends the recorded timeout when its local timeout fires. Its signer is replaced by one that fails every signature, so the
// message that goes out can only be the recorded one, never a new one.
func TestManagerSendsTheRecordedTimeoutAfterARestart(t *testing.T) {
	c := newAnchorCluster(t)
	for _, r := range c.replicas {
		require.NoError(t, r.store.ActivateSigning(2, domainBoundConfig()))
	}
	r := firstReplica(c.replicas)
	cm := r.manager
	ctx := context.Background()

	r.net.ResetSentMessages(network.ProtocolRootTimeout)
	cm.onLocalTimeout(ctx)
	sent := r.net.SentMessages(network.ProtocolRootTimeout)
	require.NotEmpty(t, sent, "the first local timeout signs and sends a timeout")
	first := sent[0].Message.(*abdrc.TimeoutMsg)
	require.EqualValues(t, votesig.SchemeDomainBound, first.Scheme)
	recorded, err := cm.safety.RecordedTimeout(first.Timeout.Epoch, first.Timeout.Round)
	require.NoError(t, err)
	require.NotNil(t, recorded, "the signed timeout is recorded with its decision")

	// the restart: the pacemaker starts the round again without its timeout vote, and nothing can be signed any more
	cm.pacemaker.timeoutVote = nil
	// and what it would build now is a different statement (the first timeout carried the epoch anchor, as the first round of
	// the epoch has no QC; the restarted node's HighQC has moved on, which a timeout of its own would carry instead)
	require.NotNil(t, first.Timeout.Anchor, "premise: the first timeout of the epoch carries the anchor")
	cm.epochAnchor = nil
	cm.safety.signer = &crashingSigner{Signer: cm.safety.signer, failFrom: 1}
	r.net.ResetSentMessages(network.ProtocolRootTimeout)
	cm.onLocalTimeout(ctx)
	sent = r.net.SentMessages(network.ProtocolRootTimeout)
	require.NotEmpty(t, sent, "the recorded timeout is sent again")
	again := sent[0].Message.(*abdrc.TimeoutMsg)
	require.Equal(t, first.Signature, again.Signature, "it is the message that was recorded, not a new signature")
	require.Equal(t, first.Timeout.GetHqcRound(), again.Timeout.GetHqcRound())
}
