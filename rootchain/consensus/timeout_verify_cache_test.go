package consensus

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

// timeoutVotesOf makes every replica except the first leader time out and returns the real, signed votes it sent, with a receiver that is
// not the author of any of them. Fewer than a quorum is delivered in these tests, so the receiver stays in the round.
func timeoutVotesOf(t *testing.T) (receiver *anchorReplica, votes []*abdrc.TimeoutMsg) {
	t.Helper()
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	ctx := context.Background()
	firstLeader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	nextLeader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 2)
	require.NoError(t, err)
	for id, r := range replicas {
		if id != firstLeader {
			r.manager.onLocalTimeout(ctx)
		}
	}
	for id, r := range replicas {
		if id == firstLeader || id == nextLeader {
			continue
		}
		msgs := r.net.SentMessages(network.ProtocolRootTimeout)
		require.NotEmpty(t, msgs)
		votes = append(votes, msgs[0].Message.(*abdrc.TimeoutMsg))
	}
	require.NotEmpty(t, votes)
	return replicas[nextLeader], votes
}

// countVerifications puts a counting seam in front of the real verification and returns the counter.
func countVerifications(m *ConsensusManager) *int {
	n := 0
	m.timeoutVerify = func(v *abdrc.TimeoutMsg) error { n++; return v.Verify(m.trustBaseStore) }
	return &n
}

func recodeTimeout(t *testing.T, v *abdrc.TimeoutMsg) *abdrc.TimeoutMsg {
	t.Helper()
	raw, err := types.Cbor.Marshal(v)
	require.NoError(t, err)
	c := &abdrc.TimeoutMsg{}
	require.NoError(t, types.Cbor.Unmarshal(raw, c))
	return c
}

func corrupted(t *testing.T, v *abdrc.TimeoutMsg) *abdrc.TimeoutMsg {
	c := recodeTimeout(t, v)
	c.Signature = bytes.Repeat([]byte{0x5a}, len(v.Signature))
	return c
}

// An identical replay of a counted message is not verified again; the registration still gives its ordinary answer (the signer is counted).
func TestIdenticalReplayOfACountedTimeoutVoteIsNotVerifiedAgain(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	ctx := context.Background()
	calls := countVerifications(receiver.manager)
	v := votes[0]

	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v))
	require.Equal(t, 1, *calls)
	for i := 0; i < 3; i++ {
		err := receiver.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)) // a fresh decode of the same bytes: a retransmission
		require.ErrorIs(t, err, quorumweight.ErrDuplicateSigner, "the registration answers as before")
	}
	require.Equal(t, 1, *calls, "three replays, no further verification")
	require.EqualValues(t, 3, receiver.manager.profile.verifyHits)
}

// A corrupted signature is a different message: it misses, is verified and refused as invalid, and does not disturb the counted vote.
func TestCorruptedReplayMissesAndFailsVerification(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	ctx := context.Background()
	calls := countVerifications(receiver.manager)
	v := votes[0]
	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v))

	err := receiver.manager.onTimeoutMsg(ctx, corrupted(t, v))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid timeout vote")
	require.NotErrorIs(t, err, quorumweight.ErrDuplicateSigner)
	require.Equal(t, 2, *calls, "it was verified")
	require.ErrorIs(t, receiver.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 2, *calls, "the original still hits")
}

// An invalid first message of a signer neither is counted nor pre-empts the valid one that follows.
func TestInvalidFirstTimeoutVoteDoesNotPreemptTheValidOne(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	ctx := context.Background()
	calls := countVerifications(receiver.manager)
	v := votes[0]
	require.Error(t, receiver.manager.onTimeoutMsg(ctx, corrupted(t, v)))
	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v), "the valid message is verified and counted")
	require.Equal(t, 2, *calls)
	require.ErrorIs(t, receiver.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 2, *calls)
}

// A different message of the same signer, round and epoch (here: another last TC, another scheme) is a different digest and misses.
func TestChangedEnvelopeOfACountedSignerMisses(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	ctx := context.Background()
	calls := countVerifications(receiver.manager)
	v := votes[0]
	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v))
	base, _, ok := receiver.manager.timeoutCacheKey(v)
	require.True(t, ok)

	mutations := map[string]func(c *abdrc.TimeoutMsg){
		"last TC": func(c *abdrc.TimeoutMsg) {
			c.LastTC = &drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Epoch: v.Timeout.Epoch, Round: v.Timeout.Round - 1}, Signatures: map[string]*drctypes.TimeoutVote{}}
		},
		"scheme": func(c *abdrc.TimeoutMsg) { c.Scheme = votesig.SchemeDomainBound },
		"high QC round": func(c *abdrc.TimeoutMsg) {
			if c.Timeout.HighQc != nil {
				c.Timeout.HighQc.VoteInfo.RoundNumber++
			} else {
				c.Timeout.Round++
			}
		},
		"anchor":    func(c *abdrc.TimeoutMsg) { c.Timeout.Anchor = &drctypes.EpochAnchor{Epoch: 99} },
		"signature": func(c *abdrc.TimeoutMsg) { c.Signature = append([]byte{0}, c.Signature...) },
	}
	for name, mutate := range mutations {
		c := recodeTimeout(t, v)
		mutate(c)
		d, _, ok := receiver.manager.timeoutCacheKey(c)
		require.True(t, ok, name)
		require.NotEqual(t, base, d, "%s changes the digest", name)
		before := *calls
		_ = receiver.manager.onTimeoutMsg(ctx, c) // whatever the ordinary path answers
		require.Greater(t, *calls, before, "%s: not a hit, the message was verified", name)
	}
}

// The register forgets with the round: after a Reset the same message is verified again.
func TestVerifiedTimeoutsAreForgottenOnReset(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	ctx := context.Background()
	calls := countVerifications(receiver.manager)
	v := votes[0]
	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v))
	receiver.manager.pacemaker.pendingVotes.Reset()
	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)))
	require.Equal(t, 2, *calls)
}

// Register-level properties: the first remembered digest is kept, a different context or round or epoch misses, and mutating the message
// afterwards cannot change what was saved (the digest is a value).
func TestVerifiedTimeoutRegisterKeysAndKeepsTheFirstDigest(t *testing.T) {
	var r VoteRegister
	d1, d2 := [32]byte{1}, [32]byte{2}
	ctx := verifyContext{n: 1}
	ctx.epochs[0], ctx.cfgs[0] = 1, votesig.Config{Scheme: 1}
	other := ctx
	other.cfgs[0] = votesig.Config{Scheme: 2}

	r.NoteVerifiedTimeout("a", 5, 1, d1, ctx)
	r.NoteVerifiedTimeout("a", 5, 1, d2, ctx) // a different message of the same signer never replaces it
	require.True(t, r.VerifiedTimeoutHit("a", 5, 1, d1, ctx))
	require.False(t, r.VerifiedTimeoutHit("a", 5, 1, d2, ctx))
	require.False(t, r.VerifiedTimeoutHit("a", 5, 1, d1, other), "another signing context")
	require.False(t, r.VerifiedTimeoutHit("a", 6, 1, d1, ctx), "another round")
	require.False(t, r.VerifiedTimeoutHit("a", 5, 2, d1, ctx), "another epoch")
	require.False(t, r.VerifiedTimeoutHit("b", 5, 1, d1, ctx), "another signer")
	r.Reset()
	require.False(t, r.VerifiedTimeoutHit("a", 5, 1, d1, ctx))
}

// realQCTimeouts drives an anchored epoch through its first certified round and then makes every replica time out the next one: the votes
// carry a real, non-anchor high QC (the QC of round anchor.Slot+1, a quorum of real signatures). Returns the replicas, ordered, and each
// one's round-(anchor.Slot+2) timeout vote.
func realQCTimeouts(t *testing.T) (replicas []*anchorReplica, votes []*abdrc.TimeoutMsg, round uint64) {
	t.Helper()
	replicas, votes, round, _, _ = realQCTimeoutsWith(t, false)
	return replicas, votes, round
}

// realQCTimeoutsWith with lag=true leaves one replica (neither of the two leaders) without both proposals: it has not seen the blocks the high
// QC certifies. It is returned apart (not among replicas or votes), with the two proposals it missed.
func realQCTimeoutsWith(t *testing.T, lag bool) (replicas []*anchorReplica, votes []*abdrc.TimeoutMsg, round uint64, lagger *anchorReplica, missed []*abdrc.ProposalMsg) {
	t.Helper()
	byID, anchor, _ := newAnchorReplicas(t, 4)
	ctx := context.Background()
	firstLeader, err := firstReplica(byID).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	nextLeader, err := firstReplica(byID).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 2)
	require.NoError(t, err)
	if lag {
		for id, r := range byID {
			if id != firstLeader && id != nextLeader {
				lagger = r
				break
			}
		}
		require.NotNil(t, lagger)
	}
	byID[firstLeader].manager.processNewRoundEvent(ctx)
	proposal := byID[firstLeader].net.WaitRootProposal(t)
	missed = append(missed, proposal)
	for _, r := range byID {
		if r != lagger {
			require.NoError(t, r.manager.onProposalMsg(ctx, proposal))
		}
	}
	byID[nextLeader].manager.pacemaker.setState(ctx, pmsRoundMatured)
	for _, r := range byID {
		if byID[nextLeader].manager.pacemaker.GetCurrentRound() > anchor.Slot+1 {
			break
		}
		vs := r.net.SentMessages(network.ProtocolRootVote)
		if r == lagger {
			continue
		}
		require.Len(t, vs, 1)
		require.NoError(t, byID[nextLeader].manager.onVoteMsg(ctx, vs[0].Message.(*abdrc.VoteMsg)))
	}
	proposal = byID[nextLeader].net.WaitRootProposal(t)
	missed = append(missed, proposal)
	for _, r := range byID {
		if r == lagger {
			continue
		}
		r.net.ResetSentMessages(network.ProtocolRootVote)
		require.NoError(t, r.manager.onProposalMsg(ctx, proposal))
	}
	round = anchor.Slot + 2
	for _, r := range byID {
		if r == lagger {
			continue
		}
		require.Equal(t, round, r.manager.pacemaker.GetCurrentRound())
		r.manager.onLocalTimeout(ctx)
		replicas = append(replicas, r)
		msgs := r.net.SentMessages(network.ProtocolRootTimeout)
		require.NotEmpty(t, msgs)
		v := msgs[0].Message.(*abdrc.TimeoutMsg)
		require.NotNil(t, v.Timeout.HighQc, "a real QC, not an anchor")
		require.EqualValues(t, round-1, v.Timeout.HighQc.VoteInfo.RoundNumber)
		votes = append(votes, v)
	}
	return replicas, votes, round, lagger, missed
}

// timeoutCertOf feeds the first three votes to a replica other than the author of votes[0] and returns the timeout certificate it formed.
func timeoutCertOf(t *testing.T, replicas []*anchorReplica, votes []*abdrc.TimeoutMsg) *drctypes.TimeoutCert {
	t.Helper()
	ctx := context.Background()
	b := replicas[len(replicas)-1]
	for _, v := range votes[:3] {
		require.NoError(t, b.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)))
	}
	tc := b.manager.pacemaker.lastRoundTC
	require.NotNil(t, tc, "three of four timeout votes form the certificate")
	return tc
}

// A same-round changed QC under a still-valid vote signature (the signature covers the high QC's round, not its content) is a different
// message: it is verified and refused, and the counted original is untouched.
func TestChangedHighQCOfTheSameRoundIsVerifiedAndRefused(t *testing.T) {
	replicas, votes, round := realQCTimeouts(t)
	rx := replicas[0]
	ctx := context.Background()
	calls := countVerifications(rx.manager)
	v := votes[1]
	require.NoError(t, rx.manager.onTimeoutMsg(ctx, v))
	require.Equal(t, 1, *calls)

	changed := recodeTimeout(t, v)
	changed.Timeout.HighQc.VoteInfo.Timestamp++ // content of the QC, same round: the vote's own signature is still valid
	require.Equal(t, v.Timeout.HighQc.VoteInfo.RoundNumber, changed.Timeout.HighQc.VoteInfo.RoundNumber)
	err := rx.manager.onTimeoutMsg(ctx, changed)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid timeout vote")
	require.Equal(t, 2, *calls, "a miss: it was verified")

	fewer := recodeTimeout(t, v)
	for id := range fewer.Timeout.HighQc.Signatures {
		delete(fewer.Timeout.HighQc.Signatures, id) // witnesses removed, same round
		break
	}
	err = rx.manager.onTimeoutMsg(ctx, fewer)
	require.Error(t, err)
	require.Equal(t, 3, *calls)
	require.ErrorIs(t, rx.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 3, *calls, "the original still hits")
	require.Equal(t, round, rx.manager.pacemaker.GetCurrentRound())
}

// A copy of a counted vote that carries a valid later timeout certificate is a different message: it misses, is verified, and its
// certificate still advances the receiver. (An early drop on signer/round/epoch would have lost this.) An identical replay advances nothing.
func TestChangedLastTCOfACountedVoteStillAdvancesTheReceiver(t *testing.T) {
	replicas, votes, round := realQCTimeouts(t)
	ctx := context.Background()
	rx := replicas[0]
	tc := timeoutCertOf(t, replicas, votes)
	calls := countVerifications(rx.manager)
	v := votes[1]
	require.NoError(t, rx.manager.onTimeoutMsg(ctx, v))
	require.Equal(t, round, rx.manager.pacemaker.GetCurrentRound())
	require.ErrorIs(t, rx.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 1, *calls)
	require.Equal(t, round, rx.manager.pacemaker.GetCurrentRound(), "an identical replay moves nothing")

	withTC := recodeTimeout(t, v)
	withTC.LastTC = tc
	_ = rx.manager.onTimeoutMsg(ctx, withTC) // the registration may refuse the repeat signer; the certificate is processed before that
	require.Equal(t, 2, *calls, "a miss: verified")
	require.Equal(t, round+1, rx.manager.pacemaker.GetCurrentRound(), "its timeout certificate advanced the receiver")
}

// Consecutive timeouts: a lagging replica catches up through the last TC of a later round's timeout vote, with the verification done once
// and an identical replay verified no more.
func TestConsecutiveTimeoutCatchUpThroughTheLastTC(t *testing.T) {
	replicas, votes, round := realQCTimeouts(t)
	ctx := context.Background()
	tc := timeoutCertOf(t, replicas, votes)
	lagging := replicas[0]
	require.Equal(t, round, lagging.manager.pacemaker.GetCurrentRound())
	// another replica advanced with the certificate and times out the next round: its vote carries the last TC
	other := replicas[len(replicas)-1]
	require.Equal(t, round+1, other.manager.pacemaker.GetCurrentRound())
	other.net.ResetSentMessages(network.ProtocolRootTimeout)
	other.manager.onLocalTimeout(ctx)
	next := other.net.SentMessages(network.ProtocolRootTimeout)[0].Message.(*abdrc.TimeoutMsg)
	require.NotNil(t, next.LastTC)
	require.Equal(t, tc.GetRound(), next.LastTC.GetRound())

	calls := countVerifications(lagging.manager)
	require.NoError(t, lagging.manager.onTimeoutMsg(ctx, next))
	require.Equal(t, 1, *calls)
	require.Equal(t, round+1, lagging.manager.pacemaker.GetCurrentRound(), "the lagging replica caught up through the last TC")
	require.ErrorIs(t, lagging.manager.onTimeoutMsg(ctx, recodeTimeout(t, next)), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 1, *calls, "the replay hit: not verified again")
}

// A real context change through the handler: after the vote was counted, the epoch activates the domain-bound scheme. The same bytes now
// have another signing configuration, so they miss and are verified, and the legacy form is refused with the scheme error.
func TestSigningConfigChangeInvalidatesTheRememberedMessage(t *testing.T) {
	replicas, votes, _ := realQCTimeouts(t)
	ctx := context.Background()
	rx := replicas[0]
	calls := countVerifications(rx.manager)
	v := votes[1]
	require.NoError(t, rx.manager.onTimeoutMsg(ctx, v))
	require.ErrorIs(t, rx.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 1, *calls)

	require.NoError(t, rx.manager.trustBaseStore.ActivateSigning(v.Timeout.Epoch, domainBoundConfig()))
	err := rx.manager.onTimeoutMsg(ctx, recodeTimeout(t, v))
	require.ErrorIs(t, err, votesig.ErrScheme)
	require.Equal(t, 2, *calls, "the changed context is a miss")
}

// A message whose epoch has no installed trust base or signing configuration gets no key at all: nothing is remembered or found for it.
func TestNoKeyWithoutASigningConfiguration(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	v := recodeTimeout(t, votes[0])
	v.Timeout.Epoch = 99
	_, _, ok := receiver.manager.timeoutCacheKey(v)
	require.False(t, ok)
	_, _, ok = receiver.manager.timeoutCacheKey(votes[0])
	require.True(t, ok)
}

// First copy meets a receiver that has not seen the certified blocks: it needs recovery, is not counted and nothing is remembered. After
// the receiver catches up, the same message is verified again, counted and remembered; its replay then hits.
func TestRecoveryFirstThenRetryIsVerifiedAgainAndRemembered(t *testing.T) {
	_, votes, _, lagger, missed := realQCTimeoutsWith(t, true)
	ctx := context.Background()
	calls := countVerifications(lagger.manager)
	v := votes[0]

	err := lagger.manager.onTimeoutMsg(ctx, v)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recovery")
	require.Equal(t, 1, *calls)
	require.False(t, lagger.manager.pacemaker.VerifiedTimeoutHit(v.Author, v.Timeout.Round, v.Timeout.Epoch, mustDigest(t, lagger.manager, v), mustCtx(t, lagger.manager, v)), "an uncounted message is not remembered")

	for _, p := range missed { // the receiver catches up
		require.NoError(t, lagger.manager.onProposalMsg(ctx, p))
	}
	require.NoError(t, lagger.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)), "the retry is processed and counted")
	require.Equal(t, 2, *calls, "it was verified again, not served from the first attempt")
	require.ErrorIs(t, lagger.manager.onTimeoutMsg(ctx, recodeTimeout(t, v)), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 2, *calls, "now it hits")
}

func mustDigest(t *testing.T, m *ConsensusManager, v *abdrc.TimeoutMsg) [32]byte {
	t.Helper()
	d, _, ok := m.timeoutCacheKey(v)
	require.True(t, ok)
	return d
}

func mustCtx(t *testing.T, m *ConsensusManager, v *abdrc.TimeoutMsg) verifyContext {
	t.Helper()
	_, c, ok := m.timeoutCacheKey(v)
	require.True(t, ok)
	return c
}

// The certificate a replayed (hit) message carries is still processed: with the stored last TC older than it (a failed or lost write), the
// replay writes it, and the verification was not repeated.
func TestCertificateOfAHitIsStillProcessedAndPersisted(t *testing.T) {
	replicas, votes, round := realQCTimeouts(t)
	ctx := context.Background()
	tc := timeoutCertOf(t, replicas, votes)
	lagging := replicas[0]
	other := replicas[len(replicas)-1]
	other.net.ResetSentMessages(network.ProtocolRootTimeout)
	other.manager.onLocalTimeout(ctx)
	next := other.net.SentMessages(network.ProtocolRootTimeout)[0].Message.(*abdrc.TimeoutMsg)
	require.NotNil(t, next.LastTC)

	calls := countVerifications(lagging.manager)
	require.NoError(t, lagging.manager.onTimeoutMsg(ctx, next))
	last, err := lagging.db.ReadLastTC()
	require.NoError(t, err)
	require.Equal(t, tc.GetRound(), last.GetRound(), "the first copy persisted its last TC")

	// a lost write: the stored TC is older than the one the message carries
	stale := &drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Epoch: tc.Timeout.Epoch, Round: round - 1}, Signatures: map[string]*drctypes.TimeoutVote{}}
	require.NoError(t, lagging.db.WriteTC(stale))
	last, err = lagging.db.ReadLastTC()
	require.NoError(t, err)
	require.Equal(t, round-1, last.GetRound())

	require.ErrorIs(t, lagging.manager.onTimeoutMsg(ctx, recodeTimeout(t, next)), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 1, *calls, "the replay hit: not verified again")
	last, err = lagging.db.ReadLastTC()
	require.NoError(t, err)
	require.Equal(t, tc.GetRound(), last.GetRound(), "the hit still processed its certificate: the write was retried")
}

type unknownMembers struct{}

func (unknownMembers) GetQuorumThreshold() uint64      { return 3 }
func (unknownMembers) GetMaxFaultyNodes() uint64       { return 1 }
func (unknownMembers) GetRootNodes() []*types.NodeInfo { return nil }

// A weight error after the signature was added to the certificate leaves nothing remembered: the vote is not a verified, counted one.
func TestWeightFailureAfterAddRemembersNothing(t *testing.T) {
	var r VoteRegister
	vote := &abdrc.TimeoutMsg{Timeout: &drctypes.Timeout{Round: 5, Epoch: 1}, Author: "stranger", Signature: []byte{1}}
	ctx := verifyContext{n: 1}
	_, _, err := r.InsertTimeoutVote(vote, profile2QuorumInfo{QuorumInfo: unknownMembers{}}, timeoutMemo{digest: [32]byte{7}, ctx: ctx})
	require.ErrorIs(t, err, quorumweight.ErrUnknownSigner)
	require.Contains(t, r.timeoutCert.Signatures, "stranger", "the signature was added before the weight failed")
	require.False(t, r.VerifiedTimeoutHit("stranger", 5, 1, [32]byte{7}, ctx), "and nothing was remembered")
}
