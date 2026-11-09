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
