package consensus

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

// timeoutVotesOf makes every replica except one time out and returns the (real, signed) votes it sent, plus a receiver that is not the author
// of any of them. Fewer than a quorum is delivered in these tests, so the receiver stays in the round.
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

func corrupted(v *abdrc.TimeoutMsg) *abdrc.TimeoutMsg {
	c := *v
	c.Signature = bytes.Repeat([]byte{0x5a}, len(v.Signature))
	return &c
}

// A retransmission of a counted vote is refused before its signatures are checked: a repeat whose signature is garbage still gets the
// duplicate answer. Were the signature checked first, the answer would be "invalid timeout vote".
func TestCountedTimeoutVoteIsRefusedBeforeItsSignatureIsChecked(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	ctx := context.Background()
	v := votes[0]
	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v))
	require.True(t, receiver.manager.pacemaker.HasTimeoutVote(v.Author, v.Timeout.Round, v.Timeout.Epoch))

	err := receiver.manager.onTimeoutMsg(ctx, v)
	require.ErrorIs(t, err, errDuplicateTimeoutVote)
	require.ErrorIs(t, err, quorumweight.ErrDuplicateSigner, "the same answer RegisterTimeoutVote gives")

	err = receiver.manager.onTimeoutMsg(ctx, corrupted(v))
	require.ErrorIs(t, err, errDuplicateTimeoutVote, "refused before Verify: not an invalid-signature error")
	require.NotContains(t, err.Error(), "invalid timeout vote")
}

// An unverified message never pre-empts a valid one: an invalid first message of a signer is refused by the verification (and counts for
// nothing), the valid one that follows is counted.
func TestInvalidFirstTimeoutVoteDoesNotPreemptTheValidOne(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	ctx := context.Background()
	v := votes[0]

	err := receiver.manager.onTimeoutMsg(ctx, corrupted(v))
	require.Error(t, err)
	require.NotErrorIs(t, err, errDuplicateTimeoutVote)
	require.Contains(t, err.Error(), "invalid timeout vote")
	require.False(t, receiver.manager.pacemaker.HasTimeoutVote(v.Author, v.Timeout.Round, v.Timeout.Epoch), "an invalid message is not counted")

	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v), "the valid vote that follows is processed and counted")
	require.True(t, receiver.manager.pacemaker.HasTimeoutVote(v.Author, v.Timeout.Round, v.Timeout.Epoch))
}

// Only the same signer, round and epoch is refused: another signer's vote, another round or another epoch is not.
func TestEarlyRefusalKeysOnSignerRoundAndEpoch(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	ctx := context.Background()
	v := votes[0]
	require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v))
	pm := receiver.manager.pacemaker
	require.True(t, pm.HasTimeoutVote(v.Author, v.Timeout.Round, v.Timeout.Epoch))
	require.False(t, pm.HasTimeoutVote(v.Author, v.Timeout.Round+1, v.Timeout.Epoch), "another round")
	require.False(t, pm.HasTimeoutVote(v.Author, v.Timeout.Round, v.Timeout.Epoch+1), "another epoch")
	require.False(t, pm.HasTimeoutVote(v.Author+"x", v.Timeout.Round, v.Timeout.Epoch), "another signer")
	if len(votes) > 1 {
		require.NotEqual(t, v.Author, votes[1].Author)
		require.NoError(t, receiver.manager.onTimeoutMsg(ctx, votes[1]), "a different signer's vote is processed")
	}
}

// The register forgets counted votes with the round.
func TestCountedTimeoutVotesAreForgottenOnReset(t *testing.T) {
	receiver, votes := timeoutVotesOf(t)
	v := votes[0]
	require.NoError(t, receiver.manager.onTimeoutMsg(context.Background(), v))
	receiver.manager.pacemaker.pendingVotes.Reset()
	require.False(t, receiver.manager.pacemaker.HasTimeoutVote(v.Author, v.Timeout.Round, v.Timeout.Epoch))
}
