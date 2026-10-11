package consensus

import (
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A root signs one timeout vote per round. It remembers the vote in its pacemaker and stores it as its last vote; a recovery (state
// sync from a peer) resets the pacemaker and can come back to the SAME round with a newer high QC. The root must then send the
// timeout vote it already signed for the round, not sign a second, different one.
//
// The sequence is the one TestQ4Fault/restarts hit under load: round 2 times out (TC), the root signs its timeout vote for round 3
// with the high QC of round 1, a late QC for round 2 arrives, and the recovery's pacemaker reset re-enters round 3.
func TestALocalTimeoutAfterARecoveryResendsTheTimeoutVoteAlreadySignedForTheRound(t *testing.T) {
	mockNet := testnetwork.NewRootMockNetwork()
	cm, _, _ := initConsensusManager(t, mockNet)
	ctx := context.Background()

	genesisQC := cm.blockStore.GetHighQc()
	require.EqualValues(t, 1, genesisQC.GetRound())
	// round 2: a block on genesis, executed and stored
	rh2, err := cm.blockStore.Add(&drctypes.BlockData{Version: 1, Round: 2, Epoch: genesisQC.VoteInfo.Epoch, Payload: &drctypes.Payload{}, Qc: genesisQC}, cm.irReqVerifier)
	require.NoError(t, err)
	// round 2 times out: its block is set aside, and the pacemaker enters round 3 under the TC
	tc2 := &drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Round: 2, Epoch: genesisQC.VoteInfo.Epoch, HighQc: genesisQC}}
	require.NoError(t, cm.blockStore.ProcessTc(tc2))
	cm.pacemaker.Reset(ctx, genesisQC.GetRound(), tc2, nil)
	t.Cleanup(cm.pacemaker.Stop)
	require.EqualValues(t, 3, cm.pacemaker.GetCurrentRound())

	cm.onLocalTimeout(ctx)
	first := testutils.MockAwaitMessage[*abdrc.TimeoutMsg](t, mockNet, network.ProtocolRootTimeout)
	require.EqualValues(t, 3, first.Timeout.Round)
	require.EqualValues(t, 1, first.Timeout.GetHqcRound(), "premise: signed with the high QC of round 1")
	firstID := timeoutMessageID(first)

	// a late QC for round 2 (votes delayed past the TC): the root's high QC is now round 2, its round is still 3
	qc2 := &drctypes.QuorumCert{
		VoteInfo:         &drctypes.RoundInfo{RoundNumber: 2, Epoch: genesisQC.VoteInfo.Epoch, Timestamp: genesisQC.VoteInfo.Timestamp + 1, ParentRoundNumber: 1, CurrentRootHash: rh2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1},
	}
	qc2.LedgerCommitInfo.PreviousHash, err = qc2.VoteInfo.Hash(crypto.SHA256)
	require.NoError(t, err)
	_, err = cm.blockStore.ProcessQc(qc2)
	require.NoError(t, err)
	require.EqualValues(t, 2, cm.blockStore.GetHighQc().GetRound())
	// what a recovery does to the pacemaker when it completes (sendRecoveryRequests' handler): reset to the recovered high QC's
	// round, with no vote handed over
	cm.pacemaker.Reset(ctx, cm.blockStore.GetHighQc().GetRound(), nil, nil)
	require.EqualValues(t, 3, cm.pacemaker.GetCurrentRound(), "premise: the recovery came back to the round already timed out in")
	require.Nil(t, cm.pacemaker.GetTimeoutVote(), "premise: the pacemaker no longer remembers the vote")

	cm.onLocalTimeout(ctx)
	second := testutils.MockAwaitMessage[*abdrc.TimeoutMsg](t, mockNet, network.ProtocolRootTimeout)
	require.EqualValues(t, 3, second.Timeout.Round)
	require.Equal(t, firstID, timeoutMessageID(second), "one timeout vote per round: the stored one is sent again (it carried high QC round %d; a newly signed one would carry %d)",
		first.Timeout.GetHqcRound(), cm.blockStore.GetHighQc().GetRound())

	// once the stored round has passed, the stored vote is of an older round and a new one is signed for the new round
	tc3 := &drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Round: 3, Epoch: genesisQC.VoteInfo.Epoch, HighQc: qc2}}
	cm.pacemaker.Reset(ctx, cm.blockStore.GetHighQc().GetRound(), tc3, nil)
	require.EqualValues(t, 4, cm.pacemaker.GetCurrentRound())
	cm.onLocalTimeout(ctx)
	next := testutils.MockAwaitMessage[*abdrc.TimeoutMsg](t, mockNet, network.ProtocolRootTimeout)
	require.EqualValues(t, 4, next.Timeout.Round, "a new vote for the new round, not the stored one of round 3")
	require.NotEqual(t, firstID, timeoutMessageID(next))
	stored, err := cm.blockStore.ReadLastVote()
	require.NoError(t, err)
	require.Equal(t, timeoutMessageID(next), timeoutMessageID(stored.(*abdrc.TimeoutMsg)), "and it is now the stored last vote")
}

// storedTimeoutVote returns the stored last vote only when it is this root's own timeout vote for exactly the epoch and round asked
// for. The epoch matters most: rounds start again in a new epoch, and a vote of the previous epoch with the same round number, sent
// in place of a new one, would leave the root never signing for that round.
func TestStoredTimeoutVoteIsOnlyThisRootsVoteForExactlyTheEpochAndRound(t *testing.T) {
	cm, _, _ := initConsensusManager(t, testnetwork.NewRootMockNetwork())
	ctx := context.Background()
	self := cm.id.String()
	timeoutVote := func(epoch, round uint64, author string) *abdrc.TimeoutMsg {
		return &abdrc.TimeoutMsg{Timeout: &drctypes.Timeout{Epoch: epoch, Round: round, HighQc: cm.blockStore.GetHighQc()}, Author: author, Signature: []byte{1}}
	}

	require.Nil(t, cm.storedTimeoutVote(ctx, 1, 7), "an empty store")

	require.NoError(t, cm.blockStore.StoreLastVote(timeoutVote(1, 7, self)))
	got := cm.storedTimeoutVote(ctx, 1, 7)
	require.NotNil(t, got, "this root's timeout vote for the epoch and round")
	require.EqualValues(t, 7, got.Timeout.Round)
	require.EqualValues(t, 1, got.Timeout.Epoch)
	require.Equal(t, self, got.Author)
	for name, ask := range map[string][2]uint64{
		"another round, later":   {1, 8},
		"another round, earlier": {1, 6},
		"another epoch, later":   {2, 7},
		"another epoch, earlier": {0, 7},
	} {
		require.Nil(t, cm.storedTimeoutVote(ctx, ask[0], ask[1]), name)
	}

	require.NoError(t, cm.blockStore.StoreLastVote(timeoutVote(1, 7, "another-root")))
	require.Nil(t, cm.storedTimeoutVote(ctx, 1, 7), "another author's vote")

	require.NoError(t, cm.blockStore.StoreLastVote(timeoutVote(1, 7, self)))
	require.NotNil(t, cm.storedTimeoutVote(ctx, 1, 7), "(premise for the next case: the timeout vote is back)")
	require.NoError(t, cm.blockStore.StoreLastVote(&abdrc.VoteMsg{VoteInfo: &drctypes.RoundInfo{RoundNumber: 7, Epoch: 1}, Author: self}))
	require.Nil(t, cm.storedTimeoutVote(ctx, 1, 7), "a vote for a proposal of the same round is not a timeout vote")
}
