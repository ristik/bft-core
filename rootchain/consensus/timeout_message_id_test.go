package consensus

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The identity the lane compares across a crash: the same recorded statement has one identity, any other statement another.
func TestTheTimeoutMessageIdentifiesTheExactStatement(t *testing.T) {
	msg := abdrc.NewTimeoutMsg(drctypes.NewTimeout(14, 2, nil), "node-a", nil)
	id := timeoutMessageID(msg)
	require.Len(t, id, 64)
	require.Equal(t, id, timeoutMessageID(msg), "deterministic")

	again := abdrc.NewTimeoutMsg(drctypes.NewTimeout(14, 2, nil), "node-a", nil)
	require.Equal(t, id, timeoutMessageID(again), "the same statement rebuilt is the same identity")
	require.NotEqual(t, id, timeoutMessageID(abdrc.NewTimeoutMsg(drctypes.NewTimeout(15, 2, nil), "node-a", nil)), "another round")
	require.NotEqual(t, id, timeoutMessageID(abdrc.NewTimeoutMsg(drctypes.NewTimeout(14, 2, nil), "node-b", nil)), "another author")
}

// A signed vote has an identity like a timeout vote, and the vote recovered at start is logged under the identity it was signed with.
func TestRecoveredLastVoteIsLoggedUnderItsSigningIdentity(t *testing.T) {
	vote := &abdrc.VoteMsg{VoteInfo: &drctypes.RoundInfo{RoundNumber: 21, Epoch: 2}, Author: "node-a"}
	id := voteMessageID(vote)
	require.Equal(t, id, voteMessageID(vote), "deterministic")
	require.NotEqual(t, id, voteMessageID(&abdrc.VoteMsg{VoteInfo: &drctypes.RoundInfo{RoundNumber: 22, Epoch: 2}, Author: "node-a"}), "another round")

	timeout := abdrc.NewTimeoutMsg(drctypes.NewTimeout(14, 2, nil), "node-a", nil)
	for name, tc := range map[string]struct {
		last         any
		kind, wantID string
		wantRound    string
	}{
		"a vote":         {vote, "vote", id, "round=21"},
		"a timeout vote": {timeout, "timeout", timeoutMessageID(timeout), "round=14"},
	} {
		var out bytes.Buffer
		logRecoveredVote(context.Background(), slog.New(slog.NewTextHandler(&out, nil)), tc.last)
		require.Contains(t, out.String(), `msg="recovered last vote"`, name)
		require.Contains(t, out.String(), "kind="+tc.kind, name)
		require.Contains(t, out.String(), tc.wantRound, name)
		require.Contains(t, out.String(), "messageID="+tc.wantID, name)
	}
	var out bytes.Buffer
	logRecoveredVote(context.Background(), slog.New(slog.NewTextHandler(&out, nil)), nil)
	require.Empty(t, out.String(), "no vote was held")
}
