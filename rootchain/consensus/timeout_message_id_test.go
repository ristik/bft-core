package consensus

import (
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
