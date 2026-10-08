package consensus

import (
	"math"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type askedSelector struct {
	Leader
	asked []uint64
}

func (a *askedSelector) GetLeaderForRound(r uint64) (peer.ID, error) {
	a.asked = append(a.asked, r)
	return "leader", nil
}

// The successor round is overflow-checked before any lookup: the top of the round space is refused and never wraps to round 0.
func TestLeaderAfterRefusesTheSuccessorOverflow(t *testing.T) {
	sel := &askedSelector{}
	x := &ConsensusManager{leaderSelector: sel}
	id, err := x.leaderAfter(41)
	require.NoError(t, err)
	require.Equal(t, peer.ID("leader"), id)
	require.Equal(t, []uint64{42}, sel.asked)
	_, err = x.leaderAfter(math.MaxUint64)
	require.ErrorIs(t, err, errRoundOverflow)
	require.Equal(t, []uint64{42}, sel.asked, "the selector was not asked for a wrapped round")
	_, err = x.leaderAfter(math.MaxUint64 - 1)
	require.NoError(t, err)
	require.Equal(t, uint64(math.MaxUint64), sel.asked[1])
}
