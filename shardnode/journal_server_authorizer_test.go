package shardnode

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func nodeInfos(ids ...peer.ID) []*types.NodeInfo {
	out := make([]*types.NodeInfo, len(ids))
	for i, id := range ids {
		out[i] = &types.NodeInfo{NodeID: id.String(), SigKey: bytes.Repeat([]byte{byte(i + 2)}, 33), Stake: 1}
	}
	return out
}

// The journal server's allowlist is the active assignment's validator set: a joiner may fetch once its step is installed, a retired
// validator may not, and nobody may while the set is held.
func TestTheJournalServerAllowsTheActiveAssignmentsValidators(t *testing.T) {
	self, kept, retired, joiner := newPeerID(t), newPeerID(t), newPeerID(t), newPeerID(t)
	active, err := NewActivePeers(self, nodeInfos(self, kept, retired))
	require.NoError(t, err)
	s := &JournalServer{}
	s.SetPeerAuthorizer(active.Allowed)
	require.True(t, s.permits(retired), "genesis set before any step")
	require.False(t, s.permits(joiner))

	require.NoError(t, active.Install(1, nodeInfos(self, kept, joiner)))
	require.True(t, s.permits(joiner), "the joiner may fetch once its step is installed")
	require.False(t, s.permits(retired), "the retired validator may not")
	active.Hold()
	require.False(t, s.permits(kept), "held until the replay is done")

	fixed := &JournalServer{}
	fixed.RestrictToPeers([]peer.ID{kept})
	require.True(t, fixed.permits(kept))
	require.False(t, fixed.permits(joiner), "a deployment with a fixed list is unchanged")
	require.True(t, (&JournalServer{}).permits(joiner), "and one with neither stays open, as before")
}
