package shardnode

import (
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func newPeerID(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	id, err := peer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	return id
}

func validatorsOf(ids ...peer.ID) []*types.NodeInfo {
	out := make([]*types.NodeInfo, len(ids))
	for i, id := range ids {
		out[i] = &types.NodeInfo{NodeID: id.String(), SigKey: []byte{byte(i)}, Stake: 1}
	}
	return out
}

// The peers this node serves are the validators of the ACTIVE assignment: genesis at first, then each verified installed step's set.
func TestActivePeersFollowTheInstalledAssignment(t *testing.T) {
	self, v2, v3, v4, joiner := newPeerID(t), newPeerID(t), newPeerID(t), newPeerID(t), newPeerID(t)
	peers, err := NewActivePeers(self, validatorsOf(self, v2, v3, v4))
	require.NoError(t, err)

	t.Run("genesis validators are peers, this node itself and a joiner are not (before the install)", func(t *testing.T) {
		require.True(t, peers.Allowed(v2) && peers.Allowed(v3) && peers.Allowed(v4))
		require.False(t, peers.Allowed(self))
		require.False(t, peers.Allowed(joiner), "a joiner is refused before its assignment is installed")
	})
	t.Run("the installed assignment's joiner is allowed and a retired validator is refused", func(t *testing.T) {
		require.NoError(t, peers.Install(1, validatorsOf(self, v2, v3, joiner)))
		require.True(t, peers.Allowed(joiner), "allowed once its assignment is installed (before it acknowledges)")
		require.False(t, peers.Allowed(v4), "a validator the assignment retires is refused after the install")
		require.True(t, peers.Allowed(v2) && peers.Allowed(v3))
		require.False(t, peers.Allowed(self))
	})
	t.Run("replaying an installed step is harmless; a different set for the active epoch is refused", func(t *testing.T) {
		require.NoError(t, peers.Install(1, validatorsOf(self, v2, v3, joiner)))
		require.ErrorIs(t, peers.Install(1, validatorsOf(self, v2, v3, v4)), ErrActivePeersConflict)
		require.True(t, peers.Allowed(joiner) && !peers.Allowed(v4), "a refused install changes nothing")
	})
	t.Run("a later supersession replaces the set", func(t *testing.T) {
		other := newPeerID(t)
		require.NoError(t, peers.Install(3, validatorsOf(self, v2, other)))
		require.True(t, peers.Allowed(other))
		require.False(t, peers.Allowed(joiner), "the superseded assignment's joiner is refused")
		require.NoError(t, peers.Install(2, validatorsOf(self, v2, joiner)), "an older epoch's bundle is history: it neither fails nor moves the set backwards")
		require.False(t, peers.Allowed(joiner))
		require.Len(t, peers.Peers(), 2)
	})
	t.Run("a malformed validator id is refused", func(t *testing.T) {
		require.Error(t, peers.Install(4, []*types.NodeInfo{{NodeID: "not-a-peer-id", SigKey: []byte{1}, Stake: 1}}))
	})
}
