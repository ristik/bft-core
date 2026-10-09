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
		require.ErrorIs(t, peers.Install(4, []*types.NodeInfo{{NodeID: "not-a-peer-id", SigKey: []byte{1}, Stake: 1}}), ErrActivePeersInvalid)
		require.ErrorIs(t, peers.Install(4, []*types.NodeInfo{nil}), ErrActivePeersInvalid)
	})
}

// After a restart the persisted verified steps are replayed AFTER the archive server could already be asked who may connect. Until the
// replay is done the set is held: nobody is authorized (the genesis set may still name a validator a persisted step retired), the
// installs made by the replay still update the set, and releasing opens exactly the replayed set.
func TestActivePeersAreHeldUntilThePersistedStepsAreReplayed(t *testing.T) {
	self, v2, v3, v4, joiner := newPeerID(t), newPeerID(t), newPeerID(t), newPeerID(t), newPeerID(t)
	peers, err := NewActivePeers(self, validatorsOf(self, v2, v3, v4))
	require.NoError(t, err)
	peers.Hold()
	require.False(t, peers.Allowed(v2) || peers.Allowed(v3) || peers.Allowed(v4), "a held set authorizes nobody, not even the genesis validators")
	require.False(t, peers.Allowed(joiner))

	// the replay installs the persisted step that retired v4 and admitted the joiner
	require.NoError(t, peers.Install(1, validatorsOf(self, v2, v3, joiner)))
	require.False(t, peers.Allowed(v2) || peers.Allowed(joiner), "still held while the replay runs")
	require.Len(t, peers.Peers(), 3, "the held set is still rebuilt: only authorization is withheld")

	peers.Release()
	require.True(t, peers.Allowed(v2) && peers.Allowed(v3) && peers.Allowed(joiner))
	require.False(t, peers.Allowed(v4), "the retired validator was never authorized after the restart")
	require.False(t, peers.Allowed(self))
}

// A staged successor assignment's validators may fetch from this node before their assignment is installed (a joiner that is behind has to
// catch up before it can give readiness); the stage is replaced by the next one, cleared by an install, never names this node and never
// authorizes while the set is held.
func TestActivePeersServeTheStagedSuccessorUntilItIsInstalledOrReplaced(t *testing.T) {
	self, v2, v3, joiner, other := newPeerID(t), newPeerID(t), newPeerID(t), newPeerID(t), newPeerID(t)
	peers, err := NewActivePeers(self, validatorsOf(self, v2, v3))
	require.NoError(t, err)

	require.False(t, peers.Allowed(joiner))
	require.NoError(t, peers.Stage([]string{self.String(), v2.String(), joiner.String()}))
	require.True(t, peers.Allowed(joiner), "a staged successor member is served before its install")
	require.True(t, peers.Allowed(v3), "the active set is untouched by a stage")
	require.False(t, peers.Allowed(self))
	require.False(t, peers.Allowed(other), "a peer no assignment names")

	require.NoError(t, peers.Stage([]string{other.String()}))
	require.False(t, peers.Allowed(joiner), "the next stage replaces the earlier one")
	require.True(t, peers.Allowed(other))

	require.ErrorIs(t, peers.Stage([]string{"not a peer"}), ErrActivePeersInvalid)
	require.True(t, peers.Allowed(other), "a refused stage changes nothing")

	require.NoError(t, peers.Install(1, validatorsOf(self, v2, joiner)))
	require.False(t, peers.Allowed(other), "the install clears the stage")
	require.True(t, peers.Allowed(joiner))

	held, err := NewActivePeers(self, validatorsOf(self, v2))
	require.NoError(t, err)
	held.Hold()
	require.NoError(t, held.Stage([]string{joiner.String()}))
	require.False(t, held.Allowed(joiner), "a held set authorizes nobody, staged or not")
}
