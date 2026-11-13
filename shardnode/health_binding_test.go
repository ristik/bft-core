package shardnode

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// bft-core#1057: the installed set names the signing key it gives this node, and the health report carries the binding it was told, as a copy.
func TestTheInstalledSetNamesThisNodesKeyAndTheHealthCarriesTheBinding(t *testing.T) {
	self, a, b := newPeerID(t), newPeerID(t), newPeerID(t)
	peers, err := NewActivePeers(self, validatorsOf(a, b))
	require.NoError(t, err)
	epoch, member, key := peers.Installed()
	require.Zero(t, epoch)
	require.False(t, member)
	require.Nil(t, key, "a set that does not name this node gives it no key")

	joined := validatorsOf(a, b, self)
	joined[2].SigKey = []byte{0xaa, 0xbb}
	require.NoError(t, peers.Install(3, joined))
	epoch, member, key = peers.Installed()
	require.Equal(t, uint64(3), epoch)
	require.True(t, member)
	require.Equal(t, []byte{0xaa, 0xbb}, key)
	key[0] = 0
	_, _, again := peers.Installed()
	require.Equal(t, []byte{0xaa, 0xbb}, again, "a copy")

	require.NoError(t, peers.Install(4, validatorsOf(a, b)))
	_, member, key = peers.Installed()
	require.False(t, member)
	require.Nil(t, key, "retired: no key")
	require.NoError(t, peers.Install(2, joined), "an older step changes nothing")
	_, member, _ = peers.Installed()
	require.False(t, member)

	h := NewHealth()
	require.Nil(t, h.Snapshot().Binding)
	in := Binding{NodeID: self.String(), NetworkID: 5, PartitionID: 8, ShardID: types.ShardID{}.String(), ShardEpoch: 4, ShardConfHash: "ab",
		History: []HistoryEntry{{Epoch: 1, BodyID: "01"}, {Epoch: 2, BodyID: "02"}}}
	h.UpdateBinding(in)
	in.History[0].BodyID = "changed"
	got := h.Snapshot().Binding
	require.NotNil(t, got)
	require.Equal(t, "01", got.History[0].BodyID, "the health keeps its own copy")
	got.History[1].BodyID = "changed"
	require.Equal(t, "02", h.Snapshot().Binding.History[1].BodyID, "and hands out copies")
	var nilHealth *Health
	nilHealth.UpdateBinding(in) // nil-safe like every update
}
