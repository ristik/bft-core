package cmd

import (
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-go-base/types"
)

// bft-core#1057: the health binding names this node, its network and shard, the installed configuration (epoch, hash, the key it names for
// this node) and the verified history; what cannot be read is left out, so a comparison of it fails closed.
func TestTheShardBindingReportsTheInstalledEvidence(t *testing.T) {
	_, pub, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	self, err := libp2ppeer.IDFromPublicKey(pub)
	require.NoError(t, err)
	conf := &types.PartitionDescriptionRecord{NetworkID: 5, PartitionID: 8, ShardID: types.ShardID{}}
	src := shardBindingSource{self: self, shard: conf,
		installed: func() (uint64, bool, []byte) { return 4, true, []byte{0xaa} },
		confHash: func(epoch uint64) ([]byte, bool) {
			if epoch == 4 {
				return []byte{0x01, 0x02}, true
			}
			return nil, false
		},
		history: func() ([]q3active.HistoryEntry, error) {
			return []q3active.HistoryEntry{{Epoch: 1, BodyID: "b1"}, {Epoch: 2, BodyID: "b2", CommitID: "c2"}}, nil
		}}
	b := src.binding()
	require.Equal(t, self.String(), b.NodeID)
	require.Equal(t, uint64(5), b.NetworkID)
	require.Equal(t, uint64(8), b.PartitionID)
	require.Equal(t, conf.ShardID.String(), b.ShardID)
	require.Equal(t, uint64(4), b.ShardEpoch)
	require.True(t, b.Member)
	require.Equal(t, "aa", b.SigKey)
	require.Equal(t, "0102", b.ShardConfHash)
	require.Len(t, b.History, 2)
	require.Equal(t, "b2", b.History[1].BodyID)

	src.installed = func() (uint64, bool, []byte) { return 5, false, nil }
	src.history = func() ([]q3active.HistoryEntry, error) { return nil, errors.New("not loaded") }
	b = src.binding()
	require.False(t, b.Member)
	require.Empty(t, b.SigKey, "not named: no key")
	require.Empty(t, b.ShardConfHash, "no installed hash for the epoch: left out")
	require.Empty(t, b.History, "an unreadable history is left out")
	src.history = nil
	require.Empty(t, src.binding().History, "no Q3 runtime")
}
