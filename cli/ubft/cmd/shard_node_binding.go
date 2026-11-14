package cmd

import (
	"encoding/hex"

	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// shardBindingSource is what the health binding of a shard node is read from (bft-core#1057): this node's identity, its configured network
// and shard, the installed (verified) assignment, the installed configuration hash per shard epoch, and the verified activation history.
type shardBindingSource struct {
	self      libp2ppeer.ID
	shard     *types.PartitionDescriptionRecord
	installed func() (epoch uint64, member bool, key []byte)
	confHash  func(epoch uint64) ([]byte, bool)
	// history is the verified activation history, nil without a Q3 runtime
	history func() ([]q3active.HistoryEntry, error)
}

// binding is the current evidence. A configuration hash or history that cannot be read is left out: the orchestration that compares the
// binding then refuses (it fails closed on what is absent).
func (s shardBindingSource) binding() shardnode.Binding {
	epoch, member, key := s.installed()
	b := shardnode.Binding{NodeID: s.self.String(), NetworkID: uint64(s.shard.NetworkID), PartitionID: uint64(s.shard.PartitionID),
		ShardID: s.shard.ShardID.String(), ShardEpoch: epoch, Member: member}
	if member && len(key) > 0 {
		b.SigKey = hex.EncodeToString(key)
	}
	if hash, ok := s.confHash(epoch); ok {
		b.ShardConfHash = hex.EncodeToString(hash)
	}
	if s.history != nil {
		if entries, err := s.history(); err == nil {
			for _, e := range entries {
				b.History = append(b.History, shardnode.HistoryEntry{Epoch: e.Epoch, BodyID: e.BodyID})
			}
		}
	}
	return b
}
