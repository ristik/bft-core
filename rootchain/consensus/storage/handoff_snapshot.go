package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

// RecoveryHandoffSnapshot is the local/test injection boundary for a verified
// old checkpoint. Transport is supplied by H4. The root and every shard leaf
// are reconstructed through NewRootBlock and the production UnicityTree path.
type RecoveryHandoffSnapshot struct {
	Head          *abdrc.CommittedBlock
	Orchestration Orchestration
}

func (s RecoveryHandoffSnapshot) VerifyHandoffSnapshot(v evmroot.VerifiedHandoff) error {
	if s.Head == nil || s.Head.Block == nil || s.Head.Control == nil || s.Orchestration == nil ||
		v.Epoch == 0 || s.Head.Block.Epoch != v.Epoch || s.Head.Block.Round != v.CommitSealRound ||
		!s.Head.Control.Matches(v.Record) || !bytes.Equal(s.Head.Control.Digest(), v.ControlDigest) {
		return errors.New("handoff snapshot checkpoint does not match verified proof")
	}
	configRound := s.Head.Control.OrderedRound
	configs, err := s.Orchestration.ShardConfigs(configRound)
	if err != nil {
		return fmt.Errorf("load handoff shard configurations: %w", err)
	}
	if len(s.Head.ShardInfo) != len(configs) {
		return errors.New("handoff snapshot has missing or extra shards")
	}
	seen := make(map[types.PartitionShardID]struct{}, len(s.Head.ShardInfo))
	for _, info := range s.Head.ShardInfo {
		key := types.PartitionShardID{PartitionID: info.Partition, ShardID: info.Shard.Key()}
		if _, exists := seen[key]; exists {
			return errors.New("handoff snapshot has duplicate shard")
		}
		seen[key] = struct{}{}
		if _, exists := configs[key]; !exists {
			return errors.New("handoff snapshot has unknown shard")
		}
	}
	block, err := NewRootBlock(s.Head, crypto.SHA256, s.Orchestration, ProfileHandoff)
	if err != nil {
		return fmt.Errorf("reconstruct handoff checkpoint: %w", err)
	}
	if !bytes.Equal(block.RootHash, v.Root) || !bytes.Equal(s.Head.CommitQc.LedgerCommitInfo.Hash, v.Root) {
		return errors.New("handoff snapshot root differs from committed proof")
	}
	return nil
}
