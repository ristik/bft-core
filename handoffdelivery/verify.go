// Package handoffdelivery verifies the native root handoff evidence fetched by
// a shard. A peer supplies bytes; the shard selects the old trust from its
// lineage-verified history and checks the complete checkpoint locally.
package handoffdelivery

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
)

var ErrBundle = errors.New("handoff delivery: invalid committed bundle")

// Bundle is the complete data needed at a shard epoch boundary. The proof
// authenticates the control leaf, while the snapshot reconstructs all shard
// leaves under the same committed root.
type Bundle struct {
	_        struct{} `cbor:",toarray"`
	Proof    handoff.OldCommitProof
	Body     evmroot.TrustBaseBodyV2
	Snapshot *abdrc.CommittedBlock
}

type Verified struct {
	Genesis evmroot.EpochGenesis
	Record  handoff.VerifiedRecord
	Shard   abdrc.ShardInfo
}

// Verify requires the caller's authenticated old trust base and exact local
// shard configuration hash. It does not trust any identity supplied by a peer.
func Verify(bundle Bundle, old *types.RootTrustBaseV1, partition types.PartitionID, shard types.ShardID, shardConfHash []byte) (Verified, error) {
	v, err := handoff.VerifyOldCommitProof(bundle.Proof, old)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: old commit: %v", ErrBundle, err)
	}
	verified := evmroot.VerifiedHandoff{RecordID: v.RecordID[:], Root: v.StateRoot[:],
		ControlDigest: v.ControlDigest[:], OrderRound: v.OrderRound,
		CommitSealRound: v.CommitSealRound, Epoch: v.SignerEpoch, Record: bundle.Proof.Record}
	g, err := evmroot.DeriveEpochGenesis(verified, bundle.Body)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: successor body: %v", ErrBundle, err)
	}
	s := bundle.Snapshot
	if s == nil || s.Block == nil || s.Control == nil || s.CommitQc == nil || s.CommitQc.LedgerCommitInfo == nil ||
		s.Block.Epoch != v.SignerEpoch || s.Block.Round != v.CommitSealRound || !s.Control.Matches(bundle.Proof.Record) ||
		!bytes.Equal(s.Control.Digest(), v.ControlDigest[:]) || !bytes.Equal(s.CommitQc.LedgerCommitInfo.Hash, v.StateRoot[:]) {
		return Verified{}, ErrBundle
	}
	proofQC, err := types.Cbor.Marshal(bundle.Proof.CommitQC)
	if err != nil {
		return Verified{}, err
	}
	snapshotQC, err := types.Cbor.Marshal(s.CommitQc)
	if err != nil || !bytes.Equal(proofQC, snapshotQC) {
		return Verified{}, ErrBundle
	}
	root, target, err := snapshotRoot(s, partition, shard)
	if err != nil || !bytes.Equal(root, v.StateRoot[:]) || target == nil ||
		!bytes.Equal(target.ShardConfHash, shardConfHash) {
		return Verified{}, ErrBundle
	}
	return Verified{Genesis: g, Record: v, Shard: *target}, nil
}

func snapshotRoot(s *abdrc.CommittedBlock, partition types.PartitionID, shard types.ShardID) ([]byte, *abdrc.ShardInfo, error) {
	groups := make(map[types.PartitionID][]abdrc.ShardInfo)
	seen := make(map[types.PartitionShardID]struct{})
	var target *abdrc.ShardInfo
	for i := range s.ShardInfo {
		entry := &s.ShardInfo[i]
		key := types.PartitionShardID{PartitionID: entry.Partition, ShardID: entry.Shard.Key()}
		if entry.Partition == evmroot.D4ControlPartition || entry.IR == nil || len(entry.ShardConfHash) != 32 {
			return nil, nil, ErrBundle
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, ErrBundle
		}
		stat := abhash.New(crypto.SHA256.New())
		stat.WriteRaw(entry.PrevEpochStat)
		stat.Write(entry.Stat)
		statHash, err := stat.Sum()
		if err != nil || !bytes.Equal(statHash, entry.IRTR.StatHash) {
			return nil, nil, ErrBundle
		}
		fees := abhash.New(crypto.SHA256.New())
		fees.WriteRaw(entry.PrevEpochFees)
		fees.Write(entry.Fees)
		feeHash, err := fees.Sum()
		if err != nil || !bytes.Equal(feeHash, entry.IRTR.FeeHash) {
			return nil, nil, ErrBundle
		}
		seen[key] = struct{}{}
		groups[entry.Partition] = append(groups[entry.Partition], *entry)
		if entry.Partition == partition && entry.Shard.Equal(shard) {
			target = entry
		}
	}
	if target == nil {
		return nil, nil, ErrBundle
	}
	leaves := []*types.UnicityTreeData{{Partition: evmroot.D4ControlPartition, ShardTreeRoot: s.Control.Digest()}}
	for partitionID, entries := range groups {
		scheme := make(types.ShardingScheme, 0, len(entries))
		inputs := make([]types.ShardTreeInput, 0, len(entries))
		for _, entry := range entries {
			if entry.Shard.Length() != 0 {
				scheme = append(scheme, entry.Shard)
			}
			trHash, err := entry.IRTR.Hash()
			if err != nil {
				return nil, nil, err
			}
			inputs = append(inputs, types.ShardTreeInput{Shard: entry.Shard, IR: entry.IR, TRHash: trHash,
				ShardConfHash: entry.ShardConfHash})
		}
		shardTree, err := types.CreateShardTree(scheme, inputs, crypto.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: shard tree: %v", ErrBundle, err)
		}
		leaves = append(leaves, &types.UnicityTreeData{Partition: partitionID, ShardTreeRoot: shardTree.RootHash()})
	}
	tree, err := types.NewUnicityTree(crypto.SHA256, leaves)
	if err != nil {
		return nil, nil, err
	}
	return tree.RootHash(), target, nil
}
