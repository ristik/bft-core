package storage

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// FrontierCutSnapshot is owned raw storage data for proving one shard leaf at
// a committed root. Cryptographic verification, not this storage read, grants
// evidence status.
type FrontierCutSnapshot struct {
	RootRound              uint64
	RootEpoch              uint64
	RootHash               []byte
	CommitQC               *rctypes.QuorumCert
	LastCR                 *certification.CertificationResponse
	ShardTreeCertificate   types.ShardTreeCertificate
	UnicityTreeCertificate *types.UnicityTreeCertificate
}

// ReadFrontierCutSnapshot copies a bounded committed snapshot under the tree
// lock, then builds the authentication paths from only those owned leaf inputs.
func (bt *BlockTree) ReadFrontierCutSnapshot(partition types.PartitionID, shard types.ShardID) (*FrontierCutSnapshot, error) {
	if bt == nil {
		return nil, fmt.Errorf("block tree is nil")
	}
	if shard.Length() > frontierMaxShardBits {
		return nil, fmt.Errorf("requested shard ID exceeds cut bounds")
	}
	bt.m.RLock()
	if bt.root == nil || bt.root.data == nil || bt.root.data.BlockData == nil || bt.root.data.CommitQc == nil {
		bt.m.RUnlock()
		return nil, fmt.Errorf("committed root cut is unavailable")
	}
	root := bt.root.data
	if root.HashAlgo != crypto.SHA256 {
		bt.m.RUnlock()
		return nil, fmt.Errorf("committed root cut hash algorithm is unsupported")
	}
	if root.CommitQc.VoteInfo == nil || root.CommitQc.LedgerCommitInfo == nil || root.ShardState.States == nil {
		bt.m.RUnlock()
		return nil, fmt.Errorf("committed root cut is incomplete")
	}
	if len(root.ShardState.States) == 0 || len(root.ShardState.States) > frontierMaxCollectionSize {
		bt.m.RUnlock()
		return nil, fmt.Errorf("committed shard set exceeds cut bounds")
	}
	var budget frontierCopyBudget
	rootRound, rootEpoch := root.BlockData.Round, root.BlockData.Epoch
	qc, err := cloneFrontierValue(root.CommitQc, &budget)
	if err != nil {
		bt.m.RUnlock()
		return nil, fmt.Errorf("copying committed cut QC: %w", err)
	}
	rootHash, err := copyFrontierBytes(root.RootHash, &budget)
	if err != nil {
		bt.m.RUnlock()
		return nil, fmt.Errorf("copying committed root hash: %w", err)
	}
	states := ShardStates{States: make(map[types.PartitionShardID]*ShardInfo, len(root.ShardState.States))}
	if control := root.ShardState.Control; control != nil {
		// The handoff network profile commits its control record as one more unicity-tree leaf. The
		// rebuilt tree must carry it or its root can never equal the stored root of a profile-2 root.
		ownedControl := *control
		var copyErr error
		for _, field := range []*[]byte{&ownedControl.PredecessorBodyID, &ownedControl.RecordBytes, &ownedControl.PreviousDigest, &ownedControl.FrozenParent} {
			if *field, copyErr = copyFrontierBytes(*field, &budget); copyErr != nil {
				bt.m.RUnlock()
				return nil, fmt.Errorf("copying handoff control record: %w", copyErr)
			}
		}
		states.Control = &ownedControl
	}
	var requested *certification.CertificationResponse
	for key, source := range root.ShardState.States {
		if source == nil || source.IR == nil || source.TR.Round == 0 || len(source.ShardConfHash) == 0 || source.ShardID.Length() > frontierMaxShardBits {
			bt.m.RUnlock()
			return nil, fmt.Errorf("committed shard leaf is incomplete")
		}
		ir, copyErr := cloneFrontierValue(source.IR, &budget)
		if copyErr != nil {
			bt.m.RUnlock()
			return nil, fmt.Errorf("copying shard input record: %w", copyErr)
		}
		tr, copyErr := cloneFrontierValue(&source.TR, &budget)
		if copyErr != nil {
			bt.m.RUnlock()
			return nil, fmt.Errorf("copying shard technical record: %w", copyErr)
		}
		conf, copyErr := copyFrontierBytes(source.ShardConfHash, &budget)
		if copyErr != nil {
			bt.m.RUnlock()
			return nil, fmt.Errorf("copying shard configuration hash: %w", copyErr)
		}
		ownedShard, copyErr := cloneFrontierShardID(source.ShardID, &budget)
		if copyErr != nil {
			bt.m.RUnlock()
			return nil, fmt.Errorf("copying shard identity: %w", copyErr)
		}
		states.States[key] = &ShardInfo{PartitionID: source.PartitionID, ShardID: ownedShard, IR: ir, TR: *tr, ShardConfHash: conf}
		if source.PartitionID == partition && source.ShardID.Equal(shard) {
			if source.LastCR == nil {
				bt.m.RUnlock()
				return nil, fmt.Errorf("requested shard LastCR is unavailable")
			}
			requested, copyErr = cloneFrontierValue(source.LastCR, &budget)
			if copyErr != nil {
				bt.m.RUnlock()
				return nil, fmt.Errorf("copying requested shard LastCR: %w", copyErr)
			}
		}
	}
	bt.m.RUnlock()
	if requested == nil {
		return nil, fmt.Errorf("requested shard is unavailable")
	}
	selected := states.States[types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}]
	if selected == nil || requested.UC.InputRecord == nil || requested.UC.UnicitySeal == nil || requested.UC.UnicityTreeCertificate == nil || !requested.Shard.Equal(shard) || requested.Partition != partition || !bytes.Equal(requested.UC.ShardConfHash, selected.ShardConfHash) {
		return nil, fmt.Errorf("requested committed assignment is incomplete or inconsistent")
	}
	equalIR, err := types.EqualIR(requested.UC.InputRecord, selected.IR)
	if err != nil || !equalIR {
		return nil, fmt.Errorf("requested committed input record does not match LastCR")
	}
	lastTR, err := types.Cbor.Marshal(&requested.Technical)
	if err != nil {
		return nil, fmt.Errorf("encoding requested LastCR technical record: %w", err)
	}
	selectedTR, err := types.Cbor.Marshal(&selected.TR)
	if err != nil || !bytes.Equal(lastTR, selectedTR) {
		return nil, fmt.Errorf("requested committed technical record does not match LastCR")
	}
	trHash, err := selected.TR.Hash()
	if err != nil || !bytes.Equal(trHash, requested.UC.TRHash) {
		return nil, fmt.Errorf("requested committed technical record hash does not match LastCR")
	}
	if rootRound == 0 || rootEpoch == 0 || len(rootHash) != crypto.SHA256.Size() || qc.LedgerCommitInfo.RootChainRoundNumber != rootRound || qc.LedgerCommitInfo.Epoch != rootEpoch || !bytes.Equal(qc.LedgerCommitInfo.Hash, rootHash) {
		return nil, fmt.Errorf("committed root cut metadata is inconsistent")
	}
	ut, shardTrees, err := states.UnicityTree(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("building committed cut tree: %w", err)
	}
	if !bytes.Equal(ut.RootHash(), rootHash) {
		return nil, fmt.Errorf("committed cut tree root does not match stored root")
	}
	st := shardTrees[partition]
	stCert, err := st.Certificate(shard)
	if err != nil {
		return nil, fmt.Errorf("building shard membership path: %w", err)
	}
	utCert, err := ut.Certificate(partition)
	if err != nil {
		return nil, fmt.Errorf("building unicity membership path: %w", err)
	}
	return &FrontierCutSnapshot{RootRound: rootRound, RootEpoch: rootEpoch, RootHash: rootHash, CommitQC: qc, LastCR: requested, ShardTreeCertificate: stCert, UnicityTreeCertificate: utCert}, nil
}
