package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// InstallEpochAnchor installs the previously verified old checkpoint as a
// distinct, noncommittable root at A*-1. The proof and new body are verified
// by the caller; this method rechecks the native checkpoint reconstruction.
// Transport is a local/test injection point until H4 supplies the snapshot.
func (x *BlockStore) InstallEpochAnchor(head *abdrc.CommittedBlock, v evmroot.VerifiedHandoff, g evmroot.EpochGenesis) (*rctypes.EpochAnchor, error) {
	if x.profile != ProfileHandoff || head == nil || g.Start < 2 || g.Epoch != v.Epoch+1 ||
		g.Network != v.Record.Network || g.OrderedRound != v.OrderRound || g.Start != v.Record.ActivationRound ||
		!bytes.Equal(g.Root, v.Root) || !bytes.Equal(g.ControlDigest, v.ControlDigest) ||
		!bytes.Equal(g.RecordID, v.RecordID) || !bytes.Equal(g.NextBodyID, v.Record.NextBodyID) ||
		!bytes.Equal(g.FrozenID, v.Record.FrozenID) || !bytes.Equal(g.SuccessorTRHash, v.Record.SuccessorTRHash) {
		return nil, ErrNetworkProfile
	}
	if err := (RecoveryHandoffSnapshot{Head: head, Orchestration: x.orchestration}).VerifyHandoffSnapshot(v); err != nil {
		return nil, err
	}
	a := &rctypes.EpochAnchor{GenesisID: g.ID(), Epoch: g.Epoch, Slot: g.Start - 1, StateRoot: bytes.Clone(v.Root)}
	if err := a.IsValid(); err != nil {
		return nil, err
	}
	x.lock.Lock()
	defer x.lock.Unlock()
	current := x.blockTree.Root()
	if current.BlockData.Epoch >= a.Epoch {
		if isEpochAnchorRoot(current) && bytes.Equal(current.BlockData.Anchor.GenesisID, a.GenesisID) {
			return a, nil
		}
		return nil, errors.New("successor consensus already started")
	}
	if current.BlockData.Epoch > v.Epoch {
		return nil, errors.New("local root is beyond old handoff epoch")
	}
	oldRoot, err := NewRootBlock(head, crypto.SHA256, x.orchestration, ProfileHandoff)
	if err != nil {
		return nil, fmt.Errorf("reconstruct old checkpoint: %w", err)
	}
	oldRoot.BlockData = &rctypes.BlockData{Version: 2, Epoch: a.Epoch, Round: a.Slot,
		Payload: &rctypes.Payload{Version: 2}, Anchor: a}
	oldRoot.Qc, oldRoot.CommitQc = nil, nil
	tree, err := NewBlockTreeWithRootBlock(oldRoot, x.storage)
	if err != nil {
		return nil, err
	}
	x.blockTree = tree
	return a, nil
}

func (x *BlockStore) RootAnchor() *rctypes.EpochAnchor {
	root := x.blockTree.Root()
	if isEpochAnchorRoot(root) {
		return root.BlockData.Anchor
	}
	return nil
}

func (x *BlockStore) RootEpoch() uint64 { return x.blockTree.Root().BlockData.Epoch }

// VerifyRecoveryAnchor reconstructs the received recovery ShardInfo and P_CTL
// with the production tree, then compares it to the locally proof-verified G.
func (x *BlockStore) VerifyRecoveryAnchor(head *abdrc.CommittedBlock) error {
	if x.profile != ProfileHandoff || head == nil || head.Anchor == nil {
		return rctypes.ErrEpochAnchor
	}
	installed := x.RootAnchor()
	if installed == nil || installed.Epoch != head.Anchor.Epoch || installed.Slot != head.Anchor.Slot ||
		!bytes.Equal(installed.GenesisID, head.Anchor.GenesisID) || !bytes.Equal(installed.StateRoot, head.Anchor.StateRoot) {
		return rctypes.ErrEpochAnchor
	}
	root := x.blockTree.Root()
	if root.ShardState.Control == nil || head.Control == nil ||
		!bytes.Equal(root.ShardState.Control.Digest(), head.Control.Digest()) {
		return ErrControlCheckpoint
	}
	_, err := x.reconstructAnchorHead(head)
	return err
}

func (x *BlockStore) reconstructAnchorHead(head *abdrc.CommittedBlock) (*ExecutedBlock, error) {
	oldBlock := *head.Block
	oldBlock.Anchor = nil
	oldBlock.Epoch = head.Control.Epoch
	oldBlock.Round = head.Control.OrderedRound
	oldBlock.Qc = nil
	checkpoint := *head
	checkpoint.Block = &oldBlock
	checkpoint.Anchor = nil
	checkpoint.CommitQc = &rctypes.QuorumCert{LedgerCommitInfo: &basetypes.UnicitySeal{Hash: head.Anchor.StateRoot}}
	block, err := NewRootBlock(&checkpoint, crypto.SHA256, x.orchestration, ProfileHandoff)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(block.RootHash, head.Anchor.StateRoot) {
		return nil, ErrControlCheckpoint
	}
	block.BlockData = head.Block
	block.Qc, block.CommitQc = nil, nil
	return block, nil
}

// NewFromAnchorState restores an already verified local anchor and discards
// divergent pending blocks before applying the received successor suffix.
func (x *BlockStore) NewFromAnchorState(head *abdrc.CommittedBlock) (*BlockStore, error) {
	if err := x.VerifyRecoveryAnchor(head); err != nil {
		return nil, err
	}
	root, err := x.reconstructAnchorHead(head)
	if err != nil {
		return nil, err
	}
	tree, err := NewBlockTreeWithRootBlock(root, x.storage)
	if err != nil {
		return nil, err
	}
	return &BlockStore{hash: x.hash, blockTree: tree, storage: x.storage,
		orchestration: x.orchestration, profile: x.profile, log: x.log}, nil
}
