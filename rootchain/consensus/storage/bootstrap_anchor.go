package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"slices"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
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
	// Derive and install the committed successor assignment before the anchor is
	// written. Either order of a crash is repaired from committed history: the
	// install is idempotent and startup reconciles it before any block is read.
	if err := x.installCommittedAssignment(oldRoot, v, g); err != nil {
		return nil, err
	}
	oldRoot.BlockData = &rctypes.BlockData{Version: 2, Epoch: a.Epoch, Round: a.Slot,
		Payload: &rctypes.Payload{Version: 2}, Anchor: a}
	oldRoot.Qc, oldRoot.CommitQc = nil, nil
	installer, ok := x.storage.(interface {
		InstallEpochAnchorRoot(*ExecutedBlock, *rctypes.EpochAnchor) error
	})
	if !ok {
		return nil, errors.New("atomic epoch anchor storage unavailable")
	}
	if err := installer.InstallEpochAnchorRoot(oldRoot, a); err != nil {
		return nil, err
	}
	root := newNode(oldRoot)
	tree := &BlockTree{root: root, roundToNode: map[uint64]*node{a.Slot: root}, blocksDB: x.storage}
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

// anchoredCommit returns the installed anchor root's committed record and the
// frozen EVM shard H names, with the retained candidate preimage when H changes the
// assignment.
func (x *BlockStore) anchoredCommit() (*ExecutedBlock, evmroot.OrderedHandoffRecord, *ShardInfo, []byte, error) {
	root := x.blockTree.Root()
	if !isEpochAnchorRoot(root) || root.ShardState.Control == nil {
		return nil, evmroot.OrderedHandoffRecord{}, nil, nil, rctypes.ErrEpochAnchor
	}
	control := root.ShardState.Control
	record, err := decodeOrderedRecord(control.RecordBytes)
	if err != nil || len(control.FrozenParent) != 32 {
		return nil, record, nil, nil, rctypes.ErrEpochAnchor
	}
	configs, err := x.orchestration.ShardConfigs(control.OrderedRound)
	if err != nil {
		return nil, record, nil, nil, err
	}
	key, err := frozenShard(root.ShardState, configs, control.FrozenParent)
	if err != nil {
		return nil, record, nil, nil, rctypes.ErrEpochAnchor
	}
	preimage, err := x.HandoffCandidate(record.NextBodyID)
	if err != nil {
		return nil, record, nil, nil, errors.Join(ErrAssignmentHistory, err)
	}
	return root, record, root.ShardState.States[key], preimage, nil
}

// AnchoredTechnicalRecord selects the committed shard assignment named by H.
// It is available only while the installed snapshot is still the root. For an
// assignment-bearing H the committed record is the one the retained candidate
// derives, so the returned record is the shard's last one in the checkpoint, which
// the caller advances by exactly one shard round; the hash is checked here.
func (x *BlockStore) AnchoredTechnicalRecord(hash []byte) (certification.TechnicalRecord, error) {
	x.lock.RLock()
	defer x.lock.RUnlock()
	root := x.blockTree.Root()
	if !isEpochAnchorRoot(root) || len(hash) != 32 {
		return certification.TechnicalRecord{}, rctypes.ErrEpochAnchor
	}
	if _, record, si, preimage, err := x.anchoredCommit(); err == nil && len(preimage) != 0 {
		want, err := AssignmentSuccessorTRHash(si, preimage, record.ActivationRound, x.hash)
		if err != nil || !bytes.Equal(want, hash) || !bytes.Equal(record.SuccessorTRHash, hash) {
			return certification.TechnicalRecord{}, rctypes.ErrEpochAnchor
		}
		return si.TR, nil
	}
	var matched *certification.TechnicalRecord
	for _, shard := range root.ShardState.States {
		if shard == nil {
			return certification.TechnicalRecord{}, rctypes.ErrEpochAnchor
		}
		digest, err := shard.TR.Hash()
		if err != nil {
			return certification.TechnicalRecord{}, err
		}
		if bytes.Equal(digest, hash) {
			if matched != nil {
				return certification.TechnicalRecord{}, rctypes.ErrEpochAnchor
			}
			tr := shard.TR
			matched = &tr
		}
	}
	if matched == nil || matched.Round == 0 {
		return certification.TechnicalRecord{}, rctypes.ErrEpochAnchor
	}
	return *matched, nil
}

// AnchoredAssignmentStep is the EVM assignment context of the committed H: the
// retained candidate's replacement for an assignment handoff, the shard's own
// unchanged assignment for a root-only one.
func (x *BlockStore) AnchoredAssignmentStep(record evmroot.OrderedHandoffRecord) (handoff.AssignmentStep, error) {
	x.lock.RLock()
	defer x.lock.RUnlock()
	_, committed, si, preimage, err := x.anchoredCommit()
	if err != nil || !bytes.Equal(committed.ID(), record.ID()) {
		return handoff.AssignmentStep{}, rctypes.ErrEpochAnchor
	}
	var installed [32]byte
	if len(si.ShardConfHash) != 32 {
		return handoff.AssignmentStep{}, rctypes.ErrEpochAnchor
	}
	copy(installed[:], si.ShardConfHash)
	if len(preimage) == 0 {
		return handoff.AssignmentStep{OldShardEpoch: si.TR.Epoch, NewShardEpoch: si.TR.Epoch,
			OldActiveConfHash: installed, NewActiveConfHash: installed}, nil
	}
	c, pdr, err := candidateActivatedPDR(preimage, committed.ActivationRound)
	if err != nil {
		return handoff.AssignmentStep{}, err
	}
	newHash, err := evmassign.PDRHash(pdr)
	if err != nil || c.OldShardEpoch != si.TR.Epoch || !bytes.Equal(c.OldActiveHash, installed[:]) {
		return handoff.AssignmentStep{}, errors.Join(ErrAssignmentHistory, err)
	}
	return handoff.AssignmentStep{Assignment: true, OldShardEpoch: c.OldShardEpoch, NewShardEpoch: pdr.Epoch,
		OldActiveConfHash: installed, NewActiveConfHash: newHash}, nil
}

// AnchoredFrozenParent binds the EVM shard assignment named by H to the last
// certified old EVM block imported in the same verified checkpoint.
func (x *BlockStore) AnchoredFrozenParent(trHash, parent []byte) error {
	if len(parent) != 32 {
		return rctypes.ErrEpochAnchor
	}
	x.lock.RLock()
	defer x.lock.RUnlock()
	root := x.blockTree.Root()
	if !isEpochAnchorRoot(root) {
		return rctypes.ErrEpochAnchor
	}
	configs, err := x.orchestration.ShardConfigs(root.ShardState.Control.OrderedRound)
	if err != nil {
		return err
	}
	selected, err := frozenShard(root.ShardState, configs, parent)
	if err != nil {
		return rctypes.ErrEpochAnchor
	}
	shard := root.ShardState.States[selected]
	digest, err := shard.TR.Hash()
	if err != nil {
		return err
	}
	if bytes.Equal(digest, trHash) {
		return nil
	}
	// An assignment-bearing H commits the derived successor record instead.
	if _, record, si, preimage, cerr := x.anchoredCommit(); cerr == nil && si == shard && len(preimage) != 0 {
		want, werr := AssignmentSuccessorTRHash(si, preimage, record.ActivationRound, x.hash)
		if werr == nil && bytes.Equal(want, trHash) {
			return nil
		}
	}
	return rctypes.ErrEpochAnchor
}

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

// RetainHandoffArtifacts stores the successor body and, for an EVM assignment,
// the candidate preimage a peer's handoff bundle carried, so a root that did not
// order the freeze can derive the same configuration. Different bytes under the
// same body id are refused.
func (x *BlockStore) RetainHandoffArtifacts(bodyID, body, preimage []byte) error {
	if archive, ok := x.storage.(interface{ StoreHandoffBody([]byte, []byte) error }); ok && len(body) != 0 {
		if err := archive.StoreHandoffBody(bodyID, body); err != nil {
			return err
		}
	}
	if len(preimage) == 0 {
		return nil
	}
	archive, ok := x.storage.(interface{ StoreHandoffCandidate([]byte, []byte) error })
	if !ok {
		return ErrAssignmentHistory
	}
	return archive.StoreHandoffCandidate(bodyID, preimage)
}

// installCommittedAssignment is the BlockStore form of installCommittedAssignmentFrom.
func (x *BlockStore) installCommittedAssignment(oldRoot *ExecutedBlock, v evmroot.VerifiedHandoff, g evmroot.EpochGenesis) error {
	return installCommittedAssignmentFrom(x.storage, x.orchestration, x.hash, oldRoot, v.Record, g.OrderedRound)
}

func readHandoffArtifact(db PersistentStore, name string, id []byte) ([]byte, error) {
	switch name {
	case "candidate":
		if a, ok := db.(candidateSource); ok {
			return a.HandoffCandidate(id)
		}
		return nil, nil
	default:
		if a, ok := db.(interface{ HandoffBody([]byte) ([]byte, error) }); ok {
			return a.HandoffBody(id)
		}
		return nil, ErrAssignmentHistory
	}
}

// installCommittedAssignmentFrom ties the committed H to the EVM shard of the
// verified checkpoint. A root-only H must commit the shard's unchanged technical
// record. An assignment-bearing H must have its retained candidate derive a
// configuration whose successor technical record is exactly the committed one;
// only then is that configuration installed at the activation round. Missing
// candidate or body refuses activation; nothing falls back to the retired set.
// It is idempotent, so startup repeats it for a crash between the anchor write
// and the derived-index write.
func installCommittedAssignmentFrom(db PersistentStore, orchestration Orchestration, hashAlg crypto.Hash,
	oldRoot *ExecutedBlock, record evmroot.OrderedHandoffRecord, orderedRound uint64) error {
	control := oldRoot.ShardState.Control
	if control == nil || len(control.FrozenParent) != 32 {
		return ErrAssignmentHistory
	}
	configs, err := orchestration.ShardConfigs(orderedRound)
	if err != nil {
		return err
	}
	key, err := frozenShard(oldRoot.ShardState, configs, control.FrozenParent)
	if err != nil {
		return errors.Join(ErrAssignmentHistory, err)
	}
	si := oldRoot.ShardState.States[key]
	preimage, err := readHandoffArtifact(db, "candidate", record.NextBodyID)
	if err != nil {
		return errors.Join(ErrAssignmentHistory, err)
	}
	if len(preimage) == 0 {
		digest, err := si.TR.Hash()
		if err != nil || !bytes.Equal(digest, record.SuccessorTRHash) {
			return fmt.Errorf("%w: the committed successor technical record is neither the shard's own nor derived from a retained assignment",
				ErrAssignmentHistory)
		}
		return nil
	}
	rawBody, err := readHandoffArtifact(db, "body", record.NextBodyID)
	if err != nil || len(rawBody) == 0 {
		return fmt.Errorf("%w: successor body unavailable", ErrAssignmentHistory)
	}
	body, err := DecodeHandoffBody(rawBody)
	if err != nil {
		return err
	}
	pdr, provenance, err := DeriveActivatedPDR(record, body, preimage, control.FrozenParent)
	if err != nil {
		return err
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil {
		return errors.Join(ErrAssignmentHistory, err)
	}
	succ, err := c.Successor()
	if err != nil {
		return errors.Join(ErrAssignmentHistory, err)
	}
	if err := evmassign.VerifyInstalled(c, succ, configs[key]); err != nil {
		return errors.Join(ErrAssignmentHistory, err)
	}
	tr, err := successorTechnicalRecord(si, pdr, hashAlg)
	if err != nil {
		return err
	}
	digest, err := tr.Hash()
	if err != nil || !bytes.Equal(digest, record.SuccessorTRHash) {
		return fmt.Errorf("%w: derived successor technical record differs from H", ErrAssignmentHistory)
	}
	installer, ok := orchestration.(DerivedConfigInstaller)
	if !ok {
		return fmt.Errorf("%w: orchestration cannot install a derived configuration", ErrAssignmentHistory)
	}
	return installer.InstallDerivedShardConfig(pdr, provenance)
}

// repairCommittedAssignment runs before the block tree is loaded. When the
// stored root is an epoch anchor, the derived configuration for its committed H
// is recomputed from committed data and installed if the crash lost it, so the
// first successor block, frontier service and voting never see the retired set.
func repairCommittedAssignment(db PersistentStore, orchestration Orchestration, hashAlg crypto.Hash, profile uint64) error {
	if profile != ProfileHandoff {
		return nil
	}
	blocks, err := db.LoadBlocks()
	if err != nil || len(blocks) == 0 {
		return err
	}
	idx := slices.IndexFunc(blocks, func(b *ExecutedBlock) bool { return b.CommitQc != nil || isEpochAnchorRoot(b) })
	if idx < 0 || !isEpochAnchorRoot(blocks[idx]) {
		return nil
	}
	root := blocks[idx]
	control := root.ShardState.Control
	if control == nil || control.Phase != "committed" {
		return nil
	}
	record, err := decodeOrderedRecord(control.RecordBytes)
	if err != nil {
		return errors.Join(ErrAssignmentHistory, err)
	}
	return installCommittedAssignmentFrom(db, orchestration, hashAlg, root, record, control.OrderedRound)
}
