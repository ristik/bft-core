package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

type (
	BlockStore struct {
		hash          crypto.Hash // hash algorithm
		blockTree     *BlockTree
		storage       PersistentStore
		orchestration Orchestration
		profile       uint64
		handoffAuth   handoffAuthority
		lock          sync.RWMutex
		log           *slog.Logger
	}

	PersistentStore interface {
		LoadBlocks() ([]*ExecutedBlock, error)
		WriteBlock(block *ExecutedBlock, root bool) error

		WriteVote(vote any) error
		ReadLastVote() (msg any, err error)

		WriteTC(tc *rctypes.TimeoutCert) error
		ReadLastTC() (*rctypes.TimeoutCert, error)
	}

	Orchestration interface {
		NetworkID() types.NetworkID
		ShardConfig(partition types.PartitionID, shard types.ShardID, rootRound uint64) (*types.PartitionDescriptionRecord, error)
		ShardConfigs(rootRound uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error)
	}
)

func New(hashAlgo crypto.Hash, db PersistentStore, orchestration Orchestration, log *slog.Logger, networkProfile ...uint64) (block *BlockStore, err error) {
	if db == nil {
		return nil, errors.New("storage is nil")
	}

	profile, err := profileVersion(networkProfile)
	if err != nil {
		return nil, err
	}
	blTree, err := NewBlockTree(db, orchestration, profile)
	if err != nil {
		return nil, fmt.Errorf("initializing block tree: %w", err)
	}
	return &BlockStore{
		hash:          hashAlgo,
		blockTree:     blTree,
		storage:       db,
		orchestration: orchestration,
		profile:       profile,
		log:           log,
	}, nil
}

func NewFromState(hash crypto.Hash, block *abdrc.CommittedBlock, db PersistentStore, orchestration Orchestration, log *slog.Logger, networkProfile ...uint64) (*BlockStore, error) {
	if db == nil {
		return nil, errors.New("storage is nil")
	}

	profile, err := profileVersion(networkProfile)
	if err != nil {
		return nil, err
	}
	rootNode, err := NewRootBlock(block, hash, orchestration, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to create new root node: %w", err)
	}

	blTree, err := NewBlockTreeWithRootBlock(rootNode, db)
	if err != nil {
		return nil, fmt.Errorf("creating block tree from recovery: %w", err)
	}
	return &BlockStore{
		hash:          hash,
		blockTree:     blTree,
		storage:       db,
		orchestration: orchestration,
		profile:       profile,
		log:           log,
	}, nil
}

func (x *BlockStore) ProcessTc(tc *rctypes.TimeoutCert) (rErr error) {
	if tc == nil {
		return fmt.Errorf("error tc is nil")
	}
	// persist last known TC
	if err := x.storage.WriteTC(tc); err != nil {
		// store DB error and continue
		rErr = fmt.Errorf("TC write failed: %w", err)
	}
	// Remove proposal/block for TC round if it exists, since quorum voted for timeout.
	// It will never be committed, hence it can be removed immediately.
	// It is fine if the block is not found, it does not matter anyway
	if err := x.blockTree.RemoveLeaf(tc.GetRound()); err != nil {
		return errors.Join(rErr, fmt.Errorf("removing timeout block %v: %w", tc.GetRound(), err))
	}
	return rErr
}

/*
IsChangeInProgress - return input record if shard has a pending IR change in the pipeline
or nil if no change is currently in the pipeline.
*/
func (x *BlockStore) IsChangeInProgress(partition types.PartitionID, shard types.ShardID) *types.InputRecord {
	k := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
	// go through the block we have and make sure that there is no change in progress for this shard
	for _, b := range x.blockTree.GetAllUncommittedNodes() {
		if _, ok := b.ShardState.Changed[k]; ok {
			return b.ShardState.States[k].IR
		}
	}
	return nil
}

func (x *BlockStore) GetDB() PersistentStore {
	return x.storage
}

func (x *BlockStore) ProcessQc(qc *rctypes.QuorumCert) ([]*certification.CertificationResponse, error) {
	if qc == nil {
		return nil, fmt.Errorf("qc is nil")
	}
	// if we have processed it already then skip (in case we are the next leader we have already handled the QC)
	if x.GetHighQc().GetRound() >= qc.GetRound() {
		// stale qc
		return nil, nil
	}
	// add Qc to block tree
	if err := x.blockTree.InsertQc(qc); err != nil {
		return nil, fmt.Errorf("failed to insert QC into block tree: %w", err)
	}
	// If the QC does not serve as commit QC, then we are done.
	// Non-commit QC has LedgerCommitInfo.RootChainRoundNumber == 0. It used to be LedgerCommitInfo.Hash == nil,
	// but now this is a committable value for new shards that have not yet agreed on the genesis state.
	if qc.LedgerCommitInfo.RootChainRoundNumber == 0 || qc.GetRound() == rctypes.GenesisRootRound {
		// NB! exception, no commit for genesis round
		return nil, nil
	}
	// If the QC commits a state committed block becomes the new root
	ucs, err := x.blockTree.Commit(qc)
	if err != nil {
		return nil, fmt.Errorf("committing new root block: %w", err)
	}
	return ucs, nil
}

// Add adds new round state to pipeline and returns the new state root hash a.k.a. execStateID
func (x *BlockStore) Add(block *rctypes.BlockData, verifier IRChangeReqVerifier) ([]byte, error) {
	if block == nil || block.Payload == nil {
		return nil, errors.New("missing block or payload")
	}
	if (x.profile == ProfileHandoff && (block.GetVersion() != 2 || block.Payload.Version != 2)) ||
		(x.profile == ProfileLegacy && (block.GetVersion() != 1 || block.Payload.Version > 1 || len(block.Payload.HandoffRecords) != 0)) {
		return nil, ErrNetworkProfile
	}
	if x.profile == ProfileHandoff {
		for _, req := range block.Payload.Requests {
			if req == nil || req.Partition == rctypes.ControlPartition {
				return nil, rctypes.ErrControlPartition
			}
		}
	}
	// verify that block for the round does not exist yet
	// if block already exists, then check that it is the same block by comparing block hash
	if b, err := x.blockTree.FindBlock(block.GetRound()); err == nil && b != nil {
		b1h, err := b.BlockData.Hash(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("add block failed: cannot compute existing block's hash: %w", err)
		}
		b2h, err := block.Hash(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("add block failed: cannot compute block's hash %w", err)
		}
		// ignore if it is the same block, recovery may have added it when state was duplicated
		if bytes.Equal(b1h, b2h) {
			return b.RootHash, nil
		}
		return nil, fmt.Errorf("add block failed: different block for round %v is already in store", block.Round)
	}
	// block was not present, check parent block (QC round) is stored (if not node needs to recover)
	parentBlock, err := x.blockTree.FindBlock(block.GetParentRound())
	if err != nil {
		return nil, fmt.Errorf("add block failed: parent round %v not found, recover", block.Qc.VoteInfo.RoundNumber)
	}
	if err := checkProfile(x.profile, parentBlock.ShardState); err != nil {
		return nil, err
	}
	if x.profile == ProfileHandoff && block.Epoch != parentBlock.BlockData.Epoch {
		return nil, ErrNetworkProfile
	}
	if x.profile == ProfileHandoff && (block.Anchor != nil) != isEpochAnchorRoot(parentBlock) {
		return nil, ErrNetworkProfile
	}
	if !isEpochAnchorRoot(parentBlock) && parentBlock.ShardState.Control != nil && parentBlock.ShardState.Control.Phase == "committed" && !block.Payload.IsEmpty() {
		return nil, ErrHandoffSuffix
	}
	// Extend state from parent block
	exeBlock, err := parentBlock.extendWithAuthority(block, verifier, x.orchestration, x.hash, x.log, x.handoffAuth)
	if err != nil {
		return nil, fmt.Errorf("error processing block round %v, %w", block.Round, err)
	}
	if x.profile == ProfileHandoff && len(block.Payload.HandoffRecords) == 2 &&
		exeBlock.ShardState.Control != nil && exeBlock.ShardState.Control.Phase == "endorsed" {
		record, decodeErr := decodeOrderedRecord(block.Payload.HandoffRecords[0])
		if decodeErr != nil || record.Kind != "freeze" {
			return nil, ErrHandoffRecord
		}
		var companion FreezeAuthorization
		if err := types.Cbor.Unmarshal(block.Payload.HandoffRecords[1], &companion); err != nil {
			return nil, ErrHandoffRecord
		}
		if archive, ok := x.storage.(interface{ StoreHandoffBody([]byte, []byte) error }); ok {
			if err := archive.StoreHandoffBody(record.NextBodyID, companion.Body); err != nil {
				return nil, fmt.Errorf("retaining verified successor body: %w", err)
			}
		}
	}
	// append new block
	if err = x.blockTree.Add(exeBlock); err != nil {
		return nil, fmt.Errorf("adding block to the tree: %w", err)
	}
	return exeBlock.RootHash, nil
}

func (x *BlockStore) GetHighQc() *rctypes.QuorumCert {
	return x.blockTree.HighQc()
}

// SuffixParent reports whether an old-epoch proposal extends a branch that
// already contains a committed handoff record.
func (x *BlockStore) SuffixParent(parentRound, epoch uint64) (bool, error) {
	parent, err := x.blockTree.FindBlock(parentRound)
	if err != nil {
		return false, err
	}
	if err := checkProfile(x.profile, parent.ShardState); err != nil {
		return false, err
	}
	if x.profile == ProfileHandoff && epoch != parent.BlockData.Epoch {
		return false, ErrNetworkProfile
	}
	control := parent.ShardState.Control
	return control != nil && control.Phase == "committed", nil
}

// ReadFrontierStorageView returns an owned raw storage view for one shard.
// Callers that need consensus serialization must invoke it from the manager's
// serialized loop; this method does not provide freshness or authority.
func (x *BlockStore) ReadFrontierStorageView(partition types.PartitionID, shard types.ShardID) (*FrontierStorageView, error) {
	if x == nil || x.blockTree == nil {
		return nil, errors.New("block store is unavailable")
	}
	return x.blockTree.ReadFrontierStorageView(partition, shard)
}

// ReadFrontierCutSnapshot returns owned raw data and freshly generated
// membership paths for the current committed root.
func (x *BlockStore) ReadFrontierCutSnapshot(partition types.PartitionID, shard types.ShardID) (*FrontierCutSnapshot, error) {
	if x == nil || x.blockTree == nil {
		return nil, fmt.Errorf("block store is unavailable")
	}
	return x.blockTree.ReadFrontierCutSnapshot(partition, shard)
}

func (x *BlockStore) GetLastTC() (*rctypes.TimeoutCert, error) {
	return x.storage.ReadLastTC()
}

func (x *BlockStore) GetCertificate(id types.PartitionID, shard types.ShardID) (*certification.CertificationResponse, error) {
	x.lock.RLock()
	defer x.lock.RUnlock()

	committedBlock := x.blockTree.Root()
	key := types.PartitionShardID{PartitionID: id, ShardID: shard.Key()}
	if si, ok := committedBlock.ShardState.States[key]; ok {
		return si.LastCR, nil
	}
	return nil, fmt.Errorf("no certificate found for shard %s - %s", id, shard)
}

func (x *BlockStore) GetCertificates() []*types.UnicityCertificate {
	x.lock.RLock()
	defer x.lock.RUnlock()

	committedBlock := x.blockTree.Root()
	ucs := make([]*types.UnicityCertificate, 0, len(committedBlock.ShardState.States))
	for _, v := range committedBlock.ShardState.States {
		if v.LastCR != nil {
			ucs = append(ucs, &v.LastCR.UC)
		}
	}
	return ucs
}

func (x *BlockStore) ShardInfo(partition types.PartitionID, shard types.ShardID) *ShardInfo {
	x.lock.RLock()
	defer x.lock.RUnlock()

	committedBlock := x.blockTree.Root()
	key := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
	if si, ok := committedBlock.ShardState.States[key]; ok {
		return si
	}
	return nil
}

func (x *BlockStore) GetState() (*abdrc.StateMsg, error) {
	return x.blockTree.CurrentState()
}

func (x *BlockStore) HandoffBody(id []byte) ([]byte, error) {
	archive, ok := x.storage.(interface{ HandoffBody([]byte) ([]byte, error) })
	if !ok {
		return nil, ErrHandoffRecord
	}
	return archive.HandoffBody(id)
}

func (x *BlockStore) HandoffCheckpoint() (*abdrc.CommittedBlock, *types.UnicityTreeCertificate, evmroot.OrderedHandoffRecord, error) {
	if x.profile != ProfileHandoff {
		return nil, nil, evmroot.OrderedHandoffRecord{}, ErrNetworkProfile
	}
	return x.blockTree.HandoffCheckpoint()
}

/*
Block returns block for given round.
When store doesn't have block for the round it returns error.
*/
func (x *BlockStore) Block(round uint64) (*ExecutedBlock, error) {
	return x.blockTree.FindBlock(round)
}

// StoreLastVote stores last sent vote message by this node
func (x *BlockStore) StoreLastVote(vote any) error {
	return x.storage.WriteVote(vote)
}

// ReadLastVote returns last sent vote message by this node
func (x *BlockStore) ReadLastVote() (any, error) {
	return x.storage.ReadLastVote()
}

func NewGenesisBlock(networkID types.NetworkID, hashAlgo crypto.Hash, networkProfile ...uint64) (*ExecutedBlock, error) {
	profile, err := profileVersion(networkProfile)
	if err != nil {
		return nil, err
	}
	genesisBlock := &rctypes.BlockData{
		Version:   1,
		Author:    "genesis",
		Round:     rctypes.GenesisRootRound,
		Epoch:     rctypes.GenesisRootEpoch,
		Timestamp: types.GenesisTime,
		Payload:   &rctypes.Payload{},
		Qc:        nil, // no parent block -> no parent QC
	}
	if profile == ProfileHandoff {
		genesisBlock.Version = 2
		genesisBlock.Payload.Version = 2
	}

	// Info about the round that commits the genesis block.
	// GenesisRootRound "produced" the genesis block and also commits it.
	commitRoundInfo := &rctypes.RoundInfo{
		Version:           1,
		RoundNumber:       genesisBlock.Round,
		Epoch:             genesisBlock.Epoch,
		Timestamp:         genesisBlock.Timestamp,
		ParentRoundNumber: 0,   // no parent block
		CurrentRootHash:   nil, // no shards -> Unicity Tree root hash is nil
	}
	var state ShardStates
	if profile == ProfileHandoff {
		state = ShardStates{States: map[types.PartitionShardID]*ShardInfo{}, Changed: ShardSet{}}
		state.Control = initialControl(networkID)
		ut, _, err := state.UnicityTree(hashAlgo)
		if err != nil {
			return nil, err
		}
		commitRoundInfo.CurrentRootHash = ut.RootHash()
	}
	commitRoundInfoHash, err := commitRoundInfo.Hash(hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate round info hash: %w", err)
	}

	// QC that commits the genesis block
	commitQc := &rctypes.QuorumCert{
		VoteInfo: commitRoundInfo,
		LedgerCommitInfo: &types.UnicitySeal{
			Version:   1,
			NetworkID: networkID,
			// Usually the round that gets committed is different from
			// the round that commits, but for genesis block they are the same.
			RootChainRoundNumber: commitRoundInfo.RoundNumber,
			Epoch:                commitRoundInfo.Epoch,
			Timestamp:            commitRoundInfo.Timestamp,
			Hash:                 commitRoundInfo.CurrentRootHash,
			PreviousHash:         commitRoundInfoHash,
			Signatures:           nil, // QuorumCert.Signatures field is used
		},
		Signatures: nil, // root validators agree on the first block by running the same software, no need to sign
	}

	return &ExecutedBlock{
		BlockData: genesisBlock,
		HashAlgo:  hashAlgo,

		// the same QC accepts the genesis block and commits it, usually commit comes later
		Qc:         commitQc,
		CommitQc:   commitQc,
		RootHash:   commitQc.LedgerCommitInfo.Hash,
		ShardState: state,
	}, nil
}
