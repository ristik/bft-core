package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/unicitynetwork/bft-core/rootrecords"
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
		pos           *PosServices // the P85 control executor's collaborators; nil refuses every control
		lock          sync.RWMutex
		log           *slog.Logger
		// the attempt whose lapse was last reported (reported once)
		lapseLogged                          bool
		lapseLoggedEpoch, lapseLoggedAttempt uint64
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
	if err := repairCommittedAssignment(db, orchestration, hashAlgo, profile); err != nil {
		return nil, fmt.Errorf("reconciling committed EVM assignment: %w", err)
	}
	blTree, err := NewBlockTree(db, orchestration, profile)
	if err != nil {
		return nil, fmt.Errorf("initializing block tree: %w", err)
	}
	blTree.log = log
	return &BlockStore{
		hash:          hashAlgo,
		blockTree:     blTree,
		storage:       db,
		orchestration: orchestration,
		profile:       profile,
		log:           log,
	}, nil
}

// ErrRefusedBeforeWrite marks a recovery state that NewFromState or NewFromAnchorState refused before writing anything: the store is as it
// was, so the caller has nothing to be uncertain about. The wrapped error and its message are unchanged.
var ErrRefusedBeforeWrite = errors.New("recovery state refused before any write")

type refusedBeforeWrite struct{ err error }

func (e refusedBeforeWrite) Error() string      { return e.err.Error() }
func (e refusedBeforeWrite) Unwrap() error      { return e.err }
func (refusedBeforeWrite) Is(target error) bool { return target == ErrRefusedBeforeWrite }

func NewFromState(hash crypto.Hash, block *abdrc.CommittedBlock, db PersistentStore, orchestration Orchestration, log *slog.Logger, networkProfile ...uint64) (*BlockStore, error) {
	if db == nil {
		return nil, refusedBeforeWrite{errors.New("storage is nil")}
	}

	profile, err := profileVersion(networkProfile)
	if err != nil {
		return nil, refusedBeforeWrite{err}
	}
	rootNode, err := NewRootBlock(block, hash, orchestration, profile)
	if err != nil {
		// Nothing has been written: the first write is NewBlockTreeWithRootBlock below.
		return nil, refusedBeforeWrite{fmt.Errorf("failed to create new root node: %w", err)}
	}

	blTree, err := NewBlockTreeWithRootBlock(rootNode, db)
	if err != nil {
		return nil, fmt.Errorf("creating block tree from recovery: %w", err)
	}
	blTree.log = log
	// A root that recovers with the block that CARRIES the handoff record as its head captures the canonical checkpoint now: the next
	// commit would find the record already committed and skip it. The carrier is the one block whose round is the control state's
	// ordered round. A head past the carrier cannot be captured (the carrier is pruned everywhere): such a root refuses to serve the
	// checkpoint and the follower asks another root.
	if c := rootNode.ShardState.Control; c != nil && rootNode.GetRound() == c.OrderedRound {
		if err := blTree.captureHandoffCheckpoint(nil, rootNode); err != nil {
			return nil, fmt.Errorf("capturing the handoff checkpoint of the recovered head: %w", err)
		}
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

// ClosureControls are the CloseLiability controls a block proposed at round on the parent round's state must carry: one for every epoch
// whose closure is outstanding after that block's own ordinary-round effect, oldest first. A chain without the closure duty needs none.
func (x *BlockStore) ClosureControls(parentRound, epoch, round uint64) ([]rctypes.PosControl, error) {
	x.lock.RLock()
	svc := x.pos
	x.lock.RUnlock()
	if x.profile != ProfileHandoff || !svc.mandatory() {
		return nil, nil
	}
	parent, err := x.blockTree.FindBlock(parentRound)
	if err != nil {
		return nil, err
	}
	pos, err := loadPos(parent.ShardState.Control)
	if err != nil || !pos.on {
		return nil, err
	}
	next, err := pos.state.Block(epoch, round)
	if err != nil {
		return nil, errors.Join(ErrPosSource, err)
	}
	if len(next.Awaiting) == 0 {
		return nil, nil
	}
	if svc.Proposer == nil {
		return nil, fmt.Errorf("%w: no proposer to build the closure of epoch %d", ErrWitnessUnavailable, next.Awaiting[0].Epoch)
	}
	controls := make([]rctypes.PosControl, 0, len(next.Awaiting))
	for _, a := range next.Awaiting {
		c, witness, err := svc.Proposer.Closure(a.Epoch, epoch, round)
		if err != nil {
			return nil, errors.Join(ErrWitnessUnavailable, err)
		}
		// the proposer retains the witness before it proposes: its own validation of the block reads it back by hash
		if err := x.StoreWitness(witness); err != nil {
			return nil, err
		}
		controls = append(controls, c)
	}
	return controls, nil
}

// StoreWitness retains control witness bytes under their SHA-256.
func (x *BlockStore) StoreWitness(data []byte) error {
	store, ok := x.storage.(WitnessStore)
	if !ok {
		return ErrNoWitnessStore
	}
	return store.StoreWitness(sha256.Sum256(data), data)
}

// Witness is the WitnessSource of the retained control witnesses.
func (x *BlockStore) Witness(hash [32]byte) ([]byte, error) {
	store, ok := x.storage.(WitnessStore)
	if !ok {
		return nil, ErrNoWitnessStore
	}
	data, err := store.Witness(hash)
	if err == nil && data == nil {
		return nil, ErrWitnessUnavailable
	}
	return data, err
}

// TrialExecute executes a proposed block on its parent's state exactly as Add would and discards the result: a leader uses it to learn
// whether an optional control it would include makes the block invalid before it signs the proposal. Nothing is stored. The parent
// block is only read: extendWithAuthority builds the child on a copy of the parent's state, which Add relies on for forks as well.
func (x *BlockStore) TrialExecute(block *rctypes.BlockData, verifier IRChangeReqVerifier) error {
	parent, err := x.blockTree.FindBlock(block.GetParentRound())
	if err != nil {
		return fmt.Errorf("trial: parent round %d: %w", block.GetParentRound(), err)
	}
	x.lock.RLock()
	svc := x.pos
	x.lock.RUnlock()
	_, err = parent.extendWithAuthority(block, verifier, x.orchestration, x.hash, x.log, x.handoffAuth, x, svc)
	return err
}

// ControlCut is the retained control cut of the committed root block of the round: its control state and the path of its leaf in that
// block's unicity tree.
func (x *BlockStore) ControlCut(round uint64) (ControlCut, error) {
	return x.blockTree.ControlCut(round)
}

// Records returns up to max records of the retained source log from the index.
func (x *BlockStore) Records(from uint64, max int) ([]rootrecords.Record, error) {
	store, ok := x.storage.(RecordStore)
	if !ok {
		return nil, ErrNoRecordStore
	}
	return store.Records(from, max)
}

// HasWitness reports whether the witness with this hash is retained.
func (x *BlockStore) HasWitness(hash [32]byte) bool {
	store, ok := x.storage.(WitnessStore)
	if !ok {
		return false
	}
	has, err := store.HasWitness(hash)
	return err == nil && has
}

// PosServices returns the installed control collaborators, nil when there are none. A store built by recovery inherits them from the one
// it replaces.
func (x *BlockStore) PosServices() *PosServices {
	x.lock.RLock()
	defer x.lock.RUnlock()
	return x.pos
}

// SetPosServices installs the collaborators the P85 control executor verifies controls with. It must be set before the store executes a
// block that carries a control.
func (x *BlockStore) SetPosServices(s *PosServices) {
	x.lock.Lock()
	defer x.lock.Unlock()
	x.pos = s
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
	x.logHandoffOutcome(x.blockTree.Root())
	return ucs, nil
}

// logHandoffOutcome reports the terminal outcomes of a handoff attempt when the committed root passes them: the committed or aborted
// record, and the lapse of a Prepare (reported once per attempt).
func (x *BlockStore) logHandoffOutcome(root *ExecutedBlock) {
	if x.profile != ProfileHandoff || x.log == nil || root == nil {
		return
	}
	if control := root.ShardState.Control; control != nil && root.GetRound() == control.OrderedRound &&
		(control.Phase == "committed" || control.Phase == "aborted") {
		x.log.Info("root handoff outcome", "phase", control.Phase, "attempt", control.Attempt,
			"rootEpoch", control.Epoch, "rootRound", root.GetRound())
	}
	// A lapse is not an ordered record: it is the committed round passing the Prepare's window. Report it once per attempt so the
	// operator (and the lane) retries at once instead of waiting out its own timeout.
	if control := root.ShardState.Control; PrepareLapsed(control, root.GetRound()) &&
		!(x.lapseLogged && x.lapseLoggedEpoch == control.Epoch && x.lapseLoggedAttempt == control.Attempt) {
		x.lapseLogged, x.lapseLoggedEpoch, x.lapseLoggedAttempt = true, control.Epoch, control.Attempt
		x.log.Info("root handoff outcome", "phase", "lapsed", "attempt", control.Attempt,
			"rootEpoch", control.Epoch, "rootRound", root.GetRound(), "preparedRound", control.OrderedRound,
			"reason", "no Freeze within the endorsement window; the EVM certifies again and the next plan is attempt+1")
	}
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
	if x.profile == ProfileHandoff && len(block.Payload.HandoffRecords) > 0 {
		record, err := decodeOrderedRecord(block.Payload.HandoffRecords[0])
		if err != nil {
			return nil, err
		}
		if record.Kind == "commit" {
			control := parentBlock.ShardState.Control
			if control == nil || control.Phase != "endorsed" {
				return nil, ErrHandoffRecord
			}
			configs, err := x.orchestration.ShardConfigs(parentBlock.GetRound())
			if err != nil {
				return nil, err
			}
			key, err := frozenShard(parentBlock.ShardState, configs, control.FrozenParent)
			if err != nil {
				return nil, err
			}
			committed := x.blockTree.Root()
			if committed == nil || committed.ShardState.States[key] == nil || committed.ShardState.States[key].IR == nil ||
				!bytes.Equal(committed.ShardState.States[key].IR.BlockHash, control.FrozenParent) {
				return nil, ErrHandoffRecord
			}
		}
	}
	// Extend state from parent block
	exeBlock, err := parentBlock.extendWithAuthority(block, verifier, x.orchestration, x.hash, x.log, x.handoffAuth, x, x.pos)
	if err != nil {
		return nil, fmt.Errorf("error processing block round %v, %w", block.Round, err)
	}
	if x.profile == ProfileHandoff && len(block.Payload.HandoffRecords) == 2 &&
		exeBlock.ShardState.Control != nil && exeBlock.ShardState.Control.Phase == "endorsed" {
		record, decodeErr := decodeOrderedRecord(block.Payload.HandoffRecords[0])
		if decodeErr != nil || record.Kind != "freeze" {
			return nil, ErrHandoffRecord
		}
		companion, err := ParseFreezeCompanion(block.Payload.HandoffRecords[1])
		if err != nil {
			return nil, ErrHandoffRecord
		}
		if archive, ok := x.storage.(interface{ StoreHandoffBody([]byte, []byte) error }); ok {
			if err := archive.StoreHandoffBody(record.NextBodyID, companion.Body); err != nil {
				return nil, fmt.Errorf("retaining verified successor body: %w", err)
			}
		}
		if len(companion.Receipts) != 0 {
			archive, ok := x.storage.(interface{ StoreHandoffReceipts([]byte, []byte) error })
			if !ok {
				return nil, fmt.Errorf("%w: receipt retention unavailable", ErrHandoffRecord)
			}
			if err := archive.StoreHandoffReceipts(record.NextBodyID, companion.Receipts); err != nil {
				return nil, fmt.Errorf("retaining verified readiness receipts: %w", err)
			}
		}
		if len(companion.Preimage) != 0 {
			archive, ok := x.storage.(interface{ StoreHandoffCandidate([]byte, []byte) error })
			if !ok {
				return nil, fmt.Errorf("%w: candidate retention unavailable", ErrHandoffRecord)
			}
			if err := archive.StoreHandoffCandidate(record.NextBodyID, companion.Preimage); err != nil {
				return nil, fmt.Errorf("retaining verified assignment candidate: %w", err)
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

// HandoffReceipts returns the retained readiness receipts of a V3 successor body, or nil.
func (x *BlockStore) HandoffReceipts(id []byte) ([]byte, error) {
	archive, ok := x.storage.(interface{ HandoffReceipts([]byte) ([]byte, error) })
	if !ok {
		return nil, ErrHandoffRecord
	}
	return archive.HandoffReceipts(id)
}

// HandoffCandidate returns the retained H3 candidate preimage for a successor
// body, or nil for a root-only handoff.
func (x *BlockStore) HandoffCandidate(id []byte) ([]byte, error) {
	archive, ok := x.storage.(interface{ HandoffCandidate([]byte) ([]byte, error) })
	if !ok {
		// A store without candidate retention cannot have admitted an
		// assignment-bearing freeze, which is refused when it is added.
		return nil, nil
	}
	return archive.HandoffCandidate(id)
}

func (x *BlockStore) HandoffCheckpoint() (*abdrc.CommittedBlock, *types.UnicityTreeCertificate, evmroot.OrderedHandoffRecord, error) {
	if x.profile != ProfileHandoff {
		return nil, nil, evmroot.OrderedHandoffRecord{}, ErrNetworkProfile
	}
	return x.blockTree.HandoffCheckpoint()
}

func (x *BlockStore) CommittedFrozenParent(parent []byte) bool {
	if x.profile != ProfileHandoff {
		return false
	}
	root := x.blockTree.Root()
	configs, err := x.orchestration.ShardConfigs(root.GetRound())
	if err != nil {
		return false
	}
	_, err = frozenShard(root.ShardState, configs, parent)
	return err == nil
}

// FrozenShardAt is FrozenShardForBlock for the block built directly after round's block.
func (x *BlockStore) FrozenShardAt(round uint64) (types.PartitionShardID, bool, error) {
	return x.FrozenShardForBlock(round, round+1)
}

// FrozenShardForBlock is the shard a block of blockRound, built on parentRound's block, must not certify. The block round matters:
// a Prepare-time freeze lapses by round count.
func (x *BlockStore) FrozenShardForBlock(parentRound, blockRound uint64) (types.PartitionShardID, bool, error) {
	round := parentRound
	var zero types.PartitionShardID
	if x.profile != ProfileHandoff {
		return zero, false, nil
	}
	parent, err := x.blockTree.FindBlock(round)
	if err != nil {
		return zero, false, err
	}
	control := parent.ShardState.Control
	if control == nil || (control.Phase != "prepared" && control.Phase != "endorsed") {
		return zero, false, nil
	}
	configs, err := x.orchestration.ShardConfigs(parent.GetRound())
	if err != nil {
		return zero, false, err
	}
	return frozenShardOf(parent.ShardState, configs, control, blockRound)
}

// CertifiedEVMShardAt selects the sole EVM shard with the verified parent at
// the given root round. Ambiguous or non-EVM matches fail closed.
func (x *BlockStore) CertifiedEVMShardAt(round uint64, frozenParent []byte) (types.PartitionShardID, error) {
	parent, err := x.blockTree.FindBlock(round)
	if err != nil {
		return types.PartitionShardID{}, err
	}
	configs, err := x.orchestration.ShardConfigs(round)
	if err != nil {
		return types.PartitionShardID{}, err
	}
	return frozenShard(parent.ShardState, configs, frozenParent)
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
