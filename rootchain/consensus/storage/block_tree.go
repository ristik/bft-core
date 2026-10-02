package storage

import (
	"bytes"
	"cmp"
	"crypto"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/unicitynetwork/bft-core/evmroot"
	rcnet "github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abdrc "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

type (
	// tree node creates a tree of consecutive blocks
	node struct {
		data  *ExecutedBlock
		child []*node // child nodes
	}

	BlockTree struct {
		root        *node
		roundToNode map[uint64]*node
		highQc      *abdrc.QuorumCert
		blocksDB    PersistentStore
		m           sync.RWMutex
	}
)

var (
	ErrCommitFailed         = errors.New("commit failed")
	ErrPersistenceUncertain = errors.New("block tree persistence uncertain")
)

type persistenceUncertainError struct{ err error }

func (e persistenceUncertainError) Error() string   { return e.err.Error() }
func (e persistenceUncertainError) Unwrap() []error { return []error{e.err, ErrPersistenceUncertain} }
func persistenceUncertain(err error) error          { return persistenceUncertainError{err: err} }

func newNode(b *ExecutedBlock) *node {
	return &node{data: b, child: make([]*node, 0, 2)}
}

func (l *node) addChild(child *node) {
	l.child = append(l.child, child)
}

func (l *node) removeChild(child *node) {
	for i, n := range l.child {
		if n == child {
			l.child = slices.Delete(l.child, i, i+1)
			break
		}
	}
}

/*
NewBlockTreeWithRootBlock creates BlockTree with given block as root node.

Intended use-case is for recovery - acquire latest committed block and build on that state.
*/
func NewBlockTreeWithRootBlock(block *ExecutedBlock, bDB PersistentStore) (*BlockTree, error) {
	if err := bDB.WriteBlock(block, true); err != nil {
		return nil, fmt.Errorf("block write failed: %w", err)
	}
	rootNode := newNode(block)

	return &BlockTree{
		roundToNode: map[uint64]*node{rootNode.data.GetRound(): rootNode},
		root:        rootNode,
		highQc:      block.CommitQc,
		blocksDB:    bDB,
	}, nil
}

func initBlock(block *ExecutedBlock, orchestration Orchestration) error {
	// init SI data which is not persisted
	configRound := block.GetRound()
	if block.ShardState.Control != nil && block.ShardState.Control.Phase == "committed" {
		configRound = block.ShardState.Control.OrderedRound
	}
	shardConfs, err := orchestration.ShardConfigs(configRound)
	if err != nil {
		return fmt.Errorf("loading shard configurations for round %d: %w", block.GetRound(), err)
	}
	for k, si := range block.ShardState.States {
		pdr, ok := shardConfs[k]
		if !ok {
			return fmt.Errorf("block has a shard %s but orchestration doesn't have such shard for round %d", k, block.GetRound())
		}
		// Every shard's installed configuration is authenticated state under the handoff profile: the configuration derived from
		// committed history (genesis plus handoffs) must be the one the block stored, or a retired, edited or unrecovered set would
		// be loaded into the trust base. A lost or stale derived index, or an edited genesis file, stops the root instead of
		// silently loading other keys.
		if block.ShardState.Control != nil {
			pdrHash, err := pdr.Hash(crypto.SHA256)
			if err != nil {
				return fmt.Errorf("hashing shard configuration (%s): %w", k, err)
			}
			if !bytes.Equal(pdrHash, si.ShardConfHash) {
				return fmt.Errorf("%w: shard %s stores configuration %x, committed history derives %x for round %d",
					ErrAssignmentHistory, k, si.ShardConfHash, pdrHash, block.GetRound())
			}
		}
		if err = si.resetTrustBase(pdr); err != nil {
			return fmt.Errorf("init shard trustbase (%s): %w", k, err)
		}
	}
	return nil
}

func NewBlockTree(bDB PersistentStore, orchestration Orchestration, networkProfile ...uint64) (*BlockTree, error) {
	profile, err := profileVersion(networkProfile)
	if err != nil {
		return nil, err
	}
	if bDB == nil {
		return nil, fmt.Errorf("block tree init failed, database is nil")
	}
	blocks, err := bDB.LoadBlocks()
	if err != nil {
		return nil, fmt.Errorf("root DB read error: %w", err)
	}
	if len(blocks) == 0 {
		// must be system bootstrap - init tree with genesis block
		genesisBlock, err := NewGenesisBlock(orchestration.NetworkID(), crypto.SHA256, profile)
		if err != nil {
			return nil, fmt.Errorf("creating genesis block for empty DB: %w", err)
		}
		return NewBlockTreeWithRootBlock(genesisBlock, bDB)
	}
	// blocks are sorted in descending order, first one with commit QC is the root
	rootIdx := slices.IndexFunc(blocks, func(b *ExecutedBlock) bool {
		return b.CommitQc != nil || isEpochAnchorRoot(b)
	})
	if rootIdx == -1 {
		return nil, errors.New("root block not found")
	}
	rootNode := newNode(blocks[rootIdx])
	for _, block := range blocks {
		if err := checkStoredRoot(block, profile); err != nil {
			return nil, err
		}
	}
	if err = initBlock(rootNode.data, orchestration); err != nil {
		return nil, fmt.Errorf("init root block: %w", err)
	}
	hQC := rootNode.data.CommitQc
	treeNodes := map[uint64]*node{rootNode.data.GetRound(): rootNode}
	for i := rootIdx - 1; i >= 0; i-- {
		block := blocks[i]
		// if parent round does not exist then reject, parent must be recovered
		parent, found := treeNodes[block.GetParentRound()]
		if !found {
			return nil, fmt.Errorf("cannot add block for round %d, parent block %d not found", block.GetRound(), block.GetParentRound())
		}
		// init ShardInfo data which is not persisted
		if err = initBlock(block, orchestration); err != nil {
			return nil, fmt.Errorf("init child block: %w", err)
		}
		if profile == ProfileHandoff {
			if block.BlockData.Epoch != parent.data.BlockData.Epoch {
				return nil, ErrNetworkProfile
			}
			if err := checkStoredSuffix(parent.data, block); err != nil {
				return nil, err
			}
		}
		// append block and add a child to parent
		n := newNode(block)
		treeNodes[block.BlockData.Round] = n
		parent.addChild(n)
		if n.data.BlockData.Qc.GetRound() > hQC.GetRound() {
			hQC = n.data.BlockData.Qc
		}
	}

	return &BlockTree{
		roundToNode: treeNodes,
		root:        rootNode,
		highQc:      hQC,
		blocksDB:    bDB,
	}, nil
}

func isEpochAnchorRoot(b *ExecutedBlock) bool {
	return b != nil && b.BlockData != nil && b.BlockData.Anchor != nil && b.BlockData.Round == b.BlockData.Anchor.Slot
}

func (bt *BlockTree) InsertQc(qc *abdrc.QuorumCert) error {
	// find block, if it does not exist, return error we need to recover missing info
	b, err := bt.FindBlock(qc.GetRound())
	if err != nil {
		return fmt.Errorf("find block: %w", err)
	}
	if !bytes.Equal(b.RootHash, qc.VoteInfo.CurrentRootHash) {
		return errors.New("qc state hash is different from local computed state hash")
	}

	bt.m.Lock()
	defer bt.m.Unlock()

	b.Qc = qc
	// persist changes
	if err = bt.blocksDB.WriteBlock(b, false); err != nil {
		return fmt.Errorf("failed to persist block for round %d: %w", b.BlockData.Round, err)
	}
	bt.highQc = qc
	return nil
}

func (bt *BlockTree) HighQc() *abdrc.QuorumCert {
	bt.m.Lock()
	defer bt.m.Unlock()
	return bt.highQc
}

// Add adds new leaf to the block tree
func (bt *BlockTree) Add(block *ExecutedBlock) error {
	bt.m.Lock()
	defer bt.m.Unlock()
	// every round can exist only once
	// reject a block if this round has already been added
	if _, found := bt.roundToNode[block.GetRound()]; found {
		return fmt.Errorf("block for round %d already exists", block.BlockData.Round)
	}
	// if parent round does not exist then reject, parent must be recovered
	parent, found := bt.roundToNode[block.GetParentRound()]
	if !found {
		return fmt.Errorf("cannot add block for round %d, parent block %d not found", block.GetRound(), block.GetParentRound())
	}
	// append block and add a child to parent
	n := newNode(block)
	parent.addChild(n)
	bt.roundToNode[block.GetRound()] = n
	// persist block
	return bt.blocksDB.WriteBlock(n.data, false)
}

// RemoveLeaf removes leaf node if it is not root node
func (bt *BlockTree) RemoveLeaf(round uint64) error {
	bt.m.Lock()
	defer bt.m.Unlock()
	// root cannot be removed
	if bt.root.data.GetRound() == round {
		return errors.New("root block cannot be removed")
	}
	n, found := bt.roundToNode[round]
	if !found {
		// this is ok if we do not have the node, on TC remove might be triggered twice
		return nil
	}
	if len(n.child) > 0 {
		return fmt.Errorf("error round %v is not leaf node", round)
	}
	parent, found := bt.roundToNode[n.data.GetParentRound()]
	if !found {
		return fmt.Errorf("error parent block %v not found", n.data.GetParentRound())
	}
	delete(bt.roundToNode, round)
	parent.removeChild(n)
	return nil
}

func (bt *BlockTree) Root() *ExecutedBlock {
	bt.m.Lock()
	defer bt.m.Unlock()
	return bt.root.data
}

// findPathToRoot finds bath from node with round to root node
// returns nil in case of failure, when a node is not found
// otherwise it will return list of data stored in the path nodes, excluding the root data itself, so if
// the root node is previous node then the list is empty
func (bt *BlockTree) findPathToRoot(round uint64) []*ExecutedBlock {
	n, f := bt.roundToNode[round]
	if !f {
		return nil
	}
	// if the node is root
	if n == bt.root {
		return []*ExecutedBlock{}
	}
	// find path
	path := make([]*ExecutedBlock, 0, 2)
	for {
		if parent, found := bt.roundToNode[n.data.GetParentRound()]; found {
			path = append(path, n.data)
			// if parent is root then break out of loop
			if parent == bt.root {
				break
			}
			n = parent
			continue
		}
		// node not found, should never happen, this is not a tree data structure then
		return nil
	}
	return path
}

func (bt *BlockTree) GetAllUncommittedNodes() []*ExecutedBlock {
	bt.m.Lock()
	defer bt.m.Unlock()

	return bt.allUncommittedNodes()
}

func (bt *BlockTree) allUncommittedNodes() []*ExecutedBlock {
	blocks := make([]*ExecutedBlock, 0, 2)
	// start from root children
	var blocksToCheck []*node
	blocksToCheck = append(blocksToCheck, bt.root.child...)
	for len(blocksToCheck) > 0 {
		var n *node
		// pop last node from blocks to check
		n, blocksToCheck = blocksToCheck[len(blocksToCheck)-1], blocksToCheck[:len(blocksToCheck)-1]
		// append it's child nodes to check for root
		blocksToCheck = append(blocksToCheck, n.child...)
		// if this node was not the new root then append to pruned blocks
		blocks = append(blocks, n.data)
	}
	return blocks
}

// findBlocksToPrune will return all blocks that can be removed from previous root to new root
// - In a normal case there is only one block, the previous root that will be pruned
// - In case of timeouts there can be more than one, the blocks in between old root and new
// are committed by the same QC.
/*
For example:
	B5--> B6--> B7
	       ╰--> B8--> B9
a call findBlocksToPrune(newRootRound = 9) results in a rounds, 5,6,7,8 all pruned new root node is 9
a call findBlocksToPrune(newRootRound = 8) results in a rounds, 5,6,7 pruned new root node is 8 and tree B8->B9
*/
func (bt *BlockTree) findBlocksToPrune(newRootRound uint64) ([]uint64, error) {
	prunedBlocks := make([]uint64, 0, 2)
	// nothing to be pruned
	if newRootRound == bt.root.data.GetRound() {
		return prunedBlocks, nil
	}
	blocksToCheck := []*node{bt.root}
	newRootFound := false
	for len(blocksToCheck) > 0 {
		var n *node
		// pop last node from blocks to check
		n, blocksToCheck = blocksToCheck[len(blocksToCheck)-1], blocksToCheck[:len(blocksToCheck)-1]
		for _, child := range n.child {
			if child.data.GetRound() == newRootRound {
				newRootFound = true
				continue
			}
			// append new node to check for root
			blocksToCheck = append(blocksToCheck, child)
		}
		// if this node was not the new root then append to pruned blocks
		prunedBlocks = append(prunedBlocks, n.data.GetRound())
	}
	if !newRootFound {
		return nil, fmt.Errorf("new root round %v not found", newRootRound)
	}
	return prunedBlocks, nil
}

func (bt *BlockTree) FindBlock(round uint64) (*ExecutedBlock, error) {
	bt.m.Lock()
	defer bt.m.Unlock()

	if b, found := bt.roundToNode[round]; found {
		return b.data, nil
	}
	return nil, fmt.Errorf("block for round %v not found", round)
}

/*
Commit commits block for round and prunes all preceding blocks from the tree,
the committed block becomes the new root of the tree.
It returns new certificates generated by the block (ie only for those shards
which did have change in progress).
*/
func (bt *BlockTree) Commit(commitQc *abdrc.QuorumCert) ([]*certification.CertificationResponse, error) {
	bt.m.Lock()
	defer bt.m.Unlock()

	commitRound := commitQc.GetParentRound()
	commitNode, found := bt.roundToNode[commitRound]
	if !found {
		return nil, errors.Join(ErrCommitFailed, fmt.Errorf("block for round %v not found", commitRound))
	}
	if a := commitNode.data.BlockData.Anchor; a != nil && commitNode.data.BlockData.Round == a.Slot {
		return nil, errors.Join(ErrCommitFailed, fmt.Errorf("epoch anchor is not a commit subject"))
	}

	for k, parentSI := range bt.root.data.ShardState.States {
		// between blocks there might have been epoch change and thus new state
		// might not have all the shards of the old state
		if si, ok := commitNode.data.ShardState.States[k]; ok {
			si.LastCR = parentSI.LastCR
		}
	}

	// Find if there are uncommitted nodes between new root and previous root
	path := bt.findPathToRoot(commitRound)
	// new committed block also certifies the changes from pending rounds
	for _, cb := range path {
		maps.Copy(commitNode.data.ShardState.Changed, cb.ShardState.Changed)
	}
	if oldControl, newControl := bt.root.data.ShardState.Control, commitNode.data.ShardState.Control; oldControl != nil && newControl != nil && oldControl.Phase == "committed" && newControl.Phase == "committed" && oldControl.Epoch == newControl.Epoch {
		clear(commitNode.data.ShardState.Changed)
	}
	// prune the chain, the committed block becomes new root of the chain
	blocksToPrune, err := bt.findBlocksToPrune(commitRound)
	if err != nil {
		return nil, persistenceUncertain(fmt.Errorf("finding blocks to prune on round %d: %w", commitRound, err))
	}
	for _, round := range blocksToPrune {
		delete(bt.roundToNode, round)
	}
	// generate certificates for all the shards that have changes in progress
	ucs, err := commitNode.data.GenerateCertificates(commitQc)
	if err != nil {
		return nil, persistenceUncertain(fmt.Errorf("generating certificates for round %d: %w", commitNode.data.GetRound(), err))
	}
	// update the new root with commit QC info
	commitNode.data.CommitQc = commitQc
	// The block that first commits the handoff record is THE checkpoint of that handoff. It is captured here, once, and persisted before
	// the block becomes the root (a later commit prunes it), so every honest root serves the same one whenever it is asked.
	if err := bt.captureHandoffCheckpoint(bt.root.data, commitNode.data); err != nil {
		return nil, persistenceUncertain(err)
	}

	if err := bt.blocksDB.WriteBlock(commitNode.data, true); err != nil {
		return nil, persistenceUncertain(err)
	}

	bt.root = commitNode
	return ucs, nil
}

func (bt *BlockTree) CurrentState() (*rcnet.StateMsg, error) {
	bt.m.Lock()
	defer bt.m.Unlock()

	pendingBlocks := bt.allUncommittedNodes()
	pending := make([]*abdrc.BlockData, len(pendingBlocks))
	for i, b := range pendingBlocks {
		pending[i] = b.BlockData
	}

	committedBlock := bt.root.data
	var anchor *abdrc.EpochAnchor
	if isEpochAnchorRoot(committedBlock) {
		anchor = committedBlock.BlockData.Anchor
	}
	si, err := toRecoveryShardInfo(committedBlock)
	if err != nil {
		return nil, fmt.Errorf("building recovery info of the root block: %w", err)
	}
	return &rcnet.StateMsg{
		CommittedHead: &rcnet.CommittedBlock{
			ShardInfo: si,
			Block:     committedBlock.BlockData,
			Qc:        committedBlock.Qc,
			CommitQc:  committedBlock.CommitQc,
			Control:   committedBlock.ShardState.Control,
			Anchor:    anchor,
		},
		Pending: pending,
	}, nil
}

// handoffCheckpointStore is the optional durable store of canonical handoff checkpoints.
type handoffCheckpointStore interface {
	StoreHandoffCheckpoint(epoch uint64, data []byte) error
	HandoffCheckpoint(epoch uint64) ([]byte, error)
}

// canonicalCheckpoint is the persisted form: the committed block that carries the handoff record (with its commit certificate, shard
// entries, control state) and the path of its control leaf. The record is decoded from the control state, never stored twice.
type canonicalCheckpoint struct {
	_     struct{} `cbor:",toarray"`
	Block *rcnet.CommittedBlock
	Path  *basetypes.UnicityTreeCertificate
}

// committedRecord is the handoff commit record of a block's control state, when the block's control state is the committed phase.
func committedRecord(block *ExecutedBlock) (evmroot.OrderedHandoffRecord, bool) {
	if block == nil || block.ShardState.Control == nil || block.ShardState.Control.Phase != "committed" {
		return evmroot.OrderedHandoffRecord{}, false
	}
	record, err := decodeOrderedRecord(block.ShardState.Control.RecordBytes)
	if err != nil || record.Kind != "commit" {
		return evmroot.OrderedHandoffRecord{}, false
	}
	return record, true
}

// captureHandoffCheckpoint persists the checkpoint when `next` is the block that first commits a handoff record: its control state is
// the committed phase and the old root's is not the same committed handoff.
func (bt *BlockTree) captureHandoffCheckpoint(old, next *ExecutedBlock) error {
	record, ok := committedRecord(next)
	if !ok {
		return nil
	}
	if prior, committed := committedRecord(old); committed && prior.Epoch == record.Epoch && bytes.Equal(old.ShardState.Control.RecordBytes, next.ShardState.Control.RecordBytes) {
		return nil // the record was committed by an earlier block: that one is the checkpoint
	}
	store, ok := bt.blocksDB.(handoffCheckpointStore)
	if !ok {
		return nil
	}
	head, path, err := checkpointOf(next)
	if err != nil {
		return err
	}
	raw, err := basetypes.Cbor.Marshal(canonicalCheckpoint{Block: head, Path: path})
	if err != nil {
		return fmt.Errorf("encoding the handoff checkpoint: %w", err)
	}
	return store.StoreHandoffCheckpoint(record.Epoch+1, raw)
}

// checkpointOf is the committed block as a handoff checkpoint, with a path for its control leaf.
func checkpointOf(root *ExecutedBlock) (*rcnet.CommittedBlock, *basetypes.UnicityTreeCertificate, error) {
	if root == nil || root.CommitQc == nil {
		return nil, nil, ErrHandoffRecord
	}
	if _, ok := committedRecord(root); !ok {
		return nil, nil, ErrHandoffRecord
	}
	tree, _, err := root.ShardState.UnicityTree(crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	if err != nil {
		return nil, nil, err
	}
	shards, err := toRecoveryShardInfo(root)
	if err != nil {
		return nil, nil, err
	}
	return &rcnet.CommittedBlock{Block: root.BlockData, ShardInfo: shards, Qc: root.Qc,
		CommitQc: root.CommitQc, Control: root.ShardState.Control}, path, nil
}

// HandoffCheckpoint returns the canonical checkpoint of the committed handoff: the block that carried the commit record, as captured
// when it committed, and not whatever the current committed root happens to be (a later empty block would give another, equally valid,
// checkpoint: a different byte string for the same handoff). The tree lock keeps the current record and the stored checkpoint from
// different handoffs from being paired.
//
// A root whose store retains checkpoints but holds none for this record (its commit predates the capture, or it recovered to a head PAST
// the carrier, which is pruned everywhere) REFUSES with ErrHandoffRecord rather than serve the current root: a non-canonical copy served
// once is retained by the bundle archive and served for good, and replicas then refuse the canonical one. The follower asks every root,
// so another one, which did capture it, serves it. Only a store without checkpoint retention (tests) serves the current root.
func (bt *BlockTree) HandoffCheckpoint() (*rcnet.CommittedBlock, *basetypes.UnicityTreeCertificate, evmroot.OrderedHandoffRecord, error) {
	bt.m.Lock()
	defer bt.m.Unlock()
	root := bt.root.data
	record, ok := committedRecord(root)
	if !ok || root.CommitQc == nil {
		return nil, nil, evmroot.OrderedHandoffRecord{}, ErrHandoffRecord
	}
	if store, ok := bt.blocksDB.(handoffCheckpointStore); ok {
		raw, err := store.HandoffCheckpoint(record.Epoch + 1)
		if err != nil {
			return nil, nil, evmroot.OrderedHandoffRecord{}, err
		}
		if len(raw) != 0 {
			var stored canonicalCheckpoint
			if err := basetypes.Cbor.Unmarshal(raw, &stored); err != nil || stored.Block == nil || stored.Path == nil || stored.Block.Control == nil ||
				stored.Block.CommitQc == nil {
				return nil, nil, evmroot.OrderedHandoffRecord{}, ErrHandoffRecord
			}
			if !bytes.Equal(stored.Block.Control.RecordBytes, root.ShardState.Control.RecordBytes) {
				return nil, nil, evmroot.OrderedHandoffRecord{}, ErrHandoffRecord
			}
			return stored.Block, stored.Path, record, nil
		}
		return nil, nil, evmroot.OrderedHandoffRecord{}, fmt.Errorf("%w: this root holds no canonical checkpoint for the handoff into epoch %d", ErrHandoffRecord, record.Epoch+1)
	}
	head, path, err := checkpointOf(root)
	if err != nil {
		return nil, nil, evmroot.OrderedHandoffRecord{}, err
	}
	return head, path, record, nil
}

// toRecoveryShardInfo lists the block's shard entries in canonical order (partition, then shard): the entries come from a map, and an
// order that depends on its iteration makes two honest roots serve different bytes for the same state. The root hash does not depend on
// the order (it is built from the entries by partition and shard).
func toRecoveryShardInfo(block *ExecutedBlock) ([]rcnet.ShardInfo, error) {
	si := make([]rcnet.ShardInfo, len(block.ShardState.States))
	idx := 0
	for _, v := range block.ShardState.States {
		si[idx].Partition = v.PartitionID
		si[idx].Shard = v.ShardID
		si[idx].T2Timeout = v.T2Timeout
		si[idx].RootHash = v.RootHash
		si[idx].PrevEpochStat = v.PrevEpochStat
		si[idx].Stat = v.Stat
		si[idx].PrevEpochFees = v.PrevEpochFees
		si[idx].Fees = maps.Clone(v.Fees)
		si[idx].IR = v.IR
		si[idx].IRTR = v.TR
		si[idx].ShardConfHash = v.ShardConfHash
		if v.LastCR != nil {
			si[idx].UC = &v.LastCR.UC
			si[idx].TR = &v.LastCR.Technical
		}

		idx++
	}
	slices.SortFunc(si, func(a, b rcnet.ShardInfo) int {
		if a.Partition != b.Partition {
			return cmp.Compare(a.Partition, b.Partition)
		}
		return strings.Compare(string(a.Shard.Key()), string(b.Shard.Key()))
	})
	return si, nil
}
