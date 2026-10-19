package storage

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootrecords"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	testpartition "github.com/unicitynetwork/bft-core/rootchain/partitions/testutils"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

func initBlockStoreFromGenesis(t *testing.T, shardConf *types.PartitionDescriptionRecord) *BlockStore {
	t.Helper()
	dir := t.TempDir()

	db, err := NewBoltStorage(filepath.Join(dir, "blocks.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	log := logger.New(t)
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), log)
	require.NoError(t, err)
	if shardConf != nil {
		require.NoError(t, orchestration.AddShardConfig(shardConf))
		require.NoError(t, db.WriteBlock(genesisBlockWithShard(t, shardConf), true))
	}
	t.Cleanup(func() { _ = orchestration.Close() })

	bStore, err := New(crypto.SHA256, db, orchestration, log)
	require.NoError(t, err)
	return bStore
}

func Test_BlockStore_New(t *testing.T) {
	t.Run("invalid arguments", func(t *testing.T) {
		bs, err := New(crypto.SHA256, nil, nil, nil)
		require.EqualError(t, err, `storage is nil`)
		require.Nil(t, bs)
	})

	t.Run("loading tree failure", func(t *testing.T) {
		expErr := errors.New("failure to load blocks")
		db := mockPersistentStore{
			loadBlocks: func() ([]*ExecutedBlock, error) { return nil, expErr },
		}
		bs, err := New(crypto.SHA256, db, nil, nil)
		require.ErrorIs(t, err, expErr)
		require.Nil(t, bs)
	})

	t.Run("loading existing state success", func(t *testing.T) {
		orchestration := mockOrchestration{
			shardConfigs: func(rootRound uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
				return nil, nil
			},
		}

		rootBlock := ExecutedBlock{BlockData: &rctypes.BlockData{Round: 90}, CommitQc: &rctypes.QuorumCert{}}
		db := mockPersistentStore{
			loadBlocks: func() ([]*ExecutedBlock, error) { return []*ExecutedBlock{&rootBlock}, nil },
		}
		bs, err := New(crypto.SHA256, db, orchestration, nil)
		require.NoError(t, err)
		require.NotNil(t, bs)

		b, err := bs.Block(rootBlock.GetRound())
		require.NoError(t, err)
		require.Equal(t, &rootBlock, b)
	})
}

func TestHandleTcError(t *testing.T) {
	bStore := initBlockStoreFromGenesis(t, nil)
	require.ErrorContains(t, bStore.ProcessTc(nil), "tc is nil")
	tc := &rctypes.TimeoutCert{
		Timeout: &rctypes.Timeout{
			Round: 3,
		},
	}
	// For now ignore if we do not have a block that timeouts
	require.NoError(t, bStore.ProcessTc(tc))
}

func TestHandleQcError(t *testing.T) {
	bStore := initBlockStoreFromGenesis(t, nil)
	ucs, err := bStore.ProcessQc(nil)
	require.ErrorContains(t, err, "qc is nil")
	require.Nil(t, ucs)
	// qc for non-existing round
	qc := &rctypes.QuorumCert{
		VoteInfo: &rctypes.RoundInfo{
			RoundNumber:       3,
			ParentRoundNumber: 2,
		},
	}
	ucs, err = bStore.ProcessQc(qc)
	require.ErrorContains(t, err, "block for round 3 not found")
	require.Nil(t, ucs)
}

func TestBlockStoreAdd(t *testing.T) {
	bStore := initBlockStoreFromGenesis(t, nil)
	rBlock := bStore.blockTree.Root()
	mockBlockVer := mockIRVerifier{
		verify: func(round uint64, irChReq *rctypes.IRChangeReq) (*types.InputRecord, error) {
			luc, err := bStore.GetCertificate(irChReq.Partition, irChReq.Shard)
			if err != nil {
				return nil, fmt.Errorf("invalid payload: partition %s state is missing: %w", irChReq.Partition, err)
			}
			switch irChReq.CertReason {
			case rctypes.Quorum:
				// NB! there was at least one request, otherwise we would not be here
				return irChReq.Requests[0].InputRecord, nil
			case rctypes.QuorumNotPossible:
			case rctypes.T2Timeout:
				return luc.UC.InputRecord, nil
			}
			return nil, fmt.Errorf("unknown certification reason %v", irChReq.CertReason)
		},
	}
	block := &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound,
		Payload: &rctypes.Payload{},
		Qc:      nil,
	}
	_, err := bStore.Add(block, mockBlockVer)
	require.ErrorContains(t, err, "add block failed: different block for round 1 is already in store")
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 1,
		Payload: &rctypes.Payload{},
		Qc:      bStore.GetHighQc(), // the qc is genesis qc
	}
	// Proposal always comes with Qc and Block, process Qc first and then new block
	// add stale qc for block 1 - this is already present as highQC from genesis block
	ucs, err := bStore.ProcessQc(block.Qc)
	require.NoError(t, err)
	require.Nil(t, ucs)

	// and the new block 2 - since there is no shards, RootHash stays nil
	rh, err := bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)

	// add qc for round 3, commits round 1
	vInfo := &rctypes.RoundInfo{
		RoundNumber:       rctypes.GenesisRootRound + 1,
		ParentRoundNumber: rctypes.GenesisRootRound,
		CurrentRootHash:   rh,
	}
	qc := &rctypes.QuorumCert{
		VoteInfo: vInfo,
		LedgerCommitInfo: &types.UnicitySeal{
			Version:              1,
			Hash:                 rBlock.RootHash,
			RootChainRoundNumber: rctypes.GenesisRootRound,
		},
	}
	ucs, err = bStore.ProcessQc(qc)
	require.NoError(t, err)
	require.Empty(t, ucs)

	b, err := bStore.Block(rctypes.GenesisRootRound + 1)
	require.NoError(t, err)
	require.EqualValues(t, rctypes.GenesisRootRound+1, b.BlockData.Round)

	// add block 3
	// qc for round 2, does not commit a round
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 2,
		Payload: &rctypes.Payload{},
		Qc:      qc,
	}
	rh, err = bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)
	// prepare block 4
	vInfo = &rctypes.RoundInfo{
		RoundNumber:       rctypes.GenesisRootRound + 2,
		ParentRoundNumber: rctypes.GenesisRootRound + 1,
		CurrentRootHash:   rh,
	}
	qc = &rctypes.QuorumCert{
		VoteInfo: vInfo,
		LedgerCommitInfo: &types.UnicitySeal{
			Version:              1,
			Hash:                 rBlock.RootHash,
			RootChainRoundNumber: rctypes.GenesisRootRound + 1,
		},
	}
	// qc for round 4, commits round 2
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 3,
		Payload: &rctypes.Payload{},
		Qc:      qc,
	}
	// Add
	ucs, err = bStore.ProcessQc(qc)
	require.NoError(t, err)
	require.Empty(t, ucs)
	// add block 4
	rh, err = bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)
	rBlock = bStore.blockTree.Root()
	// block in round 2 becomes root
	require.Equal(t, uint64(2), rBlock.BlockData.Round)
	hQc := bStore.GetHighQc()
	require.Equal(t, uint64(3), hQc.VoteInfo.RoundNumber)
	// try to read a non-existing block
	b, err = bStore.Block(100)
	require.ErrorContains(t, err, "block for round 100 not found")
	require.Nil(t, b)
}

func Test_BlockStoreStore_LastVote(t *testing.T) {
	// just check that calls are routed to persistent storage,
	// there is no other logic in these methods
	orchestration := mockOrchestration{
		shardConfigs: func(rootRound uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
			return nil, nil
		},
	}

	rootBlock := ExecutedBlock{BlockData: &rctypes.BlockData{Round: 4}, CommitQc: &rctypes.QuorumCert{}}
	var msg any
	db := mockPersistentStore{
		// to avoid init of genesis return committed block
		loadBlocks: func() ([]*ExecutedBlock, error) { return []*ExecutedBlock{&rootBlock}, nil },
		// returning the value passed to write from read verifies that the persistent store methods are called
		readVote: func() (any, error) { return msg, nil },
		writeVote: func(vote any) error {
			msg = vote
			return nil
		},
	}

	bStore, err := New(crypto.SHA256, db, orchestration, nil)
	require.NoError(t, err)
	// the message type is verified by the storage!
	require.NoError(t, bStore.StoreLastVote(920))
	vote, err := bStore.ReadLastVote()
	require.NoError(t, err)
	require.Equal(t, 920, vote)
}

func Test_BlockStore_ShardInfo(t *testing.T) {
	shardConf := newShardConf(t)
	bStore := initBlockStoreFromGenesis(t, shardConf)
	si := bStore.ShardInfo(0xFFFFFFFF, types.ShardID{})
	require.Nil(t, si)
}

func Test_BlockStore_StateRoundtrip(t *testing.T) {
	shardConf := newShardConf(t)
	storeA := initBlockStoreFromGenesis(t, shardConf)
	// the genesis block is created with the shard marked as "changed" - clear
	// it as the state message does not carry that information
	clear(storeA.blockTree.root.data.ShardState.Changed)

	// modify Fees to see if they are restored correctly
	si := storeA.ShardInfo(shardConf.PartitionID, shardConf.ShardID)
	si.Fees[si.nodeIDs[0]] = 10
	var err error
	si.TR.FeeHash, err = si.feeHash(crypto.SHA256) // the technical record commits the accumulators (a recovered head is checked for it)
	require.NoError(t, err)
	ut, _, err := storeA.blockTree.root.data.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	storeA.blockTree.root.data.RootHash = ut.RootHash()

	state, err := storeA.GetState()
	require.NoError(t, err)
	require.NotNil(t, state)

	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "blocks.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	// state msg is used to init "shard info registry", the orchestration provides data which is not part of state msg
	storeB, err := NewFromState(crypto.SHA256, state.CommittedHead, db, storeA.orchestration, logger.New(t))
	require.NoError(t, err)
	require.NotNil(t, storeB)

	// two stores should have the same state now
	require.Equal(t, storeA.blockTree.root.data.ShardState.States, storeB.blockTree.root.data.ShardState.States)
	require.Equal(t, storeA.blockTree.root.data.ShardState.Changed, storeB.blockTree.root.data.ShardState.Changed)
	require.Equal(t, storeA.blockTree.root.data.RootHash, storeB.blockTree.root.data.RootHash, "root hash")
	require.Equal(t, storeA.blockTree.root.child, storeB.blockTree.root.child)
	require.Len(t, storeB.blockTree.roundToNode, len(storeA.blockTree.roundToNode))
	for k, v := range storeA.blockTree.roundToNode {
		bNode, ok := storeB.blockTree.roundToNode[k]
		require.True(t, ok)
		require.ElementsMatch(t, v.child, bNode.child)
	}
	require.Equal(t, storeA.blockTree.highQc, storeB.blockTree.highQc)

	siA := storeA.ShardInfo(shardConf.PartitionID, shardConf.ShardID)
	require.NoError(t, err)
	require.NotNil(t, siA)
	require.NoError(t, siA.IsValid())

	siB := storeB.ShardInfo(shardConf.PartitionID, shardConf.ShardID)
	require.NoError(t, err)
	require.NotNil(t, siB)
	require.NoError(t, siB.IsValid())

	require.Equal(t, siA, siB)
}

func Test_BlockStore_persistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "blocks.db")
	// init new (empty) DB from genesis
	db, err := NewBoltStorage(dbPath)
	require.NoError(t, err)
	log := logger.New(t)
	shardConf := newShardConf(t)
	blockA := genesisBlockWithShard(t, shardConf)
	require.NoError(t, db.WriteBlock(blockA, false))

	orchestration := testpartition.NewOrchestration(t, log)
	require.NoError(t, orchestration.AddShardConfig(shardConf))
	storeA, err := New(crypto.SHA256, db, orchestration, log)
	require.NoError(t, err)
	require.NotNil(t, storeA)

	// load new DB instance from the non-empty file - must get the same state
	require.NoError(t, db.Close())
	db, err = NewBoltStorage(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// to make sure we load the state from db send in empty genesis record
	storeB, err := New(crypto.SHA256, db, orchestration, log)
	require.NoError(t, err)

	siA := blockA.ShardState.States[types.PartitionShardID{PartitionID: shardConf.PartitionID, ShardID: shardConf.ShardID.Key()}]
	siB := storeB.ShardInfo(shardConf.PartitionID, shardConf.ShardID)
	require.NoError(t, err)
	require.Equal(t, siA, siB)

	blockB, err := storeB.Block(blockA.GetRound())
	require.NoError(t, err)
	require.Equal(t, blockA, blockB)
}

func newShardConf(t *testing.T) *types.PartitionDescriptionRecord {
	node := testutils.NewTestNode(t)
	return &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     1,
		PartitionTypeID: 1,
		ShardID:         types.ShardID{},
		UnitIDLen:       256,
		TypeIDLen:       32,
		T2Timeout:       2500 * time.Millisecond,
		Validators:      []*types.NodeInfo{node.NodeInfo(t)},
	}
}

func genesisBlockWithShard(t *testing.T, shardConf *types.PartitionDescriptionRecord) *ExecutedBlock {
	hashAlgo := crypto.SHA256
	genesisBlock := &rctypes.BlockData{
		Version:   1,
		Author:    "testgenesis",
		Round:     rctypes.GenesisRootRound,
		Epoch:     rctypes.GenesisRootEpoch,
		Timestamp: types.GenesisTime,
	}

	si, err := NewShardInfo(shardConf, hashAlgo)
	require.NoError(t, err)
	psID := types.PartitionShardID{PartitionID: si.PartitionID, ShardID: si.ShardID.Key()}
	commitQc := &rctypes.QuorumCert{
		VoteInfo: &rctypes.RoundInfo{
			Version:           1,
			RoundNumber:       genesisBlock.Round,
			Epoch:             genesisBlock.Epoch,
			Timestamp:         genesisBlock.Timestamp,
			ParentRoundNumber: 0, // no parent block
		},
		LedgerCommitInfo: &types.UnicitySeal{
			Version:              1,
			NetworkID:            5,
			RootChainRoundNumber: 4,
			Epoch:                rctypes.GenesisRootEpoch,
			Timestamp:            123,
			Hash:                 []byte{1, 2, 3},
			PreviousHash:         []byte{3, 2, 1},
		},
	}

	eb := &ExecutedBlock{
		BlockData: genesisBlock,
		HashAlgo:  hashAlgo,
		ShardState: ShardStates{
			States:  map[types.PartitionShardID]*ShardInfo{psID: si},
			Changed: ShardSet{psID: struct{}{}},
		},
		Qc:       commitQc,
		CommitQc: commitQc,
	}
	ut, _, err := eb.ShardState.UnicityTree(hashAlgo)
	require.NoError(t, err)
	eb.RootHash = ut.RootHash()
	commitQc.VoteInfo.CurrentRootHash = eb.RootHash

	return eb
}

type mockPersistentStore struct {
	loadBlocks func() ([]*ExecutedBlock, error)
	writeBlock func(block *ExecutedBlock, root bool) error
	readVote   func() (msg any, err error)
	writeVote  func(vote any) error
	writeTC    func(tc *rctypes.TimeoutCert) error
	readLastTC func() (*rctypes.TimeoutCert, error)
}

func (mps mockPersistentStore) LoadBlocks() ([]*ExecutedBlock, error) {
	return mps.loadBlocks()
}

func (mps mockPersistentStore) WriteBlock(block *ExecutedBlock, root bool) error {
	return mps.writeBlock(block, root)
}

func (mps mockPersistentStore) ReadLastVote() (msg any, err error) {
	return mps.readVote()
}

func (mps mockPersistentStore) WriteVote(vote any) error {
	return mps.writeVote(vote)
}

func (mps mockPersistentStore) WriteTC(tc *rctypes.TimeoutCert, _ bool) error {
	return mps.writeTC(tc)
}

func (mps mockPersistentStore) ReadLastTC() (*rctypes.TimeoutCert, error) {
	return mps.readLastTC()
}

// A round can get both a TC and a QC: the roots vote for the block, then time out, and a vote delayed past the TC completes the QC.
// The TC must not cost the block, or no root can process that QC (nor recover it: no peer holds the block either).
func TestBlockStore_LateQcAfterTc(t *testing.T) {
	irVer := mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) {
		return nil, errors.New("no IR changes in this test")
	}}
	// a QC that commits its parent names the parent's round and root hash; any other QC leaves the commit info empty
	qcFor := func(round, parent uint64, rh []byte, commits *ExecutedBlock) *rctypes.QuorumCert {
		qc := &rctypes.QuorumCert{
			VoteInfo:         &rctypes.RoundInfo{RoundNumber: round, ParentRoundNumber: parent, CurrentRootHash: rh},
			LedgerCommitInfo: &types.UnicitySeal{Version: 1},
		}
		if commits != nil {
			qc.LedgerCommitInfo.RootChainRoundNumber = commits.GetRound()
			qc.LedgerCommitInfo.Hash = commits.RootHash
		}
		return qc
	}
	add := func(t *testing.T, bs *BlockStore, round uint64, qc *rctypes.QuorumCert) []byte {
		t.Helper()
		_, err := bs.ProcessQc(qc)
		require.NoError(t, err)
		rh, err := bs.Add(&rctypes.BlockData{Round: round, Payload: &rctypes.Payload{}, Qc: qc}, irVer)
		require.NoError(t, err)
		return rh
	}
	tcFor := func(round uint64) *rctypes.TimeoutCert {
		return &rctypes.TimeoutCert{Timeout: &rctypes.Timeout{Round: round}}
	}
	// genesis (round 1) <- 2 <- 3; round 3 times out
	setup := func(t *testing.T) (*BlockStore, []byte, []byte) {
		bs := initBlockStoreFromGenesis(t, nil)
		rh2 := add(t, bs, 2, bs.GetHighQc())
		rh3 := add(t, bs, 3, qcFor(2, 1, rh2, nil))
		require.NoError(t, bs.ProcessTc(tcFor(3)))
		require.NotContains(t, roundsOf(bs.blockTree.GetAllUncommittedNodes()), uint64(3), "the timed-out block is off the tree")
		return bs, rh2, rh3
	}

	t.Run("late QC for the timed-out round is processed and extended", func(t *testing.T) {
		bs, _, rh3 := setup(t)
		qc3 := qcFor(3, 2, rh3, nil)
		_, err := bs.ProcessQc(qc3)
		require.NoError(t, err, "the late QC finds its block")
		require.EqualValues(t, 3, bs.GetHighQc().GetRound())
		b, err := bs.Block(3)
		require.NoError(t, err)
		require.EqualValues(t, 3, b.GetRound())
		// the next leader extends the late QC
		_, err = bs.Add(&rctypes.BlockData{Round: 4, Payload: &rctypes.Payload{}, Qc: qc3}, irVer)
		require.NoError(t, err)
		require.Contains(t, roundsOf(bs.blockTree.GetAllUncommittedNodes()), uint64(3))
	})

	t.Run("a repeated TC is harmless", func(t *testing.T) {
		bs, _, rh3 := setup(t)
		require.NoError(t, bs.ProcessTc(tcFor(3)))
		_, err := bs.ProcessQc(qcFor(3, 2, rh3, nil))
		require.NoError(t, err)
	})

	t.Run("a commit past the timed-out round prunes it", func(t *testing.T) {
		bs, rh2, _ := setup(t)
		// the next leader extends round 2 under the TC: 2 <- 4 <- 5, and the QC of 5 commits 4
		rh4 := add(t, bs, 4, qcFor(2, 1, rh2, nil))
		add(t, bs, 5, qcFor(4, 2, rh4, nil))
		b4, err := bs.Block(4)
		require.NoError(t, err)
		_, err = bs.ProcessQc(qcFor(5, 4, nil, b4))
		require.NoError(t, err)
		require.EqualValues(t, 4, bs.blockTree.Root().GetRound())
		require.Empty(t, bs.blockTree.timedOut)
		_, err = bs.Block(3)
		require.ErrorContains(t, err, "block for round 3 not found")
	})
}

func roundsOf(blocks []*ExecutedBlock) []uint64 {
	rounds := make([]uint64, 0, len(blocks))
	for _, b := range blocks {
		rounds = append(rounds, b.GetRound())
	}
	return rounds
}

// A root that recovers from a state message has missed the records committed meanwhile. The head commits the log it ends with; the
// next commit that carries a record finds a gap unless the log was completed first (bft-core#644).
func Test_BlockStore_StateRecoveryCompletesTheCommittedSourceLog(t *testing.T) {
	recs := chainOf(3)
	head := func(t *testing.T) *abdrc.CommittedBlock {
		storeA := profileStore(t)
		clear(storeA.blockTree.root.data.ShardState.Changed)
		storeA.blockTree.root.data.ShardState.Control.Pos = stateOver(recs).Bytes()
		ut, _, err := storeA.blockTree.root.data.ShardState.UnicityTree(crypto.SHA256)
		require.NoError(t, err)
		storeA.blockTree.root.data.RootHash = ut.RootHash()
		storeA.blockTree.root.data.CommitQc.LedgerCommitInfo.Hash = ut.RootHash()
		state, err := storeA.GetState()
		require.NoError(t, err)
		return state.CommittedHead
	}
	next := func() []rootrecords.Record {
		r := rootrecords.Record{Index: 3, Predecessor: recs[2].ID, Kind: rootrecords.KindSessionClosed, Progress: 99, UCTime: 99, Data: make([]byte, 32)}
		r.ID = rootrecords.RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
		return []rootrecords.Record{r}
	}
	// the recovering root retained one record of the three the head commits
	recovering := func(t *testing.T, fetcher RecordFetcher) (*BlockStore, BoltDB) {
		db, err := NewBoltStorage(filepath.Join(t.TempDir(), "blocks.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		require.NoError(t, db.AppendRecords(recs[:1]))
		old := profileStore(t)
		old.storage, old.prefixSource = db, fetcher
		return old, db
	}

	t.Run("without the prefix the first record past the head finds a gap", func(t *testing.T) {
		old, db := recovering(t, nil)
		_, err := NewFromState(crypto.SHA256, head(t), db, old.orchestration, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		require.ErrorIs(t, db.AppendRecords(next()), ErrRecordLog)
	})
	t.Run("with the prefix completed before the head is installed it extends the log", func(t *testing.T) {
		old, db := recovering(t, &sliceFetcher{recs: recs})
		h := head(t)
		require.NoError(t, old.EnsureRecordPrefix(context.Background(), h))
		_, err := NewFromState(crypto.SHA256, h, db, old.orchestration, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		require.NoError(t, db.AppendRecords(next()))
		n, err := db.RecordCount()
		require.NoError(t, err)
		require.EqualValues(t, 4, n)
	})
	t.Run("a head whose source state is not the certified one drives no fetch and no write", func(t *testing.T) {
		forged := chainOf(5) // self-consistent, links to the retained first record, ends at the forged tip
		forgedHead := *head(t)
		control := *forgedHead.Control
		control.Pos = stateOver(forged).Bytes()
		forgedHead.Control = &control
		f := &sliceFetcher{recs: forged}
		old, db := recovering(t, f)
		require.ErrorIs(t, old.EnsureRecordPrefix(context.Background(), &forgedHead), ErrControlCheckpoint)
		require.Zero(t, f.calls)
		n, err := db.RecordCount()
		require.NoError(t, err)
		require.EqualValues(t, 1, n)
	})
	t.Run("a log that cannot be completed is a refusal that writes nothing", func(t *testing.T) {
		defer func(d, b time.Duration) { prefixTimeout, prefixBackoff = d, b }(prefixTimeout, prefixBackoff)
		prefixTimeout, prefixBackoff = 50*time.Millisecond, time.Millisecond
		old, db := recovering(t, &sliceFetcher{err: errors.New("no root serves the feed")})
		require.ErrorIs(t, old.EnsureRecordPrefix(context.Background(), head(t)), ErrRecordPrefixMissing)
		n, err := db.RecordCount()
		require.NoError(t, err)
		require.EqualValues(t, 1, n)
	})
}

// The roots restart together: a fetch that finds no serving peer is repeated until one answers, within the bound (bft-core#638).
func TestPrefixFetchRepeatsWhileNoPeerServes(t *testing.T) {
	defer func(d, b time.Duration) { prefixTimeout, prefixBackoff = d, b }(prefixTimeout, prefixBackoff)
	prefixTimeout, prefixBackoff = 5*time.Second, time.Millisecond
	recs := chainOf(10)
	control := &evmroot.ControlState{Pos: stateOver(recs).Bytes()}
	db := newBolt(t)
	f := &flakyFetcher{sliceFetcher: sliceFetcher{recs: recs}, failures: 3}
	s := &BlockStore{storage: db, prefixSource: f}
	require.NoError(t, s.ensureRetainedPrefix(control))
	require.Equal(t, 4, f.calls, "three misses, then the page")
	n, err := db.RecordCount()
	require.NoError(t, err)
	require.EqualValues(t, 10, n)

	// a source that never serves ends at the bound with the sentinel, and nothing is retained
	prefixTimeout = 30 * time.Millisecond
	db = newBolt(t)
	s = &BlockStore{storage: db, prefixSource: &flakyFetcher{sliceFetcher: sliceFetcher{recs: recs}, failures: 1 << 30}}
	err = s.ensureRetainedPrefix(control)
	require.ErrorIs(t, err, ErrRecordPrefixMissing)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	n, _ = db.RecordCount()
	require.Zero(t, n)

	// a source that answers with nothing is waited on in the same way
	db = newBolt(t)
	s = &BlockStore{storage: db, prefixSource: &sliceFetcher{}}
	require.ErrorIs(t, s.ensureRetainedPrefix(control), ErrRecordPrefixMissing)
}

// flakyFetcher fails its first `failures` calls with the error of a peer that is not up yet, then serves.
type flakyFetcher struct {
	sliceFetcher
	failures int
}

func (f *flakyFetcher) Records(ctx context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	if f.calls < f.failures {
		f.calls++
		return nil, errors.New("dial: connection refused")
	}
	return f.sliceFetcher.Records(ctx, from, max)
}
