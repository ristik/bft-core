package storage

import (
	"bytes"
	"crypto"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"go.etcd.io/bbolt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

func cutBlock(epoch, round uint64, pos []byte) *ExecutedBlock {
	return &ExecutedBlock{
		BlockData:  &rctypes.BlockData{Round: round, Epoch: epoch},
		ShardState: ShardStates{Control: &evmroot.ControlState{Network: 5, Epoch: 1, Phase: "idle", PreviousDigest: make([]byte, 32), Pos: pos}},
		HashAlgo:   crypto.SHA256,
	}
}

func newBolt(t *testing.T) BoltDB {
	t.Helper()
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "blocks.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// The coordinates of a cut come from the committed block (its epoch and round) and its tree, never from the control state's own epoch.
func TestACommittedBlockWithASourceStateHasACutKeyedByItsOwnCoordinates(t *testing.T) {
	pos := rootrecords.NewState(1, 1).Bytes()
	b := cutBlock(3, 7, pos)
	entry, err := cutEntryOf(b)
	require.NoError(t, err)
	require.NotNil(t, entry)
	tree, _, err := b.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	root, err := handoff.ControlRoot(entry.Cut.Control, entry.Cut.Path)
	require.NoError(t, err)
	require.Equal(t, tree.RootHash(), root, "the path leads to the block's own tree root")
	require.Equal(t, CutKey{Network: 5, Epoch: 3, Round: 7, TreeRoot: [32]byte(tree.RootHash())}, entry.Key)
	require.NotEqual(t, b.ShardState.Control.Epoch, entry.Key.Epoch, "not the control state's inherited epoch")

	none, err := cutEntryOf(cutBlock(3, 8, nil))
	require.NoError(t, err)
	require.Nil(t, none, "a block without a source state has no cut")
	none, err = cutEntryOf(&ExecutedBlock{BlockData: &rctypes.BlockData{Round: 9}})
	require.NoError(t, err)
	require.Nil(t, none, "a chain without a control state has no cut")
}

func TestTheCutRingKeepsTheLatestAndEvictsTheOldest(t *testing.T) {
	var r cutRing
	k := func(i uint64) CutKey { return CutKey{Network: 5, Epoch: 1, Round: i} }
	for i := uint64(1); i <= MaxRetainedCuts+3; i++ {
		r.put(k(i), ControlCut{Control: &evmroot.ControlState{Epoch: i}})
	}
	for i := uint64(1); i <= 3; i++ {
		_, ok := r.get(k(i))
		require.False(t, ok, "round %d is evicted", i)
	}
	for i := uint64(4); i <= MaxRetainedCuts+3; i++ {
		cut, ok := r.get(k(i))
		require.True(t, ok)
		require.Equal(t, i, cut.Control.Epoch)
	}
	r.put(k(10), ControlCut{Control: &evmroot.ControlState{Epoch: 99}})
	cut, _ := r.get(k(10))
	require.EqualValues(t, 99, cut.Control.Epoch)
	require.Len(t, r.order, MaxRetainedCuts)
	// the same round of another epoch is another entry
	other := k(10)
	other.Epoch = 2
	_, ok := r.get(other)
	require.False(t, ok)
}

func commitFixture(t *testing.T, db PersistentStore) (*BlockTree, *ExecutedBlock, *ExecutedBlock) {
	t.Helper()
	rootBlock, childBlock := mockExecutedBlock(1, 0), mockExecutedBlock(2, 1)
	rootBlock.ShardState.Changed, childBlock.ShardState.Changed = ShardSet{}, ShardSet{}
	childBlock.ShardState.Control = &evmroot.ControlState{Network: 5, Epoch: 1, Phase: "idle", PreviousDigest: make([]byte, 32), Pos: rootrecords.NewState(1, 1).Bytes()}
	root, child := newNode(&rootBlock), newNode(&childBlock)
	root.addChild(child)
	bt := &BlockTree{root: root, roundToNode: map[uint64]*node{1: root, 2: child}, blocksDB: db}
	ut, _, err := child.data.ShardState.UnicityTree(child.data.HashAlgo)
	require.NoError(t, err)
	child.data.RootHash = ut.RootHash()
	return bt, &rootBlock, &childBlock
}

func commitQC(t *testing.T, b *ExecutedBlock) *rctypes.QuorumCert {
	return &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: b.GetRound() + 1, ParentRoundNumber: b.GetRound()},
		LedgerCommitInfo: &types.UnicitySeal{RootChainRoundNumber: b.GetRound(), Hash: b.RootHash},
	}
}

func TestCommittingABlockRetainsItsCutDurablyBeforeItBecomesTheRoot(t *testing.T) {
	db := newBolt(t)
	bt, rootBlock, child := commitFixture(t, db)
	rootBlock.CommitQc = &rctypes.QuorumCert{}
	require.NoError(t, db.WriteBlock(rootBlock, true))
	_, err := bt.Commit(commitQC(t, child))
	require.NoError(t, err)

	entry, err := cutEntryOf(child)
	require.NoError(t, err)
	got, err := db.GetCut(entry.Key)
	require.NoError(t, err)
	root, err := handoff.ControlRoot(got.Control, got.Path)
	require.NoError(t, err)
	require.Equal(t, entry.Key.TreeRoot[:], root, "the cut authenticates against the tree root the block was sealed with")

	// a cold tree over the same store (restart, or the tree replaced by an epoch install) serves it
	cold := &BlockTree{blocksDB: db}
	cut, err := cold.ControlCut(entry.Key)
	require.NoError(t, err)
	require.True(t, bytes.Equal(cut.Control.Pos, child.ShardState.Control.Pos))
	_, hot := cold.cuts.get(entry.Key)
	require.True(t, hot, "read-through fills the bounded cache")

	other := entry.Key
	other.Round++
	_, err = cold.ControlCut(other)
	require.ErrorIs(t, err, ErrCutUnavailable, "a round never committed here")
}

// a block that cannot have its cut retained is not committed: no certificate is visible without the cut a shard needs
type recordsOnly struct{ PersistentStore }

func TestACommitWithoutADurableCutIsRefusedAndLeavesTheRootAlone(t *testing.T) {
	bt, _, child := commitFixture(t, mockPersistentStore{writeBlock: func(*ExecutedBlock, bool) error { t.Fatal("the block must not be written"); return nil }})
	_, err := bt.Commit(commitQC(t, child))
	require.ErrorIs(t, err, ErrNoCutStore)
	require.True(t, errors.Is(err, ErrCommitFailed) || err != nil)
	require.EqualValues(t, 1, bt.root.data.GetRound(), "the block did not become the root")
}

func TestAConflictingCutFailsTheWholeCommit(t *testing.T) {
	db := newBolt(t)
	bt, rootBlock, child := commitFixture(t, db)
	rootBlock.CommitQc = &rctypes.QuorumCert{}
	require.NoError(t, db.WriteBlock(rootBlock, true))
	entry, err := cutEntryOf(child)
	require.NoError(t, err)
	// the retained cut of that key differs (written raw: a valid entry can never be built for another control under the same root)
	forged := entry.Cut
	other := *forged.Control
	other.Phase = "frozen"
	forged.Control = &other
	raw, err := types.Cbor.Marshal(forged)
	require.NoError(t, err)
	require.NoError(t, db.db.Update(func(tx *bbolt.Tx) error { return tx.Bucket(bucketMetadata).Put(entry.Key.bytes(), raw) }))

	before, err := db.RecordCount()
	require.NoError(t, err)
	_, err = bt.Commit(commitQC(t, child))
	require.ErrorIs(t, err, ErrCutConflict)
	require.EqualValues(t, 1, bt.root.data.GetRound())
	blocks, err := db.LoadBlocks()
	require.NoError(t, err)
	require.Len(t, blocks, 1, "the commit wrote nothing")
	after, err := db.RecordCount()
	require.NoError(t, err)
	require.Equal(t, before, after)
}
