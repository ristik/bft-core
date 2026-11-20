package storage

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

func obsFor(round uint64) ObservationInput {
	return ObservationInput{RootRound: round, ParentRound: round - 1, RootUCTime: 1000 + round, BlockHash: [32]byte{byte(round)}, StateRoot: [32]byte{byte(round), 1}, ShardRound: round + 3}
}

// The queue entries are written with the committing block in one transaction, survive a reopen, are consumed in order, and the cursor
// stored with an acknowledgement survives too; a queue is pruned by consumption and bounded when nothing consumes it.
func TestTheObservationQueueIsDurableOrderedAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.db")
	db, err := NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	require.NoError(t, db.db.Update(func(tx *bbolt.Tx) error {
		return appendObservationsTx(tx.Bucket(bucketMetadata), []ObservationInput{obsFor(5), obsFor(6), obsFor(7)})
	}))
	require.NoError(t, db.Close())

	// a restart with a non-empty durable queue
	db, err = NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	got, cur, err := db.PendingObservations(10)
	require.NoError(t, err)
	require.False(t, cur.Set)
	require.Equal(t, []ObservationInput{obsFor(5), obsFor(6), obsFor(7)}, got, "oldest first")
	require.NoError(t, db.AckObservation(6, ObservationCursor{Set: true, Round: 6, Prev: [32]byte{9}}))
	got, cur, err = db.PendingObservations(10)
	require.NoError(t, err)
	require.Equal(t, []ObservationInput{obsFor(7)}, got, "consumed entries are pruned")
	require.Equal(t, ObservationCursor{Set: true, Round: 6, Prev: [32]byte{9}}, cur)
	require.NoError(t, db.Close())
	db, err = NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	_, cur, err = db.PendingObservations(10)
	require.NoError(t, err)
	require.EqualValues(t, 6, cur.Round, "the cursor survives a restart")

	// bounded when nothing consumes it: the oldest are dropped
	var many []ObservationInput
	for r := uint64(100); r < 100+MaxObservationQueue+50; r++ {
		many = append(many, obsFor(r))
	}
	require.NoError(t, db.db.Update(func(tx *bbolt.Tx) error { return appendObservationsTx(tx.Bucket(bucketMetadata), many) }))
	all, _, err := db.PendingObservations(MaxObservationQueue + 1000)
	require.NoError(t, err)
	require.Len(t, all, MaxObservationQueue)
	require.EqualValues(t, 100+MaxObservationQueue+49, all[len(all)-1].RootRound, "the newest are kept")
	require.NoError(t, db.AckObservation(all[len(all)-1].RootRound, ObservationCursor{Set: true, Round: all[len(all)-1].RootRound}))
	all, _, err = db.PendingObservations(10)
	require.NoError(t, err)
	require.Empty(t, all, "an acknowledged queue is empty")
	require.NoError(t, db.Close())
}

// observationsOf lists the certified EVM block of EVERY block of a commit path (newest first in the path), oldest first, of the observed
// shard only, skipping a block without a complete certified block, and nothing when no shard is observed.
func TestObservationsOfACommitPathAreOldestFirst(t *testing.T) {
	key := types.PartitionShardID{PartitionID: 8, ShardID: types.ShardID{}.Key()}
	other := types.PartitionShardID{PartitionID: 9, ShardID: types.ShardID{}.Key()}
	blk := func(round, parent uint64, hash byte, complete bool) *ExecutedBlock {
		si := &ShardInfo{IR: &types.InputRecord{BlockHash: bytes.Repeat([]byte{hash}, 32), Hash: bytes.Repeat([]byte{hash, 1}, 16), RoundNumber: round + 10}}
		if !complete {
			si.IR.BlockHash = nil
		}
		return &ExecutedBlock{BlockData: &rctypes.BlockData{Round: round, Timestamp: 100 + round, Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: parent}}},
			ShardState: ShardStates{States: map[types.PartitionShardID]*ShardInfo{key: si, other: {IR: &types.InputRecord{BlockHash: bytes.Repeat([]byte{0xee}, 32), Hash: bytes.Repeat([]byte{0xee}, 32)}}}}}
	}
	path := []*ExecutedBlock{blk(4, 3, 4, true), blk(3, 2, 3, false), blk(2, 1, 2, true)} // newest first, as findPathToRoot lists it
	got := observationsOf(path, &key)
	require.Len(t, got, 2, "the block without a certified block contributes nothing")
	require.EqualValues(t, 2, got[0].RootRound)
	require.EqualValues(t, 4, got[1].RootRound, "oldest first")
	require.EqualValues(t, 3, got[1].ParentRound)
	require.EqualValues(t, 104, got[1].RootUCTime)
	require.EqualValues(t, 14, got[1].ShardRound)
	require.Equal(t, [32]byte(bytes.Repeat([]byte{4}, 32)), got[1].BlockHash)
	require.Empty(t, observationsOf(path, nil), "no shard observed: nothing queued")
}

// The commit transaction writes the entries with the block: persistCommit of a block with observations makes them durable, and a store that
// cannot commit atomically refuses them rather than queueing them separately.
func TestPersistCommitWritesTheObservationsWithTheBlock(t *testing.T) {
	bs := initBlockStoreFromGenesis(t, newShardConf(t))
	root := bs.tree().Root()
	require.NoError(t, bs.tree().persistCommit(root, nil, []ObservationInput{obsFor(5), obsFor(6)}))
	got, _, err := bs.PendingObservations(10)
	require.NoError(t, err)
	require.Equal(t, []ObservationInput{obsFor(5), obsFor(6)}, got)
}
