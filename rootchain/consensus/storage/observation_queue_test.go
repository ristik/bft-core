package storage

import (
	"bytes"
	"crypto"
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

func TestTheObservationQueueRetainsThePublishingRoundAcrossABacklog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.db")
	db, err := NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	prior, publication := obsFor(10), obsFor(11)
	require.NoError(t, db.db.Update(func(tx *bbolt.Tx) error {
		return appendObservationsTx(tx.Bucket(bucketMetadata), []ObservationInput{prior, publication})
	}))
	require.NoError(t, db.AckObservation(prior.ID(), [32]byte{}))

	// The execution client comes back after more than the former 4,096-entry eviction limit.
	var later []ObservationInput
	for round := uint64(12); round < 12+4096; round++ {
		entry := publication
		entry.RootRound, entry.ParentRound = round, round-1
		later = append(later, entry)
	}
	require.NoError(t, db.db.Update(func(tx *bbolt.Tx) error {
		return appendObservationsTx(tx.Bucket(bucketMetadata), later)
	}))
	require.NoError(t, db.Close())

	db, err = NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	got, cur, err := db.PendingObservations(64)
	require.NoError(t, err)
	require.Len(t, got, 64)
	require.Equal(t, publication, got[0])
	require.Equal(t, later[:63], got[1:])
	require.Equal(t, ObservationCursor{Set: true, ID: prior.ID()}, cur)
	require.Error(t, db.AckObservation(got[1].ID(), [32]byte{9}), "an acknowledgement may not skip the boundary")
	require.NoError(t, db.AckObservation(publication.ID(), [32]byte{9}))
	got, cur, err = db.PendingObservations(1)
	require.NoError(t, err)
	require.Equal(t, later[:1], got)
	require.Equal(t, ObservationCursor{Set: true, ID: publication.ID(), Prev: [32]byte{9}}, cur)
}

func TestAnOldEpochAcknowledgementKeepsTheSuccessorAtTheReusedRound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.db")
	db, err := NewBoltStorage(path)
	require.NoError(t, err)
	commit := func(entry ObservationInput) {
		b := &ExecutedBlock{BlockData: &rctypes.BlockData{Version: 3, Epoch: entry.RootEpoch, Round: entry.RootRound,
			Payload: &rctypes.Payload{Version: 3}}, CommitQc: &rctypes.QuorumCert{}}
		require.NoError(t, db.CommitBlock(b, nil, nil, []ObservationInput{entry}))
	}

	old := obsFor(13)
	old.RootEpoch = 1
	commit(old)
	batch, _, err := db.PendingObservations(64)
	require.NoError(t, err)
	require.Equal(t, []ObservationInput{old}, batch)

	anchor := &rctypes.EpochAnchor{Epoch: 2, Slot: 12, GenesisID: bytes.Repeat([]byte{2}, 32), StateRoot: bytes.Repeat([]byte{3}, 32)}
	root := &ExecutedBlock{BlockData: &rctypes.BlockData{Version: 3, Epoch: anchor.Epoch, Round: anchor.Slot,
		Payload: &rctypes.Payload{Version: 3}, Anchor: anchor}}
	require.NoError(t, db.InstallEpochAnchorRoot(root, anchor))
	successor := old
	successor.RootEpoch, successor.BlockHash, successor.StateRoot = 2, [32]byte{99}, [32]byte{100}
	commit(successor)
	require.NoError(t, db.AckObservation(batch[0].ID(), [32]byte{1}))
	require.Error(t, db.AckObservation(batch[0].ID(), [32]byte{2}), "a stale acknowledgement cannot rewrite the cursor")
	require.NoError(t, db.Close())

	db, err = NewBoltStorage(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	got, cur, err := db.PendingObservations(64)
	require.NoError(t, err)
	require.Equal(t, []ObservationInput{successor}, got)
	require.Equal(t, ObservationCursor{Set: true, ID: old.ID(), Prev: [32]byte{1}}, cur)
}

func TestRecoveryQueuesTheCertifiedHeadAndReplayedCommits(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1}})
	shard := types.PartitionShardID{PartitionID: 1, ShardID: types.ShardID{}.Key()}
	c.certifiedEVM = true
	c.store.SetObservedShard(shard)
	c.next()
	c.next()
	c.next(1)
	c.next()
	msg := received(t, c.state())
	head := msg.CommittedHead.GetRound()
	donor, _, err := c.store.PendingObservations(64)
	require.NoError(t, err)
	require.Len(t, donor, 1)
	require.Equal(t, head, donor[0].RootRound)

	c.next()
	c.propose(nil, nil)
	for round := head + 2; round <= c.round; round++ {
		block, err := c.store.Block(round)
		require.NoError(t, err)
		msg.Pending = append(msg.Pending, block.BlockData)
	}
	msg = received(t, msg)
	path := filepath.Join(t.TempDir(), "receiver.db")
	db, err := NewBoltStorage(path)
	require.NoError(t, err)
	receiver, err := New(crypto.SHA256, db, c.orch, c.log)
	require.NoError(t, err)
	receiver.SetObservedShard(shard)
	configure := func(bs *BlockStore) (IRChangeReqVerifier, error) {
		bs.SetObservedShard(shard)
		return chainVerifier{bs}, nil
	}
	require.NoError(t, ValidateRecoveryState(crypto.SHA256, msg, c.round, c.orch, db, configure, c.log),
		"pending QCs commit a certified EVM input even if the same verifier setup enables observation")
	before, _, err := db.PendingObservations(64)
	require.NoError(t, err)
	require.Empty(t, before)

	replacement, err := receiver.RecoverFromState(msg.CommittedHead)
	require.NoError(t, err)
	afterHead, _, err := db.PendingObservations(64)
	require.NoError(t, err)
	require.Equal(t, donor, afterHead)
	for i, block := range msg.Pending {
		_, err := replacement.ProcessQc(block.Qc)
		if i == 0 && errorsIsCommitFailed(err) {
			err = nil
		}
		require.NoError(t, err)
		_, err = replacement.Add(block, chainVerifier{replacement})
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())

	db, err = NewBoltStorage(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	got, _, err := db.PendingObservations(64)
	require.NoError(t, err)
	donor, _, err = c.store.PendingObservations(64)
	require.NoError(t, err)
	require.Len(t, donor, 2)
	require.Equal(t, donor, got)
	blocks, err := db.LoadBlocks()
	require.NoError(t, err)
	require.Equal(t, head+1, got[1].RootRound)
	require.Equal(t, replacement.tree().Root().GetRound(), blocks[len(blocks)-1].GetRound())
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
