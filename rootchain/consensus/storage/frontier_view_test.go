package storage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

func frontierTestTree(t *testing.T) (*BlockTree, *ExecutedBlock, types.PartitionID, types.ShardID, string) {
	t.Helper()
	conf := newShardConf(t)
	root := genesisBlockWithShard(t, conf)
	oldKey := types.PartitionShardID{PartitionID: conf.PartitionID, ShardID: conf.ShardID.Key()}
	selected := root.ShardState.States[oldKey]
	delete(root.ShardState.States, oldKey)
	conf.ShardID, _ = conf.ShardID.Split()
	selected.ShardID = conf.ShardID
	root.ShardState.States[types.PartitionShardID{PartitionID: conf.PartitionID, ShardID: conf.ShardID.Key()}] = selected
	root.CommitQc.VoteInfo.CurrentRootHash = []byte{11, 12, 13}
	root.CommitQc.Signatures = map[string]hex.Bytes{"root-1": {14, 15}}
	key := types.PartitionShardID{PartitionID: conf.PartitionID, ShardID: conf.ShardID.Key()}
	root.ShardState.States[key].LastCR = &certification.CertificationResponse{
		Partition: conf.PartitionID,
		Shard:     conf.ShardID,
		Technical: certification.TechnicalRecord{Round: 1, Epoch: 1, Leader: "leader", StatHash: []byte{1}, FeeHash: []byte{2}},
		UC: types.UnicityCertificate{
			Version: 1, InputRecord: &types.InputRecord{Version: 1, Epoch: 1, RoundNumber: 1, Hash: []byte{3, 4, 5}}, TRHash: []byte{6, 7},
			ShardTreeCertificate:   types.ShardTreeCertificate{Version: 1, Shard: conf.ShardID, SiblingHashes: [][]byte{{9, 10}}},
			UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: conf.PartitionID},
			UnicitySeal:            &types.UnicitySeal{Version: 1, RootChainRoundNumber: 3, Timestamp: 12345, Signatures: map[string]hex.Bytes{"root-1": {7, 8}}},
		},
	}
	dbName := filepath.Join(t.TempDir(), "frontier.db")
	db, err := NewBoltStorage(dbName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	tree, err := NewBlockTreeWithRootBlock(root, db)
	require.NoError(t, err)
	return tree, root, conf.PartitionID, conf.ShardID, dbName
}

func TestBlockTreeReadFrontierStorageViewOwnsSelectedData(t *testing.T) {
	tree, source, partition, shard, dbName := frontierTestTree(t)
	before, err := os.ReadFile(dbName)
	require.NoError(t, err)

	view, err := (&BlockStore{blockTree: tree}).ReadFrontierStorageView(partition, shard)
	require.NoError(t, err)
	require.Equal(t, source.GetRound(), view.CommittedRootRound)
	require.Equal(t, source.CommitQc.LedgerCommitInfo.NetworkID, view.RootNetworkID)
	require.Equal(t, partition, view.PartitionID)
	require.True(t, view.ShardID.Equal(shard))
	require.Equal(t, source.ShardState.States[types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}].ShardConfHash, view.ShardConfigHash)
	sourceRootHash := append([]byte(nil), source.CommitQc.VoteInfo.CurrentRootHash...)

	view.CommitQC.VoteInfo.CurrentRootHash[0] ^= 0xff
	view.LastCR.UC.InputRecord.Hash[0] ^= 0xff
	view.ShardConfigHash[0] ^= 0xff
	viewRootHash := append([]byte(nil), view.CommitQC.VoteInfo.CurrentRootHash...)
	viewConfigHash := append([]byte(nil), view.ShardConfigHash...)
	require.Equal(t, sourceRootHash, []byte(source.CommitQc.VoteInfo.CurrentRootHash))
	require.NotEqual(t, view.LastCR.UC.InputRecord.Hash, source.ShardState.States[types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}].LastCR.UC.InputRecord.Hash)

	source.CommitQc.VoteInfo.CurrentRootHash[0] ^= 0xaa
	source.ShardState.States[types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}].ShardConfHash[0] ^= 0xaa
	require.Equal(t, viewRootHash, []byte(view.CommitQC.VoteInfo.CurrentRootHash))
	require.Equal(t, viewConfigHash, view.ShardConfigHash)

	// The QC candidates may alias in the tree but must not alias in the view.
	view.CommitQC.Signatures["root-1"][0] = 99
	require.Equal(t, byte(14), source.CommitQc.Signatures["root-1"][0])
	require.Equal(t, byte(14), view.HighQC.Signatures["root-1"][0])
	view.LastCR.UC.UnicitySeal.Signatures["root-1"][0] = 99
	require.Equal(t, byte(7), source.ShardState.States[types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}].LastCR.UC.UnicitySeal.Signatures["root-1"][0])
	source.ShardState.States[types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}].LastCR.UC.UnicitySeal.Signatures["root-1"][1] = 98
	require.Equal(t, byte(8), view.LastCR.UC.UnicitySeal.Signatures["root-1"][1])
	require.EqualValues(t, 3, view.LastCR.UC.UnicitySeal.RootChainRoundNumber)
	require.EqualValues(t, 12345, view.LastCR.UC.UnicitySeal.Timestamp)
	require.NotEqual(t, view.CommittedRootRound, view.LastCR.UC.UnicitySeal.RootChainRoundNumber)
	require.NotEqual(t, reflect.ValueOf(shard).FieldByName("bits").Pointer(), reflect.ValueOf(view.ShardID).FieldByName("bits").Pointer())

	after, err := os.ReadFile(dbName)
	require.NoError(t, err)
	require.Equal(t, before, after, "storage view must not write the database")
}

func TestBlockTreeReadFrontierStorageViewSelectedShardOnly(t *testing.T) {
	tree, source, partition, shard, _ := frontierTestTree(t)
	otherShard := types.PartitionShardID{PartitionID: partition + 1, ShardID: shard.Key()}
	other := &ShardInfo{PartitionID: otherShard.PartitionID, ShardID: shard, Fees: make(map[string]uint64, frontierMaxCollectionSize+1)}
	for i := 0; i <= frontierMaxCollectionSize; i++ {
		other.Fees[fmt.Sprintf("fee-%d", i)] = uint64(i)
	}
	source.ShardState.States[otherShard] = other
	view, err := tree.ReadFrontierStorageView(partition, shard)
	require.NoError(t, err)
	require.Equal(t, partition, view.PartitionID)
}

func TestBlockTreeReadFrontierStorageViewMissingRequiredData(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*ExecutedBlock, types.PartitionShardID)
	}{
		{name: "block data", mutate: func(root *ExecutedBlock, _ types.PartitionShardID) { root.BlockData = nil }},
		{name: "input record", mutate: func(root *ExecutedBlock, key types.PartitionShardID) {
			root.ShardState.States[key].LastCR.UC.InputRecord = nil
		}},
		{name: "seal", mutate: func(root *ExecutedBlock, key types.PartitionShardID) {
			root.ShardState.States[key].LastCR.UC.UnicitySeal = nil
		}},
		{name: "tree proof", mutate: func(root *ExecutedBlock, key types.PartitionShardID) {
			root.ShardState.States[key].LastCR.UC.UnicityTreeCertificate = nil
		}},
		{name: "commit QC", mutate: func(root *ExecutedBlock, _ types.PartitionShardID) { root.CommitQc = nil }},
		{name: "shard", mutate: func(root *ExecutedBlock, key types.PartitionShardID) { delete(root.ShardState.States, key) }},
		{name: "LastCR", mutate: func(root *ExecutedBlock, key types.PartitionShardID) { root.ShardState.States[key].LastCR = nil }},
		{name: "configuration identity", mutate: func(root *ExecutedBlock, key types.PartitionShardID) { root.ShardState.States[key].ShardConfHash = nil }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			tree, source, partition, shard, dbName := frontierTestTree(t)
			before, err := os.ReadFile(dbName)
			require.NoError(t, err)
			key := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
			testCase.mutate(source, key)
			view, err := tree.ReadFrontierStorageView(partition, shard)
			require.Error(t, err)
			require.Nil(t, view)
			after, err := os.ReadFile(dbName)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestBlockTreeReadFrontierStorageViewRejectsOversizedNestedAndAggregateData(t *testing.T) {
	t.Run("nested map", func(t *testing.T) {
		tree, source, partition, shard, _ := frontierTestTree(t)
		source.CommitQc.Signatures = make(map[string]hex.Bytes, frontierMaxCollectionSize+1)
		for i := 0; i <= frontierMaxCollectionSize; i++ {
			source.CommitQc.Signatures[fmt.Sprintf("signer-%d", i)] = []byte{1}
		}
		view, err := tree.ReadFrontierStorageView(partition, shard)
		require.Error(t, err)
		require.Nil(t, view)
	})

	t.Run("nested byte field", func(t *testing.T) {
		tree, source, partition, shard, _ := frontierTestTree(t)
		source.CommitQc.Signatures["root-1"] = make([]byte, frontierMaxFieldBytes+1)
		view, err := tree.ReadFrontierStorageView(partition, shard)
		require.ErrorContains(t, err, "byte field exceeds")
		require.Nil(t, view)
	})
	t.Run("per-object cumulative", func(t *testing.T) {
		tree, source, partition, shard, _ := frontierTestTree(t)
		source.CommitQc.Signatures = map[string]hex.Bytes{
			"root-1": bytes.Repeat([]byte{1}, 140<<10),
			"root-2": bytes.Repeat([]byte{2}, 140<<10),
		}
		view, err := tree.ReadFrontierStorageView(partition, shard)
		require.ErrorContains(t, err, "per-object copy bounds")
		require.Nil(t, view)
	})
	// The aggregate cap is defensive given the three per-object caps and small
	// metadata. Test the shared preflight budget directly without pretending a
	// per-object refusal proves the aggregate guard.
	t.Run("aggregate preflight", func(t *testing.T) {
		b := frontierCopyBudget{estimatedBytes: frontierMaxAggregateBytes - 10, objectStart: frontierMaxAggregateBytes - 10}
		err := inspectFrontierValue(reflect.ValueOf([]byte{1, 2}), 0, &b)
		require.ErrorContains(t, err, "aggregate value exceeds")
	})
	t.Run("node budget", func(t *testing.T) {
		b := frontierCopyBudget{nodes: frontierMaxNodes}
		require.ErrorContains(t, inspectFrontierValue(reflect.ValueOf(uint64(0)), 0, &b), "too many nested fields")
	})

	t.Run("shard id bound", func(t *testing.T) {
		tree, _, partition, shard, _ := frontierTestTree(t)
		// ShardID is private-field backed; Split is the public constructor.
		tooDeep := shard
		for i := uint(0); i < frontierMaxShardBits; i++ {
			tooDeep, _ = tooDeep.Split()
		}
		view, err := tree.ReadFrontierStorageView(partition, tooDeep)
		require.Error(t, err)
		require.Nil(t, view)
	})
}

func TestBlockTreeReadFrontierStorageViewDoesNotMutateZeroVersions(t *testing.T) {
	tree, source, partition, shard, _ := frontierTestTree(t)
	source.CommitQc.VoteInfo.Version = 0
	before := source.CommitQc.VoteInfo.Version
	_, err := tree.ReadFrontierStorageView(partition, shard)
	require.NoError(t, err)
	require.Equal(t, before, source.CommitQc.VoteInfo.Version)
}

func TestFrontierStorageViewOptionalHighQCAndEmptyStore(t *testing.T) {
	tree, _, partition, shard, _ := frontierTestTree(t)
	tree.highQc = nil
	v, err := tree.ReadFrontierStorageView(partition, shard)
	require.NoError(t, err)
	require.Nil(t, v.HighQC)
	var store *BlockStore
	v, err = store.ReadFrontierStorageView(partition, shard)
	require.Error(t, err)
	require.Nil(t, v)
}
