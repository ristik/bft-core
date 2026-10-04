package storage

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"
)

// These tests exercise raw storage coherence and ownership. Authentication is
// exercised separately by the real-root-loop client tests.
func reviewCutTree(t *testing.T) (*BlockTree, *ExecutedBlock, types.PartitionShardID, string) {
	t.Helper()
	return reviewCutTreeWithControl(t, nil)
}

// reviewCutTreeWithControl is reviewCutTree for a handoff-profile root: its committed state carries the
// control record, which is a leaf of the unicity tree the root hash commits to.
func reviewCutTreeWithControl(t *testing.T, control *evmroot.ControlState) (*BlockTree, *ExecutedBlock, types.PartitionShardID, string) {
	t.Helper()
	conf := newShardConf(t)
	conf.T2Timeout = 5 * time.Second
	root := genesisBlockWithShard(t, conf)
	if control != nil {
		root.ShardState.Control = control
		ut, _, err := root.ShardState.UnicityTree(crypto.SHA256)
		require.NoError(t, err)
		root.RootHash = ut.RootHash()
	}
	root.BlockData.Round = 4
	root.BlockData.Epoch = 1
	root.CommitQc.LedgerCommitInfo.Epoch = 1
	root.CommitQc.LedgerCommitInfo.RootChainRoundNumber = 4
	root.CommitQc.LedgerCommitInfo.Hash = bytes.Clone(root.RootHash)
	_, err := root.GenerateCertificates(root.CommitQc)
	require.NoError(t, err)
	// The committed root advances without replacing the genuine shard LastCR.
	root.BlockData.Round = 6
	root.CommitQc.LedgerCommitInfo.RootChainRoundNumber = 6
	root.CommitQc.VoteInfo.RoundNumber = 7
	root.CommitQc.VoteInfo.ParentRoundNumber = 6
	root.CommitQc.VoteInfo.Epoch = 1
	path := filepath.Join(t.TempDir(), "cut.db")
	db, err := NewBoltStorage(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	bt, err := NewBlockTreeWithRootBlock(root, db)
	require.NoError(t, err)
	return bt, root, types.PartitionShardID{PartitionID: conf.PartitionID, ShardID: conf.ShardID.Key()}, path
}

func TestReviewFrontierCutSnapshotOwnsDataAndDoesNotWrite(t *testing.T) {
	bt, root, key, path := reviewCutTree(t)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	last := root.ShardState.States[key].LastCR
	original, err := types.Cbor.Marshal(last)
	require.NoError(t, err)
	cut, err := bt.ReadFrontierCutSnapshot(key.PartitionID, last.Shard)
	require.NoError(t, err)
	require.EqualValues(t, 6, cut.RootRound)
	require.EqualValues(t, 4, cut.LastCR.UC.UnicitySeal.RootChainRoundNumber)
	actual, err := types.Cbor.Marshal(cut.LastCR)
	require.NoError(t, err)
	require.Equal(t, original, actual, "snapshot must not reseal or alter LastCR")
	shardRoot, err := cut.ShardTreeCertificate.ComputeCertificateHash(cut.LastCR.UC.InputRecord, cut.LastCR.UC.TRHash, cut.LastCR.UC.ShardConfHash, crypto.SHA256)
	require.NoError(t, err)
	computed, err := cut.UnicityTreeCertificate.EvalAuthPath(shardRoot, crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, cut.RootHash, computed)

	cut.RootHash[0] ^= 1
	cut.CommitQC.LedgerCommitInfo.Hash[0] ^= 1
	cut.LastCR.Technical.StatHash[0] ^= 1
	cut.LastCR.UC.ShardConfHash[0] ^= 1
	unchanged, err := types.Cbor.Marshal(last)
	require.NoError(t, err)
	require.Equal(t, original, unchanged)
	fresh, err := bt.ReadFrontierCutSnapshot(key.PartitionID, last.Shard)
	require.NoError(t, err)
	freshBytes, err := types.Cbor.Marshal(fresh)
	require.NoError(t, err)
	root.RootHash[0] ^= 1
	last.UC.ShardConfHash[0] ^= 1
	last.Technical.StatHash[0] ^= 1
	still, err := types.Cbor.Marshal(fresh)
	require.NoError(t, err)
	require.Equal(t, freshBytes, still, "later source mutation must not change the snapshot")
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestReviewFrontierCutRefusesInconsistentCommittedState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ExecutedBlock, types.PartitionShardID)
	}{
		{"missing QC", func(b *ExecutedBlock, _ types.PartitionShardID) { b.CommitQc = nil }},
		{"missing block", func(b *ExecutedBlock, _ types.PartitionShardID) { b.BlockData = nil }},
		{"missing LastCR", func(b *ExecutedBlock, k types.PartitionShardID) { b.ShardState.States[k].LastCR = nil }},
		{"missing IR", func(b *ExecutedBlock, k types.PartitionShardID) { b.ShardState.States[k].IR = nil }},
		{"committed round mismatch", func(b *ExecutedBlock, _ types.PartitionShardID) { b.BlockData.Round++ }},
		{"epoch mismatch", func(b *ExecutedBlock, _ types.PartitionShardID) { b.BlockData.Epoch++ }},
		{"root mismatch", func(b *ExecutedBlock, _ types.PartitionShardID) { b.RootHash = bytes.Repeat([]byte{9}, 32) }},
		{"algorithm mismatch", func(b *ExecutedBlock, _ types.PartitionShardID) { b.HashAlgo = crypto.SHA512 }},
		{"assignment mismatch", func(b *ExecutedBlock, k types.PartitionShardID) { b.ShardState.States[k].TR.Round++ }},
		{"IR mismatch", func(b *ExecutedBlock, k types.PartitionShardID) {
			b.ShardState.States[k].IR = &types.InputRecord{Version: 1, RoundNumber: 1}
		}},
		{"configuration mismatch", func(b *ExecutedBlock, k types.PartitionShardID) {
			b.ShardState.States[k].ShardConfHash = bytes.Repeat([]byte{9}, 32)
		}},
		{"TR hash mismatch", func(b *ExecutedBlock, k types.PartitionShardID) {
			b.ShardState.States[k].LastCR.UC.TRHash = bytes.Repeat([]byte{9}, 32)
		}},
		{"large leaf field", func(b *ExecutedBlock, k types.PartitionShardID) {
			b.ShardState.States[k].IR = &types.InputRecord{Version: 1, Hash: make([]byte, frontierMaxFieldBytes+1)}
		}},
		{"too many leaves", func(b *ExecutedBlock, _ types.PartitionShardID) {
			for n := 0; n <= frontierMaxCollectionSize; n++ {
				b.ShardState.States[types.PartitionShardID{PartitionID: types.PartitionID(n + 10)}] = nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bt, root, key, path := reviewCutTree(t)
			shard := root.ShardState.States[key].ShardID
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			tc.change(root, key)
			cut, err := bt.ReadFrontierCutSnapshot(key.PartitionID, shard)
			require.Error(t, err)
			require.Nil(t, cut)
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestReviewFrontierCutIgnoresPendingBlocksAndUnrelatedHistory(t *testing.T) {
	bt, root, key, _ := reviewCutTree(t)
	si := root.ShardState.States[key]
	// Neither pending blocks nor fee/stat history are proof inputs.
	bt.roundToNode[1000] = &node{data: &ExecutedBlock{}}
	si.Fees = make(map[string]uint64, frontierMaxCollectionSize+1)
	for n := 0; n <= frontierMaxCollectionSize; n++ {
		si.Fees[string(rune(n))] = uint64(n)
	}
	cut, err := bt.ReadFrontierCutSnapshot(key.PartitionID, si.ShardID)
	require.NoError(t, err)
	require.EqualValues(t, 6, cut.RootRound)
}

// A profile-2 root commits its handoff control record in the unicity tree. The cut snapshot must rebuild the
// same tree, or no replacement validator can ever obtain a cut from such a root (found by the H3 lane, #350).
func TestReviewFrontierCutSnapshotCarriesTheHandoffControlLeaf(t *testing.T) {
	control := &evmroot.ControlState{Network: 5, Epoch: 1, Attempt: 1, Phase: "committed", OrderedRound: 3,
		PredecessorBodyID: bytes.Repeat([]byte{1}, 32), RecordBytes: []byte{2, 3}, PreviousDigest: bytes.Repeat([]byte{4}, 32), FrozenParent: bytes.Repeat([]byte{5}, 32)}
	bt, root, key, _ := reviewCutTreeWithControl(t, control)
	last := root.ShardState.States[key].LastCR
	cut, err := bt.ReadFrontierCutSnapshot(key.PartitionID, last.Shard)
	require.NoError(t, err)
	shardRoot, err := cut.ShardTreeCertificate.ComputeCertificateHash(cut.LastCR.UC.InputRecord, cut.LastCR.UC.TRHash, cut.LastCR.UC.ShardConfHash, crypto.SHA256)
	require.NoError(t, err)
	computed, err := cut.UnicityTreeCertificate.EvalAuthPath(shardRoot, crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, []byte(root.RootHash), []byte(computed), "the membership path must reach the stored root that includes the control leaf")

	control.RecordBytes[0] ^= 0xff
	again, err := bt.ReadFrontierCutSnapshot(key.PartitionID, last.Shard)
	require.ErrorContains(t, err, "does not match stored root", "a control record that no longer matches the stored root is refused, not papered over")
	require.Nil(t, again)
}
