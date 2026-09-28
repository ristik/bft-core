package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestHandoffCheckpointRefusalGuards(t *testing.T) {
	record := evmroot.OrderedHandoffRecord{Network: 1, Epoch: 1, OrderedRound: 4, Kind: "commit",
		PredecessorBodyID: bytes.Repeat([]byte{1}, 32), NextBodyID: bytes.Repeat([]byte{2}, 32),
		FrozenID: bytes.Repeat([]byte{3}, 32), SuccessorTRHash: bytes.Repeat([]byte{4}, 32)}
	control := &evmroot.ControlState{Phase: "committed", RecordBytes: record.Bytes()}
	base := &ExecutedBlock{BlockData: &rctypes.BlockData{Version: 2, Epoch: 1, Round: 4},
		CommitQc: &rctypes.QuorumCert{}, ShardState: ShardStates{States: map[types.PartitionShardID]*ShardInfo{}, Control: control}}
	positive := &BlockTree{root: newNode(base)}
	_, _, gotRecord, err := positive.HandoffCheckpoint()
	require.NoError(t, err)
	require.Equal(t, "commit", gotRecord.Kind)
	check := func(t *testing.T, root *ExecutedBlock) {
		t.Helper()
		bt := &BlockTree{root: newNode(root)}
		_, _, _, err := bt.HandoffCheckpoint()
		require.Error(t, err)
	}
	check(t, nil)
	for _, tc := range []struct {
		name   string
		change func(*ExecutedBlock)
	}{
		{"missing control", func(b *ExecutedBlock) { b.ShardState.Control = nil }},
		{"prepared control", func(b *ExecutedBlock) { b.ShardState.Control.Phase = "prepared" }},
		{"missing commit QC", func(b *ExecutedBlock) { b.CommitQc = nil }},
		{"invalid record", func(b *ExecutedBlock) { b.ShardState.Control.RecordBytes = []byte{1} }},
		{"wrong record kind", func(b *ExecutedBlock) {
			r := record
			r.Kind = "abort"
			b.ShardState.Control.RecordBytes = r.Bytes()
		}},
		{"invalid shard tree", func(b *ExecutedBlock) {
			b.ShardState.States = map[types.PartitionShardID]*ShardInfo{
				{PartitionID: evmroot.D4ControlPartition}: {PartitionID: evmroot.D4ControlPartition},
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := *base
			c := *control
			b.ShardState.Control = &c
			tc.change(&b)
			check(t, &b)
		})
	}
	legacy := &BlockStore{profile: ProfileLegacy, blockTree: &BlockTree{root: newNode(base)}}
	_, _, _, err = legacy.HandoffCheckpoint()
	require.ErrorIs(t, err, ErrNetworkProfile)
}
