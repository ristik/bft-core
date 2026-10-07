package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	abhex "github.com/unicitynetwork/bft-go-base/types/hex"
)

func emptyOrchestration() mockOrchestration {
	return mockOrchestration{shardConfigs: func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil
	}}
}

type testRecordAuthority struct{ predecessor []byte }

func (a testRecordAuthority) Predecessor() []byte {
	if len(a.predecessor) != 0 {
		return a.predecessor
	}
	return make([]byte, 32)
}
func (testRecordAuthority) CurrentRoot() []evmassign.RootMember { return []evmassign.RootMember{} }

func (testRecordAuthority) VerifyFreeze(evmroot.OrderedHandoffRecord, []byte) ([]byte, error) {
	return bytes.Repeat([]byte{0x42}, 32), nil
}
func (testRecordAuthority) VerifyAbort(evmroot.OrderedHandoffRecord, []byte) error { return nil }

func profileStore(t *testing.T) *BlockStore {
	t.Helper()
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(crypto.SHA256, db, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	s.handoffAuth = testRecordAuthority{}
	return s
}

func installTestFrozenShard(t *testing.T, s *BlockStore, parent []byte) {
	t.Helper()
	key := []byte{0x3, 0x24, 0x8b, 0x61, 0x68, 0x51, 0xac, 0x6e, 0x43, 0x7e, 0xc2, 0x4e, 0xcc, 0x21, 0x9e, 0x5b, 0x42, 0x43, 0xdf, 0xa5, 0xdb, 0xdb, 0x8, 0xce, 0xa6, 0x48, 0x3a, 0xc9, 0xe0, 0xdc, 0x6b, 0x55, 0xcd}
	conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8,
		Validators: []*types.NodeInfo{{NodeID: "n", SigKey: key, Stake: 1}}}
	si, err := NewShardInfo(conf, crypto.SHA256)
	require.NoError(t, err)
	si.IR.BlockHash = bytes.Clone(parent)
	shard := types.PartitionShardID{PartitionID: conf.PartitionID, ShardID: conf.ShardID.Key()}
	s.orchestration = mockOrchestration{shardConfigs: func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{shard: conf}, nil
	}}
	root := s.blockTree.Root()
	root.ShardState.States[shard] = si
	tree, _, err := root.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	root.RootHash = tree.RootHash()
	if root.CommitQc != nil && root.CommitQc.LedgerCommitInfo != nil {
		root.CommitQc.LedgerCommitInfo.Hash = root.RootHash
	}
	require.NoError(t, s.storage.WriteBlock(root, true))
}

func installTestAggregatorShards(t *testing.T, s *BlockStore) [2]types.PartitionShardID {
	t.Helper()
	left, right := (types.ShardID{}).Split()
	ids := [2]types.ShardID{left, right}
	var keys [2]types.PartitionShardID
	configs, err := s.orchestration.ShardConfigs(1)
	require.NoError(t, err)
	evmKey := configs[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}].Validators[0].SigKey
	root := s.blockTree.Root()
	for i, id := range ids {
		conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, ShardID: id,
			Validators: []*types.NodeInfo{{NodeID: "n", SigKey: evmKey, Stake: 1}}}
		key := types.PartitionShardID{PartitionID: 9, ShardID: id.Key()}
		si, err := NewShardInfo(conf, crypto.SHA256)
		require.NoError(t, err)
		si.IR.BlockHash = bytes.Repeat([]byte{byte(i + 10)}, 32)
		root.ShardState.States[key] = si
		configs[key] = conf
		keys[i] = key
	}
	s.orchestration = mockOrchestration{shardConfigs: func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return configs, nil
	}}
	tree, _, err := root.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	root.RootHash = tree.RootHash()
	if root.CommitQc != nil && root.CommitQc.LedgerCommitInfo != nil {
		root.CommitQc.LedgerCommitInfo.Hash = root.RootHash
	}
	require.NoError(t, s.storage.WriteBlock(root, true))
	return keys
}

func TestFrozenEVMShardSelectionRejectsIsolatedMutations(t *testing.T) {
	parent := bytes.Repeat([]byte{0x42}, 32)
	evm := types.PartitionShardID{PartitionID: 8}
	agg := types.PartitionShardID{PartitionID: 9}
	other := types.PartitionShardID{PartitionID: 10}
	base := func() (ShardStates, map[types.PartitionShardID]*types.PartitionDescriptionRecord) {
		return ShardStates{States: map[types.PartitionShardID]*ShardInfo{
				evm:   {IR: &types.InputRecord{BlockHash: bytes.Clone(parent)}},
				agg:   {IR: &types.InputRecord{BlockHash: bytes.Repeat([]byte{1}, 32)}},
				other: {IR: &types.InputRecord{BlockHash: bytes.Repeat([]byte{2}, 32)}},
			}}, map[types.PartitionShardID]*types.PartitionDescriptionRecord{
				evm: {PartitionTypeID: 8}, agg: {PartitionTypeID: 9}, other: {PartitionTypeID: 9},
			}
	}
	state, configs := base()
	key, err := frozenShard(state, configs, parent)
	require.NoError(t, err)
	require.Equal(t, evm, key)

	t.Run("wrong shard", func(t *testing.T) {
		state, configs := base()
		state.States[evm].IR.BlockHash = bytes.Repeat([]byte{3}, 32)
		state.States[agg].IR.BlockHash = bytes.Clone(parent)
		_, err := frozenShard(state, configs, parent)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("ambiguous EVM", func(t *testing.T) {
		state, configs := base()
		state.States[other].IR.BlockHash = bytes.Clone(parent)
		configs[other].PartitionTypeID = 8
		_, err := frozenShard(state, configs, parent)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("EVM and aggregator collide", func(t *testing.T) {
		state, configs := base()
		state.States[agg].IR.BlockHash = bytes.Clone(parent)
		selected, err := frozenShard(state, configs, parent)
		require.NoError(t, err)
		require.Equal(t, evm, selected)
	})
}

func record(kind string, round, activation uint64, frozen, body, tr []byte) []byte {
	return (evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: 0, OrderedRound: round,
		PredecessorBodyID: make([]byte, 32), FrozenID: frozen, NextBodyID: body,
		ActivationRound: activation, SuccessorTRHash: tr, Kind: kind}).Bytes()
}

func addProfileBlock(t *testing.T, s *BlockStore, round uint64, records [][]byte) *ExecutedBlock {
	t.Helper()
	parent, err := s.Block(round - 1)
	require.NoError(t, err)
	block := &rctypes.BlockData{Version: 2, Round: round, Epoch: 1, Payload: &rctypes.Payload{Version: 2, HandoffRecords: records},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}
	_, err = s.Add(block, nil)
	require.NoError(t, err)
	added, err := s.Block(round)
	require.NoError(t, err)
	return added
}

func TestOrderedFreezeStopsOnlyFrozenShardAndAbortReopensIt(t *testing.T) {
	s := profileStore(t)
	frozenParent := bytes.Repeat([]byte{0x42}, 32)
	installTestFrozenShard(t, s, frozenParent)
	root := s.blockTree.Root()
	rootShard := types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}
	aggregator := types.PartitionShardID{PartitionID: 9, ShardID: (types.ShardID{}).Key()}
	conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9,
		Validators: []*types.NodeInfo{{NodeID: "n", SigKey: []byte{0x3, 0x24, 0x8b, 0x61, 0x68, 0x51, 0xac, 0x6e, 0x43, 0x7e, 0xc2, 0x4e, 0xcc, 0x21, 0x9e, 0x5b, 0x42, 0x43, 0xdf, 0xa5, 0xdb, 0xdb, 0x8, 0xce, 0xa6, 0x48, 0x3a, 0xc9, 0xe0, 0xdc, 0x6b, 0x55, 0xcd}, Stake: 1}}}
	aggregatorState, err := NewShardInfo(conf, crypto.SHA256)
	require.NoError(t, err)
	root.ShardState.States[aggregator] = aggregatorState
	previousOrchestration := s.orchestration
	s.orchestration = mockOrchestration{shardConfigs: func(round uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		confs, err := previousOrchestration.ShardConfigs(round)
		confs[aggregator] = conf
		return confs, err
	}}
	tree, _, err := root.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	root.RootHash = tree.RootHash()
	require.NoError(t, s.storage.WriteBlock(root, true))

	zero := make([]byte, 32)
	body, frozen := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	request := func(round uint64, partition types.PartitionID, records [][]byte) error {
		parent, err := s.Block(round - 1)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: round, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: partition}}, HandoffRecords: records},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = s.Add(block, mockIRVerifier{verify: func(_ uint64, _ *rctypes.IRChangeReq) (*types.InputRecord, error) {
			return &types.InputRecord{Version: 1, RoundNumber: round, BlockHash: bytes.Repeat([]byte{byte(round)}, 32)}, nil
		}})
		return err
	}
	require.ErrorIs(t, request(3, rootShard.PartitionID, [][]byte{record("freeze", 3, 7, frozen, body, zero)}), ErrHandoffFrozen,
		"the Freeze block itself must refuse an EVM certification")
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	require.ErrorIs(t, request(4, rootShard.PartitionID, nil), ErrHandoffFrozen)
	require.ErrorIs(t, request(4, evmroot.D4ControlPartition, nil), rctypes.ErrControlPartition)
	freezeParent, err := s.Block(3)
	require.NoError(t, err)
	_, err = freezeParent.Extend(&rctypes.BlockData{Version: 2, Epoch: 1, Round: 4,
		Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: evmroot.D4ControlPartition}}}},
		nil, s.orchestration, crypto.SHA256, logger.New(t))
	require.ErrorIs(t, err, ErrHandoffRecord, "direct execution must also reject a forged control request")
	require.NoError(t, request(4, aggregator.PartitionID, nil), "aggregator certification remains live")
	added, err := s.Block(4)
	require.NoError(t, err)
	require.True(t, bytes.Equal(frozenParent, added.ShardState.States[rootShard].IR.BlockHash))
	addProfileBlock(t, s, 5, [][]byte{record("abort", 5, 7, frozen, body, zero)})
	require.NoError(t, request(6, rootShard.PartitionID, nil), "Abort lifts the EVM freeze")
}

func TestCommitRequiresFrozenParentAtCommittedTip(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	zero := make([]byte, 32)
	body, frozen := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	root := s.blockTree.Root()
	rootShard := root.ShardState.States[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}]
	changedIR := *rootShard.IR
	changedIR.BlockHash = bytes.Repeat([]byte{0x43}, 32)
	rootShard.IR = &changedIR
	parent, err := s.Block(3)
	require.NoError(t, err)
	block := &rctypes.BlockData{Version: 2, Round: 4, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{record("commit", 4, 7, frozen, body, bytes.Repeat([]byte{3}, 32))}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 3, Epoch: 1, CurrentRootHash: parent.RootHash}}}
	_, err = s.Add(block, nil)
	require.ErrorIs(t, err, ErrHandoffRecord)
}

func TestFrozenShardQueriesFollowTheCommittedBranch(t *testing.T) {
	s := profileStore(t)
	parent := bytes.Repeat([]byte{0x42}, 32)
	installTestFrozenShard(t, s, parent)
	other := bytes.Repeat([]byte{0x43}, 32)
	require.True(t, s.CommittedFrozenParent(parent))
	require.False(t, s.CommittedFrozenParent(other))
	_, active, err := s.FrozenShardAt(1)
	require.NoError(t, err)
	require.False(t, active)
	_, _, err = s.FrozenShardAt(99)
	require.Error(t, err)
	s.profile = ProfileLegacy
	require.False(t, s.CommittedFrozenParent(parent))
	_, active, err = s.FrozenShardAt(1)
	require.NoError(t, err)
	require.False(t, active)
	s.profile = ProfileHandoff
	zero := make([]byte, 32)
	body, frozen := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	key, active, err := s.FrozenShardAt(3)
	require.NoError(t, err)
	require.True(t, active)
	require.Equal(t, types.PartitionID(8), key.PartitionID)
	freeze, err := s.Block(3)
	require.NoError(t, err)
	freeze.ShardState.Control.FrozenParent = other
	_, active, err = s.FrozenShardAt(3)
	require.ErrorIs(t, err, ErrHandoffRecord)
	require.False(t, active)
	freeze.ShardState.Control = nil
	_, active, err = s.FrozenShardAt(3)
	require.NoError(t, err)
	require.False(t, active)
}

func TestHandoffControlLeafAndSuffix(t *testing.T) {
	require.Equal(t, evmroot.D4ControlPartition, rctypes.ControlPartition)
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	genesis, err := s.Block(1)
	require.NoError(t, err)
	require.NotNil(t, genesis.ShardState.Control)
	ut, _, err := genesis.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	path, err := ut.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	root, err := path.EvalAuthPath(genesis.ShardState.Control.Digest(), crypto.SHA256)
	require.NoError(t, err)
	require.True(t, bytes.Equal(genesis.RootHash, root))

	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	h := addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	require.Equal(t, "committed", h.ShardState.Control.Phase)
	for _, tc := range []struct {
		name     string
		records  [][]byte
		requests []*rctypes.IRChangeReq
	}{
		{"prepare", [][]byte{record("prepare", 5, 8, zero, body, zero)}, nil},
		{"freeze", [][]byte{record("freeze", 5, 8, frozen, body, zero)}, nil},
		{"commit", [][]byte{record("commit", 5, 8, frozen, body, tr)}, nil},
		{"abort", [][]byte{record("abort", 5, 8, frozen, body, zero)}, nil},
		{"unknown", [][]byte{{0x01}}, nil},
		{"request", nil, []*rctypes.IRChangeReq{{Partition: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := &rctypes.BlockData{Version: 2, Round: 5, Epoch: 1, Payload: &rctypes.Payload{Version: 2, HandoffRecords: tc.records, Requests: tc.requests},
				Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4, Epoch: 1}}}
			_, err := s.Add(block, nil)
			require.ErrorIs(t, err, ErrHandoffSuffix)
		})
	}
	suffix := addProfileBlock(t, s, 5, nil)
	require.True(t, bytes.Equal(h.RootHash, suffix.RootHash))
	require.Equal(t, h.ShardState.Control.Bytes(), suffix.ShardState.Control.Bytes())
	shards, err := toRecoveryShardInfo(suffix)
	require.NoError(t, err)
	checkpoint := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control, ShardInfo: shards,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
	committedRecord := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: 4,
		PredecessorBodyID: zero, FrozenID: frozen, NextBodyID: body,
		ActivationRound: 7, SuccessorTRHash: tr, Kind: "commit"}
	verified := evmroot.VerifiedHandoff{Record: committedRecord, Root: suffix.RootHash,
		ControlDigest: suffix.ShardState.Control.Digest(), CommitSealRound: 5, Epoch: 1}
	verifySnapshot := RecoveryHandoffSnapshot{Head: checkpoint, Orchestration: s.orchestration}
	require.NoError(t, verifySnapshot.VerifyHandoffSnapshot(verified))
	wrongRoot := verified
	wrongRoot.Root = bytes.Repeat([]byte{0x7f}, 32)
	require.Error(t, verifySnapshot.VerifyHandoffSnapshot(wrongRoot))
	recovered, err := NewRootBlock(checkpoint, crypto.SHA256, s.orchestration, ProfileHandoff)
	require.NoError(t, err)
	require.True(t, bytes.Equal(suffix.RootHash, recovered.RootHash))
	recoveryDB, err := NewBoltStorage(filepath.Join(t.TempDir(), "recovery.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = recoveryDB.Close() })
	recovery, err := NewFromState(crypto.SHA256, checkpoint, recoveryDB, s.orchestration, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	_, err = recovery.Add(&rctypes.BlockData{Version: 2, Round: 6, Epoch: 1, Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{record("abort", 6, 8, frozen, body, zero)}},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 5, Epoch: 1}}}, nil)
	require.ErrorIs(t, err, ErrHandoffSuffix)
	checkpoint.Control = nil
	_, err = NewRootBlock(checkpoint, crypto.SHA256, emptyOrchestration(), ProfileHandoff)
	require.ErrorIs(t, err, ErrNetworkProfile)
	checkpoint.Control = suffix.ShardState.Control
	checkpoint.CommitQc.LedgerCommitInfo.Hash = bytes.Repeat([]byte{8}, 32)
	_, err = NewRootBlock(checkpoint, crypto.SHA256, s.orchestration, ProfileHandoff)
	require.ErrorIs(t, err, ErrControlCheckpoint)
	checkpoint.CommitQc.LedgerCommitInfo.Hash = suffix.RootHash
	checkpoint.Control = &evmroot.ControlState{Network: 5, Epoch: 1, PredecessorBodyID: zero, Phase: "committed", OrderedRound: 4, RecordBytes: []byte{1}}
	_, err = NewRootBlock(checkpoint, crypto.SHA256, s.orchestration, ProfileHandoff)
	require.ErrorIs(t, err, ErrControlCheckpoint)
}

func TestRecoveryHandoffSnapshotUsesProductionShardTree(t *testing.T) {
	key := []byte{0x3, 0x24, 0x8b, 0x61, 0x68, 0x51, 0xac, 0x6e, 0x43, 0x7e, 0xc2, 0x4e, 0xcc, 0x21, 0x9e, 0x5b, 0x42, 0x43, 0xdf, 0xa5, 0xdb, 0xdb, 0x8, 0xce, 0xa6, 0x48, 0x3a, 0xc9, 0xe0, 0xdc, 0x6b, 0x55, 0xcd}
	conf := &types.PartitionDescriptionRecord{PartitionID: 7, Epoch: 1, Validators: []*types.NodeInfo{{NodeID: "n", SigKey: key, Stake: 1}}}
	si, err := NewShardInfo(conf, crypto.SHA256)
	require.NoError(t, err)
	shard := types.PartitionShardID{PartitionID: conf.PartitionID, ShardID: conf.ShardID.Key()}
	zero := make([]byte, 32)
	rec := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: 4, PredecessorBodyID: zero,
		FrozenID: bytes.Repeat([]byte{1}, 32), NextBodyID: bytes.Repeat([]byte{2}, 32),
		ActivationRound: 7, SuccessorTRHash: bytes.Repeat([]byte{3}, 32), Kind: "commit"}
	control := &evmroot.ControlState{Network: 5, Epoch: 1, OrderedRound: 4, PredecessorBodyID: zero,
		Phase: "committed", RecordBytes: rec.Bytes(), PreviousDigest: zero, FrozenParent: bytes.Repeat([]byte{4}, 32)}
	state := ShardStates{States: map[types.PartitionShardID]*ShardInfo{shard: si}, Control: control}
	tree, _, err := state.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	block := &ExecutedBlock{ShardState: state}
	info, err := toRecoveryShardInfo(block)
	require.NoError(t, err)
	head := &abdrc.CommittedBlock{Block: &rctypes.BlockData{Version: 2, Epoch: 1, Round: 4, Payload: &rctypes.Payload{Version: 2}},
		ShardInfo: info, Control: control, CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: tree.RootHash()}}}
	orchestration := mockOrchestration{shardConfigs: func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{shard: conf}, nil
	}}
	snapshot := RecoveryHandoffSnapshot{Head: head, Orchestration: orchestration}
	verified := evmroot.VerifiedHandoff{Record: rec, Root: tree.RootHash(), ControlDigest: control.Digest(), CommitSealRound: 4, Epoch: 1}
	require.NoError(t, snapshot.VerifyHandoffSnapshot(verified))
	head.ShardInfo[0].IRTR.Round++
	require.Error(t, snapshot.VerifyHandoffSnapshot(verified))
}

func TestInstallEpochAnchorFromRecoveryCheckpoint(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	zero := make([]byte, 32)
	body, frozen := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	tr, err := s.blockTree.Root().ShardState.States[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}].TR.Hash()
	require.NoError(t, err)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	h := addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	suffix := addProfileBlock(t, s, 5, nil)
	anchoredTR, err := suffix.ShardState.States[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}].TR.Hash()
	require.NoError(t, err)
	_, err = s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 5, ParentRoundNumber: 4, Epoch: 1},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 4, Epoch: 1, Hash: h.RootHash}})
	require.NoError(t, err)
	rec := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: 4, PredecessorBodyID: zero,
		FrozenID: frozen, NextBodyID: body, ActivationRound: 7, SuccessorTRHash: tr, Kind: "commit"}
	head := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
	head.ShardInfo, err = toRecoveryShardInfo(suffix)
	require.NoError(t, err)
	v := evmroot.VerifiedHandoff{RecordID: rec.ID(), Record: rec, Root: suffix.RootHash,
		ControlDigest: suffix.ShardState.Control.Digest(), OrderRound: 4, CommitSealRound: 5, Epoch: 1}
	g := evmroot.EpochGenesis{Network: 5, Epoch: 2, Start: 7, OrderedRound: 4, NextBodyID: body,
		RecordID: rec.ID(), Root: suffix.RootHash, ControlDigest: v.ControlDigest, FrozenID: frozen, SuccessorTRHash: tr}
	require.ErrorIs(t, s.AnchoredFrozenParent(anchoredTR, bytes.Repeat([]byte{0x42}, 32)), rctypes.ErrEpochAnchor)
	a, err := s.InstallEpochAnchor(head, v, g)
	require.NoError(t, err)
	require.NoError(t, s.AnchoredFrozenParent(anchoredTR, bytes.Repeat([]byte{0x42}, 32)))
	require.ErrorIs(t, s.AnchoredFrozenParent(anchoredTR, bytes.Repeat([]byte{0x43}, 32)), rctypes.ErrEpochAnchor)
	require.ErrorIs(t, s.AnchoredFrozenParent(anchoredTR, []byte{1}), rctypes.ErrEpochAnchor)
	require.ErrorIs(t, s.AnchoredFrozenParent(bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x42}, 32)), rctypes.ErrEpochAnchor)
	anchoredRoot := s.blockTree.Root()
	shardKey := types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}
	anchoredShard := anchoredRoot.ShardState.States[shardKey]
	anchoredRoot.ShardState.States[shardKey] = nil
	require.ErrorIs(t, s.AnchoredFrozenParent(anchoredTR, bytes.Repeat([]byte{0x42}, 32)), rctypes.ErrEpochAnchor)
	anchoredRoot.ShardState.States[shardKey] = anchoredShard
	duplicateKey := types.PartitionShardID{PartitionID: 9, ShardID: (types.ShardID{}).Key()}
	anchoredRoot.ShardState.States[duplicateKey] = anchoredShard
	require.ErrorIs(t, s.AnchoredFrozenParent(anchoredTR, bytes.Repeat([]byte{0x42}, 32)), rctypes.ErrEpochAnchor)
	delete(anchoredRoot.ShardState.States, duplicateKey)
	require.EqualValues(t, 6, a.Slot)
	require.True(t, isEpochAnchorRoot(s.blockTree.Root()))
	reloaded, err := New(crypto.SHA256, s.storage, s.orchestration, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	require.True(t, isEpochAnchorRoot(reloaded.blockTree.Root()))
	anchorState, err := reloaded.GetState()
	require.NoError(t, err)
	require.Equal(t, a, anchorState.CommittedHead.Anchor)
	require.NoError(t, reloaded.VerifyRecoveryAnchor(anchorState.CommittedHead))
	corrupt := *anchorState.CommittedHead
	controlCopy := *corrupt.Control
	controlCopy.PreviousDigest = bytes.Repeat([]byte{9}, 32)
	corrupt.Control = &controlCopy
	require.ErrorIs(t, reloaded.VerifyRecoveryAnchor(&corrupt), ErrControlCheckpoint)
	first := &rctypes.BlockData{Version: 2, Round: 7, Epoch: 2, Payload: &rctypes.Payload{Version: 2}, Anchor: a}
	_, err = reloaded.Add(first, nil)
	require.NoError(t, err)
	child, err := reloaded.Block(7)
	require.NoError(t, err)
	require.Equal(t, "idle", child.ShardState.Control.Phase)
	require.EqualValues(t, 2, child.ShardState.Control.Epoch)
	require.False(t, bytes.Equal(child.RootHash, a.StateRoot))
	recoveredAnchor, err := reloaded.NewFromAnchorState(anchorState.CommittedHead)
	require.NoError(t, err)
	require.Equal(t, a, recoveredAnchor.RootAnchor())
	_, err = recoveredAnchor.Block(7)
	require.Error(t, err)
}

func TestTwoConsecutiveRootHandoffsRestartAtEachPhase(t *testing.T) {
	s := profileStore(t)
	parent := bytes.Repeat([]byte{0x42}, 32)
	installTestFrozenShard(t, s, parent)
	aggregators := installTestAggregatorShards(t, s)
	shardIDs := [2]types.ShardID{}
	shardIDs[0], shardIDs[1] = (types.ShardID{}).Split()
	assertAggregators := func(block *ExecutedBlock, round uint64) {
		t.Helper()
		for _, key := range aggregators {
			require.Equal(t, bytes.Repeat([]byte{byte(round)}, 32), []byte(block.ShardState.States[key].IR.BlockHash))
		}
		certs, err := block.GenerateCertificates(&rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{
			Version: 1, NetworkID: 5, RootChainRoundNumber: round, Epoch: block.BlockData.Epoch, Hash: block.RootHash}})
		require.NoError(t, err)
		certified := map[string]bool{}
		for _, cert := range certs {
			if cert.Partition != 9 {
				continue
			}
			certified[cert.Shard.Key()] = true
			require.Equal(t, round, cert.UC.InputRecord.RoundNumber)
			require.Equal(t, block.BlockData.Epoch, cert.UC.UnicitySeal.Epoch)
			key := types.PartitionShardID{PartitionID: cert.Partition, ShardID: cert.Shard.Key()}
			require.Equal(t, block.ShardState.States[key].TR.Leader, cert.Technical.Leader,
				"root round/leader changes must not replace the shard TR authorizer")
		}
		for _, key := range aggregators {
			require.True(t, certified[key.ShardID], "aggregator shard must receive a certificate")
		}
	}
	predecessor := make([]byte, 32)
	bodies := [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}
	restart := func() {
		var err error
		s, err = New(crypto.SHA256, s.storage, s.orchestration, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		s.handoffAuth = testRecordAuthority{predecessor: predecessor}
	}
	add := func(epoch, round uint64, record evmroot.OrderedHandoffRecord) *ExecutedBlock {
		prior, err := s.Block(round - 1)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Epoch: epoch, Round: round,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{record.Bytes()},
				Requests: []*rctypes.IRChangeReq{{Partition: 9, Shard: shardIDs[0]}, {Partition: 9, Shard: shardIDs[1]}}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1,
				Epoch: epoch, CurrentRootHash: prior.RootHash}}}
		_, err = s.Add(block, mockIRVerifier{verify: func(_ uint64, _ *rctypes.IRChangeReq) (*types.InputRecord, error) {
			return &types.InputRecord{Version: 1, RoundNumber: round, BlockHash: bytes.Repeat([]byte{byte(round)}, 32)}, nil
		}})
		require.NoError(t, err)
		added, err := s.Block(round)
		require.NoError(t, err)
		assertAggregators(added, round)
		return added
	}
	refuseEVM := func(epoch, round uint64, want error) {
		t.Helper()
		prior, err := s.Block(round - 1)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Epoch: epoch, Round: round,
			Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: 8}}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1,
				Epoch: epoch, CurrentRootHash: prior.RootHash}}}
		_, err = s.Add(block, mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) {
			return &types.InputRecord{Version: 1, BlockHash: bytes.Repeat([]byte{0x44}, 32)}, nil
		}})
		require.ErrorIs(t, err, want)
	}
	for epoch := uint64(1); epoch <= 2; epoch++ {
		base := uint64(2)
		if epoch == 2 {
			base = 8
		}
		body := bodies[epoch-1]
		frozen := bytes.Repeat([]byte{byte(epoch + 2)}, 32)
		tr, err := s.blockTree.Root().ShardState.States[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}].TR.Hash()
		require.NoError(t, err)
		makeRecord := func(kind string, round uint64) evmroot.OrderedHandoffRecord {
			return evmroot.OrderedHandoffRecord{Network: 5, Epoch: epoch, OrderedRound: round,
				PredecessorBodyID: predecessor, NextBodyID: body, FrozenID: frozen,
				ActivationRound: base + 5, SuccessorTRHash: tr, Kind: kind}
		}
		prepare := makeRecord("prepare", base)
		prepare.FrozenID = make([]byte, 32)
		prepare.SuccessorTRHash = make([]byte, 32)
		add(epoch, base, prepare)
		restart()
		require.Equal(t, "prepared", mustBlock(t, s, base).ShardState.Control.Phase)
		assertAggregators(mustBlock(t, s, base), base)
		freeze := makeRecord("freeze", base+1)
		freeze.SuccessorTRHash = make([]byte, 32)
		add(epoch, base+1, freeze)
		restart()
		require.Equal(t, "endorsed", mustBlock(t, s, base+1).ShardState.Control.Phase)
		assertAggregators(mustBlock(t, s, base+1), base+1)
		refuseEVM(epoch, base+2, ErrHandoffFrozen)
		commit := makeRecord("commit", base+2)
		h := add(epoch, base+2, commit)
		restart()
		require.Equal(t, "committed", mustBlock(t, s, base+2).ShardState.Control.Phase)
		assertAggregators(mustBlock(t, s, base+2), base+2)
		refuseEVM(epoch, base+3, ErrHandoffSuffix)
		// Certify H, install the successor anchor, then restart before its
		// first ordinary block and the next changed committee's handoff.
		prior := mustBlock(t, s, base+2)
		_, err = s.Add(&rctypes.BlockData{Version: 2, Epoch: epoch, Round: base + 3,
			Payload: &rctypes.Payload{Version: 2}, Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{
				RoundNumber: base + 2, Epoch: epoch, CurrentRootHash: prior.RootHash}}}, nil)
		require.NoError(t, err)
		suffix := mustBlock(t, s, base+3)
		_, err = s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{
			RoundNumber: base + 3, ParentRoundNumber: base + 2, Epoch: epoch},
			LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: base + 2,
				Epoch: epoch, Hash: h.RootHash}})
		require.NoError(t, err)
		checkpoint := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control,
			CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
		checkpoint.ShardInfo, err = toRecoveryShardInfo(suffix)
		require.NoError(t, err)
		verified := evmroot.VerifiedHandoff{RecordID: commit.ID(), Record: commit, Root: suffix.RootHash,
			ControlDigest: suffix.ShardState.Control.Digest(), OrderRound: base + 2,
			CommitSealRound: base + 3, Epoch: epoch}
		genesis := evmroot.EpochGenesis{Network: 5, Epoch: epoch + 1, Start: base + 5,
			OrderedRound: base + 2, NextBodyID: body, RecordID: commit.ID(), Root: suffix.RootHash,
			ControlDigest: verified.ControlDigest, FrozenID: frozen, SuccessorTRHash: tr}
		anchor, err := s.InstallEpochAnchor(checkpoint, verified, genesis)
		require.NoError(t, err)
		predecessor = body
		restart()
		first, err := s.Add(&rctypes.BlockData{Version: 2, Epoch: epoch + 1, Round: genesis.Start,
			Anchor: anchor, Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{
				{Partition: 9, Shard: shardIDs[0]}, {Partition: 9, Shard: shardIDs[1]},
			}}}, mockIRVerifier{verify: func(_ uint64, _ *rctypes.IRChangeReq) (*types.InputRecord, error) {
			return &types.InputRecord{Version: 1, RoundNumber: genesis.Start,
				BlockHash: bytes.Repeat([]byte{byte(genesis.Start)}, 32)}, nil
		}})
		require.NoError(t, err)
		require.NotEmpty(t, first)
		restart()
		require.Equal(t, "idle", mustBlock(t, s, genesis.Start).ShardState.Control.Phase)
		assertAggregators(mustBlock(t, s, genesis.Start), genesis.Start)
	}
}

func mustBlock(t *testing.T, s *BlockStore, round uint64) *ExecutedBlock {
	t.Helper()
	block, err := s.Block(round)
	require.NoError(t, err)
	return block
}

func TestProfileSwitchRejectsUnsupported(t *testing.T) {
	_, err := NewGenesisBlock(5, crypto.SHA256, 99)
	require.True(t, errors.Is(err, ErrNetworkProfile))
	legacy, err := NewGenesisBlock(5, crypto.SHA256)
	require.NoError(t, err)
	require.Nil(t, legacy.RootHash)
	require.Nil(t, legacy.ShardState.Control)
	blockHash, err := legacy.BlockData.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "ada66f518cd7640e9560875c994631dc25e1474c6fbab41e26476ebb9dc30934", hex.EncodeToString(blockHash))
	encoded, err := types.Cbor.Marshal(legacy)
	require.NoError(t, err)
	digest := sha256.Sum256(encoded)
	require.Equal(t, "886683a3b83db9020f43bee8e9b49d3926cef0bff52048fe7a77dc9c5b61ed60", hex.EncodeToString(digest[:]))
}

func TestAbortRequiresPreparedOrEndorsedPhase(t *testing.T) {
	zero := make([]byte, 32)
	body := bytes.Repeat([]byte{1}, 32)
	preparedRecord := record("prepare", 2, 7, zero, body, zero)
	control := &evmroot.ControlState{Network: 5, Epoch: 1, PredecessorBodyID: zero,
		Attempt: 0, Phase: "frozen", OrderedRound: 2, RecordBytes: preparedRecord}
	_, err := applyHandoffRecord(control, record("abort", 3, 7, zero, body, zero),
		5, 1, 3, testRecordAuthority{}, nil)
	require.ErrorIs(t, err, ErrHandoffRecord)
}

func TestCommittedAbortReplayRetainsPhaseAndResumesEVMRequests(t *testing.T) {
	s := profileStore(t)
	frozenParent := bytes.Repeat([]byte{0x42}, 32)
	installTestFrozenShard(t, s, frozenParent)
	zero, body := make([]byte, 32), bytes.Repeat([]byte{0x31}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	abort := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: 0,
		OrderedRound: 3, ActivationRound: 7, PredecessorBodyID: zero,
		NextBodyID: body, FrozenID: zero, SuccessorTRHash: zero, Kind: "abort"}
	proof, err := (AbortAuthorization{Version: 1, Signatures: map[string]abhex.Bytes{"old-a": {1}}}).Bytes()
	require.NoError(t, err)
	parent, err := s.Block(2)
	require.NoError(t, err)
	abortBlock := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{abort.Bytes(), proof},
			Requests: []*rctypes.IRChangeReq{{Partition: 8}}},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
	_, err = s.Add(abortBlock, mockIRVerifier{verify: func(round uint64, _ *rctypes.IRChangeReq) (*types.InputRecord, error) {
		return &types.InputRecord{Version: 1, RoundNumber: round, BlockHash: bytes.Repeat([]byte{3}, 32)}, nil
	}})
	require.NoError(t, err, "an Abort block may itself admit EVM work after its ordered transition")
	aborted, err := s.Block(3)
	require.NoError(t, err)
	require.Equal(t, "aborted", aborted.ShardState.Control.Phase)
	checkpoint := &abdrc.CommittedBlock{Block: aborted.BlockData, Control: aborted.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: bytes.Clone(aborted.RootHash)}}}
	checkpoint.ShardInfo, err = toRecoveryShardInfo(aborted)
	require.NoError(t, err)
	restarted, err := NewFromState(crypto.SHA256, checkpoint, s.GetDB(), s.orchestration, logger.New(t), ProfileHandoff)
	require.NoError(t, err, "recovery after durable Abort retains the authenticated phase")
	root := restarted.blockTree.Root()
	require.Equal(t, "aborted", root.ShardState.Control.Phase)
	block := &rctypes.BlockData{Version: 2, Round: 4, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: 8}}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 3, Epoch: 1, CurrentRootHash: root.RootHash}}}
	_, err = restarted.Add(block, mockIRVerifier{verify: func(round uint64, _ *rctypes.IRChangeReq) (*types.InputRecord, error) {
		return &types.InputRecord{Version: 1, RoundNumber: round, BlockHash: bytes.Repeat([]byte{4}, 32)}, nil
	}})
	require.NoError(t, err, "the replayed Abort releases ordinary EVM certification")
}

func TestLegacyAddRejectsProfileTwoVersion(t *testing.T) {
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "legacy.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(crypto.SHA256, db, emptyOrchestration(), logger.New(t))
	require.NoError(t, err)
	parent, err := s.Block(1)
	require.NoError(t, err)
	for _, blockVersion := range []types.Version{1, 2} {
		block := &rctypes.BlockData{Version: blockVersion, Round: 2, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err := s.Add(block, nil)
		require.ErrorIs(t, err, ErrNetworkProfile)
	}
}

func TestCommittedHandoffSuffixClearsPendingChanges(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	h := addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	checkpoint := &abdrc.CommittedBlock{Block: h.BlockData, Control: h.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: h.RootHash}}}
	var err error
	checkpoint.ShardInfo, err = toRecoveryShardInfo(h)
	require.NoError(t, err)
	recovered, err := NewFromState(crypto.SHA256, checkpoint, s.GetDB(), s.orchestration, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	suffix := addProfileBlock(t, recovered, 5, nil)
	marker := types.PartitionShardID{PartitionID: 99}
	recovered.blockTree.Root().ShardState.Changed[marker] = struct{}{}
	suffix.ShardState.Changed[marker] = struct{}{}
	qc := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 6, ParentRoundNumber: 5, Epoch: 1},
		LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}
	ucs, err := recovered.blockTree.Commit(qc)
	require.NoError(t, err)
	require.Empty(t, ucs)
	require.Empty(t, recovered.blockTree.Root().ShardState.Changed)
}

func TestProfileOffNonemptyByteIdentity(t *testing.T) {
	key := []byte{0x3, 0x24, 0x8b, 0x61, 0x68, 0x51, 0xac, 0x6e, 0x43, 0x7e, 0xc2, 0x4e, 0xcc, 0x21, 0x9e, 0x5b, 0x42, 0x43, 0xdf, 0xa5, 0xdb, 0xdb, 0x8, 0xce, 0xa6, 0x48, 0x3a, 0xc9, 0xe0, 0xdc, 0x6b, 0x55, 0xcd}
	conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 7,
		Validators: []*types.NodeInfo{{NodeID: "n", SigKey: key, Stake: 1}}}
	si, err := NewShardInfo(conf, crypto.SHA256)
	require.NoError(t, err)
	shard := types.PartitionShardID{PartitionID: 7, ShardID: conf.ShardID.Key()}
	state := ShardStates{States: map[types.PartitionShardID]*ShardInfo{shard: si}, Changed: ShardSet{}}
	tree, _, err := state.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	proposal := &rctypes.BlockData{Version: 1, Author: "legacy", Round: 2, Epoch: 1, Timestamp: 2,
		Payload: &rctypes.Payload{Requests: []*rctypes.IRChangeReq{{Partition: 7, Shard: conf.ShardID}}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 1, Epoch: 1}}}
	executed := &ExecutedBlock{BlockData: proposal, HashAlgo: crypto.SHA256, RootHash: tree.RootHash(), ShardState: state}
	committed := *executed
	committed.CommitQc = &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 3, ParentRoundNumber: 2, Epoch: 1},
		LedgerCommitInfo: &types.UnicitySeal{Hash: tree.RootHash()}}
	goldens := []struct {
		name string
		v    any
		want string
	}{
		{"proposal", proposal, "48bac51b1dcafd07697880c90e6b579c2b760f1d0e021aadc1e046e7edb39f71"},
		{"shard-state", state, "2b8230b5f566ee8e1b5dbcb3e14d5d8bd1caf69e19ed7d4746c5bc64240eebeb"},
		{"tree-root", tree.RootHash(), "5377a9166bc43e6808b4eac7f4485c72796c37fe74c4963654c1fa33ed3955eb"},
		{"executed", executed, "9bd438fa25ea7e142c707e07296bef16e13897a7a4d6385c4758adf125dedb56"},
		{"committed", &committed, "0f8f05a198885b766c592c974bbd2f070bdb2fdf24445cc80ca0f5eb6518bd03"},
	}
	for _, g := range goldens {
		raw, err := types.Cbor.Marshal(g.v)
		require.NoError(t, err, g.name)
		digest := sha256.Sum256(raw)
		got := hex.EncodeToString(digest[:])
		require.Equal(t, g.want, got, g.name)
	}
}

func TestFourRootNodesRefusePayloadQCOnCommittedBranch(t *testing.T) {
	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	signers := map[string]abcrypto.Signer{}
	for _, id := range []string{"honest-1", "honest-2", "honest-3", "byzantine"} {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		signers[id] = signer
	}
	tb := testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
	require.Equal(t, uint64(3), tb.QuorumThreshold)
	for _, id := range []string{"honest-1", "honest-2", "honest-3"} {
		t.Run(id, func(t *testing.T) {
			s := profileStore(t)
			installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
			addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
			addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
			addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
			proposal := &rctypes.BlockData{Version: 2, Round: 5, Epoch: 1, Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{record("abort", 5, 8, frozen, body, zero)}},
				Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4, Epoch: 1}}}
			_, err := s.Add(proposal, nil)
			require.ErrorIs(t, err, ErrHandoffSuffix)
		})
	}
	message := []byte("payload vote after H")
	signature, err := signers["byzantine"].SignBytes(message)
	require.NoError(t, err)
	require.Error(t, tb.VerifyQuorumSignatures(message, map[string]abhex.Bytes{"byzantine": signature}))
}

func TestHandoffIsolatedGuards(t *testing.T) {
	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	t.Run("profile_requires_control", func(t *testing.T) {
		require.ErrorIs(t, checkProfile(ProfileHandoff, ShardStates{}), ErrNetworkProfile)
	})
	t.Run("record_order_round", func(t *testing.T) {
		_, err := applyHandoffRecord(initialControl(5), record("prepare", 3, 7, zero, body, zero), 5, 1, 2, testRecordAuthority{}, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("record_phase", func(t *testing.T) {
		_, err := applyHandoffRecord(initialControl(5), record("freeze", 2, 7, frozen, body, zero), 5, 1, 2, testRecordAuthority{}, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("one_live_attempt", func(t *testing.T) {
		prepared, err := applyHandoffRecord(initialControl(5), record("prepare", 2, 7, zero, body, zero), 5, 1, 2, testRecordAuthority{}, nil)
		require.NoError(t, err)
		_, err = applyHandoffRecord(prepared, record("prepare", 3, 7, zero, body, zero), 5, 1, 3, testRecordAuthority{}, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("terminal_outcome", func(t *testing.T) {
		prepared, err := applyHandoffRecord(initialControl(5), record("prepare", 2, 7, zero, body, zero), 5, 1, 2, testRecordAuthority{}, nil)
		require.NoError(t, err)
		prepared.FrozenParent = bytes.Repeat([]byte{0x42}, 32) // bound by the executor when it executes the Prepare
		frozenState, err := applyHandoffRecord(prepared, record("freeze", 3, 7, frozen, body, zero), 5, 1, 3, testRecordAuthority{}, nil)
		require.NoError(t, err)
		committed, err := applyHandoffRecord(frozenState, record("commit", 4, 7, frozen, body, tr), 5, 1, 4, testRecordAuthority{}, nil)
		require.NoError(t, err)
		_, err = applyHandoffRecord(committed, record("abort", 5, 8, frozen, body, zero), 5, 1, 5, testRecordAuthority{}, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("control_leaf_in_tree", func(t *testing.T) {
		g, err := NewGenesisBlock(5, crypto.SHA256, ProfileHandoff)
		require.NoError(t, err)
		forged := *g
		forged.ShardState.Control = nil
		require.ErrorIs(t, checkStoredRoot(&forged, ProfileHandoff), ErrNetworkProfile)
	})
	t.Run("stored_root_bound", func(t *testing.T) {
		g, err := NewGenesisBlock(5, crypto.SHA256, ProfileHandoff)
		require.NoError(t, err)
		forged := *g
		forged.RootHash = bytes.Repeat([]byte{9}, 32)
		require.ErrorIs(t, checkStoredRoot(&forged, ProfileHandoff), ErrNetworkProfile)
	})
	t.Run("stored_suffix_identity", func(t *testing.T) {
		s := profileStore(t)
		installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
		addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
		addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
		h := addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
		suffix := addProfileBlock(t, s, 5, nil)
		forged := *suffix
		forged.RootHash = bytes.Repeat([]byte{9}, 32)
		require.ErrorIs(t, checkStoredSuffix(h, &forged), ErrHandoffSuffix)
	})
	t.Run("executor_rejects_suffix_payload", func(t *testing.T) {
		s := profileStore(t)
		installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
		addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
		addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
		h := addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
		block := &rctypes.BlockData{Version: 2, Round: 5, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
			HandoffRecords: [][]byte{record("abort", 5, 8, frozen, body, zero)}}}
		_, err := h.Extend(block, nil, emptyOrchestration(), crypto.SHA256, logger.New(t))
		require.ErrorIs(t, err, ErrHandoffSuffix)
	})
	t.Run("control_partition_request", func(t *testing.T) {
		s := profileStore(t)
		block := &rctypes.BlockData{Version: 2, Round: 2, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
			Requests: []*rctypes.IRChangeReq{{Partition: rctypes.ControlPartition}}}, Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 1, Epoch: 1}}}
		_, err := s.Add(block, nil)
		require.ErrorIs(t, err, rctypes.ErrControlPartition)
	})
}

func TestProfileHandoffAuthenticatesDeferredShardEpochAccumulators(t *testing.T) {
	key := []byte{0x3, 0x24, 0x8b, 0x61, 0x68, 0x51, 0xac, 0x6e, 0x43, 0x7e, 0xc2, 0x4e, 0xcc, 0x21, 0x9e, 0x5b, 0x42, 0x43, 0xdf, 0xa5, 0xdb, 0xdb, 0x8, 0xce, 0xa6, 0x48, 0x3a, 0xc9, 0xe0, 0xdc, 0x6b, 0x55, 0xcd}
	conf := &types.PartitionDescriptionRecord{PartitionID: 7, Epoch: 1, Validators: []*types.NodeInfo{{NodeID: "n", SigKey: key, Stake: 1}}}
	si, err := NewShardInfo(conf, crypto.SHA256)
	require.NoError(t, err)
	si.Fees["n"] = 9
	si.TR.Epoch = 2
	conf2 := *conf
	conf2.Epoch = 2
	shard := types.PartitionShardID{PartitionID: conf.PartitionID, ShardID: conf.ShardID.Key()}
	prior := ShardStates{States: map[types.PartitionShardID]*ShardInfo{shard: si}, Changed: ShardSet{}, Control: initialControl(5)}
	next, err := prior.nextBlock(map[types.PartitionShardID]*types.PartitionDescriptionRecord{shard: &conf2}, crypto.SHA256)
	require.NoError(t, err)
	require.Empty(t, next.Changed)
	require.Equal(t, si.IR, next.States[shard].IR)
	feeHash, err := next.States[shard].feeHash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, feeHash, []byte(next.States[shard].TR.FeeHash))
	statHash, err := next.States[shard].statHash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, statHash, []byte(next.States[shard].TR.StatHash))
	legacy := prior
	legacy.Control = nil
	legacyNext, err := legacy.nextBlock(map[types.PartitionShardID]*types.PartitionDescriptionRecord{shard: &conf2}, crypto.SHA256)
	require.NoError(t, err)
	require.False(t, bytes.Equal(feeHash, legacyNext.States[shard].TR.FeeHash))
}

func TestProfileHandoffReloadRejectsForgedSuffixPayload(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	suffix := addProfileBlock(t, s, 5, nil)
	reloaded, err := New(crypto.SHA256, s.storage, s.orchestration, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	isSuffix, err := reloaded.SuffixParent(5, 1)
	require.NoError(t, err)
	require.True(t, isSuffix)
	forged := *suffix
	block := *suffix.BlockData
	block.Payload = &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{record("abort", 5, 8, frozen, body, zero)}}
	forged.BlockData = &block
	require.NoError(t, s.storage.WriteBlock(&forged, false))
	_, err = New(crypto.SHA256, s.storage, s.orchestration, logger.New(t), ProfileHandoff)
	require.ErrorIs(t, err, ErrHandoffSuffix)
}

func TestProfileHandoffRejectsEpochJumpOnEveryBlockPath(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	h := addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	jump := &rctypes.BlockData{Version: 2, Round: 5, Epoch: 2, Payload: &rctypes.Payload{Version: 2},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4, Epoch: 1, CurrentRootHash: h.RootHash}}}
	_, err := s.Add(jump, nil)
	require.EqualError(t, err, ErrNetworkProfile.Error())
	_, err = h.Extend(jump, nil, emptyOrchestration(), crypto.SHA256, logger.New(t))
	require.ErrorIs(t, err, ErrNetworkProfile)
	_, err = s.SuffixParent(4, 2)
	require.ErrorIs(t, err, ErrNetworkProfile)
	checkpoint := &abdrc.CommittedBlock{Block: h.BlockData, Control: h.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: h.RootHash}}}
	checkpoint.ShardInfo, err = toRecoveryShardInfo(h)
	require.NoError(t, err)
	recoveryDB, err := NewBoltStorage(filepath.Join(t.TempDir(), "recovery.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = recoveryDB.Close() })
	recovery, err := NewFromState(crypto.SHA256, checkpoint, recoveryDB, s.orchestration, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	_, err = recovery.Add(jump, nil)
	require.EqualError(t, err, ErrNetworkProfile.Error())
	reloadStore := profileStore(t)
	child := addProfileBlock(t, reloadStore, 2, nil)
	forged := *child
	changed := *child.BlockData
	changed.Epoch = 2
	forged.BlockData = &changed
	forged.ShardState.Control = &evmroot.ControlState{Network: 5, Epoch: 2,
		PredecessorBodyID: make([]byte, 32), Phase: "idle"}
	tree, _, err := forged.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	forged.RootHash = tree.RootHash()
	rootMismatch := forged
	rootMismatch.BlockData = child.BlockData
	require.ErrorIs(t, checkStoredRoot(&rootMismatch, ProfileHandoff), ErrNetworkProfile)
	require.NoError(t, reloadStore.storage.WriteBlock(&forged, false))
	_, err = New(crypto.SHA256, reloadStore.storage, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.ErrorIs(t, err, ErrNetworkProfile)
}

// movingParentAuthority admits any freeze, naming the frozen parent the test currently plans.
type movingParentAuthority struct{ parent *[]byte }

func (movingParentAuthority) Predecessor() []byte                                    { return make([]byte, 32) }
func (movingParentAuthority) CurrentRoot() []evmassign.RootMember                    { return []evmassign.RootMember{} }
func (movingParentAuthority) VerifyAbort(evmroot.OrderedHandoffRecord, []byte) error { return nil }
func (a movingParentAuthority) VerifyFreeze(evmroot.OrderedHandoffRecord, []byte) ([]byte, error) {
	return bytes.Clone(*a.parent), nil
}

// evmRequestBlock adds a block whose only content is an EVM certification of a new block hash.
func evmRequestBlock(s *BlockStore, round uint64, records [][]byte, hash []byte) error {
	parent, err := s.Block(round - 1)
	if err != nil {
		return err
	}
	block := &rctypes.BlockData{Version: 2, Round: round, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: 8}}, HandoffRecords: records},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}
	_, err = s.Add(block, mockIRVerifier{verify: func(_ uint64, _ *rctypes.IRChangeReq) (*types.InputRecord, error) {
		return &types.InputRecord{Version: 1, RoundNumber: round, BlockHash: bytes.Clone(hash)}, nil
	}})
	return err
}

// Prepare freezes the designated EVM shard (by type: no parent is bound yet), an aggregator shard stays live, and Abort lifts the
// Prepare-time freeze exactly as it lifts the Freeze-time one: the control state returns to "aborted", which freezes nothing.
func TestPrepareFreezesTheEVMShardAndAbortLiftsItLikeFreeze(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	aggregators := installTestAggregatorShards(t, s)
	evm := types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}
	zero := make([]byte, 32)
	body := bytes.Repeat([]byte{1}, 32)

	require.NoError(t, evmRequestBlock(s, 2, nil, bytes.Repeat([]byte{0x50}, 32)), "before Prepare the EVM certifies")
	_, active, err := s.FrozenShardAt(2)
	require.NoError(t, err)
	require.False(t, active)

	addProfileBlock(t, s, 3, [][]byte{record("prepare", 3, 9, zero, body, zero)})
	key, active, err := s.FrozenShardAt(3)
	require.NoError(t, err)
	require.True(t, active, "Prepare freezes the EVM shard")
	require.Equal(t, evm, key)
	require.ErrorIs(t, evmRequestBlock(s, 4, nil, bytes.Repeat([]byte{0x51}, 32)), ErrHandoffFrozen, "an EVM certification is refused from Prepare")
	// An aggregator shard stays live.
	parent, err := s.Block(3)
	require.NoError(t, err)
	_, err = s.Add(&rctypes.BlockData{Version: 2, Round: 4, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: aggregators[0].PartitionID}}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 3, Epoch: 1, CurrentRootHash: parent.RootHash}}},
		mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) {
			return &types.InputRecord{Version: 1, RoundNumber: 4, BlockHash: bytes.Repeat([]byte{0x60}, 32)}, nil
		}})
	require.NoError(t, err)

	addProfileBlock(t, s, 5, [][]byte{record("abort", 5, 9, zero, body, zero)})
	_, active, err = s.FrozenShardAt(5)
	require.NoError(t, err)
	require.False(t, active, "Abort lifts the Prepare-time freeze")
	require.NoError(t, evmRequestBlock(s, 6, nil, bytes.Repeat([]byte{0x52}, 32)), "the EVM certifies again after Abort")
}

// A busy EVM that certifies in every round can be handed off: Prepare freezes it, so the parent the leader checked when it ordered
// Prepare is still the certified EVM IR when Freeze is ordered. A Freeze naming any other parent is refused.
func TestBusyEVMCanBeHandedOffBecausePrepareFreezesIt(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x40}, 32))
	planned := bytes.Repeat([]byte{0x40}, 32)
	s.handoffAuth = movingParentAuthority{parent: &planned}
	evm := types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}
	zero := make([]byte, 32)
	body, frozenID := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)

	// The EVM certifies a new block in every round; the operator's plan names the latest one it saw.
	var latest []byte
	for round := uint64(2); round <= 6; round++ {
		latest = bytes.Repeat([]byte{byte(0x50 + round)}, 32)
		require.NoError(t, evmRequestBlock(s, round, nil, latest))
	}
	planned = bytes.Clone(latest)
	tip, err := s.Block(6)
	require.NoError(t, err)
	require.True(t, bytes.Equal(planned, tip.ShardState.States[evm].IR.BlockHash), "the leader's check: the plan's parent is the certified EVM IR in its branch")

	addProfileBlock(t, s, 7, [][]byte{record("prepare", 7, 15, zero, body, zero)})
	// The EVM keeps wanting to certify but is refused, so the parent cannot move before Freeze.
	require.ErrorIs(t, evmRequestBlock(s, 8, nil, bytes.Repeat([]byte{0x99}, 32)), ErrHandoffFrozen)

	t.Run("a Freeze naming a stale parent is refused", func(t *testing.T) {
		stale := bytes.Repeat([]byte{0x51}, 32)
		planned = stale
		parent, err := s.Block(7)
		require.NoError(t, err)
		_, err = s.Add(&rctypes.BlockData{Version: 2, Round: 8, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{record("freeze", 8, 15, frozenID, body, zero)}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 7, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
		planned = bytes.Clone(latest)
	})
	addProfileBlock(t, s, 8, [][]byte{record("freeze", 8, 15, frozenID, body, zero)})
	frozen := mustBlock(t, s, 8).ShardState.States[evm]
	require.True(t, bytes.Equal(planned, frozen.IR.BlockHash), "Freeze bound the parent that Prepare froze")
}

func recordAttempt(kind string, round, activation, attempt uint64, frozen, body, tr []byte) []byte {
	return (evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: attempt, OrderedRound: round,
		PredecessorBodyID: make([]byte, 32), FrozenID: frozen, NextBodyID: body,
		ActivationRound: activation, SuccessorTRHash: tr, Kind: kind}).Bytes()
}

// Prepare carries no signatures, so one faulty leader can order one for an unendorsed body. Its EVM freeze lapses by itself after
// PrepareFreezeLapseRounds (and not before); the attempt is dead, and a fresh Prepare needs the next attempt number and the cooldown.
func TestUnendorsedPrepareLapsesAndRepeatedPreparesCannotFreezeContinuously(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	zero := make([]byte, 32)
	const prepared = uint64(3)
	addProfileBlock(t, s, 2, nil)
	lapse, cooldown := uint64(PrepareFreezeLapseRounds), uint64(PrepareCooldownRounds)
	body := bytes.Repeat([]byte{1}, 32)
	addProfileBlock(t, s, prepared, [][]byte{recordAttempt("prepare", prepared, prepared+8, 0, zero, body, zero)})

	fill := func(from, to uint64) {
		for r := from; r <= to; r++ {
			addProfileBlock(t, s, r, nil)
		}
	}
	fill(prepared+1, prepared+lapse-1)
	// Still frozen on the last round of the window (a block at prepared+lapse is not yet lapsed), so not before K rounds.
	require.ErrorIs(t, evmRequestBlock(s, prepared+lapse, nil, bytes.Repeat([]byte{0x70}, 32)), ErrHandoffFrozen)
	fill(prepared+lapse, prepared+lapse)
	require.NoError(t, evmRequestBlock(s, prepared+lapse+1, nil, bytes.Repeat([]byte{0x71}, 32)), "the EVM certifies again after K rounds")

	t.Run("a Freeze for the lapsed attempt is refused", func(t *testing.T) {
		planned := bytes.Repeat([]byte{0x71}, 32)
		s.handoffAuth = movingParentAuthority{parent: &planned}
		round := prepared + lapse + 2
		parent, err := s.Block(round - 1)
		require.NoError(t, err)
		_, err = s.Add(&rctypes.BlockData{Version: 2, Round: round, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{recordAttempt("freeze", round, prepared+8, 0, bytes.Repeat([]byte{2}, 32), body, zero)}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})

	// Rounds prepared+lapse+1 .. are normal blocks from here (the EVM block above was round prepared+lapse+1).
	next := prepared + lapse + 2
	fill(next, prepared+lapse+cooldown-1)
	prepareAt := func(round, attempt uint64) error {
		parent, err := s.Block(round - 1)
		require.NoError(t, err)
		_, err = s.Add(&rctypes.BlockData{Version: 2, Round: round, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{recordAttempt("prepare", round, round+8, attempt, zero, bytes.Repeat([]byte{byte(attempt + 5)}, 32), zero)}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
		return err
	}
	cool := prepared + lapse + cooldown
	require.ErrorIs(t, prepareAt(cool, 1), ErrHandoffRecord, "no fresh Prepare while the cooldown runs")
	fill(cool, cool)
	require.ErrorIs(t, prepareAt(cool+1, 0), ErrHandoffRecord, "the lapsed attempt number is not reused")
	require.NoError(t, prepareAt(cool+1, 1), "the next attempt may be prepared once the cooldown has passed")
	require.ErrorIs(t, evmRequestBlock(s, cool+2, nil, bytes.Repeat([]byte{0x72}, 32)), ErrHandoffFrozen, "and freezes the EVM again")
	// Duty cycle: between the two Prepares the EVM was free for the whole cooldown, so a faulty leader repeating the attack freezes it
	// for at most lapse rounds out of every lapse+cooldown.
	require.GreaterOrEqual(t, cooldown, lapse)
}

// A Freeze ordered within the window keeps the EVM frozen past the window: the lapse only ends an unanswered Prepare.
func TestFreezeWithinTheWindowKeepsTheEVMFrozenPastIt(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x40}, 32))
	planned := bytes.Repeat([]byte{0x40}, 32)
	s.handoffAuth = movingParentAuthority{parent: &planned}
	zero := make([]byte, 32)
	body, frozenID := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	const prepared = uint64(3)
	addProfileBlock(t, s, 2, nil)
	addProfileBlock(t, s, prepared, [][]byte{recordAttempt("prepare", prepared, prepared+8, 0, zero, body, zero)})
	for r := prepared + 1; r < prepared+PrepareFreezeLapseRounds; r++ {
		addProfileBlock(t, s, r, nil)
	}
	freezeRound := prepared + PrepareFreezeLapseRounds // the last round inside the window
	addProfileBlock(t, s, freezeRound, [][]byte{recordAttempt("freeze", freezeRound, prepared+8, 0, frozenID, body, zero)})
	for r := freezeRound + 1; r <= freezeRound+2*PrepareFreezeLapseRounds; r++ {
		addProfileBlock(t, s, r, nil)
	}
	require.ErrorIs(t, evmRequestBlock(s, freezeRound+2*PrepareFreezeLapseRounds+1, nil, bytes.Repeat([]byte{0x73}, 32)), ErrHandoffFrozen)
}

// The root binds the frozen parent when it executes the Prepare: the EVM IR certified in that branch at that moment, whatever the
// operator planned. Freeze may then name only that parent, and no Freeze exists without a Prepare.
func TestPrepareBindsTheFrozenParentAndFreezeMustNameIt(t *testing.T) {
	zero := make([]byte, 32)
	body, frozenID := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	evm := types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}
	newStore := func(t *testing.T, authorityParent []byte) *BlockStore {
		s := profileStore(t)
		installTestFrozenShard(t, s, bytes.Repeat([]byte{0x40}, 32))
		s.handoffAuth = movingParentAuthority{parent: &authorityParent}
		addProfileBlock(t, s, 2, nil)
		return s
	}
	addAt := func(t *testing.T, s *BlockStore, round uint64, rec []byte) error {
		parent, err := s.Block(round - 1)
		require.NoError(t, err)
		_, err = s.Add(&rctypes.BlockData{Version: 2, Round: round, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{rec}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
		return err
	}

	t.Run("Prepare binds the certified EVM IR of its branch", func(t *testing.T) {
		s := newStore(t, nil)
		latest := bytes.Repeat([]byte{0x51}, 32)
		require.NoError(t, evmRequestBlock(s, 3, nil, latest))
		prepared := addProfileBlock(t, s, 4, [][]byte{record("prepare", 4, 40, zero, body, zero)})
		require.Equal(t, "prepared", prepared.ShardState.Control.Phase)
		require.Equal(t, latest, prepared.ShardState.Control.FrozenParent, "the root bound the EVM IR certified at the Prepare, not an earlier one")
		require.True(t, bytes.Equal(latest, prepared.ShardState.States[evm].IR.BlockHash))
	})
	t.Run("Freeze naming another parent is refused", func(t *testing.T) {
		bound := bytes.Repeat([]byte{0x40}, 32)
		other := bytes.Repeat([]byte{0x51}, 32)
		s := newStore(t, other) // the endorsements name `other`, the Prepare bound the installed 0x40
		addProfileBlock(t, s, 3, [][]byte{record("prepare", 3, 40, zero, body, zero)})
		require.Equal(t, bound, mustBlock(t, s, 3).ShardState.Control.FrozenParent)
		require.ErrorIs(t, addAt(t, s, 4, record("freeze", 4, 40, frozenID, body, zero)), ErrFreezeParentUnbound)
	})
	t.Run("Freeze naming the bound parent is accepted", func(t *testing.T) {
		bound := bytes.Repeat([]byte{0x40}, 32)
		s := newStore(t, bound)
		addProfileBlock(t, s, 3, [][]byte{record("prepare", 3, 40, zero, body, zero)})
		endorsed := addProfileBlock(t, s, 4, [][]byte{record("freeze", 4, 40, frozenID, body, zero)})
		require.Equal(t, "endorsed", endorsed.ShardState.Control.Phase)
		require.Equal(t, bound, endorsed.ShardState.Control.FrozenParent)
	})
	t.Run("Freeze without a Prepare is refused", func(t *testing.T) {
		s := newStore(t, bytes.Repeat([]byte{0x40}, 32))
		require.ErrorIs(t, addAt(t, s, 3, record("freeze", 3, 40, frozenID, body, zero)), ErrFreezeBeforePrepare)
		_, err := applyHandoffRecord(initialControl(5), record("freeze", 2, 7, frozenID, body, zero), 5, 1, 2, testRecordAuthority{}, nil)
		require.ErrorIs(t, err, ErrFreezeBeforePrepare)
		aborted := initialControl(5)
		aborted.Phase, aborted.Attempt = "aborted", 0
		_, err = applyHandoffRecord(aborted, record("freeze", 2, 7, frozenID, body, zero), 5, 1, 2, testRecordAuthority{}, nil)
		require.ErrorIs(t, err, ErrFreezeBeforePrepare)
	})
	t.Run("a Prepare with no certified EVM IR to bind is refused", func(t *testing.T) {
		s := newStore(t, nil)
		tip, err := s.Block(2)
		require.NoError(t, err)
		tip.ShardState.States[evm].IR.BlockHash = nil // never certified a block
		require.ErrorIs(t, addAt(t, s, 3, record("prepare", 3, 40, zero, body, zero)), ErrPrepareNoEVMParent)
	})
	t.Run("a prepared checkpoint without a bound parent is invalid", func(t *testing.T) {
		s := newStore(t, nil)
		prepared := addProfileBlock(t, s, 3, [][]byte{record("prepare", 3, 40, zero, body, zero)})
		control := *prepared.ShardState.Control
		require.NoError(t, validateControl(&control))
		control.FrozenParent = nil
		require.ErrorIs(t, validateControl(&control), ErrControlCheckpoint)
	})
}

// A Prepare whose freeze lapsed is reported once, when the committed root passes the end of its window, so the operator retries at
// once instead of waiting out its own timeout.
func TestLapsedPrepareIsReportedOnceAsAnOutcome(t *testing.T) {
	var logs bytes.Buffer
	s := &BlockStore{profile: ProfileHandoff, log: slog.New(slog.NewTextHandler(&logs, nil))}
	committedAt := func(round uint64, phase string) *ExecutedBlock {
		block := &ExecutedBlock{BlockData: &rctypes.BlockData{Round: round, Epoch: 1}}
		block.ShardState.Control = &evmroot.ControlState{Network: 5, Epoch: 1, Attempt: 2, Phase: phase, OrderedRound: 10}
		return block
	}
	count := func() int { return strings.Count(logs.String(), "phase=lapsed") }
	s.logHandoffOutcome(committedAt(10+PrepareFreezeLapseRounds, "prepared"))
	require.Zero(t, count(), "inside the window nothing is reported")
	s.logHandoffOutcome(committedAt(10+PrepareFreezeLapseRounds+1, "prepared"))
	require.Equal(t, 1, count())
	require.Contains(t, logs.String(), "attempt=2")
	s.logHandoffOutcome(committedAt(10+PrepareFreezeLapseRounds+2, "prepared"))
	require.Equal(t, 1, count(), "reported once per attempt")
	s.logHandoffOutcome(committedAt(10+PrepareFreezeLapseRounds+9, "endorsed"))
	require.Equal(t, 1, count(), "a Freeze that came in time is no lapse")
}

// The activation floor is a block-validation rule, not only the leader's choice.
func TestPrepareActivationFloorIsEnforcedByBlockValidation(t *testing.T) {
	restore := prepareActivationFloor
	prepareActivationFloor = PrepareActivationFloorRounds
	t.Cleanup(func() { prepareActivationFloor = restore })
	zero := make([]byte, 32)
	body := bytes.Repeat([]byte{1}, 32)
	const round = uint64(3)
	prepareWith := func(t *testing.T, activation uint64) error {
		s := profileStore(t)
		installTestFrozenShard(t, s, bytes.Repeat([]byte{0x40}, 32))
		addProfileBlock(t, s, 2, nil)
		rec := (evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: round, PredecessorBodyID: zero, FrozenID: zero,
			NextBodyID: body, ActivationRound: activation, SuccessorTRHash: zero, Kind: "prepare"}).Bytes()
		parent, err := s.Block(round - 1)
		require.NoError(t, err)
		_, err = s.Add(&rctypes.BlockData{Version: 2, Round: round, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{rec}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
		return err
	}
	require.ErrorIs(t, prepareWith(t, round+PrepareActivationFloorRounds-1), ErrPrepareActivationFloor)
	require.ErrorIs(t, prepareWith(t, round+8), ErrPrepareActivationFloor, "the old +8 margin is no longer enough")
	require.NoError(t, prepareWith(t, round+PrepareActivationFloorRounds))
}
