package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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

func profileStore(t *testing.T) *BlockStore {
	t.Helper()
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(crypto.SHA256, db, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	return s
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

func TestHandoffControlLeafAndSuffix(t *testing.T) {
	require.Equal(t, evmroot.D4ControlPartition, rctypes.ControlPartition)
	s := profileStore(t)
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
	checkpoint := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
	recovered, err := NewRootBlock(checkpoint, crypto.SHA256, emptyOrchestration(), ProfileHandoff)
	require.NoError(t, err)
	require.True(t, bytes.Equal(suffix.RootHash, recovered.RootHash))
	recoveryDB, err := NewBoltStorage(filepath.Join(t.TempDir(), "recovery.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = recoveryDB.Close() })
	recovery, err := NewFromState(crypto.SHA256, checkpoint, recoveryDB, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	_, err = recovery.Add(&rctypes.BlockData{Version: 2, Round: 6, Epoch: 1, Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{record("abort", 6, 8, frozen, body, zero)}},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 5, Epoch: 1}}}, nil)
	require.ErrorIs(t, err, ErrHandoffSuffix)
	checkpoint.Control = nil
	_, err = NewRootBlock(checkpoint, crypto.SHA256, emptyOrchestration(), ProfileHandoff)
	require.ErrorIs(t, err, ErrNetworkProfile)
	checkpoint.Control = suffix.ShardState.Control
	checkpoint.CommitQc.LedgerCommitInfo.Hash = bytes.Repeat([]byte{8}, 32)
	_, err = NewRootBlock(checkpoint, crypto.SHA256, emptyOrchestration(), ProfileHandoff)
	require.ErrorIs(t, err, ErrControlCheckpoint)
	checkpoint.CommitQc.LedgerCommitInfo.Hash = suffix.RootHash
	checkpoint.Control = &evmroot.ControlState{Network: 5, Epoch: 1, PredecessorBodyID: zero, Phase: "committed", OrderedRound: 4, RecordBytes: []byte{1}}
	_, err = NewRootBlock(checkpoint, crypto.SHA256, emptyOrchestration(), ProfileHandoff)
	require.ErrorIs(t, err, ErrControlCheckpoint)
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
		_, err := applyHandoffRecord(initialControl(5), record("prepare", 3, 7, zero, body, zero), 5, 1, 2)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("record_phase", func(t *testing.T) {
		_, err := applyHandoffRecord(initialControl(5), record("freeze", 2, 7, frozen, body, zero), 5, 1, 2)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("one_live_attempt", func(t *testing.T) {
		prepared, err := applyHandoffRecord(initialControl(5), record("prepare", 2, 7, zero, body, zero), 5, 1, 2)
		require.NoError(t, err)
		_, err = applyHandoffRecord(prepared, record("prepare", 3, 7, zero, body, zero), 5, 1, 3)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("terminal_outcome", func(t *testing.T) {
		prepared, err := applyHandoffRecord(initialControl(5), record("prepare", 2, 7, zero, body, zero), 5, 1, 2)
		require.NoError(t, err)
		frozenState, err := applyHandoffRecord(prepared, record("freeze", 3, 7, frozen, body, zero), 5, 1, 3)
		require.NoError(t, err)
		committed, err := applyHandoffRecord(frozenState, record("commit", 4, 7, frozen, body, tr), 5, 1, 4)
		require.NoError(t, err)
		_, err = applyHandoffRecord(committed, record("abort", 5, 8, frozen, body, zero), 5, 1, 5)
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
	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	suffix := addProfileBlock(t, s, 5, nil)
	reloaded, err := New(crypto.SHA256, s.storage, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	isSuffix, err := reloaded.SuffixParent(5, 1)
	require.NoError(t, err)
	require.True(t, isSuffix)
	forged := *suffix
	block := *suffix.BlockData
	block.Payload = &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{record("abort", 5, 8, frozen, body, zero)}}
	forged.BlockData = &block
	require.NoError(t, s.storage.WriteBlock(&forged, false))
	_, err = New(crypto.SHA256, s.storage, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.ErrorIs(t, err, ErrHandoffSuffix)
}
