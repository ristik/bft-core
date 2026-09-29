package handoffbundle

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	testutils "github.com/unicitynetwork/bft-core/rootchain/testutils"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type Fixture struct {
	Proof     handoff.OldCommitProof
	Body      evmroot.TrustBaseBodyV2
	Snapshot  *abdrc.CommittedBlock
	Old       *types.RootTrustBaseV1
	ConfHash  []byte
	Partition types.PartitionID
	Shard     types.ShardID
	State     *storage.ShardInfo
	Nodes     []*testutils.TestNode
}

func New(t *testing.T) Fixture {
	t.Helper()
	oldNodes := make([]*testutils.TestNode, 4)
	oldSigners := make(map[string]abcrypto.Signer, 4)
	for i := range oldNodes {
		oldNodes[i] = testutils.NewTestNode(t)
		oldSigners[oldNodes[i].PeerConf.ID.String()] = oldNodes[i].Signer
	}
	old := testtrustbase.NewTrustBaseFromSigners(t, oldSigners).(*types.RootTrustBaseV1)
	oldID, err := old.Hash(crypto.SHA256)
	require.NoError(t, err)
	link, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: uint64(old.NetworkID),
		Epoch: old.Epoch, HashIncludingSigs: oldID})
	require.NoError(t, err)
	members := make(evmroot.WeightSet, len(oldNodes))
	nextNodes := append([]*testutils.TestNode(nil), oldNodes...)
	nextNodes[0] = testutils.NewTestNode(t)
	for i, node := range nextNodes {
		verifier, err := node.Signer.Verifier()
		require.NoError(t, err)
		key, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		members[i] = evmroot.Member{StakingID: fmt.Sprintf("stake-%d", i), NodeID: node.PeerConf.ID.String(),
			ConsensusKey: key, Weight: 1}
	}
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: uint64(old.NetworkID), Epoch: 2,
		EarliestActivation: 7, Members: members, RootThreshold: 3, PredecessorHash: link}
	require.NoError(t, body.Validate())
	bodyID := body.Identity()
	_, shardValidators := testutils.CreateTestNodes(t, 3)
	partition := types.PartitionID(8)
	shard := types.ShardID{}
	conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: old.NetworkID,
		PartitionID: partition, ShardID: shard, PartitionTypeID: 999, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Validators: shardValidators, Epoch: 0, EpochStart: 1}
	state, err := storage.NewShardInfo(conf, crypto.SHA256)
	require.NoError(t, err)
	state.IR.BlockHash = bytes.Repeat([]byte{5}, 32)
	state.IR.Hash = bytes.Repeat([]byte{0x35}, 32)
	trHash, err := state.TR.Hash()
	require.NoError(t, err)
	record := evmroot.OrderedHandoffRecord{Network: uint64(old.NetworkID), Epoch: 1, OrderedRound: 4,
		ActivationRound: 7, PredecessorBodyID: oldID, NextBodyID: bodyID[:],
		FrozenID: bytes.Repeat([]byte{2}, 32), SuccessorTRHash: trHash, Kind: "commit"}
	control := evmroot.ControlState{Network: record.Network, Epoch: 1, OrderedRound: 4,
		PredecessorBodyID: oldID, Phase: "committed", RecordBytes: record.Bytes(),
		PreviousDigest: bytes.Repeat([]byte{4}, 32), FrozenParent: bytes.Repeat([]byte{5}, 32)}
	key := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
	states := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{key: state}, Control: &control}
	tree, _, err := states.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	stamp := types.NewTimestamp()
	vote := &rctypes.RoundInfo{Version: 1, RoundNumber: 5, ParentRoundNumber: 4, Epoch: 1,
		Timestamp: stamp, CurrentRootHash: tree.RootHash()}
	voteHash, err := vote.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: old.NetworkID, RootChainRoundNumber: 4,
		Epoch: 1, Timestamp: stamp, Hash: tree.RootHash(), PreviousHash: voteHash}
	message, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for _, node := range oldNodes[:3] {
		sig, err := node.Signer.SignBytes(message)
		require.NoError(t, err)
		qc.Signatures[node.PeerConf.ID.String()] = sig
	}
	proof := handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: record, Control: control,
		ControlPath: path, CommitQC: qc}
	_, err = handoff.VerifyOldCommitProof(proof, old)
	require.NoError(t, err)
	snapshot := &abdrc.CommittedBlock{Block: &rctypes.BlockData{Version: 2, Epoch: 1, Round: 4,
		Payload: &rctypes.Payload{Version: 2}}, Control: &control, CommitQc: qc,
		ShardInfo: []abdrc.ShardInfo{{Partition: partition, Shard: shard, T2Timeout: state.T2Timeout,
			RootHash: state.RootHash, PrevEpochStat: state.PrevEpochStat, Stat: state.Stat,
			PrevEpochFees: state.PrevEpochFees, Fees: state.Fees, IR: state.IR, IRTR: state.TR,
			ShardConfHash: state.ShardConfHash}}}
	return Fixture{Proof: proof, Body: body, Snapshot: snapshot, Old: old, ConfHash: bytes.Clone(state.ShardConfHash), Partition: partition, Shard: shard, State: state, Nodes: nextNodes}
}

// Next creates another committed handoff signed by the projected v2 trust.
func Next(t *testing.T, first Fixture, old *types.RootTrustBaseV1) Fixture {
	t.Helper()
	priorID := first.Body.Identity()
	body := first.Body
	body.Epoch = 3
	body.EarliestActivation = 11
	body.PredecessorHash = bytes.Clone(priorID[:])
	nextNodes := append([]*testutils.TestNode(nil), first.Nodes...)
	nextNodes[1] = testutils.NewTestNode(t)
	verifier, err := nextNodes[1].Signer.Verifier()
	require.NoError(t, err)
	body.Members = append(evmroot.WeightSet(nil), body.Members...)
	body.Members[1].NodeID = nextNodes[1].PeerConf.ID.String()
	body.Members[1].ConsensusKey, err = verifier.MarshalPublicKey()
	require.NoError(t, err)
	require.NoError(t, body.Validate())
	bodyID := body.Identity()
	state := *first.State
	inputRecord := *first.State.IR
	state.IR = &inputRecord
	state.IR.BlockHash = bytes.Repeat([]byte{8}, 32)
	state.IR.Hash = bytes.Repeat([]byte{0x38}, 32)
	trHash, err := state.TR.Hash()
	require.NoError(t, err)
	record := evmroot.OrderedHandoffRecord{Network: uint64(old.NetworkID), Epoch: 2, OrderedRound: 8,
		ActivationRound: 11, PredecessorBodyID: priorID[:], NextBodyID: bodyID[:],
		FrozenID: bytes.Repeat([]byte{6}, 32), SuccessorTRHash: trHash, Kind: "commit"}
	control := evmroot.ControlState{Network: record.Network, Epoch: 2, OrderedRound: 8,
		PredecessorBodyID: priorID[:], Phase: "committed", RecordBytes: record.Bytes(),
		PreviousDigest: bytes.Repeat([]byte{7}, 32), FrozenParent: bytes.Repeat([]byte{8}, 32)}
	key := types.PartitionShardID{PartitionID: first.Partition, ShardID: first.Shard.Key()}
	states := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{key: &state}, Control: &control}
	tree, _, err := states.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	stamp := types.NewTimestamp()
	vote := &rctypes.RoundInfo{Version: 1, RoundNumber: 9, ParentRoundNumber: 8, Epoch: 2,
		Timestamp: stamp, CurrentRootHash: tree.RootHash()}
	voteHash, err := vote.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: old.NetworkID, RootChainRoundNumber: 8,
		Epoch: 2, Timestamp: stamp, Hash: tree.RootHash(), PreviousHash: voteHash}
	message, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for _, node := range first.Nodes[:3] {
		sig, err := node.Signer.SignBytes(message)
		require.NoError(t, err)
		qc.Signatures[node.PeerConf.ID.String()] = sig
	}
	proof := handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: record, Control: control,
		ControlPath: path, CommitQC: qc}
	_, err = handoff.VerifyOldCommitProof(proof, old)
	require.NoError(t, err)
	snapshot := &abdrc.CommittedBlock{Block: &rctypes.BlockData{Version: 2, Epoch: 2, Round: 8,
		Payload: &rctypes.Payload{Version: 2}}, Control: &control, CommitQc: qc,
		ShardInfo: []abdrc.ShardInfo{{Partition: first.Partition, Shard: first.Shard, T2Timeout: state.T2Timeout,
			RootHash: state.RootHash, PrevEpochStat: state.PrevEpochStat, Stat: state.Stat,
			PrevEpochFees: state.PrevEpochFees, Fees: state.Fees, IR: state.IR, IRTR: state.TR,
			ShardConfHash: state.ShardConfHash}}}
	return Fixture{Proof: proof, Body: body, Snapshot: snapshot, Old: old, ConfHash: first.ConfHash,
		Partition: first.Partition, Shard: first.Shard, State: &state, Nodes: nextNodes}
}
