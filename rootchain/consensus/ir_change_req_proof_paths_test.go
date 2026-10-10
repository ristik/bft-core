package consensus

import (
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	abtypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	testpartition "github.com/unicitynetwork/bft-core/rootchain/partitions/testutils"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// The paths of the follower's vote: a legacy-dispatch shard of three, a change that carries several requests, a 'no quorum' change, and the
// proposal's execution (ExecutedBlock.Extend, which BlockStore.Add, TrialExecute and the replay run) with the real IRChangeReqVerifier.

type legacyProofRig struct {
	nodes []*testutils.TestNode
	infos []*types.NodeInfo
	conf  *types.PartitionDescriptionRecord
	orch  *partitions.Orchestration
	ver   *IRChangeReqVerifier
}

func newLegacyProofRig(t *testing.T, prev [32]byte) *legacyProofRig {
	t.Helper()
	nodes, infos := testutils.CreateTestNodes(t, 3)
	conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partitionID1, PartitionTypeID: 1, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2000 * time.Millisecond, Validators: infos, EpochStart: 1, PartitionParams: rsmtParams}
	orch := testpartition.NewOrchestration(t, logger.New(t))
	require.NoError(t, orch.AddShardConfig(conf))
	state := &MockState{shardInfo: func(id types.PartitionID, _ types.ShardID) *storage.ShardInfo {
		if id != conf.PartitionID {
			return nil
		}
		si, err := storage.NewShardInfo(conf, crypto.SHA256)
		require.NoError(t, err)
		si.LastCR = &certification.CertificationResponse{
			UC:        types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 2, Timestamp: 1}, InputRecord: &types.InputRecord{}},
			Technical: certification.TechnicalRecord{Round: 2},
		}
		si.RootHash = prev[:]
		return si
	}}
	ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: 500 * time.Millisecond, HashAlgorithm: crypto.SHA256}, state)
	require.NoError(t, err)
	return &legacyProofRig{nodes: nodes, infos: infos, conf: conf, orch: orch, ver: ver}
}

func (r *legacyProofRig) request(t *testing.T, i int, prev [32]byte, proof, hash []byte) *certification.BlockCertificationRequest {
	t.Helper()
	req := &certification.BlockCertificationRequest{PartitionID: partitionID1, NodeID: r.infos[i].NodeID, ZkProof: proof, InputRecord: &types.InputRecord{
		Version: 1, PreviousHash: prev[:], Hash: hash, BlockHash: []byte{4, 4, 4}, SummaryValue: []byte{5, 5, 5}, RoundNumber: 2, Timestamp: 1}}
	require.NoError(t, req.Sign(r.nodes[i].Signer))
	return req
}

func TestLegacyChangeWithSeveralRequestsChecksEachProof(t *testing.T) {
	valid := newProofTransition(t, 1)
	rig := newLegacyProofRig(t, valid.prev)
	change := func(second []byte) *abtypes.IRChangeReq {
		return &abtypes.IRChangeReq{Partition: partitionID1, CertReason: abtypes.Quorum, Requests: []*certification.BlockCertificationRequest{
			rig.request(t, 0, valid.prev, valid.envelope, valid.next[:]), rig.request(t, 1, valid.prev, second, valid.next[:])}}
	}
	_, err := rig.ver.VerifyIRChangeReq(2, change(valid.envelope))
	require.NoError(t, err, "control: both carried proofs hold")
	_, err = rig.ver.VerifyIRChangeReq(2, change([]byte{1, 2, 3}))
	require.ErrorIs(t, err, ErrProofInvalid, "the first request's valid proof is no reason to skip the second's")
	require.ErrorIs(t, err, zkverifier.ErrInvalidProofFormat)
}

// A 'no quorum' change certifies a repeat of the last record, but the requests it rests on are the shard's own signed statements; each carries its proof.
func TestNoQuorumChangeChecksTheProofsOfItsRequests(t *testing.T) {
	// three transitions from one certified root, their leaves bound to the round's reference time ts
	transitions := func(ts uint64) []proofTransition {
		var tr []proofTransition
		for _, k := range []byte{0x80, 0xC0, 0xA0} {
			tr = append(tr, newProofTransitionOf(t, ts, k))
		}
		for i := range tr {
			require.Equal(t, tr[0].prev, tr[i].prev, "every request builds on the same certified root")
		}
		return tr
	}

	t.Run("legacy branch", func(t *testing.T) {
		tr := transitions(1) // the legacy rig's previous UC time
		rig := newLegacyProofRig(t, tr[0].prev)
		change := func(third []byte) *abtypes.IRChangeReq {
			reqs := []*certification.BlockCertificationRequest{
				rig.request(t, 0, tr[0].prev, tr[0].envelope, tr[0].next[:]),
				rig.request(t, 1, tr[0].prev, tr[1].envelope, tr[1].next[:]),
				rig.request(t, 2, tr[0].prev, third, tr[2].next[:]),
			}
			return &abtypes.IRChangeReq{Partition: partitionID1, CertReason: abtypes.QuorumNotPossible, Requests: reqs}
		}
		_, err := rig.ver.VerifyIRChangeReq(2, change(tr[2].envelope))
		require.NoError(t, err, "control: three different transitions, each proved")
		_, err = rig.ver.VerifyIRChangeReq(2, change([]byte{1, 2, 3}))
		require.ErrorIs(t, err, ErrProofInvalid)
		require.ErrorIs(t, err, zkverifier.ErrInvalidProofFormat)
	})

	t.Run("view branch", func(t *testing.T) {
		tr := transitions(1000) // the view's previous UC time
		ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: 900 * time.Millisecond}, &MockState{})
		require.NoError(t, err)
		v := newViewTargetWith(t, 12, storage.PurposeCertify, rsmtParams, tr[0].prev[:])
		change := func(third []byte) *abtypes.IRChangeReq {
			build := func(i int, proof, hash []byte) *certification.BlockCertificationRequest {
				req := v.request(t, i)
				req.ZkProof, req.InputRecord.Hash = proof, hash
				require.NoError(t, req.Sign(v.nodes[i].Signer))
				return req
			}
			return &abtypes.IRChangeReq{Partition: 1, CertReason: abtypes.QuorumNotPossible, Requests: []*certification.BlockCertificationRequest{
				build(0, tr[0].envelope, tr[0].next[:]), build(1, tr[1].envelope, tr[1].next[:]), build(2, third, tr[2].next[:])}}
		}
		_, err = ver.VerifyIRChangeReqView(v.view, change(tr[2].envelope))
		require.NoError(t, err, "control: three different transitions, each proved")
		_, err = ver.VerifyIRChangeReqView(v.view, change([]byte{1, 2, 3}))
		require.ErrorIs(t, err, ErrProofInvalid)
		require.ErrorIs(t, err, zkverifier.ErrInvalidProofFormat)
	})
}

// The follower's vote: it executes the proposed block before it signs. A block carrying a correctly signed request with a bad proof does not extend.
func TestProposalExecutionRefusesABadProof(t *testing.T) {
	valid := newProofTransition(t, 1)
	rig := newLegacyProofRig(t, valid.prev)
	si, err := storage.NewShardInfo(rig.conf, crypto.SHA256)
	require.NoError(t, err)
	psID := types.PartitionShardID{PartitionID: si.PartitionID, ShardID: si.ShardID.Key()}
	genesis := &abtypes.BlockData{Version: 1, Author: "testgenesis", Round: abtypes.GenesisRootRound, Epoch: abtypes.GenesisRootEpoch, Timestamp: types.GenesisTime}
	qc := &abtypes.QuorumCert{
		VoteInfo: &abtypes.RoundInfo{Version: 1, RoundNumber: genesis.Round, Epoch: genesis.Epoch, Timestamp: genesis.Timestamp},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 4, Epoch: abtypes.GenesisRootEpoch, Timestamp: 123,
			Hash: []byte{1, 2, 3}, PreviousHash: []byte{3, 2, 1}},
	}
	parent := &storage.ExecutedBlock{
		BlockData:  genesis,
		HashAlgo:   crypto.SHA256,
		ShardState: storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{psID: si}, Changed: storage.ShardSet{psID: struct{}{}}},
		Qc:         qc,
		CommitQc:   qc,
	}
	si.RootHash = valid.prev[:]
	block := func(proof []byte) *abtypes.BlockData {
		change := &abtypes.IRChangeReq{Partition: partitionID1, CertReason: abtypes.Quorum, Requests: []*certification.BlockCertificationRequest{
			rig.request(t, 0, valid.prev, proof, valid.next[:]), rig.request(t, 1, valid.prev, proof, valid.next[:])}}
		return &abtypes.BlockData{Author: "test", Round: abtypes.GenesisRootRound + 1, Epoch: 0, Timestamp: 12, Payload: &abtypes.Payload{Requests: []*abtypes.IRChangeReq{change}}}
	}
	extended, err := parent.Extend(block(valid.envelope), rig.ver, rig.orch, crypto.SHA256, logger.New(t))
	require.NoError(t, err, "control: the proposal whose proofs hold is executed")
	require.Equal(t, valid.next[:], []byte(extended.ShardState.States[psID].IR.Hash))

	extended, err = parent.Extend(block([]byte{1, 2, 3}), rig.ver, rig.orch, crypto.SHA256, logger.New(t))
	require.Nil(t, extended)
	require.ErrorIs(t, err, ErrProofInvalid)
	require.ErrorIs(t, err, zkverifier.ErrInvalidProofFormat)
}
