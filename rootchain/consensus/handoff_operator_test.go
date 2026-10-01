package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

func TestOperatorHandoffEndorsementReachesPrepare(t *testing.T) {
	ctx := context.Background()
	node := testutils.NewTestNode(t)
	others := []*testutils.TestNode{testutils.NewTestNode(t), testutils.NewTestNode(t), testutils.NewTestNode(t)}
	obs := testobservability.Default(t)
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), obs.Logger(), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, orchestration.Close()) })
	signers := map[string]abcrypto.Signer{node.PeerConf.ID.String(): node.Signer}
	for _, other := range others {
		signers[other.PeerConf.ID.String()] = other.Signer
	}
	old := testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
	store, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, store.Store(old))
	identity := sha256.Sum256([]byte("operator-plan-test"))
	history, err := trusthistorystore.Open(ctx, memorydb.New(), old, identity, trustactivation.Verifier{})
	require.NoError(t, err)
	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff
	mockNet := testnetwork.NewRootMockNetwork()
	cm, err := NewConsensusManager(node.PeerConf.ID, store, orchestration, mockNet, node.Signer, db, obs, WithConsensusParams(params), WithRecoveryProfile2(history))
	require.NoError(t, err)
	next := *old
	next.Epoch = 2
	replacement := testutils.NewTestNode(t)
	verifier, err := replacement.Signer.Verifier()
	require.NoError(t, err)
	key, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	next.RootNodes = append([]*types.NodeInfo(nil), old.RootNodes...)
	next.RootNodes[3] = &types.NodeInfo{NodeID: replacement.PeerConf.ID.String(), SigKey: key, Stake: 1}
	parentHash := bytes.Repeat([]byte{7}, 32)
	_, err = cm.BuildHandoffPlan(&next, parentHash)
	require.ErrorIs(t, err, ErrHandoffApproval, "the operator cannot freeze an uncertified EVM parent")
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{IR: &types.InputRecord{BlockHash: parentHash}}}
	plan, err := cm.buildHandoffPlanFromState(&next, parentHash, state, nil)
	require.NoError(t, err)
	bad := plan
	bad.FrozenParent = bytes.Repeat([]byte{8}, 32)
	require.ErrorIs(t, cm.EndorseHandoff(ctx, bad), ErrHandoffApproval)
	stale := *state
	staleHead := *state.CommittedHead
	staleHead.ShardInfo = []abdrc.ShardInfo{{IR: &types.InputRecord{BlockHash: bytes.Repeat([]byte{9}, 32)}}}
	stale.CommittedHead = &staleHead
	require.ErrorIs(t, cm.endorseHandoffAtState(ctx, plan, &stale), ErrHandoffApproval,
		"an endorser cannot sign a plan for an older certified EVM tip")
	staleHead.ShardInfo = state.CommittedHead.ShardInfo
	staleQC := *state.CommittedHead.CommitQc
	staleSeal := *staleQC.LedgerCommitInfo
	staleSeal.Hash = bytes.Repeat([]byte{0xaa}, 32)
	staleQC.LedgerCommitInfo = &staleSeal
	staleHead.CommitQc = &staleQC
	require.ErrorIs(t, cm.endorseHandoffAtState(ctx, plan, &stale), ErrHandoffApproval,
		"an endorser cannot sign a different pre-freeze root")
	cm.handoffPlans = make(map[[32]byte]*pendingHandoff)
	for i := byte(1); i <= 4; i++ {
		cm.handoffPlans[[32]byte{i}] = &pendingHandoff{signatures: make(map[string]hex.Bytes)}
	}
	require.NoError(t, cm.endorseHandoffAtState(ctx, plan, state))
	require.Len(t, cm.handoffPlans, 4)
	_, err = cm.readyHandoff()
	require.ErrorIs(t, err, ErrHandoffApproval, "one signature cannot authorize a four-validator handoff")
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	id := body.Identity()
	domain, err := storage.EndorsementBytes(cm.handoffPlans[id].record)
	require.NoError(t, err)
	abortDomain, err := storage.AbortEndorsementBytes(cm.handoffPlans[id].record)
	require.NoError(t, err)
	for i, other := range others[:2] {
		signed := plan
		signed.Signer = other.PeerConf.ID.String()
		signed.Signature, err = other.Signer.SignBytes(domain)
		require.NoError(t, err)
		signed.AbortSignature, err = other.Signer.SignBytes(abortDomain)
		require.NoError(t, err)
		require.NoError(t, cm.onHandoffApprovalMsg(ctx, &signed))
		require.NoError(t, cm.onHandoffApprovalMsg(ctx, &signed), "duplicate endorsement is idempotent")
		if i == 0 {
			_, err = cm.readyHandoff()
			require.ErrorIs(t, err, ErrHandoffApproval)
		}
	}
	approved, err := cm.readyHandoff()
	require.NoError(t, err)
	require.Equal(t, plan.Body, approved.plan.Body)
	parent := cm.blockStore.GetHighQc()
	records, err := cm.handoffRecordsForRound(parent.GetRound()+1, parent)
	require.NoError(t, err)
	require.Len(t, records, 1)
	prepared, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "prepare", prepared.Kind)
	require.GreaterOrEqual(t, prepared.ActivationRound, prepared.OrderedRound+8)
	cm.leaderSelector = constLeader{leader: cm.id}
	cm.pacemaker.Reset(ctx, parent.GetRound(), nil, nil)
	shard := types.PartitionShardID{PartitionID: 8}
	cm.irReqBuffer.irChgReqBuffer[shard] = &irChange{Req: &rctypes.IRChangeReq{Partition: 8, CertReason: rctypes.Quorum}, InputRecord: &types.InputRecord{Version: 1}}
	cm.processNewRoundEvent(ctx)
	proposal := testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.Len(t, proposal.Block.Payload.HandoffRecords, 1)
	require.Empty(t, proposal.Block.Payload.Requests)
	require.NotEmpty(t, cm.irReqBuffer.irChgReqBuffer, "handoff proposal retains buffered shard work")
	aborted := *state
	abortedHead := *state.CommittedHead
	abortedControl := *abortedHead.Control
	abortedControl.Phase = "aborted"
	abortedControl.Attempt = 0
	abortedHead.Control = &abortedControl
	aborted.CommittedHead = &abortedHead
	retry, err := cm.buildHandoffPlanFromState(&next, parentHash, &aborted, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, retry.Attempt)
	require.NotEqual(t, plan.Body, retry.Body, "attempt+1 binds a new body and FrozenID")
	abortedHead.Control.Attempt = ^uint64(0)
	_, err = cm.buildHandoffPlanFromState(&next, parentHash, &aborted, nil)
	require.ErrorIs(t, err, ErrHandoffApproval, "retry refuses attempt overflow")
}

func TestLeaderAbortsWhenEVMAdvancesPastFrozenParent(t *testing.T) {
	ctx := context.Background()
	node := testutils.NewTestNode(t)
	obs := testobservability.Default(t)
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), obs.Logger(), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, orchestration.Close()) })
	old := testtrustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{node.PeerConf.ID.String(): node.Signer}).(*types.RootTrustBaseV1)
	store, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, store.Store(old))
	identity := sha256.Sum256([]byte("leader-abort-test"))
	history, err := trusthistorystore.Open(ctx, memorydb.New(), old, identity, trustactivation.Verifier{})
	require.NoError(t, err)
	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff
	cm, err := NewConsensusManager(node.PeerConf.ID, store, orchestration, testnetwork.NewRootMockNetwork(), node.Signer, db, obs,
		WithConsensusParams(params), WithRecoveryProfile2(history))
	require.NoError(t, err)

	frozenParent := bytes.Repeat([]byte{0x42}, 32)
	parentQC := cm.blockStore.GetHighQc()
	parent, err := cm.blockStore.Block(parentQC.GetRound())
	require.NoError(t, err)
	shardKey := types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}
	parent.ShardState.States[shardKey] = &storage.ShardInfo{IR: &types.InputRecord{BlockHash: bytes.Clone(frozenParent)}}
	verifier, err := node.Signer.Verifier()
	require.NoError(t, err)
	key, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	require.NoError(t, orchestration.AddShardConfig(&types.PartitionDescriptionRecord{Version: 1,
		NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256, EpochStart: 1, T2Timeout: 5 * time.Second,
		Validators: []*types.NodeInfo{{NodeID: node.PeerConf.ID.String(), SigKey: key, Stake: 1}}}))
	previous := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: parentQC.GetRound(),
		PredecessorBodyID: make([]byte, 32), NextBodyID: bytes.Repeat([]byte{1}, 32),
		FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), ActivationRound: 9, Kind: "prepare"}
	parent.ShardState.Control.Phase = "prepared"
	parent.ShardState.Control.RecordBytes = previous.Bytes()
	cm.handoffPlans = map[[32]byte]*pendingHandoff{{}: {
		plan:   abdrc.HandoffApprovalMsg{Body: bytes.Repeat([]byte{2}, 32), FrozenParent: frozenParent},
		record: previous, signatures: map[string]hex.Bytes{node.PeerConf.ID.String(): {1}},
		abortSignatures: map[string]hex.Bytes{node.PeerConf.ID.String(): {2}}, weight: old.QuorumThreshold,
	}}

	// A matching committed tip permits Freeze. Moving only that tip makes
	// the leader choose the already endorsed Abort in the same phase.
	records, err := cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
	require.NoError(t, err)
	require.Len(t, records, 2)
	freeze, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "freeze", freeze.Kind)
	parent.ShardState.States[shardKey].IR.BlockHash = bytes.Repeat([]byte{0x43}, 32)
	records, err = cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
	require.NoError(t, err)
	require.Len(t, records, 2)
	abort, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "abort", abort.Kind)
	require.Equal(t, previous.Attempt, abort.Attempt)
	require.Equal(t, parentQC.GetRound()+1, abort.OrderedRound)
	var authorization storage.AbortAuthorization
	require.NoError(t, types.Cbor.Unmarshal(records[1], &authorization))
	require.EqualValues(t, 1, authorization.Version)
	require.Equal(t, hex.Bytes{2}, authorization.Signatures[node.PeerConf.ID.String()])

	// The endorsed branch carries an unrelated aggregator shard. Commit must
	// bind H to the frozen EVM assignment rather than the map's only entry.
	aggKey := types.PartitionShardID{PartitionID: 9, ShardID: (types.ShardID{}).Key()}
	require.NoError(t, orchestration.AddShardConfig(&types.PartitionDescriptionRecord{Version: 1,
		NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256, EpochStart: 1, T2Timeout: 5 * time.Second,
		Validators: []*types.NodeInfo{{NodeID: node.PeerConf.ID.String(), SigKey: key, Stake: 1}}}))
	parent.ShardState.States[shardKey].IR.BlockHash = bytes.Clone(frozenParent)
	parent.ShardState.States[shardKey].TR.Round = 3
	parent.ShardState.States[shardKey].TR.Leader = "evm"
	parent.ShardState.States[aggKey] = &storage.ShardInfo{IR: &types.InputRecord{BlockHash: bytes.Repeat([]byte{0x51}, 32)}}
	parent.ShardState.States[aggKey].TR.Round = 4
	parent.ShardState.States[aggKey].TR.Leader = "aggregator"
	previous.Kind = "freeze"
	previous.FrozenID = bytes.Repeat([]byte{0x52}, 32)
	parent.ShardState.Control.Phase = "endorsed"
	parent.ShardState.Control.FrozenParent = bytes.Clone(frozenParent)
	parent.ShardState.Control.RecordBytes = previous.Bytes()
	for _, plan := range cm.handoffPlans {
		plan.record.FrozenID = bytes.Clone(previous.FrozenID)
	}
	records, err = cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
	require.NoError(t, err)
	require.Len(t, records, 1)
	commit, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "commit", commit.Kind)
	evmTR, err := parent.ShardState.States[shardKey].TR.Hash()
	require.NoError(t, err)
	require.Equal(t, evmTR, []byte(commit.SuccessorTRHash))
	aggTR, err := parent.ShardState.States[aggKey].TR.Hash()
	require.NoError(t, err)
	require.NotEqual(t, aggTR, []byte(commit.SuccessorTRHash))
}

func newExplicitAbortFixture(t *testing.T, phase ...string) (*ConsensusManager, *testnetwork.MockNet, []*testutils.TestNode, abdrc.HandoffAbortTarget, evmroot.OrderedHandoffRecord) {
	t.Helper()
	ctx := context.Background()
	nodes := []*testutils.TestNode{testutils.NewTestNode(t), testutils.NewTestNode(t), testutils.NewTestNode(t), testutils.NewTestNode(t)}
	obs := testobservability.Default(t)
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), obs.Logger(), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, orchestration.Close()) })
	signers := make(map[string]abcrypto.Signer, len(nodes))
	for _, node := range nodes {
		signers[node.PeerConf.ID.String()] = node.Signer
	}
	old := testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
	store, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, store.Store(old))
	identity := sha256.Sum256([]byte("operator-abort-test"))
	history, err := trusthistorystore.Open(ctx, memorydb.New(), old, identity, trustactivation.Verifier{})
	require.NoError(t, err)
	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff
	net := testnetwork.NewRootMockNetwork()
	cm, err := NewConsensusManager(nodes[0].PeerConf.ID, store, orchestration, net, nodes[0].Signer, db, obs,
		WithConsensusParams(params), WithRecoveryProfile2(history))
	require.NoError(t, err)
	predecessor, err := cm.handoffPredecessor()
	require.NoError(t, err)
	parentQC := cm.blockStore.GetHighQc()
	parent, err := cm.blockStore.Block(parentQC.GetRound())
	require.NoError(t, err)
	record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: 0,
		OrderedRound: parentQC.GetRound(), ActivationRound: parentQC.GetRound() + 8,
		PredecessorBodyID: predecessor, NextBodyID: bytes.Repeat([]byte{0x6a}, 32),
		FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: "prepare"}
	controlPhase := "prepared"
	if len(phase) > 0 {
		controlPhase = phase[0]
	}
	frozenParent := make([]byte, 0)
	if controlPhase == "endorsed" {
		record.Kind = "freeze"
		record.FrozenID = bytes.Repeat([]byte{0x73}, 32)
		frozenParent = bytes.Repeat([]byte{0x74}, 32)
	}
	parent.ShardState.Control = &evmroot.ControlState{Network: record.Network, Epoch: record.Epoch,
		Attempt: record.Attempt, OrderedRound: record.OrderedRound, PredecessorBodyID: bytes.Clone(predecessor),
		Phase: controlPhase, RecordBytes: record.Bytes(), PreviousDigest: bytes.Repeat([]byte{0x71}, 32), FrozenParent: frozenParent}
	target := abdrc.HandoffAbortTarget{Network: record.Network, OldEpoch: record.Epoch,
		PredecessorBodyID: bytes.Clone(record.PredecessorBodyID), Attempt: record.Attempt,
		NextBodyID: bytes.Clone(record.NextBodyID)}
	return cm, net, nodes, target, record
}

func TestExplicitAbortPrioritizesEndorsedPhaseWithoutPlanCache(t *testing.T) {
	cm, _, nodes, target, record := newExplicitAbortFixture(t, "endorsed")
	_, err := cm.SubmitHandoffAbort(context.Background(), target)
	require.NoError(t, err)
	domain, err := storage.AbortEndorsementBytes(record)
	require.NoError(t, err)
	for _, node := range nodes[1:3] {
		signature, signErr := node.Signer.SignBytes(domain)
		require.NoError(t, signErr)
		require.NoError(t, cm.onHandoffAbortApprovalMsg(&abdrc.HandoffAbortApprovalMsg{
			Network: target.Network, OldEpoch: target.OldEpoch, PredecessorBodyID: target.PredecessorBodyID,
			Attempt: target.Attempt, NextBodyID: target.NextBodyID, Signer: node.PeerConf.ID.String(), Signature: signature,
		}))
	}
	cm.handoffPlans = nil
	parentQC := cm.blockStore.GetHighQc()
	records, err := cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
	require.NoError(t, err)
	require.Len(t, records, 2)
	ordered, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "abort", ordered.Kind)
}

func TestLeaderDoesNotBuildAbortAfterCommittedH(t *testing.T) {
	cm, _, _, target, record := newExplicitAbortFixture(t)
	parentQC := cm.blockStore.GetHighQc()
	parent, err := cm.blockStore.Block(parentQC.GetRound())
	require.NoError(t, err)
	record.Kind = "commit"
	record.FrozenID = bytes.Repeat([]byte{0x73}, 32)
	record.SuccessorTRHash = bytes.Repeat([]byte{0x74}, 32)
	parent.ShardState.Control.Phase = "committed"
	parent.ShardState.Control.RecordBytes = record.Bytes()
	key, err := handoffAbortKeyFor(target)
	require.NoError(t, err)
	cm.handoffAborts = map[handoffAbortKey]*pendingHandoffAbort{key: {
		target: target, signatures: map[string]hex.Bytes{"old-quorum": {1}}, weight: cm.trustBase.Load().QuorumThreshold,
	}}
	records, err := cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
	require.NoError(t, err)
	require.Empty(t, records, "a quorum cached before H cannot make the leader build an Abort after H")
}

func TestExplicitAbortQuorumPrioritizesRecordWithoutHandoffPlanCache(t *testing.T) {
	ctx := context.Background()
	cm, net, nodes, target, record := newExplicitAbortFixture(t)
	status, err := cm.SubmitHandoffAbort(ctx, target)
	require.NoError(t, err)
	require.Equal(t, "pending", status.State, "HTTP submission is not consensus finality")
	var local *abdrc.HandoffAbortApprovalMsg
	for _, sent := range net.SentMessages(network.ProtocolRootHandoffAbort) {
		if sent.ID == nodes[1].PeerConf.ID {
			local = sent.Message.(*abdrc.HandoffAbortApprovalMsg)
			break
		}
	}
	require.NotNil(t, local, "operator approval is broadcast to old validators")
	require.NoError(t, cm.onHandoffAbortApprovalMsg(local), "duplicate approval is idempotent")
	if signatures, ready := cm.readyHandoffAbort(target); ready {
		t.Fatalf("one old-validator signature unexpectedly reached quorum: %v", signatures)
	}
	domain, err := storage.AbortEndorsementBytes(record)
	require.NoError(t, err)
	for _, node := range nodes[1:3] {
		signature, signErr := node.Signer.SignBytes(domain)
		require.NoError(t, signErr)
		msg := &abdrc.HandoffAbortApprovalMsg{Network: target.Network, OldEpoch: target.OldEpoch,
			PredecessorBodyID: bytes.Clone(target.PredecessorBodyID), Attempt: target.Attempt,
			NextBodyID: bytes.Clone(target.NextBodyID), Signer: node.PeerConf.ID.String(), Signature: signature}
		require.NoError(t, cm.onHandoffAbortApprovalMsg(msg))
	}
	signatures, ready := cm.readyHandoffAbort(target)
	require.True(t, ready, "threshold comes from the configured old trust base")
	require.Len(t, signatures, 3)
	cm.handoffAborts = nil // a process restart loses approvals but retains ordered control state
	status, err = cm.SubmitHandoffAbort(ctx, target)
	require.NoError(t, err, "operator resubmission revalidates the still-pre-H control state")
	for _, node := range nodes[1:3] {
		signature, signErr := node.Signer.SignBytes(domain)
		require.NoError(t, signErr)
		msg := &abdrc.HandoffAbortApprovalMsg{Network: target.Network, OldEpoch: target.OldEpoch,
			PredecessorBodyID: bytes.Clone(target.PredecessorBodyID), Attempt: target.Attempt,
			NextBodyID: bytes.Clone(target.NextBodyID), Signer: node.PeerConf.ID.String(), Signature: signature}
		require.NoError(t, cm.onHandoffAbortApprovalMsg(msg))
	}
	_, ready = cm.readyHandoffAbort(target)
	require.True(t, ready, "retained operator input can recollect quorum after cache loss")
	cm.handoffPlans = nil // simulate restart/cache loss for the volatile plan
	parentQC := cm.blockStore.GetHighQc()
	records, err := cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
	require.NoError(t, err)
	require.Len(t, records, 2)
	abort, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "abort", abort.Kind)
	require.EqualValues(t, target.Attempt, abort.Attempt)
	require.Equal(t, target.NextBodyID, abort.NextBodyID)
	var proof storage.AbortAuthorization
	require.NoError(t, types.Cbor.Unmarshal(records[1], &proof))
	require.Len(t, proof.Signatures, 3)
}

func TestExplicitAbortRejectsWrongTarget(t *testing.T) {
	cm, _, _, target, _ := newExplicitAbortFixture(t)
	signature, err := cm.safety.signer.SignBytes([]byte("test signature"))
	require.NoError(t, err)
	tests := []struct {
		name   string
		mutate func(*abdrc.HandoffAbortTarget)
	}{
		{"network", func(target *abdrc.HandoffAbortTarget) { target.Network++ }},
		{"old epoch", func(target *abdrc.HandoffAbortTarget) { target.OldEpoch++ }},
		{"predecessor", func(target *abdrc.HandoffAbortTarget) { target.PredecessorBodyID = bytes.Repeat([]byte{0x6b}, 32) }},
		{"attempt", func(target *abdrc.HandoffAbortTarget) { target.Attempt++ }},
		{"successor body", func(target *abdrc.HandoffAbortTarget) { target.NextBodyID = bytes.Repeat([]byte{0x6b}, 32) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrong := target
			wrong.PredecessorBodyID = bytes.Clone(target.PredecessorBodyID)
			wrong.NextBodyID = bytes.Clone(target.NextBodyID)
			tt.mutate(&wrong)
			err := cm.onHandoffAbortApprovalMsg(&abdrc.HandoffAbortApprovalMsg{Network: wrong.Network, OldEpoch: wrong.OldEpoch,
				PredecessorBodyID: wrong.PredecessorBodyID, Attempt: wrong.Attempt, NextBodyID: wrong.NextBodyID,
				Signer: cm.id.String(), Signature: signature})
			require.ErrorIs(t, err, ErrHandoffAbortTarget)
		})
	}
}

func TestExplicitAbortRejectsOutsiderSignature(t *testing.T) {
	cm, _, _, target, record := newExplicitAbortFixture(t)
	outsider := testutils.NewTestNode(t)
	domain, err := storage.AbortEndorsementBytes(record)
	require.NoError(t, err)
	signature, err := outsider.Signer.SignBytes(domain)
	require.NoError(t, err)
	err = cm.onHandoffAbortApprovalMsg(&abdrc.HandoffAbortApprovalMsg{Network: target.Network, OldEpoch: target.OldEpoch,
		PredecessorBodyID: target.PredecessorBodyID, Attempt: target.Attempt, NextBodyID: target.NextBodyID,
		Signer: outsider.PeerConf.ID.String(), Signature: signature})
	require.ErrorIs(t, err, ErrHandoffAbortSignature)
}

func TestExplicitAbortIsIdempotentAndTooLateAfterCommit(t *testing.T) {
	ctx := context.Background()
	cm, _, _, target, record := newExplicitAbortFixture(t)
	root := cm.blockStore.GetHighQc()
	parent, err := cm.blockStore.Block(root.GetRound())
	require.NoError(t, err)
	record.Kind = "abort"
	record.OrderedRound = root.GetRound()
	parent.ShardState.Control = &evmroot.ControlState{Network: target.Network, Epoch: target.OldEpoch,
		Attempt: target.Attempt, OrderedRound: record.OrderedRound, PredecessorBodyID: target.PredecessorBodyID,
		Phase: "aborted", RecordBytes: record.Bytes(), PreviousDigest: bytes.Repeat([]byte{0x72}, 32)}
	status, err := cm.SubmitHandoffAbort(ctx, target)
	require.NoError(t, err)
	require.Equal(t, "committed", status.State)
	require.Empty(t, cm.handoffAborts, "a repeated request for the committed Abort does not create a new approval")
	record.Kind = "commit"
	parent.ShardState.Control.Phase = "committed"
	parent.ShardState.Control.RecordBytes = record.Bytes()
	status, err = cm.HandoffAbortStatus(target)
	require.NoError(t, err)
	require.Equal(t, "too_late", status.State)
	_, err = cm.SubmitHandoffAbort(ctx, target)
	require.ErrorIs(t, err, ErrHandoffAbortTarget, "a committed H cannot be rewound by a late operator request")
}
