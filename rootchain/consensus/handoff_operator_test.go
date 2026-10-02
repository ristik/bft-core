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
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// Prepare comes before endorsement: the plan names no EVM parent, the leader orders a Prepare for the intent, the ROOT binds the
// frozen parent there, and validators endorse only that Prepare-bound state.
type planFixture struct {
	cm         *ConsensusManager
	node       *testutils.TestNode
	others     []*testutils.TestNode
	old        *types.RootTrustBaseV1
	next       types.RootTrustBaseV1
	parentHash []byte
	mockNet    *testnetwork.MockNet
}

// newPlanFixture is a four-validator root with a designated EVM shard and a next trust base that replaces one member.
func newPlanFixture(t *testing.T) *planFixture {
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
	nodeVerifier, err := node.Signer.Verifier()
	require.NoError(t, err)
	nodeKey, err := nodeVerifier.MarshalPublicKey()
	require.NoError(t, err)
	require.NoError(t, orchestration.InitGenesisShardConfigs(&types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8,
		PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256, EpochStart: 1, T2Timeout: 5 * time.Second,
		Validators: []*types.NodeInfo{{NodeID: node.PeerConf.ID.String(), SigKey: nodeKey, Stake: 1}}}))
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

	return &planFixture{cm: cm, node: node, others: others, old: old, next: next, parentHash: parentHash, mockNet: mockNet}
}

func TestOperatorHandoffPreparesBeforeEndorsement(t *testing.T) {
	ctx := context.Background()
	f := newPlanFixture(t)
	cm, node, others, old, next, parentHash, mockNet := f.cm, f.node, f.others, f.old, f.next, f.parentHash, f.mockNet
	_, _, _ = node, old, mockNet
	_, err := cm.PlanHandoff(&next, nil)
	require.ErrorIs(t, err, ErrHandoffApproval, "no certified EVM shard in the committed state: nothing to plan for")
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: parentHash}}}
	plan, err := cm.buildHandoffPlanFromState(&next, state, nil)
	require.NoError(t, err)
	require.Empty(t, plan.FrozenParent, "the plan binds no EVM parent: the root binds it at Prepare")
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	id := body.Identity()

	t.Run("endorsement before Prepare is refused", func(t *testing.T) {
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, plan, state), ErrEndorseBeforePrepare)
		withParent := plan
		withParent.FrozenParent = bytes.Clone(parentHash) // naming the current tip does not make the handoff prepared
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, withParent, state), ErrEndorseBeforePrepare)
	})

	t.Run("the leader orders Prepare for the held intent only", func(t *testing.T) {
		parentQC := cm.blockStore.GetHighQc()
		records, err := cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
		require.NoError(t, err)
		require.Empty(t, records, "no intent held: no Prepare")
		stale := plan
		stale.Attempt = 3
		cm.setHandoffIntent(stale)
		records, err = cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
		require.NoError(t, err)
		require.Empty(t, records, "an intent for another attempt is dead")
		cm.setHandoffIntent(plan)
		records, err = cm.handoffRecordsForRound(parentQC.GetRound()+1, parentQC)
		require.NoError(t, err)
		require.Len(t, records, 1, "Prepare alone: no endorsement exists yet")
		prepare, err := storage.DecodeOrderedHandoffRecord(records[0])
		require.NoError(t, err)
		require.Equal(t, "prepare", prepare.Kind)
		require.Equal(t, id[:], []byte(prepare.NextBodyID))
		require.GreaterOrEqual(t, prepare.ActivationRound, prepare.OrderedRound+storage.PrepareFreezeLapseRounds+8,
			"the activation leaves the whole endorsement window")
	})

	// The Prepare as the executor leaves it: control "prepared", the frozen parent bound by the root.
	prepareRecord := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: state.CommittedHead.Block.Round + 1,
		ActivationRound: state.CommittedHead.Block.Round + 1 + storage.PrepareFreezeLapseRounds + 8, PredecessorBodyID: bytes.Clone(state.CommittedHead.Control.PredecessorBodyID),
		NextBodyID: id[:], FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: "prepare"}
	preparedWith := func(mutate func(*evmroot.ControlState)) *abdrc.StateMsg {
		control := *state.CommittedHead.Control
		control.Phase, control.OrderedRound, control.RecordBytes = "prepared", prepareRecord.OrderedRound, prepareRecord.Bytes()
		control.PreviousDigest, control.FrozenParent = bytes.Repeat([]byte{9}, 32), bytes.Clone(parentHash)
		if mutate != nil {
			mutate(&control)
		}
		cp := *state
		head := *state.CommittedHead
		head.Control = &control
		cp.CommittedHead = &head
		return &cp
	}
	prepared := preparedWith(nil)

	t.Run("endorsed parent must be the Prepare-bound parent", func(t *testing.T) {
		bad := plan
		bad.FrozenParent = bytes.Repeat([]byte{8}, 32)
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, bad, prepared), ErrEndorsedParentMismatch)
	})
	t.Run("endorsed plan must be the prepared one", func(t *testing.T) {
		other := *old
		other.Epoch = 2
		other.RootNodes = append([]*types.NodeInfo(nil), next.RootNodes...)
		other.RootNodes[2] = other.RootNodes[3]
		otherPlan, err := cm.buildHandoffPlanFromState(&next, state, nil)
		require.NoError(t, err)
		otherPlan.Body = append(bytes.Clone(otherPlan.Body[:len(otherPlan.Body)-1]), otherPlan.Body[len(otherPlan.Body)-1]^1)
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, otherPlan, prepared), ErrEndorsedPlanMismatch)
		nextAttempt := plan
		nextAttempt.Attempt = 1
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, nextAttempt, prepared), ErrEndorseBeforePrepare,
			"a plan for the next attempt waits for its own Prepare")
		overtaken := preparedWith(func(c *evmroot.ControlState) { c.Attempt = 1 })
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, plan, overtaken), ErrEndorsedPlanMismatch,
			"a plan for an attempt that is already over is never endorsed")
		frozen := preparedWith(func(c *evmroot.ControlState) { c.Phase = "endorsed" })
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, plan, frozen), ErrEndorseAfterFreeze, "nothing is left to endorse once frozen")
		committed := preparedWith(func(c *evmroot.ControlState) { c.Phase = "committed" })
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, plan, committed), ErrEndorseAfterFreeze)
	})
	t.Run("endorsement after the freeze lapsed is refused", func(t *testing.T) {
		lapsed := preparedWith(nil)
		head := *lapsed.CommittedHead
		blockCopy := *head.Block
		blockCopy.Round = prepareRecord.OrderedRound + storage.PrepareFreezeLapseRounds + 1
		head.Block = &blockCopy
		lapsed.CommittedHead = &head
		require.ErrorIs(t, cm.endorseHandoffAtState(ctx, plan, lapsed), ErrPrepareLapsed)
		at := *lapsed.CommittedHead
		atBlock := *at.Block
		atBlock.Round = prepareRecord.OrderedRound + storage.PrepareFreezeLapseRounds
		at.Block = &atBlock
		last := *lapsed
		last.CommittedHead = &at
		require.NoError(t, cm.endorseHandoffAtState(ctx, plan, &last), "the last round of the window still endorses")
		cm.handoffPlans = nil
	})

	cm.handoffPlans = make(map[[32]byte]*pendingHandoff)
	for i := byte(1); i <= 4; i++ {
		cm.handoffPlans[[32]byte{i}] = &pendingHandoff{signatures: make(map[string]hex.Bytes)}
	}
	require.NoError(t, cm.endorseHandoffAtState(ctx, plan, prepared))
	require.Len(t, cm.handoffPlans, 4)
	stored := cm.handoffPlans[id]
	require.Equal(t, parentHash, []byte(stored.plan.FrozenParent), "the endorsement carries the Prepare-bound parent")
	require.Equal(t, prepareRecord.ActivationRound, stored.plan.ActivationRound, "and the Prepare's activation round")
	_, err = cm.readyHandoff()
	require.ErrorIs(t, err, ErrHandoffApproval, "one signature cannot authorize a four-validator handoff")
	domain, err := storage.EndorsementBytes(stored.record)
	require.NoError(t, err)
	abortDomain, err := storage.AbortEndorsementBytes(stored.record)
	require.NoError(t, err)
	endorsed := stored.plan
	for i, other := range others[:2] {
		signed := endorsed
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

	// With a quorum of endorsements of the PREPARED state, the leader orders the Freeze that names the bound parent.
	parentQC := cm.blockStore.GetHighQc()
	parentBlock, err := cm.blockStore.Block(parentQC.GetRound())
	require.NoError(t, err)
	parentBlock.ShardState.Control = prepared.CommittedHead.Control
	parentBlock.ShardState.States[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}] = &storage.ShardInfo{IR: &types.InputRecord{BlockHash: bytes.Clone(parentHash)}}
	records, err := cm.handoffRecordsForRound(prepared.CommittedHead.Control.OrderedRound+1, parentQC)
	require.NoError(t, err)
	require.Len(t, records, 2)
	freeze, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "freeze", freeze.Kind)
	require.Equal(t, prepareRecord.ActivationRound, freeze.ActivationRound)
	companion, err := storage.ParseFreezeCompanion(records[1])
	require.NoError(t, err)
	require.Equal(t, parentHash, []byte(companion.Parent))
	// A Freeze whose companion names another parent is never ordered.
	for _, p := range cm.handoffPlans {
		p.plan.FrozenParent = bytes.Repeat([]byte{8}, 32)
	}
	records, err = cm.handoffRecordsForRound(prepared.CommittedHead.Control.OrderedRound+1, parentQC)
	require.NoError(t, err)
	require.Empty(t, records)
	for _, p := range cm.handoffPlans {
		p.plan.FrozenParent = bytes.Clone(parentHash)
	}
	// After the lapse the leader orders nothing for the dead attempt, and the next attempt number is planned.
	lapsedRound := prepared.CommittedHead.Control.OrderedRound + storage.PrepareFreezeLapseRounds + 1
	records, err = cm.handoffRecordsForRound(lapsedRound, parentQC)
	require.NoError(t, err)
	require.Empty(t, records, "no Freeze for a lapsed Prepare, and no new Prepare before the cooldown")

	// Retry after an abort, or after a lapse: attempt+1.
	aborted := *state
	abortedHead := *state.CommittedHead
	abortedControl := *abortedHead.Control
	abortedControl.Phase = "aborted"
	abortedControl.Attempt = 0
	abortedHead.Control = &abortedControl
	aborted.CommittedHead = &abortedHead
	retry, err := cm.buildHandoffPlanFromState(&next, &aborted, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, retry.Attempt)
	require.NotEqual(t, plan.Body, retry.Body, "attempt+1 binds a new body and FrozenID")
	abortedHead.Control.Attempt = ^uint64(0)
	_, err = cm.buildHandoffPlanFromState(&next, &aborted, nil)
	require.ErrorIs(t, err, ErrHandoffApproval, "retry refuses attempt overflow")
	lapsedState := preparedWith(nil)
	lapsedHead := *lapsedState.CommittedHead
	lapsedBlock := *lapsedHead.Block
	lapsedBlock.Round = prepareRecord.OrderedRound + storage.PrepareFreezeLapseRounds + 1
	lapsedHead.Block = &lapsedBlock
	lapsedState.CommittedHead = &lapsedHead
	retry, err = cm.buildHandoffPlanFromState(&next, lapsedState, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, retry.Attempt, "a lapsed Prepare is dead: the next plan is attempt+1")
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
	// The genesis set is one atomic initialization: the EVM shard and an unrelated aggregator shard (the endorsed branch carries it,
	// and Commit must bind H to the frozen EVM assignment rather than the map's only entry).
	require.NoError(t, orchestration.InitGenesisShardConfigs(
		&types.PartitionDescriptionRecord{Version: 1,
			NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256, EpochStart: 1, T2Timeout: 5 * time.Second,
			Validators: []*types.NodeInfo{{NodeID: node.PeerConf.ID.String(), SigKey: key, Stake: 1}}},
		&types.PartitionDescriptionRecord{Version: 1,
			NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256, EpochStart: 1, T2Timeout: 5 * time.Second,
			Validators: []*types.NodeInfo{{NodeID: node.PeerConf.ID.String(), SigKey: key, Stake: 1}}}))
	previous := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: parentQC.GetRound(),
		PredecessorBodyID: make([]byte, 32), NextBodyID: bytes.Repeat([]byte{1}, 32),
		FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), ActivationRound: 9, Kind: "prepare"}
	parent.ShardState.Control.Phase = "prepared"
	parent.ShardState.Control.RecordBytes = previous.Bytes()
	parent.ShardState.Control.FrozenParent = bytes.Clone(frozenParent) // bound by the root at Prepare
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

	aggKey := types.PartitionShardID{PartitionID: 9, ShardID: (types.ShardID{}).Key()}
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

// preparedControl is the control state the executor leaves after the Prepare of plan at the given round, with the bound parent.
func (f *planFixture) preparedControl(t *testing.T, base *evmroot.ControlState, plan abdrc.HandoffApprovalMsg, round uint64) *evmroot.ControlState {
	t.Helper()
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	id := body.Identity()
	record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: plan.Attempt, OrderedRound: round,
		ActivationRound: round + storage.PrepareActivationFloorRounds, PredecessorBodyID: bytes.Clone(base.PredecessorBodyID),
		NextBodyID: id[:], FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: "prepare"}
	control := *base
	control.Phase, control.Attempt, control.OrderedRound, control.RecordBytes = "prepared", plan.Attempt, round, record.Bytes()
	control.PreviousDigest, control.FrozenParent = bytes.Repeat([]byte{9}, 32), bytes.Clone(f.parentHash)
	return &control
}

func stateWith(state *abdrc.StateMsg, headRound uint64, control *evmroot.ControlState) *abdrc.StateMsg {
	cp := *state
	head := *state.CommittedHead
	block := *head.Block
	block.Round = headRound
	head.Block, head.Control = &block, control
	cp.CommittedHead = &head
	return &cp
}

// After a lapse the next attempt can still be planned AND endorsed: its endorsement waits (ErrEndorseBeforePrepare, never
// ErrPrepareLapsed, which belongs to the plan's own attempt) until the Prepare of the new attempt is committed, and then succeeds.
func TestLapseThenReplanEndorsesAtTheNextAttempt(t *testing.T) {
	ctx := context.Background()
	f := newPlanFixture(t)
	cm := f.cm
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: f.parentHash}}}
	idle := state.CommittedHead.Control
	plan0, err := cm.buildHandoffPlanFromState(&f.next, state, nil)
	require.NoError(t, err)
	require.EqualValues(t, 0, plan0.Attempt)

	const preparedAt = uint64(10)
	lapsedControl := f.preparedControl(t, idle, plan0, preparedAt)
	lapsed := stateWith(state, preparedAt+storage.PrepareFreezeLapseRounds+1, lapsedControl)
	require.ErrorIs(t, cm.endorseHandoffAtState(ctx, plan0, lapsed), ErrPrepareLapsed, "the lapsed attempt's own plan is dead")

	plan1, err := cm.buildHandoffPlanFromState(&f.next, lapsed, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, plan1.Attempt, "the lapse is treated like an abort for numbering")
	err = cm.endorseHandoffAtState(ctx, plan1, lapsed)
	require.ErrorIs(t, err, ErrEndorseBeforePrepare, "attempt 1 waits for its own Prepare, as the CLI's retry expects")
	require.NotErrorIs(t, err, ErrPrepareLapsed)

	// Prepare of attempt 1 is committed: now the same plan endorses.
	preparedAt1 := preparedAt + storage.PrepareFreezeLapseRounds + storage.PrepareCooldownRounds + 2
	prepared1 := stateWith(state, preparedAt1+3, f.preparedControl(t, idle, plan1, preparedAt1))
	cm.handoffPlans = nil
	require.NoError(t, cm.endorseHandoffAtState(ctx, plan1, prepared1))
	body, err := storage.DecodeHandoffBody(plan1.Body)
	require.NoError(t, err)
	id := body.Identity()
	require.Equal(t, f.parentHash, []byte(cm.handoffPlans[id].plan.FrozenParent))
	require.EqualValues(t, 1, cm.handoffPlans[id].plan.Attempt)
}

// A lapse (or an Abort) leaves no plan behind: a Prepare is ordered only for a live plan of the attempt, once. A dead operator's
// plan costs one more freeze window at most, never a cycle.
func TestNoPrepareIsOrderedAfterALapseWithoutANewPlan(t *testing.T) {
	f := newPlanFixture(t)
	cm := f.cm
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: f.parentHash}}}
	idle := *state.CommittedHead.Control
	plan0, err := cm.buildHandoffPlanFromState(&f.next, state, nil)
	require.NoError(t, err)

	parentQC := cm.blockStore.GetHighQc()
	parentBlock, err := cm.blockStore.Block(parentQC.GetRound())
	require.NoError(t, err)
	preparedAt := parentQC.GetRound()
	setControl := func(c *evmroot.ControlState) { parentBlock.ShardState.Control = c }
	order := func(round uint64) [][]byte {
		records, err := cm.handoffRecordsForRound(round, parentQC)
		require.NoError(t, err)
		return records
	}
	lapseEnd := preparedAt + storage.PrepareFreezeLapseRounds
	cooldownEnd := lapseEnd + storage.PrepareCooldownRounds

	// Attempt 0: the held intent is ordered once.
	setControl(&idle)
	cm.setHandoffIntent(plan0)
	require.Len(t, order(preparedAt+1), 1, "a live plan of the right attempt orders a Prepare")

	// Its Prepare is committed and then lapses.
	prepared0 := f.preparedControl(t, &idle, plan0, preparedAt)
	setControl(prepared0)
	require.Empty(t, order(preparedAt+2), "no second Prepare while the first is prepared")
	require.Nil(t, cm.pendingIntent(0), "the intent is spent by its Prepare")
	cm.setHandoffIntent(plan0)
	require.Nil(t, cm.pendingIntent(1), "an intent of attempt 0 is never taken for attempt 1")
	require.Empty(t, order(lapseEnd+1), "inside the cooldown nothing is ordered")
	require.Empty(t, order(cooldownEnd+1), "after the cooldown and a lapse, with no new plan, no Prepare is ordered (the dead plan is not reused)")
	require.Empty(t, order(cooldownEnd+10), "and it stays quiet")

	// A new plan for the next attempt is ordered once the cooldown is over, and not before.
	lapsed := stateWith(state, lapseEnd+1, prepared0)
	plan1, err := cm.buildHandoffPlanFromState(&f.next, lapsed, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, plan1.Attempt)
	cm.setHandoffIntent(plan1)
	require.Empty(t, order(lapseEnd+1), "the cooldown still applies")
	records := order(cooldownEnd + 1)
	require.Len(t, records, 1)
	prepare, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.EqualValues(t, 1, prepare.Attempt)

	// It is spent as well: once that Prepare is in the control state, a lapse of attempt 1 needs yet another plan.
	prepared1 := f.preparedControl(t, &idle, plan1, cooldownEnd+1)
	setControl(prepared1)
	require.Empty(t, order(cooldownEnd+2))
	require.Nil(t, cm.pendingIntent(1))
	require.Empty(t, order(cooldownEnd+1+storage.PrepareFreezeLapseRounds+storage.PrepareCooldownRounds+5), "no plan, no Prepare, however long")

	// An Abort retires the plan as well.
	cm.setHandoffIntent(plan1)
	aborted := idle
	aborted.Phase, aborted.Attempt = "aborted", 1
	setControl(&aborted)
	require.Empty(t, order(cooldownEnd+200), "attempt 1 was aborted: its plan is dead")
	require.Nil(t, cm.pendingIntent(1))
}

// One validator's endorsement naming a wrong parent or activation is rejected on its own: it does not take the plan's slot and does
// not keep the honest quorum from assembling.
func TestWrongParentEndorsementDoesNotBlockTheQuorum(t *testing.T) {
	ctx := context.Background()
	f := newPlanFixture(t)
	cm := f.cm
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: f.parentHash}}}
	idle := *state.CommittedHead.Control
	plan, err := cm.buildHandoffPlanFromState(&f.next, state, nil)
	require.NoError(t, err)
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	id := body.Identity()
	predecessor, err := cm.handoffPredecessor()
	require.NoError(t, err)

	parentQC := cm.blockStore.GetHighQc()
	parentBlock, err := cm.blockStore.Block(parentQC.GetRound())
	require.NoError(t, err)
	prepared := f.preparedControl(t, &idle, plan, parentQC.GetRound())

	signAs := func(who *testutils.TestNode, parent []byte, activation uint64) abdrc.HandoffApprovalMsg {
		msg := plan
		msg.FrozenParent, msg.ActivationRound, msg.Signer = bytes.Clone(parent), activation, who.PeerConf.ID.String()
		record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: plan.Attempt, OrderedRound: 1, ActivationRound: activation,
			PredecessorBodyID: predecessor, NextBodyID: id[:], Kind: "freeze",
			FrozenID: evmroot.D4FrozenID(id[:], body.StateSummary, parent, plan.Candidate, plan.Attempt, predecessor)}
		domain, err := storage.EndorsementBytes(record)
		require.NoError(t, err)
		abortDomain, err := storage.AbortEndorsementBytes(record)
		require.NoError(t, err)
		msg.Signature, err = who.Signer.SignBytes(domain)
		require.NoError(t, err)
		msg.AbortSignature, err = who.Signer.SignBytes(abortDomain)
		require.NoError(t, err)
		return msg
	}
	activation := prepared.OrderedRound + storage.PrepareActivationFloorRounds
	wrongParent := bytes.Repeat([]byte{0xee}, 32)

	t.Run("rejected against the bound parent", func(t *testing.T) {
		parentBlock.ShardState.Control = prepared
		cm.handoffPlans = nil
		bad := signAs(f.others[2], wrongParent, activation)
		require.ErrorIs(t, cm.onHandoffApprovalMsg(ctx, &bad), ErrEndorsedParentMismatch)
		badActivation := signAs(f.others[2], f.parentHash, activation+1)
		require.ErrorIs(t, cm.onHandoffApprovalMsg(ctx, &badActivation), ErrEndorsedParentMismatch)
		require.Empty(t, cm.handoffPlans, "a rejected endorsement takes no slot")
		for _, honest := range f.others[:2] {
			good := signAs(honest, f.parentHash, activation)
			require.NoError(t, cm.onHandoffApprovalMsg(ctx, &good))
		}
		ready, err := cm.readyHandoff(plan.Attempt)
		require.Error(t, err, "two of four is not yet a quorum")
		require.Nil(t, ready)
		require.Len(t, cm.handoffPlans[id].signatures, 2)
	})
	t.Run("a slot taken before the Prepare was known here is not kept", func(t *testing.T) {
		parentBlock.ShardState.Control = &idle // this validator has not committed the Prepare yet
		cm.handoffPlans = nil
		early := signAs(f.others[2], wrongParent, activation)
		require.NoError(t, cm.onHandoffApprovalMsg(ctx, &early), "nothing to compare with yet")
		require.Equal(t, wrongParent, []byte(cm.handoffPlans[id].plan.FrozenParent))
		parentBlock.ShardState.Control = prepared // now it has
		good := signAs(f.others[0], f.parentHash, activation)
		require.NoError(t, cm.onHandoffApprovalMsg(ctx, &good), "the honest endorsement replaces the bogus slot")
		require.Equal(t, f.parentHash, []byte(cm.handoffPlans[id].plan.FrozenParent))
		require.Len(t, cm.handoffPlans[id].signatures, 1)
		require.Contains(t, cm.handoffPlans[id].signatures, f.others[0].PeerConf.ID.String())
	})
}

// The leader-side cooldown: a validator holding a live plan for the next attempt orders no Prepare while the lapsed Prepare's
// cooldown runs (voters would refuse it, wasting the leader's round), at its exact last round either, and orders exactly one the
// round after.
func TestLeaderOrdersNoPrepareDuringTheCooldownAndOneAfterIt(t *testing.T) {
	f := newPlanFixture(t)
	cm := f.cm
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: f.parentHash}}}
	idle := *state.CommittedHead.Control
	plan0, err := cm.buildHandoffPlanFromState(&f.next, state, nil)
	require.NoError(t, err)

	parentQC := cm.blockStore.GetHighQc()
	parentBlock, err := cm.blockStore.Block(parentQC.GetRound())
	require.NoError(t, err)
	preparedAt := parentQC.GetRound()
	prepared0 := f.preparedControl(t, &idle, plan0, preparedAt)
	parentBlock.ShardState.Control = prepared0
	lapsed := stateWith(state, preparedAt+storage.PrepareFreezeLapseRounds+1, prepared0)
	plan1, err := cm.buildHandoffPlanFromState(&f.next, lapsed, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, plan1.Attempt)
	cm.setHandoffIntent(plan1)
	order := func(round uint64) [][]byte {
		records, err := cm.handoffRecordsForRound(round, parentQC)
		require.NoError(t, err)
		return records
	}
	lapseEnd := preparedAt + storage.PrepareFreezeLapseRounds
	cooldownEnd := lapseEnd + storage.PrepareCooldownRounds

	require.Empty(t, order(lapseEnd), "the freeze has not lapsed yet at its last round: nothing is ordered over a live Prepare")
	for _, round := range []uint64{lapseEnd + 1, lapseEnd + storage.PrepareCooldownRounds/2, cooldownEnd} {
		require.Empty(t, order(round), "round %d is inside the cooldown (lapse ends at %d, cooldown at %d)", round, lapseEnd, cooldownEnd)
	}
	records := order(cooldownEnd + 1)
	require.Len(t, records, 1, "the first round after the cooldown orders the next attempt's Prepare")
	prepare, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.EqualValues(t, 1, prepare.Attempt)
}
