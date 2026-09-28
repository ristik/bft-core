package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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
	require.Error(t, err, "the operator cannot freeze an uncertified EVM parent")
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{IR: &types.InputRecord{BlockHash: parentHash}}}
	plan, err := cm.buildHandoffPlanFromState(&next, parentHash, state)
	require.NoError(t, err)
	bad := plan
	bad.FrozenParent = bytes.Repeat([]byte{8}, 32)
	require.Error(t, cm.EndorseHandoff(ctx, bad))
	cm.handoffPlans = make(map[[32]byte]*pendingHandoff)
	for i := byte(1); i <= 4; i++ {
		cm.handoffPlans[[32]byte{i}] = &pendingHandoff{signatures: make(map[string]hex.Bytes)}
	}
	require.NoError(t, cm.EndorseHandoff(ctx, plan))
	require.Len(t, cm.handoffPlans, 4)
	_, err = cm.readyHandoff()
	require.Error(t, err, "one signature cannot authorize a four-validator handoff")
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	id := body.Identity()
	domain, err := storage.EndorsementBytes(cm.handoffPlans[id].record)
	require.NoError(t, err)
	for i, other := range others[:2] {
		signed := plan
		signed.Signer = other.PeerConf.ID.String()
		signed.Signature, err = other.Signer.SignBytes(domain)
		require.NoError(t, err)
		require.NoError(t, cm.onHandoffApprovalMsg(ctx, &signed))
		require.NoError(t, cm.onHandoffApprovalMsg(ctx, &signed), "duplicate endorsement is idempotent")
		if i == 0 {
			_, err = cm.readyHandoff()
			require.Error(t, err)
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
}
