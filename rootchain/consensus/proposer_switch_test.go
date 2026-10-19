package consensus

import (
	"bytes"
	"context"
	"crypto"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A leader never proposes a request, or a T2 timeout request, for a shard whose configuration switches in the block it proposes (the
// executor refuses such a block whole, which would stall the chain at exactly the switch), and keeps the other shards' progress.
// Both exclusions are exercised on their own: the buffered requests (IrReqBuffer.Drop) and the timeouts (the generator's skip).

const otherPartition types.PartitionID = 0x00AB0001

func bufferRequest(cm *ConsensusManager, partition types.PartitionID) types.PartitionShardID {
	key := types.PartitionShardID{PartitionID: partition, ShardID: types.ShardID{}.Key()}
	cm.irReqBuffer.irChgReqBuffer[key] = &irChange{Req: &rctypes.IRChangeReq{Partition: partition, CertReason: rctypes.Quorum}, InputRecord: &types.InputRecord{Version: 1}}
	return key
}

// dueTimeouts replaces the manager's timeout generator by one over a state in which the given partitions are overdue (T2 passed long ago).
func dueTimeouts(t *testing.T, cm *ConsensusManager, partitions ...types.PartitionID) {
	t.Helper()
	var ucs []*types.UnicityCertificate
	for _, p := range partitions {
		ucs = append(ucs, &types.UnicityCertificate{InputRecord: &types.InputRecord{}, UnicityTreeCertificate: &types.UnicityTreeCertificate{Partition: p},
			UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 1}})
	}
	state := &MockState{certificates: ucs, shardInfo: func(types.PartitionID, types.ShardID) *storage.ShardInfo {
		return &storage.ShardInfo{T2Timeout: time.Millisecond}
	}}
	gen, err := NewLucBasedT2TimeoutGenerator(&Parameters{BlockRate: 900 * time.Millisecond, NetworkProfileVersion: cm.params.NetworkProfileVersion}, state)
	require.NoError(t, err)
	cm.t2Timeouts = gen
}

func requestedPartitions(p *rctypes.Payload) map[types.PartitionID]rctypes.IRChangeReason {
	out := map[types.PartitionID]rctypes.IRChangeReason{}
	for _, r := range p.Requests {
		out[r.Partition] = r.CertReason
	}
	return out
}

// From an epoch-anchor parent: the first successor block switches the EVM shard (the assignment installs there).
func TestLeaderFromTheEpochAnchorExcludesTheSwitchingShard(t *testing.T) {
	evm := q3fixture.PartitionID
	prepare := func(t *testing.T) (*q3Replica, *rctypes.EpochAnchor) {
		c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
		anchor := c.activateAll()
		first, err := c.replicas[0].manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
		require.NoError(t, err)
		leader := c.byID(first)
		set, err := leader.manager.blockStore.SwitchingShardsForBlock(anchor.Slot, anchor.Slot+1)
		require.NoError(t, err)
		require.Contains(t, set, types.PartitionShardID{PartitionID: evm, ShardID: types.ShardID{}.Key()}, "premise: the EVM shard switches in the first successor block")
		return leader, anchor
	}
	t.Run("buffered requests", func(t *testing.T) {
		leader, _ := prepare(t)
		bufferRequest(leader.manager, evm)
		bufferRequest(leader.manager, otherPartition)
		leader.manager.processNewRoundEvent(context.Background())
		got := requestedPartitions(leader.net.WaitRootProposal(t).Block.Payload)
		require.NotContains(t, got, evm, "the switching shard's request is not proposed")
		require.Contains(t, got, otherPartition, "another shard's progress is")
	})
	t.Run("T2 timeouts", func(t *testing.T) {
		leader, _ := prepare(t)
		dueTimeouts(t, leader.manager, evm, otherPartition)
		leader.manager.processNewRoundEvent(context.Background())
		got := requestedPartitions(leader.net.WaitRootProposal(t).Block.Payload)
		require.NotContains(t, got, evm, "the switching shard's timeout is not proposed")
		require.Equal(t, rctypes.T2Timeout, got[otherPartition], "another shard's is")
	})
}

// From a QC parent: a shard scheduled to switch at the proposed round.
func TestLeaderFromAQCParentExcludesTheSwitchingShard(t *testing.T) {
	newLeader := func(t *testing.T) (*ConsensusManager, *testnetwork.MockNet, types.PartitionID, types.PartitionID) {
		net := testnetwork.NewRootMockNetwork()
		params := *NewConsensusParams()
		rootNode := testutils.NewTestNode(t)
		obs := testobservability.Default(t)
		dir := t.TempDir()
		db, err := storage.NewBoltStorage(filepath.Join(dir, "root.db"), storage.WithNoSync())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, db.Close()) })
		orchestration, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), obs.Logger(), partitions.WithNoSync())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, orchestration.Close()) })
		conf := func(partition types.PartitionID, epoch, start uint64) *types.PartitionDescriptionRecord {
			_, infos := testutils.CreateTestNodes(t, 3)
			return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partition, PartitionTypeID: 99, ShardID: types.ShardID{}, UnitIDLen: 256, TypeIDLen: 32,
				T2Timeout: 2500 * time.Millisecond, Epoch: epoch, EpochStart: start, Validators: infos}
		}
		switching, steady := types.PartitionID(0x00AA0001), otherPartition
		a0, b0 := conf(switching, 0, 1), conf(steady, 0, 1)
		for _, c := range []*types.PartitionDescriptionRecord{a0, conf(switching, 1, 30), b0} {
			require.NoError(t, orchestration.AddShardConfig(c))
		}
		tb := testtrustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{rootNode.PeerConf.ID.String(): rootNode.Signer})
		tbStore, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
		require.NoError(t, err)
		require.NoError(t, tbStore.Store(tb))
		cm, err := NewConsensusManager(rootNode.PeerConf.ID, tbStore, orchestration, net, rootNode.Signer, db, obs, WithConsensusParams(params))
		require.NoError(t, err)
		states := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{}, Changed: storage.ShardSet{}}
		var infos []abdrc.ShardInfo
		for _, c := range []*types.PartitionDescriptionRecord{a0, b0} {
			si, err := storage.NewShardInfo(c, crypto.SHA256)
			require.NoError(t, err)
			states.States[types.PartitionShardID{PartitionID: c.PartitionID, ShardID: c.ShardID.Key()}] = si
			infos = append(infos, abdrc.ShardInfo{Partition: si.PartitionID, Shard: si.ShardID, T2Timeout: si.T2Timeout, PrevEpochStat: si.PrevEpochStat,
				Stat: si.Stat, PrevEpochFees: si.PrevEpochFees, Fees: si.Fees, IR: si.IR, IRTR: si.TR, ShardConfHash: si.ShardConfHash})
		}
		tree, _, err := states.UnicityTree(crypto.SHA256)
		require.NoError(t, err)
		checkpoint := &abdrc.CommittedBlock{Block: &rctypes.BlockData{Version: 1, Round: 29, Epoch: 1, Payload: &rctypes.Payload{},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 28, Epoch: 1}}}, ShardInfo: infos,
			CommitQc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 29, ParentRoundNumber: 28, Epoch: 1, Timestamp: types.NewTimestamp()},
				LedgerCommitInfo: &types.UnicitySeal{Hash: tree.RootHash(), PreviousHash: bytes.Repeat([]byte{1}, 32)}}}
		cm.blockStore, err = storage.NewFromState(crypto.SHA256, checkpoint, cm.blockStore.GetDB(), cm.orchestration, logger.New(t))
		require.NoError(t, err)
		cm.leaderSelector = constLeader{leader: cm.id}
		cm.pacemaker.Reset(context.Background(), 29, nil, nil)
		set, err := cm.blockStore.SwitchingShardsForBlock(29, 30)
		require.NoError(t, err)
		require.Equal(t, storage.ShardSet{{PartitionID: switching, ShardID: types.ShardID{}.Key()}: {}}, set, "premise: exactly one shard switches at round 30")
		return cm, net, switching, steady
	}
	t.Run("buffered requests", func(t *testing.T) {
		cm, net, switching, steady := newLeader(t)
		bufferRequest(cm, switching)
		bufferRequest(cm, steady)
		cm.processNewRoundEvent(context.Background())
		got := requestedPartitions(testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, net, "/ab/root-proposal/0.0.1").Block.Payload)
		require.NotContains(t, got, switching)
		require.Contains(t, got, steady)
	})
	t.Run("T2 timeouts", func(t *testing.T) {
		cm, net, switching, steady := newLeader(t)
		dueTimeouts(t, cm, switching, steady)
		cm.processNewRoundEvent(context.Background())
		got := requestedPartitions(testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, net, "/ab/root-proposal/0.0.1").Block.Payload)
		require.NotContains(t, got, switching)
		require.Equal(t, rctypes.T2Timeout, got[steady])
	})
}
