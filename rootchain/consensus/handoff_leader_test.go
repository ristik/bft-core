package consensus

import (
	"bytes"
	"context"
	"crypto"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
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
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestProfile2LeaderEmitsEmptySuffixDespiteBufferedRequest(t *testing.T) {
	net := testnetwork.NewRootMockNetwork()
	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff
	rootNode := testutils.NewTestNode(t)
	obs := testobservability.Default(t)
	dir := t.TempDir()
	db, err := storage.NewBoltStorage(filepath.Join(dir, "root.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), obs.Logger(), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, orchestration.Close()) })
	tb := testtrustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{rootNode.PeerConf.ID.String(): rootNode.Signer})
	tbStore, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, tbStore.Store(tb))
	cm, err := NewConsensusManager(rootNode.PeerConf.ID, tbStore, orchestration, net, rootNode.Signer, db, obs, WithConsensusParams(params))
	require.NoError(t, err)
	record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: 0, OrderedRound: 4,
		ActivationRound: 7, PredecessorBodyID: make([]byte, 32), FrozenID: bytes.Repeat([]byte{2}, 32),
		NextBodyID: bytes.Repeat([]byte{3}, 32), SuccessorTRHash: bytes.Repeat([]byte{4}, 32), Kind: "commit"}
	control := &evmroot.ControlState{Network: 5, Epoch: 1, Attempt: 0, OrderedRound: 4,
		PredecessorBodyID: record.PredecessorBodyID, Phase: "committed", RecordBytes: record.Bytes(), PreviousDigest: make([]byte, 32), FrozenParent: bytes.Repeat([]byte{5}, 32)}
	state := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{}, Control: control}
	tree, _, err := state.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	checkpoint := &abdrc.CommittedBlock{Block: &rctypes.BlockData{Version: 2, Round: 4, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2}, Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 3, Epoch: 1}}},
		Control: control, CommitQc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4, ParentRoundNumber: 3, Epoch: 1, Timestamp: types.NewTimestamp()},
			LedgerCommitInfo: &types.UnicitySeal{Hash: tree.RootHash(), PreviousHash: bytes.Repeat([]byte{1}, 32)}}}
	cm.blockStore, err = storage.NewFromState(crypto.SHA256, checkpoint, cm.blockStore.GetDB(), cm.orchestration, logger.New(t), storage.ProfileHandoff)
	require.NoError(t, err)
	cm.leaderSelector = constLeader{leader: cm.id}
	// The anchor stays installed after the first successor block. A later
	// handoff must still suppress buffered shard requests in its old suffix.
	cm.epochAnchor = &rctypes.EpochAnchor{}
	cm.pacemaker.Reset(context.Background(), 4, nil, nil)
	request := &rctypes.IRChangeReq{Partition: partitionID, CertReason: rctypes.Quorum}
	key := types.PartitionShardID{PartitionID: partitionID, ShardID: shardID.Key()}
	cm.irReqBuffer.irChgReqBuffer[key] = &irChange{Req: request, InputRecord: &types.InputRecord{Version: 1}}
	cm.processNewRoundEvent(context.Background())
	proposal := testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, net, network.ProtocolRootProposal)
	require.True(t, proposal.Block.Payload.IsEmpty())
	require.True(t, cm.irReqBuffer.IsChangeInBuffer(partitionID, shardID), "suffix must defer the request")
}
