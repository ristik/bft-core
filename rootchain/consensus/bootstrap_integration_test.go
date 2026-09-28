package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
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
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type anchorReplica struct {
	manager *ConsensusManager
	net     *testnetwork.MockNet
	store   *tbstore.TrustBaseStore
	history *trusthistorystore.Store
	db      storage.BoltDB
	oldHead *abdrc.CommittedBlock
}

func newAnchorReplicas(t *testing.T, commitSealRound uint64) (map[peer.ID]*anchorReplica, *rctypes.EpochAnchor, time.Time) {
	t.Helper()
	oldSigners := make(map[string]abcrypto.Signer)
	oldNodes := make([]*testutils.TestNode, 4)
	for i := range oldNodes {
		node := testutils.NewTestNode(t)
		oldNodes[i] = node
		oldSigners[node.PeerConf.ID.String()] = node.Signer
	}
	oldTrust := testtrustbase.NewTrustBaseFromSigners(t, oldSigners).(*types.RootTrustBaseV1)
	oldID, err := oldTrust.Hash(crypto.SHA256)
	require.NoError(t, err)
	link, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: 5, Epoch: 1, HashIncludingSigs: oldID})
	require.NoError(t, err)
	newNodes := make([]*testutils.TestNode, 4)
	members := make(evmroot.WeightSet, 4)
	for i := range newNodes {
		if i < 3 {
			newNodes[i] = oldNodes[i]
		} else {
			newNodes[i] = testutils.NewTestNode(t)
		}
		verifier, err := newNodes[i].Signer.Verifier()
		require.NoError(t, err)
		key, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		members[i] = evmroot.Member{StakingID: fmt.Sprintf("stake-%d", i), NodeID: newNodes[i].PeerConf.ID.String(), ConsensusKey: key, Weight: 1}
	}
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 5, Epoch: 2, EarliestActivation: 7,
		Members: members, RootThreshold: 3, PredecessorHash: link}
	require.NoError(t, body.Validate())
	bodyID := body.Identity()
	record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: 4, ActivationRound: 7,
		PredecessorBodyID: oldID, NextBodyID: bodyID[:], FrozenID: bytes.Repeat([]byte{2}, 32),
		SuccessorTRHash: bytes.Repeat([]byte{3}, 32), Kind: "commit"}
	control := evmroot.ControlState{Network: 5, Epoch: 1, OrderedRound: 4, PredecessorBodyID: oldID,
		Phase: "committed", RecordBytes: record.Bytes(), PreviousDigest: bytes.Repeat([]byte{4}, 32), FrozenParent: bytes.Repeat([]byte{5}, 32)}
	_, shardValidators := testutils.CreateTestNodes(t, 3)
	shardConf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partitionID,
		ShardID: shardID, PartitionTypeID: 999, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Validators: shardValidators, Epoch: 0, EpochStart: 1}
	shardState, err := storage.NewShardInfo(shardConf, crypto.SHA256)
	require.NoError(t, err)
	shardKey := types.PartitionShardID{PartitionID: partitionID, ShardID: shardID.Key()}
	state := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{shardKey: shardState},
		Changed: storage.ShardSet{shardKey: {}}, Control: &control}
	tree, _, err := state.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	timestamp := types.NewTimestamp()
	voteInfo := &rctypes.RoundInfo{Version: 1, RoundNumber: commitSealRound + 1, ParentRoundNumber: commitSealRound, Epoch: 1,
		Timestamp: timestamp, CurrentRootHash: tree.RootHash()}
	voteHash, err := voteInfo.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: commitSealRound, Epoch: 1,
		Timestamp: timestamp, Hash: tree.RootHash(), PreviousHash: voteHash}
	message, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: voteInfo, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for i := 0; i < 3; i++ {
		id := oldNodes[i].PeerConf.ID.String()
		signer := oldNodes[i].Signer
		sig, err := signer.SignBytes(message)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	proof := handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: record, Control: control,
		ControlPath: path, CommitQC: qc}
	_, err = handoff.VerifyOldCommitProof(proof, oldTrust)
	require.NoError(t, err)
	oldBlock := &storage.ExecutedBlock{HashAlgo: crypto.SHA256, RootHash: tree.RootHash(), ShardState: state}
	oldCertificates, err := oldBlock.GenerateCertificates(qc)
	require.NoError(t, err)
	require.Len(t, oldCertificates, 1)
	oldUCAt := time.Now()
	shardInfo := abdrc.ShardInfo{Partition: shardState.PartitionID, Shard: shardState.ShardID,
		T2Timeout: shardState.T2Timeout, RootHash: shardState.RootHash,
		PrevEpochStat: shardState.PrevEpochStat, Stat: shardState.Stat,
		PrevEpochFees: shardState.PrevEpochFees, Fees: shardState.Fees,
		IR: shardState.IR, IRTR: shardState.TR, ShardConfHash: shardState.ShardConfHash,
		UC: &shardState.LastCR.UC, TR: &shardState.LastCR.Technical}
	head := &abdrc.CommittedBlock{Block: &rctypes.BlockData{Version: 2, Epoch: 1, Round: commitSealRound,
		Payload: &rctypes.Payload{Version: 2}}, ShardInfo: []abdrc.ShardInfo{shardInfo}, Control: &control, CommitQc: qc}
	replicas := make(map[peer.ID]*anchorReplica, len(newNodes))
	var anchor *rctypes.EpochAnchor
	for _, node := range newNodes {
		obs := testobservability.Default(t)
		dir := t.TempDir()
		db, err := storage.NewBoltStorage(filepath.Join(dir, "root.db"), storage.WithNoSync())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, db.Close()) })
		orchestration, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), obs.Logger(), partitions.WithNoSync())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, orchestration.Close()) })
		require.NoError(t, orchestration.AddShardConfig(shardConf))
		trust, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
		require.NoError(t, err)
		require.NoError(t, trust.Store(oldTrust))
		historyID := sha256.Sum256([]byte("epoch-anchor-integration"))
		history, err := trusthistorystore.Open(context.Background(), memorydb.New(), oldTrust, historyID, nil)
		require.NoError(t, err)
		net := testnetwork.NewRootMockNetwork()
		params := *NewConsensusParams()
		params.NetworkProfileVersion = storage.ProfileHandoff
		manager, err := NewConsensusManager(node.PeerConf.ID, trust, orchestration, net, node.Signer, db, obs, WithConsensusParams(params), WithRecoveryProfile2(history))
		require.NoError(t, err)
		manager.blockStore, err = storage.NewFromState(crypto.SHA256, head, db, orchestration, obs.Logger(), storage.ProfileHandoff)
		require.NoError(t, err)
		installed, err := manager.InstallEpochGenesis(proof, head, body)
		require.NoError(t, err)
		transitionBytes, err := manager.InstalledEVMTransition(proof, body, 1)
		require.NoError(t, err)
		transition, err := handoff.DecodeEVMTransition(transitionBytes)
		require.NoError(t, err)
		require.Equal(t, uint64(2), transition.NewEpoch)
		require.Equal(t, bytes.Repeat([]byte{5}, 32), transition.Ack.FrozenParent[:])
		require.Equal(t, installed.GenesisID, transition.GenesisID[:])
		if anchor == nil {
			anchor = installed
		} else {
			require.Equal(t, anchor, installed)
		}
		manager.pacemaker.Reset(context.Background(), anchor.Slot, nil, nil)
		t.Cleanup(manager.pacemaker.Stop)
		replicas[node.PeerConf.ID] = &anchorReplica{manager: manager, net: net, store: trust, history: history, db: db, oldHead: head}
	}
	return replicas, anchor, oldUCAt
}

func TestEpochAnchorChangedCommitteeCommitsOnlyOrdinaryBlock(t *testing.T) {
	replicas, anchor, oldUCAt := newAnchorReplicas(t, 4)
	ctx := context.Background()
	oldQC := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{Epoch: 1, RoundNumber: anchor.Slot + 1}}
	firstReplica(replicas).manager.processQC(ctx, oldQC)
	require.Equal(t, anchor, firstReplica(replicas).manager.blockStore.RootAnchor())
	firstLeader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	replicas[firstLeader].manager.processNewRoundEvent(ctx)
	proposal := replicas[firstLeader].net.WaitRootProposal(t)
	require.Equal(t, anchor, proposal.Block.Anchor)
	for _, replica := range replicas {
		require.NoError(t, replica.manager.onProposalMsg(ctx, proposal))
	}
	nextLeader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 2)
	require.NoError(t, err)
	replicas[nextLeader].manager.pacemaker.setState(ctx, pmsRoundMatured)
	for _, replica := range replicas {
		if replicas[nextLeader].manager.pacemaker.GetCurrentRound() > anchor.Slot+1 {
			break
		}
		votes := replica.net.SentMessages(network.ProtocolRootVote)
		require.Len(t, votes, 1)
		require.NoError(t, replicas[nextLeader].manager.onVoteMsg(ctx, votes[0].Message.(*abdrc.VoteMsg)))
	}
	proposal = replicas[nextLeader].net.WaitRootProposal(t)
	require.Nil(t, proposal.Block.Anchor)
	require.Equal(t, anchor, replicas[nextLeader].manager.blockStore.RootAnchor(), "first QC cannot commit anchor")
	require.EqualValues(t, anchor.Slot+2, proposal.Block.Round)
	for _, replica := range replicas {
		replica.net.ResetSentMessages(network.ProtocolRootVote)
		require.NoError(t, replica.manager.onProposalMsg(ctx, proposal))
	}
	thirdLeader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 3)
	require.NoError(t, err)
	replicas[thirdLeader].manager.pacemaker.setState(ctx, pmsRoundMatured)
	for _, replica := range replicas {
		if replicas[thirdLeader].manager.pacemaker.GetCurrentRound() > anchor.Slot+2 {
			break
		}
		votes := replica.net.SentMessages(network.ProtocolRootVote)
		require.Len(t, votes, 1)
		require.NoError(t, replicas[thirdLeader].manager.onVoteMsg(ctx, votes[0].Message.(*abdrc.VoteMsg)))
	}
	committed, err := replicas[thirdLeader].manager.blockStore.GetState()
	require.NoError(t, err)
	require.EqualValues(t, anchor.Slot+1, committed.CommittedHead.Block.Round)
	require.Nil(t, committed.CommittedHead.Anchor)
	select {
	case certificates := <-replicas[thirdLeader].manager.ucSink:
		newUCAt := time.Now()
		require.Len(t, certificates, 1)
		require.EqualValues(t, 2, certificates[0].UC.GetRootEpoch())
		t.Logf("certification pause, old shard UC to first successor shard UC: %s", newUCAt.Sub(oldUCAt))
	default:
		t.Fatal("first new shard UC was not produced")
	}
}

func TestEpochAnchorFirstLeaderTimeoutRecoversWithTaggedTC(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	ctx := context.Background()
	firstLeader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	nextLeader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 2)
	require.NoError(t, err)
	for id, replica := range replicas {
		if id != firstLeader {
			replica.manager.onLocalTimeout(ctx)
		}
	}
	receiver := replicas[nextLeader]
	for id, replica := range replicas {
		if id == firstLeader {
			continue
		}
		messages := replica.net.SentMessages(network.ProtocolRootTimeout)
		require.Len(t, messages, len(replicas))
		vote := messages[0].Message.(*abdrc.TimeoutMsg)
		require.Equal(t, anchor, vote.Timeout.Anchor)
		require.NoError(t, receiver.manager.onTimeoutMsg(ctx, vote))
	}
	proposal := receiver.net.WaitRootProposal(t)
	require.Equal(t, anchor, proposal.Block.Anchor)
	require.NotNil(t, proposal.LastRoundTc)
	require.Equal(t, anchor, proposal.LastRoundTc.Timeout.Anchor)
	oldTC := &rctypes.TimeoutCert{Timeout: &rctypes.Timeout{Epoch: 1, Round: anchor.Slot + 1}}
	require.Error(t, receiver.manager.validateTimeoutCert(oldTC))
	currentRound := receiver.manager.pacemaker.GetCurrentRound()
	currentLeader, err := receiver.manager.leaderSelector.GetLeaderForRound(currentRound)
	require.NoError(t, err)
	receiver.manager.processTC(ctx, oldTC)
	require.Equal(t, currentRound, receiver.manager.pacemaker.GetCurrentRound())
	leaderAfter, err := receiver.manager.leaderSelector.GetLeaderForRound(currentRound)
	require.NoError(t, err)
	require.Equal(t, currentLeader, leaderAfter)
}

func TestEpochAnchorFixedStartIgnoresOldCommitSealRound(t *testing.T) {
	_, early, _ := newAnchorReplicas(t, 4)
	_, late, _ := newAnchorReplicas(t, 5)
	require.EqualValues(t, 6, early.Slot)
	require.EqualValues(t, early.Slot, late.Slot)
}

func TestEpochAnchorRestartKeepsSuccessorVoteLock(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	ctx := context.Background()
	leader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	replicas[leader].manager.processNewRoundEvent(ctx)
	proposal := replicas[leader].net.WaitRootProposal(t)
	replica := replicas[leader]
	require.NoError(t, replica.manager.onProposalMsg(ctx, proposal))
	require.EqualValues(t, anchor.Slot+1, replica.db.GetHighestVotedRound())
	replica.manager.pacemaker.Stop()
	obs := testobservability.Default(t)
	restarted, err := NewConsensusManager(leader, replica.store, replica.manager.orchestration,
		testnetwork.NewRootMockNetwork(), replica.manager.safety.signer, replica.db, obs,
		WithConsensusParams(*replica.manager.params))
	require.ErrorIs(t, err, abdrc.ErrRecoveryEpoch)
	restarted, err = NewConsensusManager(leader, replica.store, replica.manager.orchestration,
		testnetwork.NewRootMockNetwork(), replica.manager.safety.signer, replica.db, obs,
		WithConsensusParams(*replica.manager.params), WithRecoveryProfile2(replica.history))
	require.NoError(t, err)
	require.Equal(t, anchor, restarted.epochAnchor)
	require.EqualValues(t, anchor.Slot+1, replica.db.GetHighestVotedRound())
	block, err := restarted.blockStore.Block(anchor.Slot + 1)
	require.NoError(t, err)
	_, err = restarted.safety.MakeVote(proposal.Block, block.RootHash, nil, nil)
	require.Error(t, err)
}

func TestEpochAnchorRecoveryVerifiesNativeSnapshotAndOldUC(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	replica := firstReplica(replicas)
	state, err := replica.manager.blockStore.GetState()
	require.NoError(t, err)
	require.Equal(t, anchor, state.CommittedHead.Anchor)
	history := replica.history
	require.NoError(t, state.VerifyWithAnchor(crypto.SHA256, replica.manager.trustBase.Load(), history, replica.manager.blockStore))
	corrupt := *state.CommittedHead
	corrupt.ShardInfo = append([]abdrc.ShardInfo(nil), corrupt.ShardInfo...)
	corrupt.ShardInfo[0].IRTR.Round++
	require.Error(t, (&abdrc.StateMsg{CommittedHead: &corrupt}).VerifyWithAnchor(
		crypto.SHA256, replica.manager.trustBase.Load(), history, replica.manager.blockStore))
	wrong := *anchor
	wrong.GenesisID = bytes.Repeat([]byte{9}, 32)
	corrupt = *state.CommittedHead
	corrupt.Anchor = &wrong
	require.Error(t, (&abdrc.StateMsg{CommittedHead: &corrupt}).VerifyWithAnchor(
		crypto.SHA256, replica.manager.trustBase.Load(), history, replica.manager.blockStore))
}

func TestEpochAnchorRecoveryRefusesOldEpochHeadWithoutChangingAnchor(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 8)
	replica := firstReplica(replicas)
	manager := replica.manager
	oldHead := *replica.oldHead
	oldBlock := *oldHead.Block
	oldBlock.Round = oldHead.Block.Round + 2
	oldBlock.Qc = oldHead.CommitQc
	oldHead.Block = &oldBlock
	oldHead.Qc = oldHead.CommitQc
	oldHeadPtr := &oldHead
	require.Greater(t, oldHeadPtr.Block.Round, anchor.Slot)
	require.NoError(t, (&abdrc.StateMsg{CommittedHead: oldHeadPtr}).Verify(crypto.SHA256, manager.trustBase.Load()),
		"overlapping old-set keys should satisfy the successor threshold in the legacy verifier")
	before, err := replica.db.LoadBlocks()
	require.NoError(t, err)
	recoveryQC := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: oldHeadPtr.Block.Round + 1,
		ParentRoundNumber: oldHeadPtr.Block.Round}, Signatures: oldHeadPtr.CommitQc.Signatures}
	_, err = manager.recovery.Set(recoveryQC)
	require.NoError(t, err)
	err = manager.onStateResponse(context.Background(), &abdrc.StateMsg{CommittedHead: oldHeadPtr})
	require.ErrorIs(t, err, abdrc.ErrRecoveryEpoch)
	require.Equal(t, anchor, manager.blockStore.RootAnchor())
	after, err := replica.db.LoadBlocks()
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func firstReplica(replicas map[peer.ID]*anchorReplica) *anchorReplica {
	for _, replica := range replicas {
		return replica
	}
	return nil
}
