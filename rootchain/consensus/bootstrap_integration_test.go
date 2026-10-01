package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type anchorReplica struct {
	manager    *ConsensusManager
	net        *testnetwork.MockNet
	store      *tbstore.TrustBaseStore
	history    *trusthistorystore.Store
	db         storage.BoltDB
	oldHead    *abdrc.CommittedBlock
	proof      handoff.OldCommitProof
	body       evmroot.TrustBaseBodyV2
	oldSigners map[string]abcrypto.Signer
}

type oneEpochTrust struct{ tb *types.RootTrustBaseV1 }

func stoppedHandoffReplica(t *testing.T, source *anchorReplica) *ConsensusManager {
	t.Helper()
	old, err := source.store.GetByEpoch(1)
	require.NoError(t, err)
	trust, err := tbstore.NewTrustBaseStore(memorydb.New(), testobservability.Default(t).Logger())
	require.NoError(t, err)
	require.NoError(t, trust.Store(old))
	obs := testobservability.Default(t)
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "before-install.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	bodyID := source.body.Identity()
	require.NoError(t, db.StoreHandoffBody(bodyID[:], source.body.Encode()))
	identity := sha256.Sum256([]byte("bundle-order-test"))
	history, err := trusthistorystore.Open(context.Background(), memorydb.New(), old, identity, trustactivation.Verifier{})
	require.NoError(t, err)
	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff
	id := source.manager.id
	cm, err := NewConsensusManager(id, trust, source.manager.orchestration, testnetwork.NewRootMockNetwork(),
		source.oldSigners[id.String()], db, obs, WithConsensusParams(params), WithRecoveryProfile2(history))
	require.NoError(t, err)
	cm.blockStore, err = storage.NewFromState(crypto.SHA256, source.oldHead, db, source.manager.orchestration, obs.Logger(), storage.ProfileHandoff)
	require.NoError(t, err)
	return cm
}

func laterSuffixBundle(t *testing.T, source *anchorReplica) handoffdelivery.Bundle {
	t.Helper()
	original := handoffdelivery.Bundle{Proof: source.proof, Body: source.body, Snapshot: source.oldHead}
	raw, err := types.Cbor.Marshal(original)
	require.NoError(t, err)
	var later handoffdelivery.Bundle
	require.NoError(t, types.Cbor.Unmarshal(raw, &later))
	qc := later.Proof.CommitQC
	qc.VoteInfo.RoundNumber++
	qc.VoteInfo.ParentRoundNumber++
	qc.LedgerCommitInfo.RootChainRoundNumber++
	voteHash, err := qc.VoteInfo.Hash(crypto.SHA256)
	require.NoError(t, err)
	qc.LedgerCommitInfo.PreviousHash = voteHash
	message, err := qc.LedgerCommitInfo.SigBytes()
	require.NoError(t, err)
	qc.Signatures = make(map[string]hex.Bytes)
	for id, signer := range source.oldSigners {
		sig, err := signer.SignBytes(message)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	later.Snapshot.CommitQc = qc
	later.Snapshot.Block.Round++
	return later
}

func TestHandoffBundleServeSuffixThenInstallAndInstallThenServe(t *testing.T) {
	replicas, _, _ := newAnchorReplicas(t, 4)
	var source *anchorReplica
	for id, replica := range replicas {
		if replica.oldSigners[id.String()] != nil {
			source = replica
			break
		}
	}
	require.NotNil(t, source)
	old, err := source.store.GetByEpoch(1)
	require.NoError(t, err)
	later := laterSuffixBundle(t, source)
	first := later.Snapshot.ShardInfo[0]
	_, err = handoffdelivery.Verify(later, old, first.Partition, first.Shard, first.ShardConfHash)
	require.NoError(t, err)
	t.Run("serve suffix install", func(t *testing.T) {
		cm := stoppedHandoffReplica(t, source)
		served, err := cm.HandoffBundle(context.Background(), 2)
		require.NoError(t, err)
		require.EqualValues(t, 4, served.Proof.CommitQC.LedgerCommitInfo.RootChainRoundNumber)
		_, err = cm.InstallEpochGenesis(later.Proof, later.Snapshot, later.Body)
		require.NoError(t, err)
		retained, err := cm.HandoffBundle(context.Background(), 2)
		require.NoError(t, err)
		require.EqualValues(t, 4, retained.Proof.CommitQC.LedgerCommitInfo.RootChainRoundNumber)
		require.Equal(t, cm.epochAnchor.GenesisID, source.manager.epochAnchor.GenesisID)
	})
	t.Run("install serve", func(t *testing.T) {
		cm := stoppedHandoffReplica(t, source)
		_, err := cm.InstallEpochGenesis(later.Proof, later.Snapshot, later.Body)
		require.NoError(t, err)
		served, err := cm.HandoffBundle(context.Background(), 2)
		require.NoError(t, err)
		require.EqualValues(t, 5, served.Proof.CommitQC.LedgerCommitInfo.RootChainRoundNumber)
	})
}

func (s oneEpochTrust) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	if epoch != s.tb.Epoch {
		return nil, fmt.Errorf("epoch %d unavailable", epoch)
	}
	return s.tb, nil
}

// This drives the real adapter derivation with a transition exported from an
// installed root anchor. The root starts at round 7; the shard is assigned 1.
func TestInstalledTransitionAdapterUsesAssignedShardRound(t *testing.T) {
	chain := certifiedchain.New(t, 3, 0)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(chain.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for key := range alloc {
		if strings.EqualFold(strings.TrimPrefix(key, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, key)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, err := json.Marshal(doc)
	require.NoError(t, err)
	artifact, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	prepared, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), chain.Pins, artifact, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	origin := prepared.Origin()
	snapshot, err := registryproof.Verify(origin.ProofContext(), origin.BlockHash(), origin.Evidence())
	require.NoError(t, err)
	replicas, anchor, _ := newAnchorReplicas(t, 4, origin.BlockHash().Bytes())
	replica := firstReplica(replicas)
	// Reuse the verified proof and body already installed by the helper through
	// the public manager export path, rather than constructing an Ack by hand.
	transitionBytes, err := replica.manager.InstalledEVMTransition(replica.proof, replica.body)
	require.NoError(t, err)
	transition, err := handoff.DecodeEVMTransition(transitionBytes)
	require.NoError(t, err)
	require.NotEqual(t, anchor.Slot+1, transition.Ack.EVMRound)

	tr := certifiedchain.Technical(0)
	tr.Round = transition.Ack.EVMRound
	uc := chain.Certify(chain.Signer, &types.InputRecord{Version: 1}, tr, 4)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Epoch = 2
	uc.UnicitySeal.Signatures = nil
	verifier, err := chain.Signer.Verifier()
	require.NoError(t, err)
	key, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(key)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), chain.Signer))
	tb := *chain.TrustBase
	tb.Epoch = 2
	tb.Signatures = nil
	vc := &engineapi.VerifierContext{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{},
		ShardConfHash: origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: oneEpochTrust{&tb},
		GenesisOrigin: origin, BootstrapSnapshot: snapshot, Transition: transitionBytes}
	adapter := engineapi.NewAdapter(engineapi.Config{Verifier: vc}, nil)
	params := shardnode.RoundParams{Round: tr.Round, Parent: shardnode.BlockRef{Number: 0,
		Hash: origin.BlockHash().Bytes(), StateRoot: origin.StateRoot().Bytes()},
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr}
	_, err = adapter.PrepareBuild(context.Background(), params)
	require.NoError(t, err)
	wrong := transition
	wrong.Ack.EVMRound = anchor.Slot + 1
	vc.Transition, err = wrong.Encode()
	require.NoError(t, err)
	_, err = adapter.PrepareBuild(context.Background(), params)
	require.NoError(t, err, "a stale template round is rebound to the authenticated shard assignment")
}

func newAnchorReplicas(t *testing.T, commitSealRound uint64, frozenParent ...[]byte) (map[peer.ID]*anchorReplica, *rctypes.EpochAnchor, time.Time) {
	t.Helper()
	parent := bytes.Repeat([]byte{5}, 32)
	if len(frozenParent) == 1 {
		parent = frozenParent[0]
	}
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
	_, shardValidators := testutils.CreateTestNodes(t, 3)
	shardConf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partitionID,
		ShardID: shardID, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Validators: shardValidators, Epoch: 0, EpochStart: 1}
	shardState, err := storage.NewShardInfo(shardConf, crypto.SHA256)
	require.NoError(t, err)
	shardState.IR.BlockHash = bytes.Clone(parent)
	shardState.IR.Hash = bytes.Repeat([]byte{0x37}, 32)
	successorTRHash, err := shardState.TR.Hash()
	require.NoError(t, err)
	record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: 4, ActivationRound: 7,
		PredecessorBodyID: oldID, NextBodyID: bodyID[:], FrozenID: bytes.Repeat([]byte{2}, 32),
		SuccessorTRHash: successorTRHash, Kind: "commit"}
	control := evmroot.ControlState{Network: 5, Epoch: 1, OrderedRound: 4, PredecessorBodyID: oldID,
		Phase: "committed", RecordBytes: record.Bytes(), PreviousDigest: bytes.Repeat([]byte{4}, 32), FrozenParent: parent}
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
	bundle := handoffdelivery.Bundle{Proof: proof, Body: body, Snapshot: head}
	delivered, err := handoffdelivery.Verify(bundle, oldTrust, shardState.PartitionID, shardState.ShardID, shardState.ShardConfHash)
	require.NoError(t, err)
	deliveredBodyID := body.Identity()
	require.Equal(t, deliveredBodyID[:], delivered.Genesis.NextBodyID)
	tampered := *head
	tampered.ShardInfo = append([]abdrc.ShardInfo(nil), head.ShardInfo...)
	tampered.ShardInfo[0].IRTR.Round++
	_, err = handoffdelivery.Verify(handoffdelivery.Bundle{Proof: proof, Body: body, Snapshot: &tampered}, oldTrust,
		shardState.PartitionID, shardState.ShardID, shardState.ShardConfHash)
	require.ErrorIs(t, err, handoffdelivery.ErrBundle)
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
		history, err := trusthistorystore.Open(context.Background(), memorydb.New(), oldTrust, historyID, trustactivation.Verifier{})
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
		served, err := manager.HandoffBundle(context.Background(), body.Epoch)
		require.NoError(t, err)
		_, err = handoffdelivery.Verify(*served, oldTrust, shardState.PartitionID, shardState.ShardID, shardState.ShardConfHash)
		require.NoError(t, err)
		shardHistory, err := shardnode.NewHistoricalTrustBaseStore(context.Background(), memorydb.New(), oldTrust, historyID, true)
		require.NoError(t, err)
		_, err = shardHistory.InstallHandoff(context.Background(), *served, shardState.PartitionID, shardState.ShardID, shardState.ShardConfHash)
		require.NoError(t, err)
		_, err = shardHistory.InstallHandoff(context.Background(), *served, shardState.PartitionID, shardState.ShardID, shardState.ShardConfHash)
		require.NoError(t, err)
		_, err = shardHistory.GetByEpoch(context.Background(), body.Epoch)
		require.NoError(t, err)
		transitionBytes, err := manager.InstalledEVMTransition(proof, body)
		require.NoError(t, err)
		transition, err := handoff.DecodeEVMTransition(transitionBytes)
		require.NoError(t, err)
		require.Equal(t, uint64(2), transition.NewRootEpoch)
		require.NotEqual(t, installed.Slot+1, shardState.TR.Round, "root and shard counters differ in this fixture")
		require.Equal(t, shardState.TR.Round, transition.Ack.EVMRound)
		require.Equal(t, parent, transition.Ack.FrozenParent[:])
		require.Equal(t, installed.GenesisID, transition.GenesisID[:])
		if anchor == nil {
			anchor = installed
		} else {
			require.Equal(t, anchor, installed)
		}
		manager.pacemaker.Reset(context.Background(), anchor.Slot, nil, nil)
		t.Cleanup(manager.pacemaker.Stop)
		replicas[node.PeerConf.ID] = &anchorReplica{manager: manager, net: net, store: trust, history: history, db: db, oldHead: head, proof: proof, body: body, oldSigners: oldSigners}
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
