package consensus

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The epoch guard on the live vote and timeout handlers, driven with authenticated messages of the old epoch through the
// real onVoteMsg/onTimeoutMsg: the old committee keeps running the suffix after the activation round A* until the
// successor is installed (D4), and only then is an old-epoch message refused.
func TestOldEpochVotesAndTimeoutsThroughTheLiveHandlers(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 9)
	var source *anchorReplica
	for id, r := range replicas {
		if r.oldSigners[id.String()] != nil {
			source = r
			break
		}
	}
	require.NotNil(t, source)
	ctx := context.Background()
	round := source.proof.CommitQC.GetRound() + 1
	require.Greater(t, round, source.proof.Record.ActivationRound, "the message is in the suffix beyond A*")

	author := source.manager.id.String()
	vote := NewDummyVote(t, author, round, []byte{1})
	vote.HighQc = source.proof.CommitQC
	require.NoError(t, vote.Sign(source.oldSigners[author]))
	timeout := abdrc.NewTimeoutMsg(&rctypes.Timeout{Round: round, Epoch: 1, HighQc: source.proof.CommitQC}, author, nil)
	require.NoError(t, timeout.Sign(source.oldSigners[author]))

	t.Run("before the successor is installed the old committee still takes them", func(t *testing.T) {
		cm := stoppedHandoffReplica(t, source)
		t.Cleanup(cm.pacemaker.Stop)
		cm.pacemaker.Reset(ctx, round-2, nil, nil)
		cm.updateTrustBase()
		require.EqualValues(t, 1, cm.trustBase.Load().Epoch)
		require.Nil(t, cm.epochAnchor)
		require.NoError(t, vote.Verify(cm.trustBaseStore))
		require.NoError(t, cm.onVoteMsg(ctx, vote))
		require.Contains(t, cm.voteBuffer, author)
		require.NoError(t, timeout.Verify(cm.trustBaseStore))
		err := cm.onTimeoutMsg(ctx, timeout)
		require.NotErrorIs(t, err, ErrVoteEpoch)
		if err != nil {
			require.ErrorContains(t, err, "timeout vote triggers recovery")
		}
	})

	t.Run("after the successor is installed they are authentic but refused", func(t *testing.T) {
		require.EqualValues(t, 2, source.manager.trustBase.Load().Epoch)
		require.Greater(t, round, anchor.Slot)
		require.NoError(t, vote.Verify(source.store), "the vote still authenticates under its own epoch")
		require.ErrorIs(t, source.manager.onVoteMsg(ctx, vote), ErrVoteEpoch)
		require.NotContains(t, source.manager.voteBuffer, author)
		require.NoError(t, timeout.Verify(source.store))
		require.ErrorIs(t, source.manager.onTimeoutMsg(ctx, timeout), ErrVoteEpoch)
	})

	t.Run("a member whose weight changed across epochs is never weighed with the new epoch's weight", func(t *testing.T) {
		// the author weighs 6 in the installed epoch and 1 under the epoch that authenticated the vote
		setStakes(source.manager, 7, map[string]uint64{author: 6})
		before := len(source.manager.voteBuffer)
		require.ErrorIs(t, source.manager.onVoteMsg(ctx, vote), ErrVoteEpoch)
		require.Len(t, source.manager.voteBuffer, before, "the refused vote is not buffered, so it cannot count with weight 6")
		w, err := source.manager.bufferedWeight()
		require.NoError(t, err)
		require.Zero(t, w)
	})
}

// epochQC is a QC of the epoch that signed template, for the given round, signed by every one of those members (as
// laterSuffixBundle does for a later suffix): the high QC a message of a later round of that epoch carries.
func epochQC(t *testing.T, template *rctypes.QuorumCert, signers map[string]abcrypto.Signer, round uint64) *rctypes.QuorumCert {
	t.Helper()
	raw, err := types.Cbor.Marshal(template)
	require.NoError(t, err)
	var qc rctypes.QuorumCert
	require.NoError(t, types.Cbor.Unmarshal(raw, &qc))
	qc.VoteInfo.RoundNumber, qc.VoteInfo.ParentRoundNumber = round, round-1
	qc.LedgerCommitInfo.RootChainRoundNumber = round
	voteHash, err := qc.VoteInfo.Hash(crypto.SHA256)
	require.NoError(t, err)
	qc.LedgerCommitInfo.PreviousHash = voteHash
	message, err := qc.LedgerCommitInfo.SigBytes()
	require.NoError(t, err)
	qc.Signatures = make(map[string]hex.Bytes)
	for id, signer := range signers {
		sig, err := signer.SignBytes(message)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	return &qc
}

// epochMessages are an authenticated vote and timeout of the given epoch from one of its members, for the given round.
func epochMessages(t *testing.T, epoch uint64, template *rctypes.QuorumCert, signers map[string]abcrypto.Signer, author string, round uint64) (*abdrc.VoteMsg, *abdrc.TimeoutMsg) {
	t.Helper()
	high := epochQC(t, template, signers, round-1)
	vote := NewDummyVote(t, author, round, []byte{1})
	vote.VoteInfo.Epoch = epoch
	vote.LedgerCommitInfo = NewDummyLedgerCommitInfo(t, vote.VoteInfo)
	vote.HighQc = high
	require.NoError(t, vote.Sign(signers[author]))
	timeout := abdrc.NewTimeoutMsg(&rctypes.Timeout{Round: round, Epoch: epoch, HighQc: high}, author, nil)
	require.NoError(t, timeout.Sign(signers[author]))
	return vote, timeout
}

// oldEpochMessages are epochMessages of the epoch the fixture's old committee signed.
func oldEpochMessages(t *testing.T, source *anchorReplica, author string, round uint64) (*abdrc.VoteMsg, *abdrc.TimeoutMsg) {
	t.Helper()
	return epochMessages(t, 1, source.proof.CommitQC, source.oldSigners, author, round)
}

// A root that rejoined the new epoch from a peer's StateMsg (catch-up) takes the new epoch's weights; the old epoch's
// authentic, still-signed messages that arrive after the catch-up are refused by the real handlers and are neither
// buffered nor counted with the new epoch's weight for the same identity.
func TestOldEpochMessagesAfterStateMsgCatchUp(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	var source *anchorReplica
	for id, r := range c.replicas {
		if r.oldSigners[id.String()] != nil {
			source = r
			break
		}
	}
	require.NotNil(t, source)
	root := restartedRoot(t, source)
	require.NoError(t, recoverTo(t, root, state), "catch-up from the peers' state")
	require.False(t, root.recovery.InRecovery())
	require.EqualValues(t, 2, root.trustBase.Load().Epoch)

	ctx := context.Background()
	author := root.id.String()
	round := root.pacemaker.GetCurrentRound() + 1
	vote, timeout := oldEpochMessages(t, source, author, round)
	require.NoError(t, vote.Verify(root.trustBaseStore), "authentic under its own epoch")
	require.NoError(t, timeout.Verify(root.trustBaseStore))

	// the identity weighs 6 in the epoch the root now runs, and 1 in the epoch that signed the messages
	setStakes(root, 7, map[string]uint64{author: 6})
	require.ErrorIs(t, root.onVoteMsg(ctx, vote), ErrVoteEpoch)
	require.ErrorIs(t, root.onTimeoutMsg(ctx, timeout), ErrVoteEpoch)
	require.NotContains(t, root.voteBuffer, author)
	w, err := root.bufferedWeight()
	require.NoError(t, err)
	require.Zero(t, w)
}

// secondHandoff is a root that has installed epoch 2 (stopped, as an install requires) together with the proof, snapshot
// and body of the handoff that supersedes epoch 2 by epoch 3, committed by the four members of epoch 2.
type secondHandoff struct {
	root    *ConsensusManager
	proof   handoff.OldCommitProof
	head    *abdrc.CommittedBlock
	body    evmroot.TrustBaseBodyV2
	signers map[string]abcrypto.Signer // the epoch 2 members
}

func newSecondHandoff(t *testing.T, source *anchorReplica, signers map[string]abcrypto.Signer) secondHandoff {
	t.Helper()
	root := restartedRoot(t, source)
	require.EqualValues(t, 2, root.trustBase.Load().Epoch)
	require.Zero(t, root.pacemaker.GetCurrentRound(), "an install needs stopped consensus")
	old2, err := root.trustBaseStore.GetByEpoch(2)
	require.NoError(t, err)
	prior, err := root.recoveryHistory.ByEpoch(2)
	require.NoError(t, err)
	predecessor := prior.BodyID[:]
	start := old2.EpochStart

	members := make(evmroot.WeightSet, len(old2.RootNodes))
	for i, n := range old2.RootNodes {
		members[i] = evmroot.Member{StakingID: fmt.Sprintf("epoch3-stake-%d", i), NodeID: n.NodeID, ConsensusKey: bytes.Clone(n.SigKey), Weight: 1}
	}
	digest, err := evmroot.D4OperatorCandidateDigest(members)
	require.NoError(t, err)
	activation := start + 6
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 5, Epoch: 3, EarliestActivation: activation, Members: members,
		RootThreshold: 3, PredecessorHash: predecessor,
		ChangeRecordHash: evmroot.D4CandidateContextHash(5, predecessor, 0, digest[:], activation)}
	require.NoError(t, body.Validate())
	bodyID := body.Identity()

	shardConf, err := source.manager.orchestration.ShardConfig(partitionID, shardID, 1)
	require.NoError(t, err)
	shardState, err := storage.NewShardInfo(shardConf, crypto.SHA256)
	require.NoError(t, err)
	parent := bytes.Repeat([]byte{5}, 32)
	shardState.IR.BlockHash = bytes.Clone(parent)
	shardState.IR.Hash = bytes.Repeat([]byte{0x37}, 32)
	successorTRHash, err := shardState.TR.Hash()
	require.NoError(t, err)
	orderedRound, commitSealRound := start+3, start+8
	record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 2, OrderedRound: orderedRound, ActivationRound: activation,
		PredecessorBodyID: bytes.Clone(predecessor), NextBodyID: bodyID[:], FrozenID: bytes.Repeat([]byte{2}, 32),
		SuccessorTRHash: successorTRHash, Kind: "commit"}
	control := evmroot.ControlState{Network: 5, Epoch: 2, OrderedRound: orderedRound, PredecessorBodyID: bytes.Clone(predecessor),
		Phase: "committed", RecordBytes: record.Bytes(), PreviousDigest: bytes.Repeat([]byte{4}, 32), FrozenParent: parent}
	shardKey := types.PartitionShardID{PartitionID: partitionID, ShardID: shardID.Key()}
	state := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{shardKey: shardState},
		Changed: storage.ShardSet{shardKey: {}}, Control: &control}
	tree, _, err := state.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	timestamp := types.NewTimestamp()
	voteInfo := &rctypes.RoundInfo{Version: 1, RoundNumber: commitSealRound + 1, ParentRoundNumber: commitSealRound, Epoch: 2,
		Timestamp: timestamp, CurrentRootHash: tree.RootHash()}
	voteHash, err := voteInfo.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: commitSealRound, Epoch: 2,
		Timestamp: timestamp, Hash: tree.RootHash(), PreviousHash: voteHash}
	message, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: voteInfo, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for id, signer := range signers {
		sig, err := signer.SignBytes(message)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	proof := handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: record, Control: control, ControlPath: path, CommitQC: qc}
	_, err = handoff.VerifyOldCommitProof(proof, old2)
	require.NoError(t, err)
	block := &storage.ExecutedBlock{HashAlgo: crypto.SHA256, RootHash: tree.RootHash(), ShardState: state}
	_, err = block.GenerateCertificates(qc)
	require.NoError(t, err)
	shardInfo := abdrc.ShardInfo{Partition: shardState.PartitionID, Shard: shardState.ShardID,
		T2Timeout: shardState.T2Timeout, RootHash: shardState.RootHash,
		PrevEpochStat: shardState.PrevEpochStat, Stat: shardState.Stat,
		PrevEpochFees: shardState.PrevEpochFees, Fees: shardState.Fees,
		IR: shardState.IR, IRTR: shardState.TR, ShardConfHash: shardState.ShardConfHash,
		UC: &shardState.LastCR.UC, TR: &shardState.LastCR.Technical}
	head := &abdrc.CommittedBlock{Block: &rctypes.BlockData{Version: 2, Epoch: 2, Round: commitSealRound,
		Payload: &rctypes.Payload{Version: 2}}, ShardInfo: []abdrc.ShardInfo{shardInfo}, Control: &control, CommitQc: qc}

	obs := testobservability.Default(t)
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "second.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, db.StoreHandoffBody(bodyID[:], body.Encode()))
	root.blockStore, err = storage.NewFromState(crypto.SHA256, head, db, source.manager.orchestration, obs.Logger(), storage.ProfileHandoff)
	require.NoError(t, err)
	return secondHandoff{root: root, proof: proof, head: head, body: body, signers: signers}
}

// A subsequent handoff supersedes epoch 2 by epoch 3. Authentic live messages of epoch 2 (the superseded committee, which
// ran until the install) and of epoch 1 then arrive at the real handlers: both are refused with ErrVoteEpoch, are not
// buffered, and are not weighed with epoch 3's weight for the same identity.
func TestOldEpochMessagesAfterASupersedingHandoff(t *testing.T) {
	c := newAnchorCluster(t)
	signers := map[string]abcrypto.Signer{}
	var source *anchorReplica
	for id, r := range c.replicas {
		signers[id.String()] = r.manager.safety.signer
		if r.oldSigners[id.String()] != nil {
			source = r
		}
	}
	require.NotNil(t, source)
	h := newSecondHandoff(t, source, signers)
	root := h.root
	author := root.id.String()

	_, err := root.InstallEpochGenesis(h.proof, h.head, h.body)
	require.NoError(t, err, "the superseding handoff installs")
	require.EqualValues(t, 3, root.trustBase.Load().Epoch)
	root.pacemaker.Reset(context.Background(), h.head.Block.Round, nil, nil)
	t.Cleanup(root.pacemaker.Stop)

	ctx := context.Background()
	round := root.pacemaker.GetCurrentRound() + 1
	// epoch 2 is no longer the epoch of the voting weights; the identity weighs 6 in epoch 3 and 1 in epoch 2
	setStakes(root, 7, map[string]uint64{author: 6})
	for name, msgs := range map[string]func() (*abdrc.VoteMsg, *abdrc.TimeoutMsg){
		"epoch 2": func() (*abdrc.VoteMsg, *abdrc.TimeoutMsg) {
			return epochMessages(t, 2, h.proof.CommitQC, h.signers, author, round)
		},
		"epoch 1": func() (*abdrc.VoteMsg, *abdrc.TimeoutMsg) { return oldEpochMessages(t, source, author, round) },
	} {
		t.Run(name, func(t *testing.T) {
			vote, timeout := msgs()
			require.NoError(t, vote.Verify(root.trustBaseStore), "authentic under its own epoch")
			require.NoError(t, timeout.Verify(root.trustBaseStore))
			require.ErrorIs(t, root.onVoteMsg(ctx, vote), ErrVoteEpoch)
			require.ErrorIs(t, root.onTimeoutMsg(ctx, timeout), ErrVoteEpoch)
			require.NotContains(t, root.voteBuffer, author)
		})
	}
	w, err := root.bufferedWeight()
	require.NoError(t, err)
	require.Zero(t, w)
}
