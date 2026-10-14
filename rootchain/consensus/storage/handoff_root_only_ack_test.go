package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A root-only handoff changes the root committee and installs no EVM assignment, so nothing in the shard epochs shows it pending. The EVM
// shard acknowledges it by certifying a block after the frozen parent. A second root-only handoff ordered before that would bind the same
// stalled parent again, and the two could never be folded into one acknowledgement (ristik/bft-core#604). The next Prepare is therefore
// refused while the previous root-only step is unacknowledged, and accepted once the EVM has certified.
func TestSecondRootOnlyHandoffWaitsForTheEVMToAcknowledgeTheFirst(t *testing.T) {
	s := profileStore(t)
	frozenParent := bytes.Repeat([]byte{0x42}, 32)
	installTestFrozenShard(t, s, frozenParent)
	evm := types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}
	predecessor := make([]byte, 32)
	s.handoffAuth = testRecordAuthority{predecessor: predecessor}
	body1, body2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)

	add := func(epoch, round uint64, rec evmroot.OrderedHandoffRecord, evmHash []byte) error {
		prior, err := s.Block(round - 1)
		require.NoError(t, err)
		payload := &rctypes.Payload{Version: 2}
		if len(rec.Kind) != 0 {
			payload.HandoffRecords = [][]byte{rec.Bytes()}
		}
		if evmHash != nil {
			payload.Requests = []*rctypes.IRChangeReq{{Partition: 8}}
		}
		_, err = s.Add(&rctypes.BlockData{Version: 2, Epoch: epoch, Round: round, Payload: payload,
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: epoch, CurrentRootHash: prior.RootHash}}},
			mockIRVerifier{verify: func(_ uint64, _ *rctypes.IRChangeReq) (*types.InputRecord, error) {
				return &types.InputRecord{Version: 1, RoundNumber: round, BlockHash: bytes.Clone(evmHash)}, nil
			}})
		return err
	}
	zero := make([]byte, 32)
	makeRecord := func(kind string, epoch, round, activation uint64, body []byte, tr []byte) evmroot.OrderedHandoffRecord {
		r := evmroot.OrderedHandoffRecord{Network: 5, Epoch: epoch, OrderedRound: round, PredecessorBodyID: predecessor, NextBodyID: body,
			FrozenID: bytes.Repeat([]byte{3}, 32), ActivationRound: activation, SuccessorTRHash: tr, Kind: kind}
		if kind == "prepare" {
			r.FrozenID, r.SuccessorTRHash = zero, zero
		}
		if kind == "freeze" {
			r.SuccessorTRHash = zero
		}
		return r
	}

	// the first root-only handoff, epoch 1 -> 2: Prepare (2), Freeze (3), Commit (4), activation 7
	tr, err := s.blockTree.Root().ShardState.States[evm].TR.Hash()
	require.NoError(t, err)
	require.NoError(t, add(1, 2, makeRecord("prepare", 1, 2, 7, body1, tr), nil))
	require.NoError(t, add(1, 3, makeRecord("freeze", 1, 3, 7, body1, tr), nil))
	commit := makeRecord("commit", 1, 4, 7, body1, tr)
	require.NoError(t, add(1, 4, commit, nil))
	h := mustBlock(t, s, 4)
	require.NoError(t, add(1, 5, evmroot.OrderedHandoffRecord{}, nil))
	suffix := mustBlock(t, s, 5)
	_, err = s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 5, ParentRoundNumber: 4, Epoch: 1},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 4, Epoch: 1, Hash: h.RootHash}})
	require.NoError(t, err)
	checkpoint := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
	checkpoint.ShardInfo, err = toRecoveryShardInfo(suffix)
	require.NoError(t, err)
	verified := evmroot.VerifiedHandoff{RecordID: commit.ID(), Record: commit, Root: suffix.RootHash,
		ControlDigest: suffix.ShardState.Control.Digest(), OrderRound: 4, CommitSealRound: 5, Epoch: 1}
	genesis := evmroot.EpochGenesis{Network: 5, Epoch: 2, Start: 7, OrderedRound: 4, NextBodyID: body1, RecordID: commit.ID(), Root: suffix.RootHash,
		ControlDigest: verified.ControlDigest, FrozenID: commit.FrozenID, SuccessorTRHash: tr}
	anchor, err := s.InstallEpochAnchor(checkpoint, verified, genesis)
	require.NoError(t, err)
	predecessor = body1
	s.handoffAuth = testRecordAuthority{predecessor: predecessor}
	_, err = s.Add(&rctypes.BlockData{Version: 2, Epoch: 2, Round: 7, Anchor: anchor, Payload: &rctypes.Payload{Version: 2}}, nil)
	require.NoError(t, err)
	require.Equal(t, "idle", mustBlock(t, s, 7).ShardState.Control.Phase)
	require.Equal(t, frozenParent, []byte(mustBlock(t, s, 7).ShardState.States[evm].IR.BlockHash), "the EVM has certified nothing since the frozen parent")

	// the second root-only handoff cannot start: the first is not acknowledged
	require.ErrorIs(t, add(2, 8, makeRecord("prepare", 2, 8, 13, body2, tr), nil), ErrAssignmentAckPending)
	require.Equal(t, "idle", mustBlock(t, s, 7).ShardState.Control.Phase)

	// the EVM certifies a block: that is the acknowledgement
	ack := bytes.Repeat([]byte{0x77}, 32)
	require.NoError(t, add(2, 8, evmroot.OrderedHandoffRecord{}, ack))
	require.Equal(t, ack, []byte(mustBlock(t, s, 8).ShardState.States[evm].IR.BlockHash))
	require.Empty(t, mustBlock(t, s, 8).ShardState.Control.UnackedParent, "the marker is cleared by the certified block")

	// and now the next root-only Prepare is accepted
	require.NoError(t, add(2, 9, makeRecord("prepare", 2, 9, 14, body2, tr), nil))
	prepared := mustBlock(t, s, 9).ShardState.Control
	require.Equal(t, "prepared", prepared.Phase)
	require.Equal(t, ack, prepared.FrozenParent, "the second handoff binds the new parent, not the first one's")
}
