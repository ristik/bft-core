package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// countingVerifier is the legacy verifier at its most permissive: it certifies whatever it is handed (the committed-state checks of
// VerifyIRChangeReq pass for a request built on the closed epoch's certificate after a root-only activation, which changes nothing they
// compare). The block executor's activation freshness rule must refuse without it.
func countingVerifier(calls *int) mockIRVerifier {
	return mockIRVerifier{verify: func(round uint64, irChReq *rctypes.IRChangeReq) (*types.InputRecord, error) {
		*calls++
		ir := irChReq.Requests[0].InputRecord
		return &types.InputRecord{Version: 1, RoundNumber: ir.RoundNumber, Hash: bytes.Clone(ir.Hash), PreviousHash: bytes.Clone(ir.PreviousHash),
			BlockHash: bytes.Clone(ir.BlockHash), Timestamp: ir.Timestamp}, nil
	}}
}

// A real root-only activation (epoch 1 -> 2) on the legacy, view-less branch (#1036): a request built on the closed epoch's certificate,
// delivered fresh after the activation, with its quorum proof in the first ordinary successor block, is refused, and the block with it.
// The block without it is accepted; once that block, which recertifies the shard, is committed, the shard's certificate is of epoch 2 and a
// request built on it is certified.
func TestARequestOfTheClosedEpochIsNotCertifiedAfterARootOnlyActivation(t *testing.T) {
	s := profileStore(t)
	frozenParent := bytes.Repeat([]byte{0x42}, 32)
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	ver, err := signer.Verifier()
	require.NoError(t, err)
	key, err := ver.MarshalPublicKey()
	require.NoError(t, err)
	installTestFrozenShardKeyed(t, s, frozenParent, key)
	evm := types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}
	// the shard's committed certificate is of the closing root epoch, as every certificate certified in it is
	s.blockTree.Root().ShardState.States[evm].LastCR.UC.UnicitySeal.Epoch = 1
	predecessor := make([]byte, 32)
	s.handoffAuth = testRecordAuthority{predecessor: predecessor}
	body := bytes.Repeat([]byte{1}, 32)

	block := func(epoch, round uint64, payload *rctypes.Payload, anchor *rctypes.EpochAnchor) *rctypes.BlockData {
		b := &rctypes.BlockData{Version: 3, Epoch: epoch, Round: round, Payload: payload, Anchor: anchor}
		if anchor == nil {
			prior, err := s.Block(round - 1)
			require.NoError(t, err)
			b.Qc = &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: epoch, CurrentRootHash: prior.RootHash}}
		}
		return b
	}
	verified := 0
	add := func(epoch, round uint64, rec evmroot.OrderedHandoffRecord) {
		payload := &rctypes.Payload{Version: 3}
		if len(rec.Kind) != 0 {
			payload.HandoffRecords = [][]byte{rec.Bytes()}
		}
		_, err := s.Add(block(epoch, round, payload, nil), countingVerifier(&verified))
		require.NoError(t, err)
	}
	zero := make([]byte, 32)
	tr, err := s.blockTree.Root().ShardState.States[evm].TR.Hash()
	require.NoError(t, err)
	record := func(kind string, round uint64) evmroot.OrderedHandoffRecord {
		r := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: round, PredecessorBodyID: predecessor, NextBodyID: body,
			FrozenID: bytes.Repeat([]byte{3}, 32), ActivationRound: 7, SuccessorTRHash: tr, Kind: kind}
		switch kind {
		case "prepare":
			r.FrozenID, r.SuccessorTRHash = zero, zero
		case "freeze":
			r.SuccessorTRHash = zero
		}
		return r
	}

	// the root-only handoff of epoch 1: Prepare (2), Freeze (3), Commit (4), activation at round 7
	add(1, 2, record("prepare", 2))
	add(1, 3, record("freeze", 3))
	commit := record("commit", 4)
	add(1, 4, commit)
	h := mustBlock(t, s, 4)
	add(1, 5, evmroot.OrderedHandoffRecord{})
	suffix := mustBlock(t, s, 5)
	_, err = s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 5, ParentRoundNumber: 4, Epoch: 1},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 4, Epoch: 1, Hash: h.RootHash}})
	require.NoError(t, err)
	checkpoint := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
	checkpoint.ShardInfo, err = toRecoveryShardInfo(suffix)
	require.NoError(t, err)
	handoff := evmroot.VerifiedHandoff{RecordID: commit.ID(), Record: commit, Root: suffix.RootHash,
		ControlDigest: suffix.ShardState.Control.Digest(), OrderRound: 4, CommitSealRound: 5, Epoch: 1}
	genesis := evmroot.EpochGenesis{Network: 5, Epoch: 2, Start: 7, OrderedRound: 4, NextBodyID: body, RecordID: commit.ID(), Root: suffix.RootHash,
		ControlDigest: handoff.ControlDigest, FrozenID: commit.FrozenID, SuccessorTRHash: tr}
	anchor, err := s.InstallEpochAnchor(checkpoint, handoff, genesis)
	require.NoError(t, err)
	s.handoffAuth = testRecordAuthority{predecessor: body}

	// the request the shard built on its certificate of the closed epoch, delivered fresh after the activation: it matches the shard's
	// committed context in everything a root-only activation leaves unchanged
	si := s.blockTree.Root().ShardState.States[evm]
	require.EqualValues(t, 1, si.LastCR.UC.GetRootEpoch())
	request := func(on *ShardInfo) *rctypes.IRChangeReq {
		ir := &types.InputRecord{Version: 1, RoundNumber: on.LastCR.Technical.Round, Epoch: on.LastCR.Technical.Epoch, PreviousHash: bytes.Clone(on.RootHash),
			Hash: bytes.Repeat([]byte{0x55}, 32), BlockHash: bytes.Repeat([]byte{0x66}, 32), SummaryValue: []byte{1}, Timestamp: on.LastCR.UC.UnicitySeal.Timestamp}
		req := &certification.BlockCertificationRequest{PartitionID: 8, NodeID: "n", InputRecord: ir}
		require.NoError(t, req.Sign(signer))
		return &rctypes.IRChangeReq{Partition: 8, CertReason: rctypes.Quorum, Requests: []*certification.BlockCertificationRequest{req}}
	}
	old := request(si)

	_, err = s.Add(block(2, 7, &rctypes.Payload{Version: 3, Requests: []*rctypes.IRChangeReq{old}}, anchor), countingVerifier(&verified))
	require.ErrorIs(t, err, ErrRequestBeforeActivation, "the first ordinary successor block may not certify it")
	require.ErrorIs(t, err, ErrStaleRequestContext)
	require.Zero(t, verified, "refused before any verifier judges it")

	// the first ordinary block without it recertifies the shard; until that is committed, the old request is refused in its children too
	_, err = s.Add(block(2, 7, &rctypes.Payload{Version: 3}, anchor), countingVerifier(&verified))
	require.NoError(t, err)
	_, err = s.Add(block(2, 8, &rctypes.Payload{Version: 3, Requests: []*rctypes.IRChangeReq{old}}, nil), countingVerifier(&verified))
	require.ErrorIs(t, err, ErrRequestBeforeActivation)
	add(2, 8, evmroot.OrderedHandoffRecord{})
	first := mustBlock(t, s, 7)
	_, err = s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 8, ParentRoundNumber: 7, Epoch: 2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 7, Epoch: 2, Hash: first.RootHash}})
	require.NoError(t, err)
	recertified := s.blockTree.Root().ShardState.States[evm]
	require.EqualValues(t, 2, recertified.LastCR.UC.GetRootEpoch(), "the first ordinary block recertified the shard in epoch 2")

	// a request built on the recertification is certified
	_, err = s.Add(block(2, 9, &rctypes.Payload{Version: 3, Requests: []*rctypes.IRChangeReq{request(recertified)}}, nil), countingVerifier(&verified))
	require.NoError(t, err)
	require.Equal(t, 1, verified)
}

// The rule is void in the genesis root epoch: nothing precedes it, and a shard certified there (or carrying no seal epoch) is not stale.
func TestTheActivationFreshnessRuleIsVoidInTheGenesisRootEpoch(t *testing.T) {
	si := &ShardInfo{LastCR: &certification.CertificationResponse{UC: types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{Epoch: 0}}}}
	require.NoError(t, si.FreshInRootEpoch(rctypes.GenesisRootEpoch))
	require.NoError(t, si.FreshInRootEpoch(0), "a manager that names no root epoch")
	require.ErrorIs(t, si.FreshInRootEpoch(2), ErrRequestBeforeActivation)
	si.LastCR.UC.UnicitySeal.Epoch = 2
	require.NoError(t, si.FreshInRootEpoch(2))
	require.NoError(t, (*ShardInfo)(nil).FreshInRootEpoch(2))
}
