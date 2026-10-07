package abdrc

import (
	"testing"

	"github.com/stretchr/testify/require"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

func TestTimestampBoundScheme2VoteAndQC(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	v := f.voteV2(t, "1", 2, 12, true, f.legacyQC(t, 1, 11))
	// Historical bytes still verify. New votes append authenticated proposal time.
	require.NoError(t, v.Verify(f.store))
	oldHash := append([]byte(nil), v.LedgerCommitInfo.PreviousHash...)
	v.VoteInfo.Timestamp = 5000
	vi := votesig.VoteInfo{Epoch: 2, Round: 12, Parent: 11, Exec: [32]byte(v.VoteInfo.CurrentRootHash), Timestamp: 5000}
	hash, err := f.cfg.VoteInfoHash(vi)
	require.NoError(t, err)
	require.NotEqual(t, oldHash, hash[:], "new timestamp must change the signed vote-info hash")
	v.LedgerCommitInfo.PreviousHash = hash[:]
	qc := &drctypes.QuorumCert{Scheme: votesig.SchemeDomainBound, VoteInfo: v.VoteInfo, LedgerCommitInfo: v.LedgerCommitInfo,
		Signatures: map[string]hex.Bytes{}, SealSignatures: map[string]hex.Bytes{}}
	for _, id := range f.ids {
		v.Author = id
		require.NoError(t, v.SignDomainBound(f.signers[id], f.cfg))
		qc.Signatures[id] = v.Signature
		qc.SealSignatures[id] = v.SealSignature
	}
	require.NoError(t, qc.VerifyWith(f.store))
	raw, err := types.Cbor.Marshal(v)
	require.NoError(t, err)
	var vote VoteMsg
	require.NoError(t, types.Cbor.Unmarshal(raw, &vote))
	require.EqualValues(t, 5000, vote.VoteInfo.Timestamp)
	require.NoError(t, vote.Verify(f.store))
	raw, err = types.Cbor.Marshal(qc)
	require.NoError(t, err)
	var certificate drctypes.QuorumCert
	require.NoError(t, types.Cbor.Unmarshal(raw, &certificate))
	require.EqualValues(t, 5000, certificate.VoteInfo.Timestamp)
	require.NoError(t, certificate.VerifyWith(f.store))
	certificate.VoteInfo.Timestamp++
	require.ErrorIs(t, certificate.VerifyWith(f.store), votesig.ErrStatement)
	vote.VoteInfo.Timestamp++
	require.ErrorIs(t, vote.Verify(f.store), votesig.ErrStatement)
}

func TestTimestampBoundWireRejectsAmbiguousTime(t *testing.T) {
	raw, err := types.Cbor.Marshal([]any{uint64(2), uint64(12), uint64(11), make([]byte, 32), uint64(0)})
	require.NoError(t, err)
	var info drctypes.DomainBoundVoteInfo
	require.ErrorIs(t, types.Cbor.Unmarshal(raw, &info), votesig.ErrStatement)
	raw, err = types.Cbor.Marshal([]any{uint64(2), uint64(12), uint64(11)})
	require.NoError(t, err)
	require.ErrorIs(t, types.Cbor.Unmarshal(raw, &info), votesig.ErrStatement)
}

func TestTimestampLessScheme2HistoryNeedsCommitTimeProof(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	qc := f.qcV2(t, true, "1", "2", "3")
	require.NoError(t, qc.VerifyWith(f.store), "historical timestamp-less QC still verifies")
	seal := qc.LedgerCommitInfo
	head := &CommittedBlock{Block: &drctypes.BlockData{Round: seal.RootChainRoundNumber, Epoch: seal.Epoch, Timestamp: seal.Timestamp}, CommitQc: qc}
	state := &StateMsg{CommittedHead: head}
	require.NoError(t, state.verifyTimestamps(), "native signed seal authenticates committed historical time")
	head.Block.Timestamp++
	require.ErrorIs(t, state.verifyTimestamps(), ErrRecoveryTimestamp, "committed time must match its signed seal")
	head.Block.Timestamp--
	state.Pending = []*drctypes.BlockData{{Round: qc.GetRound(), Epoch: qc.VoteInfo.Epoch, Timestamp: 5000, Qc: qc}}
	require.ErrorIs(t, state.verifyTimestamps(), ErrRecoveryTimestamp, "timestamp-less uncommitted QC cannot authenticate a live parent")
	require.ErrorIs(t, state.verifyTimestamps(), drctypes.ErrTimestampProof)
}

func TestAnchorHeadUnverifiedCertificatesCannotProvePendingTime(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	qc := f.qcV2(t, true, "1", "2", "3")
	require.NoError(t, qc.VerifyWith(f.store))
	state := &StateMsg{
		CommittedHead: &CommittedBlock{Anchor: &drctypes.EpochAnchor{}, Block: &drctypes.BlockData{},
			Qc: &drctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Epoch: qc.VoteInfo.Epoch, RootChainRoundNumber: qc.GetRound(), Timestamp: 5000, Hash: make([]byte, 32)}}},
		Pending: []*drctypes.BlockData{{Epoch: qc.VoteInfo.Epoch, Round: qc.GetRound(), Timestamp: 5000, Qc: qc}},
	}
	require.ErrorIs(t, state.verifyTimestamps(), ErrRecoveryTimestamp)
	require.ErrorIs(t, state.verifyTimestamps(), drctypes.ErrTimestampProof)
}
