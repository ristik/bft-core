package storage

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

func bindingQC(round, committed uint64, utb []byte) *rctypes.QuorumCert {
	qc := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round, ParentRoundNumber: round - 1, Epoch: 2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: committed, Epoch: 2, Hash: []byte{7}}}
	if utb != nil {
		qc.UTB = &rctypes.UTBCertificate{Unsigned: utb}
	}
	return qc
}

func TestBindingRequiresExactlyTheEntryTheCommittedStateImplies(t *testing.T) {
	var asked []uint64
	entry := []byte("entry")
	var implied []byte
	var srcErr error
	b := NewUTBBinding(func(uint64) (votesig.Config, error) { return votesig.Config{UTB: true}, nil },
		func(c *rctypes.RoundInfo, epoch uint64) ([]byte, error) {
			asked = append(asked, c.RoundNumber)
			require.EqualValues(t, 2, epoch)
			require.EqualValues(t, 2, c.Epoch)
			require.Equal(t, []byte{7}, []byte(c.CurrentRootHash))
			return implied, srcErr
		})

	implied = entry
	require.NoError(t, b(bindingQC(8, 7, entry)))
	require.ErrorIs(t, b(bindingQC(8, 7, nil)), ErrUTBBinding, "the outgoing handoff without its endorsement")
	require.ErrorIs(t, b(bindingQC(8, 7, []byte("other"))), ErrUTBBinding, "another entry than the state implies")

	implied = nil
	require.NoError(t, b(bindingQC(8, 7, nil)))
	require.ErrorIs(t, b(bindingQC(8, 7, entry)), ErrUTBBinding, "an endorsement the state does not imply")

	asked = nil
	require.NoError(t, b(bindingQC(8, 0, nil)), "a non-committing certificate")
	require.ErrorIs(t, b(bindingQC(8, 0, entry)), ErrUTBBinding, "an endorsement on a non-committing certificate")
	require.Empty(t, asked, "the executed state is not consulted for a non-committing certificate")

	srcErr = errors.New("handoff body not available")
	require.ErrorIs(t, b(bindingQC(8, 7, nil)), ErrUTBBinding, "fails closed when the committed state cannot be resolved")
	require.NoError(t, b(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: rctypes.GenesisRootRound}, LedgerCommitInfo: &types.UnicitySeal{}}), "the genesis certificate")
}

func TestBindingIsOnlyForUTBEpochs(t *testing.T) {
	b := NewUTBBinding(func(uint64) (votesig.Config, error) { return votesig.Config{}, nil },
		func(*rctypes.RoundInfo, uint64) ([]byte, error) { t.Fatal("not consulted"); return nil, nil })
	require.NoError(t, b(bindingQC(8, 7, []byte("x"))))
	bad := NewUTBBinding(func(uint64) (votesig.Config, error) { return votesig.Config{}, errors.New("unknown epoch") }, nil)
	require.ErrorIs(t, bad(bindingQC(8, 7, nil)), ErrUTBBinding)
}

// ProcessQc applies the binding before anything is inserted or committed.
func TestProcessQcRefusesAMismatchedEndorsementBeforeApplyingTheCertificate(t *testing.T) {
	bStore := initBlockStoreFromGenesis(t, nil)
	rBlock := bStore.blockTree.Root()
	bStore.SetUTBBinding(func(qc *rctypes.QuorumCert) error {
		if qc.UTB == nil {
			return ErrUTBBinding
		}
		return nil
	})
	before := bStore.GetHighQc().GetRound()
	qc := &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: rctypes.GenesisRootRound + 1, ParentRoundNumber: rctypes.GenesisRootRound},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, Hash: rBlock.RootHash, RootChainRoundNumber: rctypes.GenesisRootRound},
	}
	ucs, err := bStore.ProcessQc(qc)
	require.ErrorIs(t, err, ErrUTBBinding)
	require.Nil(t, ucs)
	require.Equal(t, before, bStore.GetHighQc().GetRound(), "the certificate was not inserted")
}

func utbBindingStoreWithRootTwo(t *testing.T) *BlockStore {
	bStore := initBlockStoreFromGenesis(t, nil)
	rBlock := bStore.blockTree.Root()
	mockBlockVer := mockIRVerifier{
		verify: func(round uint64, irChReq *rctypes.IRChangeReq) (*types.InputRecord, error) {
			luc, err := bStore.GetCertificate(irChReq.Partition, irChReq.Shard)
			if err != nil {
				return nil, fmt.Errorf("invalid payload: partition %s state is missing: %w", irChReq.Partition, err)
			}
			switch irChReq.CertReason {
			case rctypes.Quorum:
				// NB! there was at least one request, otherwise we would not be here
				return irChReq.Requests[0].InputRecord, nil
			case rctypes.QuorumNotPossible:
			case rctypes.T2Timeout:
				return luc.UC.InputRecord, nil
			}
			return nil, fmt.Errorf("unknown certification reason %v", irChReq.CertReason)
		},
	}
	block := &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound,
		Payload: &rctypes.Payload{},
		Qc:      nil,
	}
	_, err := bStore.Add(block, mockBlockVer)
	require.ErrorContains(t, err, "add block failed: different block for round 1 is already in store")
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 1,
		Payload: &rctypes.Payload{},
		Qc:      bStore.GetHighQc(), // the qc is genesis qc
	}
	// Proposal always comes with Qc and Block, process Qc first and then new block
	// add stale qc for block 1 - this is already present as highQC from genesis block
	ucs, err := bStore.ProcessQc(block.Qc)
	require.NoError(t, err)
	require.Nil(t, ucs)

	// and the new block 2 - since there is no shards, RootHash stays nil
	rh, err := bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)

	// add qc for round 3, commits round 1
	vInfo := &rctypes.RoundInfo{
		RoundNumber:       rctypes.GenesisRootRound + 1,
		ParentRoundNumber: rctypes.GenesisRootRound,
		CurrentRootHash:   rh,
	}
	qc := &rctypes.QuorumCert{
		VoteInfo: vInfo,
		LedgerCommitInfo: &types.UnicitySeal{
			Version:              1,
			Hash:                 rBlock.RootHash,
			RootChainRoundNumber: rctypes.GenesisRootRound,
		},
	}
	ucs, err = bStore.ProcessQc(qc)
	require.NoError(t, err)
	require.Empty(t, ucs)

	b, err := bStore.Block(rctypes.GenesisRootRound + 1)
	require.NoError(t, err)
	require.EqualValues(t, rctypes.GenesisRootRound+1, b.BlockData.Round)

	// add block 3
	// qc for round 2, does not commit a round
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 2,
		Payload: &rctypes.Payload{},
		Qc:      qc,
	}
	rh, err = bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)
	// prepare block 4
	vInfo = &rctypes.RoundInfo{
		RoundNumber:       rctypes.GenesisRootRound + 2,
		ParentRoundNumber: rctypes.GenesisRootRound + 1,
		CurrentRootHash:   rh,
	}
	qc = &rctypes.QuorumCert{
		VoteInfo: vInfo,
		LedgerCommitInfo: &types.UnicitySeal{
			Version:              1,
			Hash:                 rBlock.RootHash,
			RootChainRoundNumber: rctypes.GenesisRootRound + 1,
		},
	}
	// qc for round 4, commits round 2
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 3,
		Payload: &rctypes.Payload{},
		Qc:      qc,
	}
	// Add
	ucs, err = bStore.ProcessQc(qc)
	require.NoError(t, err)
	require.Empty(t, ucs)
	// add block 4
	rh, err = bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)
	rBlock = bStore.blockTree.Root()
	require.Equal(t, uint64(2), rBlock.BlockData.Round)
	return bStore
}

// Recovery replays the peer's pending QCs, the first of which can commit a round the tree has already pruned. In a UTB epoch that certificate is not
// bound (the round was bound when it committed) and not refused by the binding: the commit refuses it with ErrCommitFailed, which recovery ignores for its
// first block (the commit error is whatever the commit says: "block not found" or a hash mismatch). Before, the binding failed first (ErrUTBBinding).
func TestProcessQcInAUTBEpochLeavesAPrunedCommitToTheCommit(t *testing.T) {
	bStore := utbBindingStoreWithRootTwo(t)
	require.Equal(t, uint64(3), bStore.GetHighQc().GetRound())
	entry := func(committed *rctypes.RoundInfo, epoch uint64) ([]byte, error) {
		_, _, err := bStore.HandoffCommittedAt(committed.RoundNumber, committed.Epoch, committed.CurrentRootHash)
		return nil, err
	}
	bStore.SetUTBBinding(NewUTBBinding(func(uint64) (votesig.Config, error) { return votesig.Config{UTB: true}, nil }, entry))

	// a certificate of round 4 whose commit info names round 1, below the root (2)
	pruned := &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: 4, ParentRoundNumber: 3},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1, Hash: []byte{1}},
		Envelope:         votesig.EnvelopeUTB,
	}
	_, err := bStore.ProcessQc(pruned)
	require.NotErrorIs(t, err, ErrUTBBinding, "an already committed round is not bound")
	require.ErrorContains(t, err, "committing new root block", "it reaches the commit, which refuses it as before")
	require.Equal(t, uint64(4), bStore.GetHighQc().GetRound(), "the certificate was inserted")

	// a round the tree does not hold and that is NOT below the root stays refused by the binding
	missing := &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: 5, ParentRoundNumber: 4},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 4000, Hash: []byte{1}},
		Envelope:         votesig.EnvelopeUTB,
	}
	_, err = bStore.ProcessQc(missing)
	require.ErrorIs(t, err, ErrUTBBinding)
	require.Equal(t, uint64(4), bStore.GetHighQc().GetRound(), "and it was not inserted")
}

// The endorsed entry is made durable before the certificate is inserted: a failure leaves the certificate unapplied, and a retry is not mistaken for a
// stale certificate.
func TestProcessQcRetainsTheEndorsedEntryBeforeApplyingTheCertificate(t *testing.T) {
	bStore := utbBindingStoreWithRootTwo(t)
	var calls, highAtCall []uint64
	fail := true
	bStore.SetUTBRetention(func(qc *rctypes.QuorumCert) error {
		calls = append(calls, qc.GetRound())
		highAtCall = append(highAtCall, bStore.GetHighQc().GetRound())
		if fail {
			return fmt.Errorf("disk full")
		}
		return nil
	})
	endorsed := func() *rctypes.QuorumCert {
		return &rctypes.QuorumCert{
			VoteInfo:         &rctypes.RoundInfo{RoundNumber: 4, ParentRoundNumber: 3},
			LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1, Hash: []byte{1}},
			Envelope:         votesig.EnvelopeUTB,
			UTB:              &rctypes.UTBCertificate{Unsigned: []byte("entry")},
		}
	}
	_, err := bStore.ProcessQc(endorsed())
	require.ErrorIs(t, err, ErrUTBRetention)
	require.Equal(t, uint64(3), bStore.GetHighQc().GetRound(), "the certificate was not inserted")
	require.Equal(t, []uint64{3}, highAtCall, "retention ran before the insert")

	fail = false
	_, err = bStore.ProcessQc(endorsed())
	require.NotErrorIs(t, err, ErrUTBRetention, "the retry is not stale and is applied")
	require.Equal(t, uint64(4), bStore.GetHighQc().GetRound())
	require.Equal(t, []uint64{4, 4}, calls)

	// a certificate without an endorsement never asks for retention
	calls = nil
	plain := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 5, ParentRoundNumber: 4}, LedgerCommitInfo: &types.UnicitySeal{Version: 1}}
	_, _ = bStore.ProcessQc(plain)
	require.Empty(t, calls)
}

// A certificate that commits an already committed round is not retained either: the entry was retained when that round committed.
func TestProcessQcDoesNotRetainWhatAnAlreadyCommittedRoundCarried(t *testing.T) {
	bStore := utbBindingStoreWithRootTwo(t)
	retained := 0
	bStore.SetUTBRetention(func(*rctypes.QuorumCert) error { retained++; return nil })
	bStore.SetUTBBinding(NewUTBBinding(func(uint64) (votesig.Config, error) { return votesig.Config{UTB: true}, nil },
		func(c *rctypes.RoundInfo, _ uint64) ([]byte, error) {
			_, _, err := bStore.HandoffCommittedAt(c.RoundNumber, c.Epoch, c.CurrentRootHash)
			return nil, err
		}))
	qc := &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: 4, ParentRoundNumber: 3},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1, Hash: []byte{1}},
		Envelope:         votesig.EnvelopeUTB,
		UTB:              &rctypes.UTBCertificate{Unsigned: []byte("entry")},
	}
	_, err := bStore.ProcessQc(qc)
	require.NotErrorIs(t, err, ErrUTBBinding)
	require.NotErrorIs(t, err, ErrUTBRetention)
	require.Zero(t, retained)
}
