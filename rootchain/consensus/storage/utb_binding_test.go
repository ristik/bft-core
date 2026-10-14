package storage

import (
	"errors"
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
