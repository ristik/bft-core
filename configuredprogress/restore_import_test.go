package configuredprogress

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

type restoreEpochTrust struct {
	bases map[uint64]*types.RootTrustBaseV1
}

func (t restoreEpochTrust) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	return t.bases[epoch], nil
}

type restoreEpochAuthority struct{ epoch uint64 }

func (a restoreEpochAuthority) CurrentRootEpoch() (uint64, bool) { return a.epoch, true }

func TestCrossEpochReplayedTipOpensAsCurrentJournal(t *testing.T) {
	f := newFixture(t, 1)
	base2 := *f.c.TrustBase
	base2.Epoch = 2
	base2.Signatures = nil
	trust := restoreEpochTrust{bases: map[uint64]*types.RootTrustBaseV1{1: f.c.TrustBase, 2: &base2}}
	c := f.ctx
	c.Observation.TrustBases, c.Observation.EpochAuthority = trust, restoreEpochAuthority{epoch: 2}
	c.Record.TrustBases, c.Record.EpochAuthority = trust, c.Observation.EpochAuthority
	s, path := f.open(3)
	_, _, err := s.Initialize(context.Background(), c)
	require.NoError(t, err)
	limits := JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}
	require.NoError(t, s.EnableJournal(context.Background(), c, limits))
	authorizing := f.bootstrap(1, 4)
	result := f.first(1, 2, 5)
	resultUC := result.Certificate()
	resultTR := result.TechnicalRecord()
	resultUC.UnicitySeal.Epoch = 2
	resultUC.UnicitySeal.RootChainRoundNumber = 1
	resultUC.UnicitySeal.Signatures = nil
	for signer := range authorizing.Certificate().UnicitySeal.Signatures {
		require.NoError(t, resultUC.UnicitySeal.Sign(signer, f.c.Signer))
	}
	b := f.c.Blocks[1]
	candidate := JournalCandidate{Round: 1, Number: 1, ParentNumber: 0, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(),
		ParentHash: f.c.Blocks[0].Hash.Bytes(), ParentState: f.c.Blocks[0].StateRoot.Bytes(), Raw: []byte{1, 2, 3}, BlockSize: 3,
		AuthorizingUC: authorizing.Certificate(), AuthorizingTR: authorizing.TechnicalRecord()}
	anchor := RestoreAnchor{Height: 1, Hash: [32]byte(b.Hash), StateRoot: [32]byte(b.StateRoot), RootRound: 1}
	require.NoError(t, s.InstallReplayedTip(context.Background(), c, limits, candidate, resultUC, resultTR, resultUC, resultTR, anchor))
	image, err := s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 1)
	require.Len(t, image.Observations, 1)
	require.Equal(t, uint64(2), image.Observations[0].UC.GetRootEpoch())
	require.Equal(t, anchor, *image.Restored)
	require.Equal(t, &CoverageBase{Height: anchor.Height, Hash: anchor.Hash}, image.CoverageBase)
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.EnableJournal(context.Background(), c, limits))
	_, err = s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
}
