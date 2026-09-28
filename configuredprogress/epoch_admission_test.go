package configuredprogress

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type currentEpoch struct{ epoch uint64 }

func (a *currentEpoch) CurrentRootEpoch() (uint64, bool) { return a.epoch, true }

type epochBases map[uint64]*types.RootTrustBaseV1

func (b epochBases) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	return b[epoch], nil
}

func TestProfile2JournalObservationUsesEpochOrderAndCurrentGate(t *testing.T) {
	f := newFixture(t, 1)
	oldUC, tr := f.sign(f.c.InputRecord(1), 2, 100)
	old, err := rootinput.AuthenticateObservationV2(context.Background(), f.ctx.Observation, oldUC, tr)
	require.NoError(t, err)
	newUC := *oldUC
	newSeal := *oldUC.UnicitySeal
	newUC.UnicitySeal = &newSeal
	newSeal.Epoch = 2
	newSeal.RootChainRoundNumber = 13
	newSeal.Signatures = nil
	for signer := range oldUC.UnicitySeal.Signatures {
		require.NoError(t, newSeal.Sign(signer, f.c.Signer))
	}
	newBase := *f.c.TrustBase
	newBase.Epoch = 2
	newBase.Signatures = nil
	authority := &currentEpoch{epoch: 1}
	f.ctx.Observation.TrustBases = epochBases{1: f.c.TrustBase, 2: &newBase}
	f.ctx.Observation.EpochAuthority = authority
	_, err = rootinput.AuthenticateObservationV2(context.Background(), f.ctx.Observation, &newUC, tr)
	require.ErrorIs(t, err, rootinput.ErrV2Context)
	authority.epoch = 2
	next, err := rootinput.AuthenticateObservationV2(context.Background(), f.ctx.Observation, &newUC, tr)
	require.NoError(t, err)
	rel, err := compareObservations(old, next)
	require.NoError(t, err)
	require.Equal(t, relationRepeat, rel)
	rel, err = compareObservations(old, old)
	require.NoError(t, err)
	require.Equal(t, relationDuplicate, rel)
	rel, err = compareObservations(next, old)
	require.NoError(t, err)
	require.Equal(t, relationStale, rel)
	bootstrapUC, bootstrapTR := f.sign(&types.InputRecord{Version: 1}, 1, 100)
	bootstrap, err := rootinput.AuthenticateHistoricalObservationV2(context.Background(), f.ctx.Observation, bootstrapUC, bootstrapTR)
	require.NoError(t, err)
	_, err = compareObservations(old, bootstrap)
	require.ErrorIs(t, err, ErrConflict, "an earlier shard round at the same root position is impossible")
	advancedIR := *oldUC.InputRecord
	advancedIR.RoundNumber++
	advancedIR.PreviousHash = bytes.Clone(oldUC.InputRecord.Hash)
	advancedIR.Hash = bytes.Repeat([]byte{0x42}, len(oldUC.InputRecord.Hash))
	advancedIR.BlockHash = bytes.Repeat([]byte{0x43}, len(oldUC.InputRecord.BlockHash))
	advancedUC, advancedTR := f.sign(&advancedIR, 3, 13)
	advancedUC.UnicitySeal.Epoch = 2
	advancedUC.UnicitySeal.Signatures = nil
	for signer := range oldUC.UnicitySeal.Signatures {
		require.NoError(t, advancedUC.UnicitySeal.Sign(signer, f.c.Signer))
	}
	advanced, err := rootinput.AuthenticateObservationV2(context.Background(), f.ctx.Observation, advancedUC, advancedTR)
	require.NoError(t, err)
	rel, err = compareObservations(old, advanced)
	require.NoError(t, err)
	require.Equal(t, relationAdvance, rel, "the new epoch may start at a smaller scalar root round")
	sameRootUC, sameRootTR := f.sign(&advancedIR, 3, 100)
	sameRoot, err := rootinput.AuthenticateHistoricalObservationV2(context.Background(), f.ctx.Observation, sameRootUC, sameRootTR)
	require.NoError(t, err)
	_, err = compareObservations(old, sameRoot)
	require.ErrorIs(t, err, ErrConflict, "a later shard round needs a later root position")
	brokenIR := advancedIR
	brokenIR.PreviousHash = bytes.Repeat([]byte{0x44}, len(oldUC.InputRecord.Hash))
	brokenUC, brokenTR := f.sign(&brokenIR, 3, 13)
	brokenUC.UnicitySeal.Epoch = 2
	brokenUC.UnicitySeal.Signatures = nil
	for signer := range oldUC.UnicitySeal.Signatures {
		require.NoError(t, brokenUC.UnicitySeal.Sign(signer, f.c.Signer))
	}
	broken, err := rootinput.AuthenticateObservationV2(context.Background(), f.ctx.Observation, brokenUC, brokenTR)
	require.NoError(t, err)
	_, err = compareObservations(old, broken)
	require.ErrorIs(t, err, ErrConflict, "cross-epoch order does not remove shard-state continuity")

	s, _ := f.open(2)
	defer s.Close()
	_, _, err = s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	_, _, err = s.PrepareObservation(context.Background(), f.ctx, old)
	require.ErrorIs(t, err, rootinput.ErrV2Context, "historical verification cannot become live admission")
	coordinator := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 1, duration: 1, cooldown: 1}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	base, err := coordinator.ctx.Observation.TrustBases.GetByEpoch(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, uint64(2), base.Epoch, "profile-2 admission keeps the verified per-epoch resolver")
}
