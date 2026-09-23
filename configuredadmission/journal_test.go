package configuredadmission

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

func journalBootstrap(t *testing.T, c *certifiedchain.Chain) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := c.Certify(c.Signer, &types.InputRecord{Version: 1}, tr, 4)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
	return uc, tr
}

func putAdapterB1(t *testing.T, s *configuredprogress.Store, ctx configuredprogress.Context, limits configuredprogress.JournalLimits, chain *certifiedchain.Chain, bootstrap *types.UnicityCertificate, bootTR *certification.TechnicalRecord) {
	t.Helper()
	b, parent := chain.Blocks[1], chain.Blocks[0]
	require.NoError(t, s.PutJournalCandidate(context.Background(), ctx, limits, configuredprogress.JournalCandidate{
		Round: b.Round, Number: b.Number, ParentNumber: parent.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: parent.Hash.Bytes(), ParentState: parent.StateRoot.Bytes(), Raw: []byte{1, 2, 3}, BlockSize: 3, AuthorizingUC: bootstrap, AuthorizingTR: bootTR,
	}))
}

func TestJournalAdmissionKeepsUCWithoutBodyDurableButUnready(t *testing.T) {
	chain, origin, ctx, id := adapterFixture(t)
	limits := configuredprogress.JournalLimits{Candidates: 2, Observations: 3, Bytes: 16 << 20}
	s, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	defer s.Close()
	_, _, err = s.Initialize(context.Background(), ctx)
	require.NoError(t, err)
	require.NoError(t, s.EnableJournal(context.Background(), ctx, limits))
	delivered := 0
	factory := JournalFactory{Store: s, Origin: origin, Limits: limits}
	a, err := factory.Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{
		AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {},
		DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
			delivered++
			return nil
		},
	})
	require.NoError(t, err)
	defer a.Close()
	bootstrap, bootTR := journalBootstrap(t, chain)
	require.NoError(t, a.Submit(context.Background(), bootstrap, bootTR))
	require.Equal(t, 1, delivered)
	first, firstTR := signAdapterObservation(t, chain)
	err = a.Submit(context.Background(), first, firstTR)
	require.ErrorIs(t, err, configuredprogress.ErrUnavailable)
	require.Equal(t, 1, delivered, "the live certificate cursor/round sink cannot advance without a retained body")
	image, err := s.LoadJournal(context.Background(), ctx, limits)
	require.NoError(t, err)
	require.True(t, image.Observations[1].Unresolved)
	putAdapterB1(t, s, ctx, limits, chain, bootstrap, bootTR)
	require.NoError(t, a.Submit(context.Background(), first, firstTR))
	require.Equal(t, 2, delivered)
	image, err = s.LoadJournal(context.Background(), ctx, limits)
	require.NoError(t, err)
	require.False(t, image.Observations[1].Unresolved)
	require.True(t, image.Candidates[0].Certified)
}

func TestJournalAdmissionRetriesAfterLostExecutionReplyAndIgnoresStaleCursor(t *testing.T) {
	chain, origin, ctx, id := adapterFixture(t)
	limits := configuredprogress.JournalLimits{Candidates: 2, Observations: 3, Bytes: 16 << 20}
	s, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	defer s.Close()
	_, _, err = s.Initialize(context.Background(), ctx)
	require.NoError(t, err)
	require.NoError(t, s.EnableJournal(context.Background(), ctx, limits))
	bootstrap, bootTR := journalBootstrap(t, chain)
	first, firstTR := signAdapterObservation(t, chain)
	factory := JournalFactory{Store: s, Origin: origin, Limits: limits}
	var attempted int
	a, err := factory.Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{
		AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {},
		DeliverDurable: func(_ context.Context, uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
			if uc.GetRoundNumber() == 1 {
				attempted++
				if attempted == 1 {
					return errors.New("lost Engine reply")
				}
			}
			return nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, a.Submit(context.Background(), bootstrap, bootTR))
	putAdapterB1(t, s, ctx, limits, chain, bootstrap, bootTR)
	require.ErrorContains(t, a.Submit(context.Background(), first, firstTR), "lost Engine reply")
	image, err := s.LoadJournal(context.Background(), ctx, limits)
	require.NoError(t, err)
	require.True(t, image.Candidates[0].Certified, "execution reply failure cannot undo durable certification")
	require.NoError(t, a.Submit(context.Background(), first, firstTR))
	require.Equal(t, 2, attempted, "redelivery reuses the same durable certificate and body")
	require.NoError(t, a.Close())
	var restoredRound uint64
	restarted, err := factory.Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{
		AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {},
		DeliverDurable: func(_ context.Context, uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
			restoredRound = uc.GetRoundNumber()
			return nil
		},
	})
	require.NoError(t, err)
	defer restarted.Close()
	require.NoError(t, restarted.Submit(context.Background(), bootstrap, bootTR))
	require.Equal(t, uint64(1), restoredRound, "a stale bootstrap delivery cannot replace newer durable progress")
}

func TestJournalAdmissionRefusesForeignIdentity(t *testing.T) {
	_, origin, ctx, id := adapterFixture(t)
	limits := configuredprogress.JournalLimits{Candidates: 2, Observations: 3, Bytes: 16 << 20}
	s, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	defer s.Close()
	_, _, err = s.Initialize(context.Background(), ctx)
	require.NoError(t, err)
	require.NoError(t, s.EnableJournal(context.Background(), ctx, limits))
	id.FullShardConfHash[0] ^= 1
	_, err = (JournalFactory{Store: s, Origin: origin, Limits: limits}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil }})
	require.Error(t, err)
	require.False(t, errors.Is(err, configuredprogress.ErrUnavailable))
}

func TestJournalAdmissionWriteFailurePreventsExecutionDelivery(t *testing.T) {
	chain, origin, ctx, id := adapterFixture(t)
	limits := configuredprogress.JournalLimits{Candidates: 2, Observations: 1, Bytes: 16 << 20}
	s, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	defer s.Close()
	_, _, err = s.Initialize(context.Background(), ctx)
	require.NoError(t, err)
	require.NoError(t, s.EnableJournal(context.Background(), ctx, limits))
	deliveries := 0
	a, err := (JournalFactory{Store: s, Origin: origin, Limits: limits}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{
		AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {},
		DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
			deliveries++
			return nil
		},
	})
	require.NoError(t, err)
	defer a.Close()
	bootstrap, bootTR := journalBootstrap(t, chain)
	require.NoError(t, a.Submit(context.Background(), bootstrap, bootTR))
	putAdapterB1(t, s, ctx, limits, chain, bootstrap, bootTR)
	first, firstTR := signAdapterObservation(t, chain)
	require.ErrorIs(t, a.Submit(context.Background(), first, firstTR), configuredprogress.ErrBounds)
	require.Equal(t, 1, deliveries, "no execution Commit or signing callback after a failed durable write")
	state, _, err := s.Load(context.Background(), ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), state.Revision(), "progress and journal association roll back together")
	image, err := s.LoadJournal(context.Background(), ctx, limits)
	require.NoError(t, err)
	require.False(t, image.Candidates[0].Certified)
}
