package shardnode

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// observedPair is one certificate and technical record a recordingCertificateObserver kept.
type observedPair struct {
	uc *types.UnicityCertificate
	tr *certification.TechnicalRecord
}

// recordingCertificateObserver keeps every authenticated pair the round feeds it, in order.
type recordingCertificateObserver struct {
	got []observedPair
}

func (o *recordingCertificateObserver) ObserveCertificate(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	o.got = append(o.got, observedPair{uc: uc, tr: tr})
	return nil
}

// failingCertificateObserver refuses every observation, standing in for a history that cannot retain
// the pair. The round must log the refusal and carry on.
type failingCertificateObserver struct{}

func (failingCertificateObserver) ObserveCertificate(*types.UnicityCertificate, *certification.TechnicalRecord) error {
	return errObservationRefused
}

var errObservationRefused = errors.New("observation refused")

/*
W3b-2: a block committed by anchor recovery is reported to the commit observer, and it is reported
with the certificate that certified the block rather than the certificate in hand. Across a quiet
tail the held certificate names no block at all, so a record bound to it would name one certificate
and contain another's block. These tests pin the pair that travels from the verified evidence to the
observer, and the ordering that keeps an uninstalled target from being reported.
*/

// recordingCommitObserver keeps every commit the round reports, so a test can assert what was
// reported rather than infer it from a later effect.
type recordingCommitObserver struct {
	got []CertifiedCommit
}

func (o *recordingCommitObserver) ObserveCommit(cc CertifiedCommit) {
	o.got = append(o.got, cc)
}

// TestVerifiedTargetCarriesTheAuthenticatedSource: the source pair VerifyAnchorEvidence
// authenticated reaches VerifiedTarget and ApplyResult, copied, and it is never the held
// certificate.
func TestVerifiedTargetCarriesTheAuthenticatedSource(t *testing.T) {
	stateB, blockB := h32(0x0b), h32(0xbb)
	var full AnchorEvidence
	p := newRecoveryPair(t, func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) {
		return full, nil
	})
	f := p.evidenceFixture
	source, mid, head := quietTailChain(f)
	full = bundleOf(source, mid, head)

	behind := BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(h32(0x0a))}
	p.ex.head = func(context.Context) (BlockRef, error) {
		return BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)}, nil
	}

	p.observe(t, source, mid, head)
	res := p.recoverFor(t, head, behind)
	require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)

	vt, ok := p.req.Target()
	require.True(t, ok)
	require.Equal(t, source.UC.InputRecord, vt.Source.InputRecord)
	require.Equal(t, source.Technical, vt.SourceTechnical)
	require.NotSame(t, source.UC, vt.Source, "the returned source is a copy, not the retained one")
	require.NotSame(t, head.UC, vt.Source, "the held quiet certificate is not the source")

	require.Equal(t, source.UC.InputRecord, res.Source.InputRecord)
	require.Equal(t, source.Technical, res.SourceTechnical)
	require.NotSame(t, source.UC, res.Source)
}

// recoveryRoundFixture is a returning node wired to a recovery stack built from a stub fetch, so the
// round's own report path drives the observer without a network.
type recoveryRoundFixture struct {
	round *Round
	exec  *trackingExecutor
	obs   *recordingCommitObserver
	req   *EvidenceRequester
}

func newRecoveryRoundFixture(t *testing.T, f *evidenceFixture, bundle func() AnchorEvidence) *recoveryRoundFixture {
	t.Helper()
	req, err := NewEvidenceRequester(RecoveryConfig{
		PartitionID:   evidencePartitionID,
		ShardConfHash: f.conf,
		TrustBases:    f.trust,
		Fetcher: &recordingFetcher{fn: func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) {
			return bundle(), nil
		}},
		Providers: stubProviders{"peer"},
		Limits:    DefaultAnchorEvidenceLimits,
		Budget:    testBudget(),
	})
	require.NoError(t, err)
	t.Cleanup(req.Close)

	stateB, blockB := h32(0x0b), h32(0xbb)
	genesis := BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x02))}
	behind := BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(h32(0x0a))}
	exec := newTrackingExecutor(behind, genesis)
	exec.blocks[string(blockB)] = BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)}

	gate := NewFinalityGate()
	applier, err := NewTargetApplier(ApplyConfig{Executor: exec, Source: req, Budget: testApplyBudget(), Gate: gate})
	require.NoError(t, err)
	stack := &RecoveryStack{Requester: req, Applier: applier, Gate: gate}

	r := NewRound("returning", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)
	r.SetAwaitTimeout(50 * time.Millisecond)
	r.SetRecovery(stack)
	obs := &recordingCommitObserver{}
	r.SetCommitObserver(obs)
	return &recoveryRoundFixture{round: r, exec: exec, obs: obs, req: req}
}

// TestRecoveryCommitIsReportedWithItsOwnCertificate: a recovery across a quiet tail reports the
// source certificate that names the committed block, not the held certificate, and the block hash is
// the applied target's.
func TestRecoveryCommitIsReportedWithItsOwnCertificate(t *testing.T) {
	ctx := context.Background()
	f := newEvidenceFixture(t)
	source, mid, held := quietTailChain(f)
	next := f.cert(19, 130, h32(0x0b), h32(0x0b), nil, 23)
	full := bundleOf(source, mid, held)

	fx := newRecoveryRoundFixture(t, f, func() AnchorEvidence { return full })
	require.Error(t, fx.round.HandleCertificate(ctx, held.UC, held.Technical))
	require.Empty(t, fx.obs.got, "a quiet certificate with no target to apply reports nothing")
	st := waitRecovered(t, fx.req)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)

	require.Error(t, fx.round.HandleCertificate(ctx, next.UC, next.Technical))
	require.Len(t, fx.obs.got, 1)
	got := fx.obs.got[0]
	require.Equal(t, source.UC.InputRecord, got.Certificate.InputRecord)
	require.Equal(t, source.Technical, got.Technical)
	require.Equal(t, []byte(h32(0xbb)), []byte(got.BlockHash))
	require.NotEqual(t, held.UC.InputRecord.RoundNumber, got.Certificate.InputRecord.RoundNumber,
		"the report names the certificate that certified the block, not the quiet certificate in hand")
}

// TestRecoveryFeedsTheAuthenticatedChainToObservations: the source pair and every tail link are
// observed, in order, and are exactly the bundle VerifyAnchorEvidence authenticated. The arrival
// site observes the held and next certificates live; the recovery feed then supplies the chain a
// returning node never received, so a later Prepare can connect the durable record to the held
// certificate.
func TestRecoveryFeedsTheAuthenticatedChainToObservations(t *testing.T) {
	ctx := context.Background()
	f := newEvidenceFixture(t)
	source, mid, held := quietTailChain(f)
	next := f.cert(19, 130, h32(0x0b), h32(0x0b), nil, 23)
	full := bundleOf(source, mid, held)

	fx := newRecoveryRoundFixture(t, f, func() AnchorEvidence { return full })
	obs := &recordingCertificateObserver{}
	fx.round.SetCertificateObserver(obs)

	require.Error(t, fx.round.HandleCertificate(ctx, held.UC, held.Technical))
	st := waitRecovered(t, fx.req)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	require.Error(t, fx.round.HandleCertificate(ctx, next.UC, next.Technical))

	got := obs.got
	require.Len(t, got, 6, "the two live arrivals, then the four authenticated chain pairs")
	require.Equal(t, held.UC.InputRecord, got[0].uc.InputRecord)
	require.Equal(t, next.UC.InputRecord, got[1].uc.InputRecord)
	// The held certificate is already observed at the arrival site; the recovery feed supplies it
	// again as the chain's terminal, which is idempotent for the history and completes the chain.
	want := []EvidenceLink{source, mid, held, next}
	for i, l := range want {
		require.Equal(t, l.UC.InputRecord, got[2+i].uc.InputRecord, "pair %d", i)
		require.Equal(t, l.Technical, got[2+i].tr, "pair %d", i)
	}
}

// TestNothingIsObservedWhenTheTargetIsNotInstalled: an attempt whose target does not explain the
// snapshot state observes nothing, as it reports nothing. The applier reaches the executor and
// reports ApplyApplied, but the round's snapshot revalidation refuses to install the anchor, so no
// certificate is fed to the observer.
func TestNothingIsObservedWhenTheTargetIsNotInstalled(t *testing.T) {
	ctx := context.Background()
	f := newEvidenceFixture(t)
	source, mid, held := quietTailChain(f)
	full := bundleOf(source, mid, held)
	_ = source
	_ = mid

	fx := newRecoveryRoundFixture(t, f, func() AnchorEvidence { return full })
	obs := &recordingCertificateObserver{}
	fx.round.SetCertificateObserver(obs)
	require.NoError(t, fx.req.Observe(held.UC, held.Technical))
	require.NoError(t, fx.req.Need())
	st := waitRecovered(t, fx.req)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)

	exp, err := ExpectationFromCertificate(held.UC, held.Technical.Round, held.Technical.Epoch)
	require.NoError(t, err)
	exp.PreviousHash = h32(0x0c)

	fx.round.mu.Lock()
	_, res, ok := fx.round.applyVerifiedAnchor(ctx, held.UC, exp,
		BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(h32(0x0a))})
	fx.round.mu.Unlock()

	require.False(t, ok)
	require.Equal(t, ApplyApplied, res.Outcome, "the applier did bring the executor to the block")
	require.Empty(t, obs.got, "a target that was not installed is not observed")
}

// TestRecoveryObservationRefusalDoesNotFailTheRound: a refusal from the certificate observer is
// logged and never fails the round. The certified block is still committed and still reported.
func TestRecoveryObservationRefusalDoesNotFailTheRound(t *testing.T) {
	ctx := context.Background()
	f := newEvidenceFixture(t)
	source, mid, held := quietTailChain(f)
	next := f.cert(19, 130, h32(0x0b), h32(0x0b), nil, 23)
	full := bundleOf(source, mid, held)

	fx := newRecoveryRoundFixture(t, f, func() AnchorEvidence { return full })
	fx.round.SetCertificateObserver(failingCertificateObserver{})

	require.Error(t, fx.round.HandleCertificate(ctx, held.UC, held.Technical))
	st := waitRecovered(t, fx.req)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	require.Error(t, fx.round.HandleCertificate(ctx, next.UC, next.Technical),
		"the follower arrives at its usual abstention, not at an observation failure")

	require.Equal(t, Hash(h32(0xbb)), fx.exec.currentHead().Hash, "the refusal did not stop the recovery commit")
	require.Len(t, fx.obs.got, 1, "and the commit is still reported")
}

// TestRecoveryCommitIsNotReportedWhenNothingIsInstalled: an attempt whose target does not explain
// the snapshot state installs nothing and reports nothing. The applier reaches the executor and
// reports ApplyApplied, but the round's own revalidation against the state it is building on refuses
// to install the anchor, so no commit is reported.
func TestRecoveryCommitIsNotReportedWhenNothingIsInstalled(t *testing.T) {
	ctx := context.Background()
	f := newEvidenceFixture(t)
	source, mid, held := quietTailChain(f)
	full := bundleOf(source, mid, held)
	_ = source
	_ = mid

	fx := newRecoveryRoundFixture(t, f, func() AnchorEvidence { return full })
	require.NoError(t, fx.req.Observe(held.UC, held.Technical))
	require.NoError(t, fx.req.Need())
	st := waitRecovered(t, fx.req)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)

	// The certificate names state 0b, which is what the applier applies. The round is asked to build
	// on another state, so the snapshot revalidation refuses the target after the applier succeeded.
	exp, err := ExpectationFromCertificate(held.UC, held.Technical.Round, held.Technical.Epoch)
	require.NoError(t, err)
	exp.PreviousHash = h32(0x0c)

	fx.round.mu.Lock()
	_, res, ok := fx.round.applyVerifiedAnchor(ctx, held.UC, exp,
		BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(h32(0x0a))})
	fx.round.mu.Unlock()

	require.False(t, ok)
	require.Equal(t, ApplyApplied, res.Outcome, "the applier did bring the executor to the block")
	require.Empty(t, fx.obs.got, "a target that was not installed is not reported")
}
