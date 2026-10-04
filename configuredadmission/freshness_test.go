package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierrequester"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// deadOpener models roots that never answer: every exchange fails, so no receipt is ever issued.
// calls proves the requester was actually started.
type deadOpener struct{ calls atomic.Int32 }

func (o *deadOpener) CreateStream(context.Context, peer.ID, string) (libnetwork.Stream, error) {
	o.calls.Add(1)
	return nil, errors.New("root unreachable")
}

var journalLimits = configuredprogress.JournalLimits{Candidates: 2, Observations: 3, Bytes: 16 << 20}

func newFreshnessFixture(t *testing.T) (*certifiedchain.Chain, configuredprogress.Context, shardnode.AdmissionIdentity, *JournalFactory) {
	t.Helper()
	chain, origin, c, id := adapterFixture(t)
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 2})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, _, err = store.Initialize(context.Background(), c)
	require.NoError(t, err)
	require.NoError(t, store.EnableJournal(context.Background(), c, journalLimits))
	return chain, c, id, &JournalFactory{Store: store, Origin: origin, Limits: journalLimits}
}

func startFreshAdmission(t *testing.T, ctx context.Context, factory JournalFactory, id shardnode.AdmissionIdentity, f *Freshness) *journalAdmission {
	t.Helper()
	factory.Freshness = f
	a, err := factory.Start(ctx, id, adapterGate{}, shardnode.AdmissionCallbacks{
		AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {},
		DeliverDurable:    func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil },
	})
	require.NoError(t, err, "freshness trouble must never stop the node from starting")
	t.Cleanup(func() { require.NoError(t, a.Close()) })
	return a.(*journalAdmission)
}

// fixtureTrust is the chain's root trust at the network the adapter fixture certifies under (3):
// the requester refuses a trust base whose network differs from the shard's.
func fixtureTrust(chain *certifiedchain.Chain) *types.RootTrustBaseV1 {
	tb := *chain.TrustBase
	tb.NetworkID = 3
	return &tb
}

func freshnessFor(chain *certifiedchain.Chain, o frontiertransport.StreamOpener) *Freshness {
	return &Freshness{Opener: o, TrustBase: fixtureTrust(chain)}
}

func unsupportedPair(t *testing.T, chain *certifiedchain.Chain) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := chain.Certify(chain.Signer, &types.InputRecord{Version: 1, SumOfEarnedFees: 1}, tr, 4)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := chain.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), chain.Signer))
	return uc, tr
}

// The requester is active in default startup: starting the admission with nothing but the root trust
// base and a stream opener makes it begin acquiring, and until a receipt exists bootstrap readiness
// is refused.
func TestFreshnessStartsAcquiringAndRefusesBootstrapWithoutReceipt(t *testing.T) {
	chain, _, id, factory := newFreshnessFixture(t)
	opener := &deadOpener{}
	f := freshnessFor(chain, opener)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFreshAdmission(t, ctx, *factory, id, f)
	require.Eventually(t, func() bool { return opener.calls.Load() > 0 }, 5*time.Second, 10*time.Millisecond, "the requester must start with the admission")
	require.ErrorIs(t, f.Require(), ErrFreshnessRequired)
}

func TestFreshnessIsUnavailableBeforeStartAndWhenItsProfileIsRefused(t *testing.T) {
	require.ErrorIs(t, (&Freshness{}).Require(), ErrFreshnessUnavailable, "not started")
	chain, _, id, factory := newFreshnessFixture(t)
	f := &Freshness{TrustBase: fixtureTrust(chain)} // no opener: the profile cannot be served
	startFreshAdmission(t, context.Background(), *factory, id, f)
	require.ErrorIs(t, f.Require(), ErrFreshnessUnavailable)
	var nilFreshness *Freshness
	require.NoError(t, nilFreshness.Require(), "a deployment without the gate is unchanged")
}

type scriptedReceipts struct{ validate error }

func (s scriptedReceipts) Current() frontierrequester.Receipt       { return frontierrequester.Receipt{} }
func (s scriptedReceipts) Validate(frontierrequester.Receipt) error { return s.validate }

// A receipt that has expired, was replaced or lost its caller no longer validates; readiness follows it
// at once and recovers when a new one validates.
func TestRequireFollowsTheReceiptLifetime(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	g, err := newBootstrapGuard(context.Background(), c, fixtureTrust(chain), false, nil, nil)
	require.NoError(t, err)
	f := &Freshness{guard: g, requester: scriptedReceipts{}}
	require.NoError(t, f.Require())
	f.requester = scriptedReceipts{validate: frontierrequester.ErrInvalidated}
	require.ErrorIs(t, f.Require(), ErrFreshnessRequired)
	f.requester = scriptedReceipts{}
	require.NoError(t, f.Require())
}

func TestRequireRefusesAStoppedProcess(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	g, err := newBootstrapGuard(ctx, c, fixtureTrust(chain), false, nil, nil)
	require.NoError(t, err)
	f := &Freshness{guard: g, requester: scriptedReceipts{}}
	require.NoError(t, f.Require())
	cancel()
	require.ErrorIs(t, f.Require(), ErrFreshnessUnavailable)
}

// Ordinary progress authenticated by the admission supersedes bootstrap even though the write that
// follows fails: learning it is what ends eligibility, not persisting it.
func TestOrdinaryAdmissionSupersedesBootstrapBeforeItIsPersisted(t *testing.T) {
	chain, _, id, factory := newFreshnessFixture(t)
	opener := &deadOpener{}
	f := freshnessFor(chain, opener)
	a := startFreshAdmission(t, context.Background(), *factory, id, f)
	require.ErrorIs(t, f.Require(), ErrFreshnessRequired)
	ordinary, tr := signAdapterObservation(t, chain)
	err := a.Submit(context.Background(), ordinary, tr)
	require.ErrorIs(t, err, configuredprogress.ErrUnavailable, "a fresh journal must begin with the bootstrap certificate, so nothing was written")
	status, ok := f.Status()
	require.True(t, ok)
	require.True(t, status.Invalidated)
	require.NoError(t, f.Require(), "ordinary progress needs no bootstrap receipt")
}

func TestBootstrapAdmissionDoesNotSupersedeBootstrap(t *testing.T) {
	chain, _, id, factory := newFreshnessFixture(t)
	f := freshnessFor(chain, &deadOpener{})
	a := startFreshAdmission(t, context.Background(), *factory, id, f)
	uc, tr := journalBootstrap(t, chain)
	require.NoError(t, a.Submit(context.Background(), uc, tr))
	status, _ := f.Status()
	require.False(t, status.Invalidated)
	require.ErrorIs(t, f.Require(), ErrFreshnessRequired, "persisting the bootstrap certificate is data, not freshness")
}

// A restart keeps ordinary progress forever, and keeps bootstrap data only as data.
func TestRestartNeedsNoReceiptForOrdinaryProgressAndNeverRestoresOne(t *testing.T) {
	chain, _, id, factory := newFreshnessFixture(t)
	first := freshnessFor(chain, &deadOpener{})
	a := startFreshAdmission(t, context.Background(), *factory, id, first)
	boot, bootTR := journalBootstrap(t, chain)
	require.NoError(t, a.Submit(context.Background(), boot, bootTR))
	require.NoError(t, a.Close())

	opener := &deadOpener{}
	restarted := freshnessFor(chain, opener)
	startFreshAdmission(t, context.Background(), *factory, id, restarted)
	require.ErrorIs(t, restarted.Require(), ErrFreshnessRequired, "bootstrap-only store: persisted data is not a renewed permit")
	require.Eventually(t, func() bool { return opener.calls.Load() > 0 }, 5*time.Second, 10*time.Millisecond)

	ordinary, tr := signAdapterObservation(t, chain)
	second := startFreshAdmission(t, context.Background(), *factory, id, freshnessFor(chain, &deadOpener{}))
	_ = second.Submit(context.Background(), ordinary, tr) // durable, though its body is unresolved
	require.NoError(t, second.Close())

	quiet := &deadOpener{}
	final := freshnessFor(chain, quiet)
	startFreshAdmission(t, context.Background(), *factory, id, final)
	status, _ := final.Status()
	require.True(t, status.Invalidated, "durable ordinary progress is known at start")
	require.NoError(t, final.Require())
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, quiet.calls.Load(), "no acquisition runs once ordinary progress is durable")
}

func TestAcknowledgeUnsupportedEvidenceRefusesBootstrap(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	g, err := newBootstrapGuard(context.Background(), c, fixtureTrust(chain), false, nil, nil)
	require.NoError(t, err)
	f := &Freshness{guard: g, requester: scriptedReceipts{}}
	uc, tr := unsupportedPair(t, chain)
	retained, err := g.AcknowledgePair(uc, tr)
	require.True(t, retained)
	require.True(t, rootinput.IsUnsupportedObservationV2(err))
	state := g.BootstrapState()
	require.True(t, state.BootstrapInvalidated)
	require.True(t, state.UnsupportedSeen)
	require.ErrorIs(t, f.Require(), ErrBootstrapRefused, "a live receipt cannot outvote unsupported evidence")
}

func TestAcknowledgeOrdinaryEvidenceLatchesRetainsAndForwards(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	forwarded := make(chan *types.UnicityCertificate, 2)
	g, err := newBootstrapGuard(context.Background(), c, fixtureTrust(chain), false, func(_ context.Context, uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
		forwarded <- uc
		return nil
	}, nil)
	require.NoError(t, err)
	require.True(t, g.BootstrapState().Allowed())
	uc, tr := signAdapterObservation(t, chain)
	retained, err := g.AcknowledgePair(uc, tr)
	require.NoError(t, err)
	require.True(t, retained)
	state := g.BootstrapState()
	require.True(t, state.BootstrapInvalidated)
	require.False(t, state.UnsupportedSeen)
	select {
	case got := <-forwarded:
		require.Equal(t, uc.GetRootRoundNumber(), got.GetRootRoundNumber())
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary evidence was not handed to the journal admission")
	}
	status := g.Status()
	require.NotEmpty(t, status.FirstOrdinary)
	require.Equal(t, status.FirstOrdinary, status.LatestOrdinary)
}

func TestAcknowledgeRefusesBootstrapAndForgedEvidenceWithoutInvalidating(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	var forwards atomic.Int32
	g, err := newBootstrapGuard(context.Background(), c, fixtureTrust(chain), false, func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
		forwards.Add(1)
		return nil
	}, nil)
	require.NoError(t, err)
	boot, bootTR := journalBootstrap(t, chain)
	retained, err := g.AcknowledgePair(boot, bootTR)
	require.False(t, retained)
	require.ErrorIs(t, err, configuredprogress.ErrConflict, "bootstrap evidence is not negative evidence")
	uc, tr := signAdapterObservation(t, chain)
	// Isolated mutation: exactly one signature is corrupted, nothing else about the pair changes.
	corrupted := false
	for signer, sig := range uc.UnicitySeal.Signatures {
		sig[0] ^= 0xff
		uc.UnicitySeal.Signatures[signer] = sig
		corrupted = true
		break
	}
	require.True(t, corrupted)
	retained, err = g.AcknowledgePair(uc, tr)
	require.False(t, retained)
	require.ErrorIs(t, err, rootinput.ErrUnauthenticated)
	require.False(t, rootinput.IsUnsupportedObservationV2(err), "forged evidence is not unsupported evidence")
	require.True(t, g.BootstrapState().Allowed(), "forged evidence must not end bootstrap")
	require.Zero(t, forwards.Load())
	require.Empty(t, g.Status().FirstOrdinary)
}

func TestGuardRefusesATrustBaseOfAnotherEpoch(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	other := *chain.TrustBase
	other.Epoch = c.Observation.RootEpoch + 1
	_, err := newBootstrapGuard(context.Background(), c, &other, false, nil, nil)
	require.ErrorIs(t, err, frontierrequester.ErrSettings)
}

func TestRootPeersFollowTheTrustBase(t *testing.T) {
	chain, _, _, _ := newFreshnessFixture(t)
	peers, err := RootPeers(chain.TrustBase)
	require.NoError(t, err)
	require.Len(t, peers, len(chain.TrustBase.RootNodes))
	for i, p := range peers {
		require.Equal(t, chain.TrustBase.RootNodes[i].NodeID, p.Author)
		require.Equal(t, p.Author, p.PeerID.String())
	}
	bad := *chain.TrustBase
	bad.RootNodes = append([]*types.NodeInfo{{NodeID: "not-a-peer-id"}}, bad.RootNodes...)
	_, err = RootPeers(&bad)
	require.ErrorIs(t, err, frontierrequester.ErrSettings)
	_, err = RootPeers(nil)
	require.ErrorIs(t, err, frontierrequester.ErrSettings)
}

// Readiness consults freshness before touching the executor or the journal, at preparation and again
// inside the finality gate. The recovery here has neither, so only the gate can answer.
func TestExecutionRecoveryReadinessIsGatedOnFreshness(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	g, err := newBootstrapGuard(context.Background(), c, fixtureTrust(chain), false, nil, nil)
	require.NoError(t, err)
	f := &Freshness{guard: g, requester: scriptedReceipts{validate: frontierrequester.ErrInvalidated}}
	r := &ExecutionRecovery{Freshness: f}
	held, _ := journalBootstrap(t, chain)
	_, err = r.Prepare(context.Background(), held)
	require.ErrorIs(t, err, ErrFreshnessRequired)
	err = r.Revalidate(context.Background(), recoveryTicket{anchor: shardnode.BlockRef{Hash: make([]byte, 32)}}, held)
	require.ErrorIs(t, err, ErrFreshnessRequired)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func TestFreshnessReportsAFailedAcquisitionToTheOperator(t *testing.T) {
	chain, _, id, factory := newFreshnessFixture(t)
	logs := &lockedBuffer{}
	f := freshnessFor(chain, &deadOpener{})
	f.Logger = slog.New(slog.NewTextHandler(logs, nil))
	startFreshAdmission(t, context.Background(), *factory, id, f)
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "bootstrap receipt acquisition failed") }, 10*time.Second, 10*time.Millisecond)
	require.NotContains(t, logs.String(), "bootstrap receipt acquired")
}

func TestAcknowledgeReportsOrdinaryEvidenceThatCouldNotBeAdmitted(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	logs := &lockedBuffer{}
	g, err := newBootstrapGuard(context.Background(), c, fixtureTrust(chain), false, func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
		return errors.New("journal refused")
	}, slog.New(slog.NewTextHandler(logs, nil)))
	require.NoError(t, err)
	uc, tr := signAdapterObservation(t, chain)
	retained, err := g.AcknowledgePair(uc, tr)
	require.NoError(t, err)
	require.True(t, retained, "the latch holds whether or not the admission accepts the evidence")
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "was not admitted") }, 5*time.Second, 10*time.Millisecond)
	require.True(t, g.BootstrapState().BootstrapInvalidated)
}

func TestAcknowledgeRefusesOversizeEvidenceWithoutInvalidating(t *testing.T) {
	chain, c, _, _ := newFreshnessFixture(t)
	g, err := newBootstrapGuard(context.Background(), c, fixtureTrust(chain), false, nil, nil)
	require.NoError(t, err)
	uc, tr := signAdapterObservation(t, chain)
	uc.InputRecord.SummaryValue = make([]byte, configuredprogress.MaxPairBytes+1)
	retained, err := g.AcknowledgePair(uc, tr)
	require.False(t, retained)
	require.ErrorIs(t, err, configuredprogress.ErrBounds)
	require.True(t, g.BootstrapState().Allowed())
}

// The evidence bound is exact: a pair of MaxPairBytes is within it, one byte more is not.
func TestPairBytesBoundIsExact(t *testing.T) {
	chain, _, _, _ := newFreshnessFixture(t)
	uc, tr := signAdapterObservation(t, chain)
	size := func(pad int) int {
		uc.InputRecord.SummaryValue = make([]byte, pad)
		ub, err := types.Cbor.Marshal(uc)
		require.NoError(t, err)
		tb, err := types.Cbor.Marshal(tr)
		require.NoError(t, err)
		return len(ub) + len(tb)
	}
	pad := configuredprogress.MaxPairBytes - size(0)
	for size(pad) > configuredprogress.MaxPairBytes {
		pad--
	}
	for size(pad+1) <= configuredprogress.MaxPairBytes {
		pad++
	}
	require.Equal(t, configuredprogress.MaxPairBytes, size(pad), "the header size is stable at this length")
	_, err := pairBytes(uc, tr)
	require.NoError(t, err)
	size(pad + 1)
	_, err = pairBytes(uc, tr)
	require.ErrorIs(t, err, configuredprogress.ErrBounds)
}

func ordinaryGuardFixture(t *testing.T) (*certifiedchain.Chain, *bootstrapGuard, *Freshness) {
	t.Helper()
	chain, c, _, _ := newFreshnessFixture(t)
	g, err := newBootstrapGuard(context.Background(), c, fixtureTrust(chain), false, nil, nil)
	require.NoError(t, err)
	return chain, g, &Freshness{guard: g, requester: scriptedReceipts{}}
}

// recoveryAfterFreshness drives the real readiness entry points far enough to tell whether the
// freshness predicate let them through: the recovery here is deliberately unwired, so a pass shows
// as the later incomplete-wiring refusal and never as a freshness refusal.
func recoveryAfterFreshness(t *testing.T, chain *certifiedchain.Chain, f *Freshness) (prepare, revalidate error) {
	t.Helper()
	r := &ExecutionRecovery{Freshness: f}
	held, _ := journalBootstrap(t, chain)
	_, prepare = r.Prepare(context.Background(), held)
	revalidate = r.Revalidate(context.Background(), recoveryTicket{anchor: shardnode.BlockRef{Hash: make([]byte, 32)}}, held)
	return prepare, revalidate
}

// Authenticated ordinary progress supersedes unsupported bootstrap evidence: the node that saw an
// unsupported pair first and then genuine ordinary progress is ordinary, and readiness follows.
func TestAuthenticatedOrdinaryProgressSupersedesUnsupportedEvidence(t *testing.T) {
	chain, g, f := ordinaryGuardFixture(t)
	uc, tr := unsupportedPair(t, chain)
	retained, err := g.AcknowledgePair(uc, tr)
	require.True(t, retained)
	require.ErrorIs(t, err, rootinput.ErrV2Shape)
	require.False(t, g.OrdinaryKnown(), "unsupported evidence is not ordinary progress")
	require.ErrorIs(t, f.Require(), ErrBootstrapRefused)
	prepare, revalidate := recoveryAfterFreshness(t, chain, f)
	require.ErrorIs(t, prepare, ErrBootstrapRefused)
	require.ErrorIs(t, revalidate, ErrBootstrapRefused)

	ordinary, ordinaryTR := signAdapterObservation(t, chain)
	retained, err = g.AcknowledgePair(ordinary, ordinaryTR)
	require.NoError(t, err)
	require.True(t, retained)
	require.True(t, g.OrdinaryKnown())
	require.NoError(t, f.Require())
	prepare, revalidate = recoveryAfterFreshness(t, chain, f)
	require.ErrorIs(t, prepare, ErrRecoveryUnavailable, "freshness no longer refuses; the unwired recovery does")
	require.NotErrorIs(t, prepare, ErrBootstrapRefused)
	require.ErrorIs(t, revalidate, ErrRecoveryUnavailable)
	require.NotErrorIs(t, revalidate, ErrBootstrapRefused)
	status := g.Status()
	require.True(t, status.UnsupportedSeen, "the refusal of bootstrap receipts stays irreversible")
	require.True(t, status.Ordinary)
	require.False(t, g.BootstrapState().Allowed())
}

// The opposite order: unsupported evidence arriving after ordinary progress cannot take ordinary
// operation away, and still cannot reopen bootstrap.
func TestUnsupportedEvidenceAfterOrdinaryProgressDoesNotRefuseOrdinaryOperation(t *testing.T) {
	chain, g, f := ordinaryGuardFixture(t)
	ordinary, ordinaryTR := signAdapterObservation(t, chain)
	retained, err := g.AcknowledgePair(ordinary, ordinaryTR)
	require.NoError(t, err)
	require.True(t, retained)
	require.NoError(t, f.Require())

	uc, tr := unsupportedPair(t, chain)
	retained, err = g.AcknowledgePair(uc, tr)
	require.True(t, retained)
	require.ErrorIs(t, err, rootinput.ErrV2Shape)
	require.True(t, g.Status().UnsupportedSeen)
	require.NoError(t, f.Require(), "ordinary progress needs no receipt, whatever unsupported evidence follows")
	require.False(t, g.BootstrapState().Allowed(), "bootstrap stays closed")
}

// The journal admission's own ordinary notification supersedes unsupported evidence too.
func TestJournalOrdinaryAdmissionSupersedesUnsupportedEvidence(t *testing.T) {
	chain, _, id, factory := newFreshnessFixture(t)
	f := freshnessFor(chain, &deadOpener{})
	a := startFreshAdmission(t, context.Background(), *factory, id, f)
	f.mu.Lock()
	g := f.guard
	f.mu.Unlock()
	require.NotNil(t, g)
	uc, tr := unsupportedPair(t, chain)
	_, err := g.AcknowledgePair(uc, tr)
	require.ErrorIs(t, err, rootinput.ErrV2Shape)
	require.ErrorIs(t, f.Require(), ErrBootstrapRefused)
	ordinary, ordinaryTR := signAdapterObservation(t, chain)
	err = a.Submit(context.Background(), ordinary, ordinaryTR)
	require.ErrorIs(t, err, configuredprogress.ErrUnavailable, "the fresh journal has no bootstrap certificate; ordinary progress was still learned")
	require.NoError(t, f.Require())
}

// weightedRootTrust is valid for the node but outside the frontier's unit-weight profile, so the
// requester cannot be constructed over it.
func weightedRootTrust(chain *certifiedchain.Chain) *types.RootTrustBaseV1 {
	tb := fixtureTrust(chain)
	nodes := append([]*types.NodeInfo(nil), tb.RootNodes...)
	first := nodes[0]
	nodes[0] = &types.NodeInfo{NodeID: first.NodeID, SigKey: first.SigKey, Stake: 2}
	tb.RootNodes = nodes
	return tb
}

// Ordinary operation does not depend on the bootstrap requester: durable ordinary progress is kept,
// with its guard, when the requester cannot be built, and bootstrap-only state still refuses.
func TestDurableOrdinaryProgressSurvivesRequesterConstructionFailure(t *testing.T) {
	chain, _, id, factory := newFreshnessFixture(t)
	first := startFreshAdmission(t, context.Background(), *factory, id, freshnessFor(chain, &deadOpener{}))
	boot, bootTR := journalBootstrap(t, chain)
	require.NoError(t, first.Submit(context.Background(), boot, bootTR))
	require.NoError(t, first.Close())

	bootstrapOnly := &Freshness{Opener: &deadOpener{}, TrustBase: weightedRootTrust(chain)}
	startFreshAdmission(t, context.Background(), *factory, id, bootstrapOnly)
	require.ErrorIs(t, bootstrapOnly.Require(), ErrFreshnessUnavailable, "bootstrap-only state is never granted without the receipt")

	ordinary, tr := signAdapterObservation(t, chain)
	second := startFreshAdmission(t, context.Background(), *factory, id, freshnessFor(chain, &deadOpener{}))
	_ = second.Submit(context.Background(), ordinary, tr) // durable, though its body is unresolved
	require.NoError(t, second.Close())

	restarted := &Freshness{Opener: &deadOpener{}, TrustBase: weightedRootTrust(chain)}
	startFreshAdmission(t, context.Background(), *factory, id, restarted)
	require.NoError(t, restarted.Require(), "durable ordinary progress needs no requester")
	status, ok := restarted.Status()
	require.True(t, ok, "the guard is kept when the requester cannot be constructed")
	require.True(t, status.Ordinary)
}

// Ordinary progress learned after startup is latched even when neither requester nor guard exists,
// and the admission never calls a nil guard.
func TestNewlyLearnedOrdinaryProgressSurvivesMissingRequesterAndGuard(t *testing.T) {
	for name, f := range map[string]func(*certifiedchain.Chain) *Freshness{
		"requester refused": func(chain *certifiedchain.Chain) *Freshness {
			return &Freshness{Opener: &deadOpener{}, TrustBase: weightedRootTrust(chain)}
		},
		"no guard": func(chain *certifiedchain.Chain) *Freshness { return &Freshness{TrustBase: fixtureTrust(chain)} },
	} {
		t.Run(name, func(t *testing.T) {
			chain, _, id, factory := newFreshnessFixture(t)
			fresh := f(chain)
			a := startFreshAdmission(t, context.Background(), *factory, id, fresh)
			require.ErrorIs(t, fresh.Require(), ErrFreshnessUnavailable)
			ordinary, tr := signAdapterObservation(t, chain)
			err := a.Submit(context.Background(), ordinary, tr)
			require.ErrorIs(t, err, configuredprogress.ErrUnavailable)
			require.NoError(t, fresh.Require(), "ordinary progress needs no requester")
		})
	}
}
