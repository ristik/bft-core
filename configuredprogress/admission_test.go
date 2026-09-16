package configuredprogress

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type admissionGate struct{ mu sync.Mutex }

func (g *admissionGate) WithinFinality(ctx context.Context, f func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return f()
}

type controlledClock struct {
	waits    chan time.Duration
	release  chan struct{}
	episodes chan time.Duration
	expire   chan struct{}
}

func newControlledClock() *controlledClock {
	return &controlledClock{waits: make(chan time.Duration, 16), release: make(chan struct{}, 16), episodes: make(chan time.Duration, 16), expire: make(chan struct{}, 16)}
}
func (c *controlledClock) Episode(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	c.episodes <- d
	go func() {
		select {
		case <-parent.Done():
			cancel()
		case <-c.expire:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
func (c *controlledClock) Wait(ctx context.Context, d time.Duration) error {
	select {
	case c.waits <- d:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *controlledClock) advance(t *testing.T, want time.Duration) {
	t.Helper()
	select {
	case got := <-c.waits:
		require.Equal(t, want, got)
		c.release <- struct{}{}
	case <-time.After(2 * time.Second):
		t.Fatal("coordinator did not enter expected wait")
	}
}

func waitAdmission(t *testing.T, f func() bool) {
	t.Helper()
	require.Eventually(t, f, 3*time.Second, time.Millisecond)
}

func newTestAdmission(t *testing.T, f *fixture, s *Store, gate AdmissionGate, clock admissionClock, policy admissionPolicy, invalidate func(), deliver func(context.Context, rootinput.VerifiedObservationV2) error) *AdmissionCoordinator {
	t.Helper()
	c, err := newAdmissionCoordinator(context.Background(), AdmissionConfig{Store: s, Context: f.ctx, Gate: gate, Invalidate: invalidate, Deliver: deliver}, clock, policy)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}

func TestAdmissionAuthenticatesInvalidatesPersistsThenDelivers(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	var mu sync.Mutex
	var events []string
	add := func(v string) { mu.Lock(); events = append(events, v); mu.Unlock() }
	s.checkpoint = func(string) error { add("persist"); return nil }
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 3, duration: time.Second, cooldown: time.Hour}, func() { add("invalidate") }, func(context.Context, rootinput.VerifiedObservationV2) error { add("deliver"); return nil })
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	result, err := c.Submit(context.Background(), u, tr)
	require.NoError(t, err)
	require.Equal(t, AdmissionQueued, result)
	waitAdmission(t, func() bool { return !c.Status().PendingLatest && !c.Status().DeliveryPending })
	mu.Lock()
	require.Equal(t, []string{"invalidate", "persist", "deliver"}, events)
	mu.Unlock()
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.True(t, st.Ordinary())
}

func TestAdmissionUnsupportedIsStickyButCallbackSentinelIsNot(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	invalidations := 0
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 3, duration: time.Second, cooldown: time.Hour}, func() { invalidations++ }, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	ir := &types.InputRecord{Version: 1, SumOfEarnedFees: 1}
	u, tr := f.sign(ir, 1, 4)
	result, err := c.Submit(context.Background(), u, tr)
	require.Equal(t, AdmissionUnsupported, result)
	require.True(t, rootinput.IsUnsupportedObservationV2(err))
	require.Equal(t, 1, invalidations)
	require.True(t, c.Status().UnsupportedSeen)

	bad := c.ctx.Observation
	bad.TrustBases = failingAdmissionTrust{err: fmt.Errorf("provider: %w", rootinput.ErrV2Shape)}
	c.ctx.Observation = bad
	_, err = c.Submit(context.Background(), u, tr)
	require.Error(t, err)
	require.False(t, rootinput.IsUnsupportedObservationV2(err))
	require.Equal(t, 1, invalidations, "callback-controlled errors grant no invalidation authority")
}

type failingAdmissionTrust struct{ err error }

func (f failingAdmissionTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return nil, f.err
}

func TestAdmissionRetryBudgetIsNotRenewedByDuplicateDelivery(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	clock := newControlledClock()
	deliveries := make(chan struct{}, 4)
	c := newTestAdmission(t, f, s, &admissionGate{}, clock, admissionPolicy{attempts: 2, duration: time.Minute, cooldown: 10 * time.Second}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error {
		deliveries <- struct{}{}
		return errors.New("adoption failed")
	})
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	_, err = c.Submit(context.Background(), u, tr)
	require.NoError(t, err)
	clock.advance(t, 0)
	select {
	case <-deliveries:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery was not attempted")
	}
	_, err = c.Submit(context.Background(), u, tr)
	require.NoError(t, err)
	select {
	case <-deliveries:
		t.Fatal("redelivery reset the exhausted episode")
	case <-time.After(30 * time.Millisecond):
	}
	clock.advance(t, 10*time.Second)
	select {
	case <-deliveries:
	case <-time.After(2 * time.Second):
		t.Fatal("durable delivery obligation was not retried after cooldown")
	}
}

func TestAdmissionFirstOrdinaryIsLatchedBeforeNewestAndNotDelivered(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	clock := newControlledClock()
	writes := 0
	s.checkpoint = func(string) error {
		writes++
		if writes == 1 || writes == 3 {
			return errors.New("first write failed")
		}
		return nil
	}
	delivered := make(chan evmroot.Hash32, 2)
	c := newTestAdmission(t, f, s, &admissionGate{}, clock, admissionPolicy{attempts: 3, duration: time.Minute, spacing: time.Second, cooldown: time.Hour}, func() {}, func(_ context.Context, o rootinput.VerifiedObservationV2) error {
		delivered <- o.OriginIdentity()
		return nil
	})
	a := f.first(1, 2, 5)
	b := f.ordinary(2, 3, 6)
	_, err = c.Submit(context.Background(), a.Certificate(), a.TechnicalRecord())
	require.NoError(t, err)
	select {
	case d := <-clock.waits:
		require.Equal(t, time.Second, d)
	case <-time.After(2 * time.Second):
		t.Fatal("failed A write did not consume the shared episode")
	}
	_, err = c.Submit(context.Background(), b.Certificate(), b.TechnicalRecord())
	require.NoError(t, err)
	clock.release <- struct{}{}
	clock.advance(t, time.Second)
	waitAdmission(t, func() bool {
		st, _, e := s.Load(context.Background(), f.ctx)
		if e != nil || !st.Ordinary() {
			return false
		}
		first, ok := st.FirstOrdinary()
		return ok && sameObservation(first, a)
	})
	select {
	case got := <-delivered:
		t.Fatalf("staging first ordinary was delivered: %x", got)
	default:
	}
	require.True(t, c.Status().PendingLatest, "newest B remains retryable after the shared episode is exhausted")
}

func TestAdmissionRefusesCompetingFirstOrdinaryLatch(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	clock := newControlledClock()
	fail := true
	s.checkpoint = func(string) error {
		if fail {
			fail = false
			return errors.New("A write failed")
		}
		return nil
	}
	c := newTestAdmission(t, f, s, &admissionGate{}, clock, admissionPolicy{attempts: 2, duration: time.Minute, spacing: time.Second, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error {
		t.Fatal("conflicting first latch must not deliver")
		return nil
	})
	a := f.first(1, 2, 5)
	competing := f.ordinary(2, 3, 6)
	_, err = c.Submit(context.Background(), a.Certificate(), a.TechnicalRecord())
	require.NoError(t, err)
	select {
	case d := <-clock.waits:
		require.Equal(t, time.Second, d)
	case <-time.After(2 * time.Second):
		t.Fatal("A failure did not enter spacing")
	}
	p, _, err := s.PrepareObservation(context.Background(), f.ctx, competing)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	clock.release <- struct{}{}
	waitAdmission(t, func() bool { return errors.Is(c.Status().LastError, ErrConflict) })
	require.True(t, c.Status().PendingFirst, "retained A is not cleared merely because another writer latched a first pair")
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	first, ok := st.FirstOrdinary()
	require.True(t, ok)
	require.True(t, sameObservation(first, competing))
}

func TestAdmissionCancellationWhileBlockedAtGateDoesNotCommit(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	gate := &admissionGate{}
	gate.mu.Lock()
	var invalidations atomic.Int32
	c := newTestAdmission(t, f, s, gate, wallAdmissionClock{}, admissionPolicy{attempts: 3, duration: time.Second, cooldown: time.Hour}, func() { invalidations.Add(1) }, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := c.Submit(ctx, u, tr); done <- e }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	gate.mu.Unlock()
	require.ErrorIs(t, <-done, context.Canceled)
	require.True(t, c.Status().BootstrapInvalidated, "authenticated ordinary knowledge is sticky even when gate acquisition is canceled")
	waitAdmission(t, func() bool { return invalidations.Load() == 1 })
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.Zero(t, st.Revision())
}

func TestAdmissionEpisodeDeadlineReachesBlockingDelivery(t *testing.T) {
	f := newFixture(t, 0)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	started := make(chan struct{})
	clock := newControlledClock()
	c := newTestAdmission(t, f, s, &admissionGate{}, clock, admissionPolicy{attempts: 2, duration: 5 * time.Second, cooldown: time.Hour}, func() {}, func(ctx context.Context, _ rootinput.VerifiedObservationV2) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	u, tr := f.sign(&types.InputRecord{Version: 1}, 1, 4)
	_, err = c.Submit(context.Background(), u, tr)
	require.NoError(t, err)
	require.Equal(t, 5*time.Second, <-clock.episodes)
	clock.advance(t, 0)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not start")
	}
	clock.expire <- struct{}{}
	waitAdmission(t, func() bool { return errors.Is(c.Status().LastError, context.Canceled) })
	require.True(t, c.Status().DeliveryPending)
}

func TestAdmissionRejectsOversizedEvidenceBeforeTrustOrInvalidation(t *testing.T) {
	f := newFixture(t, 0)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	called := 0
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 2, duration: time.Second, cooldown: time.Hour}, func() { called++ }, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	u, tr := f.sign(&types.InputRecord{Version: 1}, 1, 4)
	u.InputRecord.SummaryValue = make([]byte, MaxPairBytes+1)
	c.ctx.Observation.TrustBases = callbackTrust{tb: f.c.TrustBase, callback: func() { called += 100 }}
	_, err = c.Submit(context.Background(), u, tr)
	require.ErrorIs(t, err, ErrBounds)
	require.Zero(t, called)
	require.False(t, c.Status().BootstrapInvalidated)
}

func TestAdmissionCommitLinearizesUnderGateAndDeliveryRunsAfterRelease(t *testing.T) {
	f := newFixture(t, 0)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	gate := &admissionGate{}
	gate.mu.Lock()
	delivered := make(chan struct{}, 1)
	c := newTestAdmission(t, f, s, gate, wallAdmissionClock{}, admissionPolicy{attempts: 3, duration: time.Second, cooldown: time.Hour}, func() {}, func(ctx context.Context, _ rootinput.VerifiedObservationV2) error {
		// Reacquisition succeeds only because the coordinator released the commit gate.
		return gate.WithinFinality(ctx, func() error { delivered <- struct{}{}; return nil })
	})
	u, tr := f.sign(&types.InputRecord{Version: 1}, 1, 4)
	_, err = c.Submit(context.Background(), u, tr)
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.Zero(t, st.Revision(), "observation cannot linearize while an earlier finality operation holds the gate")
	select {
	case <-delivered:
		t.Fatal("delivery ran before durable commit")
	default:
	}
	gate.mu.Unlock()
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not run after gated commit released the gate")
	}
	st, _, err = s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), st.Revision())
}

func TestAdmissionRestartInvalidatesBeforeRecoveredOrdinaryDelivery(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	o := f.first(1, 2, 5)
	p, _, err := s.PrepareObservation(context.Background(), f.ctx, o)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	var mu sync.Mutex
	var events []string
	add := func(v string) { mu.Lock(); events = append(events, v); mu.Unlock() }
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 3, duration: time.Second, cooldown: time.Hour}, func() { add("invalidate") }, func(_ context.Context, got rootinput.VerifiedObservationV2) error {
		require.True(t, sameObservation(o, got))
		add("deliver")
		return nil
	})
	waitAdmission(t, func() bool { return !c.Status().DeliveryPending })
	mu.Lock()
	require.Equal(t, []string{"invalidate", "deliver"}, events)
	mu.Unlock()
}

func TestAdmissionBoundsConcurrentAuthentication(t *testing.T) {
	f := newFixture(t, 0)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	ctx := f.ctx
	ctx.Observation.TrustBases = blockingAdmissionTrust{tb: f.c.TrustBase, entered: entered, release: release}
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 3, duration: time.Second, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	c.ctx = ctx
	u, tr := f.sign(&types.InputRecord{Version: 1}, 1, 4)
	done := make(chan error, 1)
	go func() { _, e := c.Submit(context.Background(), u, tr); done <- e }()
	<-entered
	_, err = c.Submit(context.Background(), u, tr)
	require.ErrorIs(t, err, ErrAdmissionBusy)
	close(release)
	require.NoError(t, <-done)
}

func TestAdmissionConcurrentCloseWaitsForIngressAndWorker(t *testing.T) {
	f := newFixture(t, 0)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	ctx := f.ctx
	ctx.Observation.TrustBases = stubbornAdmissionTrust{tb: f.c.TrustBase, entered: entered, release: release}
	c, err := newAdmissionCoordinator(context.Background(), AdmissionConfig{Store: s, Context: ctx, Gate: &admissionGate{}, Invalidate: func() {}, Deliver: func(context.Context, rootinput.VerifiedObservationV2) error { return nil }}, wallAdmissionClock{}, admissionPolicy{attempts: 2, duration: time.Second, cooldown: time.Hour})
	require.NoError(t, err)
	u, tr := f.sign(&types.InputRecord{Version: 1}, 1, 4)
	submitDone := make(chan error, 1)
	go func() { _, e := c.Submit(context.Background(), u, tr); submitDone <- e }()
	<-entered
	closed := make(chan struct{}, 2)
	go func() { _ = c.Close(); closed <- struct{}{} }()
	go func() { _ = c.Close(); closed <- struct{}{} }()
	select {
	case <-closed:
		t.Fatal("Close returned while authentication still owned the ingress slot")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	for range 2 {
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Close did not share completed shutdown")
		}
	}
	require.Error(t, <-submitDone)
}

func TestAdmissionCanceledBootstrapAuthenticationCannotQueue(t *testing.T) {
	f := newFixture(t, 0)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	ctx := f.ctx
	ctx.Observation.TrustBases = stubbornAdmissionTrust{tb: f.c.TrustBase, entered: entered, release: release}
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 2, duration: time.Second, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	c.ctx = ctx
	u, tr := f.sign(&types.InputRecord{Version: 1}, 1, 4)
	request, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := c.Submit(request, u, tr); done <- e }()
	<-entered
	cancel()
	close(release)
	require.ErrorIs(t, <-done, context.Canceled)
	time.Sleep(10 * time.Millisecond)
	require.False(t, c.Status().PendingLatest)
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.Zero(t, st.Revision())
}

type blockingAdmissionTrust struct {
	tb      *types.RootTrustBaseV1
	entered chan struct{}
	release chan struct{}
}

type stubbornAdmissionTrust struct {
	tb      *types.RootTrustBaseV1
	entered chan struct{}
	release chan struct{}
}

func (b stubbornAdmissionTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	close(b.entered)
	<-b.release
	return b.tb, nil
}

func (b blockingAdmissionTrust) GetByEpoch(ctx context.Context, _ uint64) (*types.RootTrustBaseV1, error) {
	close(b.entered)
	select {
	case <-b.release:
		return b.tb, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
