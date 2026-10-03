package frontierrequester

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-go-base/types"
)

// maintainClock is a thread-safe controllable clock: the test moves time, Wait only yields.
type maintainClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
}

func (c *maintainClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *maintainClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
func (c *maintainClock) Wait(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Millisecond):
		return nil
	}
}
func (c *maintainClock) recorded() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// answeringRequester is the policy fixture whose roots answer with a genuine quorum and cut, on a clock the
// test moves.
func answeringRequester(t *testing.T) (*Requester, *maintainClock, *atomic.Int32, interface {
	AcknowledgePair(*types.UnicityCertificate, *certification.TechnicalRecord) (bool, error)
}, *certifiedchain.Chain) {
	t.Helper()
	var proof *reviewLifecycleProof
	var frontierCalls atomic.Int32
	r, admission, _, chain := reviewPolicyRequester(t, func(_ context.Context, _ peer.ID, protocolID string) (libnetwork.Stream, error) {
		switch protocolID {
		case frontiertransport.FrontierProtocolID:
			frontierCalls.Add(1)
			return &reviewLifecycleStream{build: proof.frontier}, nil
		case frontiertransport.CutProtocolID:
			return &reviewLifecycleStream{build: proof.cut}, nil
		}
		return nil, io.ErrUnexpectedEOF
	})
	proof = newReviewLifecycleProof(t, chain)
	clk := &maintainClock{now: time.Now()}
	r.clock = clk
	return r, clk, &frontierCalls, admission, chain
}

func supersedingEvidence(t *testing.T, chain *certifiedchain.Chain) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	tr := certifiedchain.Technical(0)
	uc := chain.Certify(chain.Signer, &types.InputRecord{Version: 1, SumOfEarnedFees: 1}, tr, 2)
	uc.UnicitySeal.NetworkID = 5
	uc.UnicitySeal.Signatures = nil
	require.NoError(t, uc.UnicitySeal.Sign(chain.TrustBase.RootNodes[0].NodeID, chain.Signer))
	return uc, tr
}

// finished waits for Maintain to return, failing the calling test rather than hanging it.
func finished(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Maintain did not return")
		return nil
	}
}

func runMaintain(r *Requester) (context.CancelFunc, <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Maintain(ctx) }()
	return cancel, done
}

func TestMaintainKeepsALiveReceiptAndRenewsItAfterExpiry(t *testing.T) {
	r, clk, frontierCalls, _, _ := answeringRequester(t)
	cancel, done := runMaintain(r)
	defer cancel()
	require.Eventually(t, func() bool { return r.Current().Valid() }, 5*time.Second, time.Millisecond)
	first := r.Current()
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, first, r.Current(), "a live receipt is not replaced")
	require.EqualValues(t, 1, frontierCalls.Load(), "no further acquisition while the receipt lives")

	clk.advance(ReceiptLifetime)
	require.ErrorIs(t, r.Validate(first), ErrInvalidated, "the receipt has expired")
	require.Eventually(t, func() bool { c := r.Current(); return c.Valid() && c.generation > first.generation }, 5*time.Second, time.Millisecond, "expiry starts a new acquisition")
	require.ErrorIs(t, r.Validate(first), ErrInvalidated, "the expired receipt stays dead")
	cancel()
	require.ErrorIs(t, finished(t, done), context.Canceled)
}

func TestMaintainStopsOnceBootstrapIsRefusedAndAsksNoRootAgain(t *testing.T) {
	r, _, frontierCalls, admission, chain := answeringRequester(t)
	cancel, done := runMaintain(r)
	defer cancel()
	require.Eventually(t, func() bool { return r.Current().Valid() }, 5*time.Second, time.Millisecond)
	receipt := r.Current()
	uc, tr := supersedingEvidence(t, chain)
	retained, err := admission.AcknowledgePair(uc, tr)
	require.True(t, retained)
	require.Error(t, err)
	require.ErrorIs(t, finished(t, done), ErrInvalidated)
	require.ErrorIs(t, r.Validate(receipt), ErrInvalidated)
	calls := frontierCalls.Load()
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, calls, frontierCalls.Load())
}

func TestMaintainDoesNotStartWhenBootstrapIsAlreadyRefused(t *testing.T) {
	r, _, frontierCalls, admission, chain := answeringRequester(t)
	uc, tr := supersedingEvidence(t, chain)
	_, _ = admission.AcknowledgePair(uc, tr)
	cancel, done := runMaintain(r)
	defer cancel()
	require.ErrorIs(t, finished(t, done), ErrInvalidated)
	require.Zero(t, frontierCalls.Load())
}

func TestMaintainBacksOffAfterAFailedEpisodeAndStopsWithItsContext(t *testing.T) {
	var calls atomic.Int32
	r, _, _, _ := reviewPolicyRequester(t, func(context.Context, peer.ID, string) (libnetwork.Stream, error) { calls.Add(1); return nil, io.EOF })
	clk := &maintainClock{now: time.Now()}
	r.clock = clk
	cancel, done := runMaintain(r)
	require.Eventually(t, func() bool { return calls.Load() >= 6 }, 5*time.Second, time.Millisecond, "failed episodes repeat")
	cancel()
	require.ErrorIs(t, finished(t, done), context.Canceled)
	waits := clk.recorded()
	require.NotEmpty(t, waits)
	for _, w := range waits {
		require.Equal(t, PassBackoff, w, "a failed episode waits one backoff, never spins")
	}
}

func TestMaintainReportsEachEpisodeOutcome(t *testing.T) {
	var mu sync.Mutex
	var outcomes []error
	report := func(err error) { mu.Lock(); outcomes = append(outcomes, err); mu.Unlock() }
	snapshot := func() []error { mu.Lock(); defer mu.Unlock(); return append([]error(nil), outcomes...) }

	r, _, _, _, _ := answeringRequester(t)
	r.report = report
	cancel, done := runMaintain(r)
	require.Eventually(t, func() bool { return len(snapshot()) == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, snapshot()[0])
	cancel()
	require.ErrorIs(t, finished(t, done), context.Canceled)

	failing, _, _, _ := reviewPolicyRequester(t, func(context.Context, peer.ID, string) (libnetwork.Stream, error) { return nil, io.EOF })
	failing.report = report
	failing.clock = &maintainClock{now: time.Now()}
	cancel, done = runMaintain(failing)
	require.Eventually(t, func() bool { return len(snapshot()) >= 2 }, 5*time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, finished(t, done), context.Canceled)
	require.ErrorIs(t, snapshot()[1], ErrUnavailable)
}

func TestMaintainWithAnEndedContextAsksNoRoot(t *testing.T) {
	r, _, frontierCalls, _, _ := answeringRequester(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, r.Maintain(ctx), context.Canceled)
	require.Zero(t, frontierCalls.Load())
}
