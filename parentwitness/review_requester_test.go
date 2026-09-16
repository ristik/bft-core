package parentwitness

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	network "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type reviewFrameOpener struct {
	mu     sync.Mutex
	frames [][]byte
	calls  int
	wg     sync.WaitGroup
}

type reviewOpenerFunc func(context.Context, peer.ID, string) (network.Stream, error)

type reviewCancelOnClose struct {
	network.Stream
	cancel context.CancelFunc
}

func (s *reviewCancelOnClose) Close() error {
	s.cancel()
	return s.Stream.Close()
}

func TestReviewRequesterCancellationAfterProofBeforePublication(t *testing.T) {
	chain, target := fixtureTarget(t)
	var valid bytes.Buffer
	require.NoError(t, WriteResponseFrame(&valid, Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: chain.Blocks[1].Evidence}))
	frames := &reviewFrameOpener{frames: [][]byte{valid.Bytes()}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opener := reviewOpenerFunc(func(ctx context.Context, p peer.ID, protocol string) (network.Stream, error) {
		st, err := frames.CreateStream(ctx, p, protocol)
		if err != nil {
			return nil, err
		}
		return &reviewCancelOnClose{Stream: st, cancel: cancel}, nil
	})
	r, err := NewRequester(context.Background(), RequesterConfig{Opener: opener, Providers: []peer.ID{"valid"}, Budget: RequesterBudget{MaxAttempts: 1, MaxProviders: 1, Overall: time.Second, PerAttempt: time.Second, MaxDownloadedBytes: MaxResponseBytes, Backoff: time.Second}})
	require.NoError(t, err)
	t.Cleanup(func() { r.Close(); frames.wg.Wait() })
	got, err := r.Request(ctx, target)
	require.NoError(t, err)
	require.Equal(t, RequesterStopped, got.Outcome)
	require.False(t, got.Response.Valid(), "a verified but canceled result must not be published")
}

func (f reviewOpenerFunc) CreateStream(ctx context.Context, p peer.ID, protocol string) (network.Stream, error) {
	return f(ctx, p, protocol)
}

func TestReviewRequesterAttemptsAndTimeBudgets(t *testing.T) {
	chain, target := fixtureTarget(t)
	var valid bytes.Buffer
	require.NoError(t, WriteResponseFrame(&valid, Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: chain.Blocks[1].Evidence}))
	for _, tc := range []struct {
		name                string
		attempts            int
		overall, perAttempt time.Duration
		want                RequesterOutcome
		wantCalls           int
	}{
		{"slow provider then valid", 2, 2 * time.Second, 100 * time.Millisecond, RequesterVerified, 2},
		{"attempt cap before valid", 1, 2 * time.Second, 100 * time.Millisecond, RequesterBudgetExhausted, 1},
		{"overall bounds first provider", 2, 100 * time.Millisecond, time.Second, RequesterBudgetExhausted, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := &reviewFrameOpener{frames: [][]byte{valid.Bytes()}}
			calls := 0
			opener := reviewOpenerFunc(func(ctx context.Context, p peer.ID, protocol string) (network.Stream, error) {
				calls++
				if p == "slow" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return frames.CreateStream(ctx, p, protocol)
			})
			r, err := NewRequester(context.Background(), RequesterConfig{Opener: opener, Providers: []peer.ID{"slow", "valid"}, Budget: RequesterBudget{MaxAttempts: tc.attempts, MaxProviders: 2, Overall: tc.overall, PerAttempt: tc.perAttempt, MaxDownloadedBytes: MaxResponseBytes, Backoff: time.Second}})
			require.NoError(t, err)
			t.Cleanup(func() { r.Close(); frames.wg.Wait() })
			result, err := r.Request(context.Background(), target)
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Outcome)
			require.Equal(t, tc.wantCalls, calls)
			if result.Response.Found() {
				owned := result.Response.Evidence()
				owned.Header[0] ^= 1
				require.Equal(t, chain.Blocks[1].Evidence.Header, result.Response.Evidence().Header)
			}
		})
	}
}

func TestReviewRequesterCumulativeMalformedBytes(t *testing.T) {
	_, target := fixtureTarget(t)
	// Each prefix declares 3 bytes but the provider closes after only 1. Both
	// malformed responses count, and the third provider cannot start.
	opener := &reviewFrameOpener{frames: [][]byte{{3, 1}, {3, 2}}}
	r, err := NewRequester(context.Background(), RequesterConfig{Opener: opener, Providers: []peer.ID{"a", "b", "c"}, Budget: RequesterBudget{MaxAttempts: 3, MaxProviders: 3, Overall: time.Second, PerAttempt: time.Second, MaxDownloadedBytes: 4, Backoff: time.Second}})
	require.NoError(t, err)
	t.Cleanup(func() { r.Close(); opener.wg.Wait() })
	result, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterBudgetExhausted, result.Outcome)
	require.EqualValues(t, 4, result.Downloaded)
	require.Equal(t, 2, result.Attempts)
	_, err = r.Request(context.Background(), target)
	require.True(t, errors.Is(err, ErrRequesterBackoff))
}

func (o *reviewFrameOpener) CreateStream(ctx context.Context, _ peer.ID, _ string) (network.Stream, error) {
	o.mu.Lock()
	frame := o.frames[o.calls]
	o.calls++
	o.mu.Unlock()
	a, b := net.Pipe()
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer b.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = b.SetDeadline(deadline)
		}
		if _, err := ReadRequestFrame(b); err == nil {
			_, _ = b.Write(frame)
		}
	}()
	return &delayedStream{conn: a}, nil
}

func TestReviewRequesterExactByteBudgetDoesNotEnableUnlimitedExchange(t *testing.T) {
	chain, target := fixtureTarget(t)
	var refusal, valid bytes.Buffer
	require.NoError(t, WriteResponseFrame(&refusal, Response{Request: target.Request(), Outcome: OutcomeUnavailable}))
	require.NoError(t, WriteResponseFrame(&valid, Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: chain.Blocks[1].Evidence}))
	opener := &reviewFrameOpener{frames: [][]byte{refusal.Bytes(), valid.Bytes()}}
	r, err := NewRequester(context.Background(), RequesterConfig{Opener: opener, Providers: []peer.ID{"missing", "valid"}, Budget: RequesterBudget{MaxAttempts: 2, MaxProviders: 2, Overall: time.Second, PerAttempt: time.Second, MaxDownloadedBytes: int64(refusal.Len()), Backoff: time.Second}})
	require.NoError(t, err)
	t.Cleanup(func() { r.Close(); opener.wg.Wait() })
	result, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterBudgetExhausted, result.Outcome)
	require.Equal(t, int64(refusal.Len()), result.Downloaded)
	require.Equal(t, 1, result.Attempts)
	opener.mu.Lock()
	defer opener.mu.Unlock()
	require.Equal(t, 1, opener.calls, "a consumed budget must not become the legacy unlimited sentinel")
}
