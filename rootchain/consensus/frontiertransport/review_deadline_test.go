package frontiertransport

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type reviewOpenFunc func(context.Context, peer.ID, string) (libp2pnetwork.Stream, error)

func (f reviewOpenFunc) CreateStream(ctx context.Context, id peer.ID, protocol string) (libp2pnetwork.Stream, error) {
	return f(ctx, id, protocol)
}

// Only these six stream methods are used by the production exchange. The
// embedded interface leaves unrelated libp2p metadata out of this fixture.
type reviewDeadlineStream struct {
	libp2pnetwork.Stream
	r        io.Reader
	deadline time.Time
}

func (s *reviewDeadlineStream) Read(p []byte) (int, error)    { return s.r.Read(p) }
func (s *reviewDeadlineStream) Write(p []byte) (int, error)   { return len(p), nil }
func (s *reviewDeadlineStream) SetDeadline(d time.Time) error { s.deadline = d; return nil }
func (s *reviewDeadlineStream) CloseWrite() error             { return nil }
func (s *reviewDeadlineStream) Close() error                  { return nil }
func (s *reviewDeadlineStream) Reset() error                  { return nil }

func TestReviewExchangeUsesTheSameAbsoluteDeadline(t *testing.T) {
	for _, callerBound := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport budget", true: "earlier caller deadline"}[callerBound], func(t *testing.T) {
			ctx := context.Background()
			var callerDeadline time.Time
			if callerBound {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
				callerDeadline, _ = ctx.Deadline()
			}
			st := &reviewDeadlineStream{r: bytes.NewReader(reviewFrame(1, []byte{1}))}
			var dialDeadline time.Time
			opener := reviewOpenFunc(func(c context.Context, _ peer.ID, protocol string) (libp2pnetwork.Stream, error) {
				require.Equal(t, FrontierProtocolID, protocol)
				var ok bool
				dialDeadline, ok = c.Deadline()
				require.True(t, ok)
				return st, nil
			})
			budget, err := NewReceiveBudget(100)
			require.NoError(t, err)
			before := time.Now()
			got := ExchangeFrontier(ctx, opener, "root", reviewFrontierRequest([]byte{0x80}), budget, MaxExchangeDuration)
			require.NoError(t, got.Err)
			require.True(t, got.Complete)
			require.Equal(t, dialDeadline, st.deadline, "dialing must not restart the exchange timeout")
			if callerBound {
				require.Equal(t, callerDeadline, dialDeadline)
			} else {
				require.False(t, dialDeadline.Before(before.Add(MaxExchangeDuration)))
				require.False(t, dialDeadline.After(time.Now().Add(MaxExchangeDuration)))
			}
			require.Zero(t, budget.Snapshot().Active)
		})
	}
}

func TestReviewUnusableBudgetRefusesBeforeDial(t *testing.T) {
	exhausted, err := NewReceiveBudget(1)
	require.NoError(t, err)
	require.NoError(t, exhausted.reserve(1))
	for _, b := range []*ReceiveBudget{nil, {}, exhausted} {
		called := false
		opener := reviewOpenFunc(func(context.Context, peer.ID, string) (libp2pnetwork.Stream, error) {
			called = true
			return nil, io.EOF
		})
		got := ExchangeFrontier(context.Background(), opener, "root", reviewFrontierRequest([]byte{0x80}), b, time.Second)
		require.ErrorIs(t, got.Err, ErrBudget)
		require.False(t, called)
	}
}
