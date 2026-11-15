package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestFetchFromRootPeers(t *testing.T) {
	a, b, c := peer.ID("peer-a"), peer.ID("peer-b"), peer.ID("peer-c")
	peers := []peer.AddrInfo{{ID: a}, {ID: b}, {ID: c}}
	errA, errB, errC := errors.New("not found"), errors.New("protocols not supported"), errors.New("stream reset")
	ctx := context.Background()

	t.Run("the first peer that answers wins and later peers are not asked", func(t *testing.T) {
		var asked []peer.ID
		got, err := fetchFromRootPeers(ctx, peers, func(_ context.Context, id peer.ID) (string, error) {
			asked = append(asked, id)
			if id == a {
				return "", errA
			}
			return "bundle from " + string(id), nil
		}, nil)
		require.NoError(t, err)
		require.Equal(t, "bundle from peer-b", got)
		require.Equal(t, []peer.ID{a, b}, asked)
	})

	t.Run("when none answers every peer's id and cause is reported and stays matchable", func(t *testing.T) {
		causes := map[peer.ID]error{a: errA, b: errB, c: errC}
		_, err := fetchFromRootPeers(ctx, peers, func(_ context.Context, id peer.ID) (string, error) { return "", causes[id] }, nil)
		require.Error(t, err)
		for id, cause := range causes {
			require.ErrorIs(t, err, cause)
			require.ErrorContains(t, err, "peer "+id.String()+": "+cause.Error())
		}
	})

	t.Run("an answer that does not authenticate passes over to the next peer", func(t *testing.T) {
		forged := errors.New("the commit proof does not verify")
		var asked []peer.ID
		got, err := fetchFromRootPeers(ctx, peers, func(_ context.Context, id peer.ID) (string, error) {
			asked = append(asked, id)
			return "bundle from " + string(id), nil
		}, func(b string) error {
			if b == "bundle from peer-a" {
				return forged
			}
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, "bundle from peer-b", got, "one bad peer does not mask a later honest one")
		require.Equal(t, []peer.ID{a, b}, asked)

		_, err = fetchFromRootPeers(ctx, peers, func(_ context.Context, id peer.ID) (string, error) { return "x", nil }, func(string) error { return forged })
		require.ErrorIs(t, err, errInvalidPeerBundle)
		require.ErrorIs(t, err, forged)
		require.ErrorContains(t, err, "peer "+c.String())
	})

	t.Run("no peer is asked once the context has ended", func(t *testing.T) {
		ended, cancel := context.WithCancel(ctx)
		var asked []peer.ID
		_, err := fetchFromRootPeers(ended, peers, func(_ context.Context, id peer.ID) (string, error) {
			asked = append(asked, id)
			cancel()
			return "", errA
		}, nil)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, []peer.ID{a}, asked)
	})

	t.Run("no peers is its own refusal", func(t *testing.T) {
		_, err := fetchFromRootPeers(ctx, nil, func(context.Context, peer.ID) (string, error) {
			t.Fatal("asked a peer that does not exist")
			return "", nil
		}, nil)
		require.ErrorIs(t, err, errNoInstallPeers)
	})
}

// #1080: the first root to restart with the install flag finds no peer that has committed the activation yet. It asks again in process,
// with a short backoff, instead of exiting into its container's restart backoff. The wait bounds the requests too (astra on #1081).
func TestAwaitFromRootPeers(t *testing.T) {
	a, b := peer.ID("peer-a"), peer.ID("peer-b")
	peers := []peer.AddrInfo{{ID: a}, {ID: b}}
	unavailable := errors.New("activation unavailable")
	fast := installRetry{first: time.Millisecond, max: 4 * time.Millisecond, wait: 5 * time.Second}

	t.Run("a peer that commits the activation later is waited for", func(t *testing.T) {
		calls, waited := 0, []int{}
		got, err := awaitFromRootPeers(context.Background(), fast, peers, func(_ context.Context, id peer.ID) (string, error) {
			calls++
			if calls < 7 || id != b { // three full refusals, then peer b serves it
				return "", unavailable
			}
			return "bundle from " + string(id), nil
		}, nil, func(attempt int, err error) {
			require.ErrorIs(t, err, unavailable)
			waited = append(waited, attempt)
		})
		require.NoError(t, err)
		require.Equal(t, "bundle from peer-b", got)
		require.Equal(t, []int{1, 2, 3}, waited, "told of each refusal it waited after")
	})

	t.Run("an invalid first answer and a valid later one: the valid one is chosen", func(t *testing.T) {
		got, err := awaitFromRootPeers(context.Background(), fast, peers, func(_ context.Context, id peer.ID) (string, error) {
			return "bundle from " + string(id), nil
		}, func(b string) error {
			if b == "bundle from peer-a" {
				return errors.New("forged")
			}
			return nil
		}, func(int, error) { t.Fatal("waited although a peer served a valid bundle") })
		require.NoError(t, err)
		require.Equal(t, "bundle from peer-b", got)
	})

	t.Run("the wait is bounded and the last refusal of every peer is reported", func(t *testing.T) {
		r := installRetry{first: time.Millisecond, max: 2 * time.Millisecond, wait: 30 * time.Millisecond}
		start := time.Now()
		_, err := awaitFromRootPeers(context.Background(), r, peers, func(context.Context, peer.ID) (string, error) { return "", unavailable }, nil, nil)
		require.ErrorIs(t, err, unavailable)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorContains(t, err, "within 30ms")
		require.Less(t, time.Since(start), time.Second)
	})

	t.Run("a slow peer is cut off at the end of the wait", func(t *testing.T) {
		r := installRetry{first: time.Millisecond, max: time.Millisecond, wait: 50 * time.Millisecond}
		start := time.Now()
		var asked []peer.ID
		_, err := awaitFromRootPeers(context.Background(), r, peers, func(ctx context.Context, id peer.ID) (string, error) {
			asked = append(asked, id)
			<-ctx.Done() // a peer that never answers: the request ends with the wait, not at its own transport deadline
			return "", ctx.Err()
		}, nil, nil)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Less(t, time.Since(start), 500*time.Millisecond)
		require.Equal(t, []peer.ID{a}, asked, "no request starts after the wait has ended")
	})

	t.Run("a request that would start after the wait is not made, and a late answer is not accepted", func(t *testing.T) {
		// the 20 ms budget of the review's probe: a fast refusal, then the backoff runs past the budget
		r := installRetry{first: time.Hour, max: time.Hour, wait: 20 * time.Millisecond}
		calls := 0
		start := time.Now()
		_, err := awaitFromRootPeers(context.Background(), r, []peer.AddrInfo{{ID: a}}, func(context.Context, peer.ID) (string, error) {
			calls++
			if calls == 1 {
				return "", unavailable
			}
			return "late bundle", nil
		}, nil, nil)
		require.ErrorIs(t, err, context.DeadlineExceeded, "the expiry during the backoff ends the wait")
		require.Equal(t, 1, calls)
		require.Less(t, time.Since(start), 500*time.Millisecond)
	})

	t.Run("the wait hands its deadline to every request", func(t *testing.T) {
		r := installRetry{first: time.Millisecond, max: time.Millisecond, wait: time.Minute}
		_, err := awaitFromRootPeers(context.Background(), r, peers, func(ctx context.Context, _ peer.ID) (string, error) {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.WithinDuration(t, time.Now().Add(time.Minute), deadline, 5*time.Second)
			return "bundle", nil
		}, nil, nil)
		require.NoError(t, err)
	})

	t.Run("a zero wait is one sweep under the caller's context", func(t *testing.T) {
		calls := 0
		_, err := awaitFromRootPeers(context.Background(), installRetry{}, peers, func(ctx context.Context, _ peer.ID) (string, error) {
			_, has := ctx.Deadline()
			require.False(t, has, "the caller's context, not a derived one")
			calls++
			return "", unavailable
		}, nil, func(int, error) { t.Fatal("waited although the wait is zero") })
		require.ErrorIs(t, err, unavailable)
		require.Equal(t, 2, calls, "each peer once")
	})

	t.Run("a cancelled context ends the wait during the backoff", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		slow := installRetry{first: time.Hour, max: time.Hour, wait: time.Hour}
		_, err := awaitFromRootPeers(ctx, slow, peers, func(context.Context, peer.ID) (string, error) { return "", unavailable }, nil, func(int, error) { cancel() })
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, unavailable)
	})

	t.Run("a cancelled context ends an in-flight request", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(30*time.Millisecond, cancel)
		start := time.Now()
		_, err := awaitFromRootPeers(ctx, installRetry{first: time.Hour, max: time.Hour, wait: time.Hour}, peers,
			func(ctx context.Context, _ peer.ID) (string, error) {
				<-ctx.Done()
				return "", ctx.Err()
			}, nil, nil)
		require.ErrorIs(t, err, context.Canceled)
		require.Less(t, time.Since(start), 500*time.Millisecond)
	})

	t.Run("without peers there is nothing to wait for", func(t *testing.T) {
		_, err := awaitFromRootPeers(context.Background(), fast, nil, func(context.Context, peer.ID) (string, error) { return "", nil }, nil,
			func(int, error) { t.Fatal("waited for no peer") })
		require.ErrorIs(t, err, errNoInstallPeers)
	})
}
