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

	t.Run("the first peer that answers wins and later peers are not asked", func(t *testing.T) {
		var asked []peer.ID
		got, err := fetchFromRootPeers(peers, func(id peer.ID) (string, error) {
			asked = append(asked, id)
			if id == a {
				return "", errA
			}
			return "bundle from " + string(id), nil
		})
		require.NoError(t, err)
		require.Equal(t, "bundle from peer-b", got)
		require.Equal(t, []peer.ID{a, b}, asked)
	})

	t.Run("when none answers every peer's id and cause is reported and stays matchable", func(t *testing.T) {
		causes := map[peer.ID]error{a: errA, b: errB, c: errC}
		_, err := fetchFromRootPeers(peers, func(id peer.ID) (string, error) { return "", causes[id] })
		require.Error(t, err)
		for id, cause := range causes {
			require.ErrorIs(t, err, cause)
			require.ErrorContains(t, err, "peer "+id.String()+": "+cause.Error())
		}
	})

	t.Run("no peers is its own refusal", func(t *testing.T) {
		_, err := fetchFromRootPeers(nil, func(peer.ID) (string, error) { t.Fatal("asked a peer that does not exist"); return "", nil })
		require.ErrorIs(t, err, errNoInstallPeers)
	})
}

// #1080: the first root to restart with the install flag finds no peer that has committed the activation yet. It asks again in process,
// with a short backoff, instead of exiting into its container's restart backoff.
func TestAwaitFromRootPeers(t *testing.T) {
	a, b := peer.ID("peer-a"), peer.ID("peer-b")
	peers := []peer.AddrInfo{{ID: a}, {ID: b}}
	unavailable := errors.New("activation unavailable")
	fast := installRetry{first: time.Millisecond, max: 4 * time.Millisecond, wait: 5 * time.Second}

	t.Run("a peer that commits the activation later is waited for", func(t *testing.T) {
		calls, waited := 0, []int{}
		got, err := awaitFromRootPeers(context.Background(), fast, peers, func(id peer.ID) (string, error) {
			calls++
			if calls < 7 || id != b { // three full refusals, then peer b serves it
				return "", unavailable
			}
			return "bundle from " + string(id), nil
		}, func(attempt int, err error) {
			require.ErrorIs(t, err, unavailable)
			waited = append(waited, attempt)
		})
		require.NoError(t, err)
		require.Equal(t, "bundle from peer-b", got)
		require.Equal(t, []int{1, 2, 3}, waited, "told of each refusal it waited after")
	})

	t.Run("the wait is bounded and the last refusal of every peer is reported", func(t *testing.T) {
		r := installRetry{first: time.Millisecond, max: 2 * time.Millisecond, wait: 30 * time.Millisecond}
		start := time.Now()
		_, err := awaitFromRootPeers(context.Background(), r, peers, func(peer.ID) (string, error) { return "", unavailable }, nil)
		require.ErrorIs(t, err, unavailable)
		require.ErrorContains(t, err, "peer "+a.String()+": activation unavailable")
		require.ErrorContains(t, err, "peer "+b.String()+": activation unavailable")
		require.ErrorContains(t, err, "attempts over 30ms")
		require.Less(t, time.Since(start), 2*time.Second)
	})

	t.Run("a zero wait asks once", func(t *testing.T) {
		calls := 0
		_, err := awaitFromRootPeers(context.Background(), installRetry{}, peers, func(peer.ID) (string, error) { calls++; return "", unavailable }, func(int, error) {
			t.Fatal("waited although the wait is zero")
		})
		require.ErrorIs(t, err, unavailable)
		require.Equal(t, 2, calls, "each peer once")
	})

	t.Run("a cancelled context ends the wait", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		slow := installRetry{first: time.Hour, max: time.Hour, wait: time.Hour}
		_, err := awaitFromRootPeers(ctx, slow, peers, func(peer.ID) (string, error) { return "", unavailable }, func(int, error) { cancel() })
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, unavailable)
	})

	t.Run("without peers there is nothing to wait for", func(t *testing.T) {
		_, err := awaitFromRootPeers(context.Background(), fast, nil, func(peer.ID) (string, error) { return "", nil }, func(int, error) { t.Fatal("waited for no peer") })
		require.ErrorIs(t, err, errNoInstallPeers)
	})
}
