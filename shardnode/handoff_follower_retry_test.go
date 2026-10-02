package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

// a joiner's follower with one archive replica whose bundle fetch is controlled by the test.
func retryFollower(t *testing.T, retry BundleRetry, fetch func(attempt int64) (handoffdelivery.Bundle, error)) (*HandoffFollower, *stepHistory, *atomic.Int64) {
	t.Helper()
	host := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	replica := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	history := &stepHistory{next: map[uint64][]byte{}, expected: map[uint64][]byte{}}
	var calls atomic.Int64
	f := &HandoffFollower{Host: host, History: history, AnchorEpoch: 1, Directory: t.TempDir(), ConfHash: bytes.Repeat([]byte{5}, 32),
		ArchiveReplicas: []peer.ID{replica.ID()}, Retry: retry,
		FetchArchive: func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error) { return fetch(calls.Add(1)) }}
	return f, history, &calls
}

func epochTwoBundle() handoffdelivery.Bundle {
	var b handoffdelivery.Bundle
	b.Body.Epoch = 2
	b.Proof.Record.Epoch = 1
	return b
}

func notReady() error {
	return fmt.Errorf("%w: archive wiring: archive peer is not allowed", ErrHandoffPeerNotReady)
}

// A joiner's CatchUp that reaches a retained validator before it has installed the assignment step is refused (ErrHandoffPeerNotReady)
// and retries with bounded backoff, then installs the bundle once the replica admits it.
func TestCatchUpRetriesAReplicaThatHasNotInstalledTheStepYet(t *testing.T) {
	t.Parallel()
	f, history, calls := retryFollower(t, BundleRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: 20 * time.Second},
		func(attempt int64) (handoffdelivery.Bundle, error) {
			if attempt <= 5 {
				return handoffdelivery.Bundle{}, notReady()
			}
			return epochTwoBundle(), nil
		})
	bundles, err := f.CatchUp(context.Background(), 2)
	require.NoError(t, err)
	require.Len(t, bundles, 1)
	require.EqualValues(t, 6, calls.Load(), "five refusals, then the replica admitted the node")
	require.NotEmpty(t, history.order)
	for _, epoch := range history.order {
		require.EqualValues(t, 2, epoch, "only the bundle for the epoch asked for is verified and installed, and only after the refusals")
	}
	_, statErr := os.Stat(f.path(2))
	require.NoError(t, statErr, "and saved")
}

// If the replicas never admit the node, CatchUp ends after the bounded wait with an error that names the sentinel and the cause, and
// nothing is installed or saved.
func TestCatchUpEndsWithAClearErrorWhenNoReplicaEverAdmitsTheNode(t *testing.T) {
	t.Parallel()
	const total = 300 * time.Millisecond
	f, history, calls := retryFollower(t, BundleRetry{Initial: 5 * time.Millisecond, Max: 20 * time.Millisecond, Total: total},
		func(int64) (handoffdelivery.Bundle, error) { return handoffdelivery.Bundle{}, notReady() })
	started := time.Now()
	_, err := f.CatchUp(context.Background(), 2)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHandoffPeerNotReady)
	require.ErrorContains(t, err, "epoch 2")
	require.ErrorContains(t, err, "attempts")
	require.ErrorContains(t, err, "retained validators have not installed the assignment step")
	require.GreaterOrEqual(t, time.Since(started), total, "the whole bounded wait is used")
	require.Less(t, time.Since(started), 10*time.Second)
	require.Greater(t, calls.Load(), int64(2), "it retried rather than failing on the first refusal")
	require.Empty(t, history.order, "nothing was installed")
	_, statErr := os.Stat(f.path(2))
	require.ErrorIs(t, statErr, os.ErrNotExist, "nothing was saved")
}

// Exactly that refusal is retried: any other failure of the replica ends CatchUp at the first attempt, as before.
func TestCatchUpDoesNotRetryAnyOtherFailure(t *testing.T) {
	t.Parallel()
	boom := errors.New("replica failed for another reason")
	f, history, calls := retryFollower(t, BundleRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: 20 * time.Second},
		func(int64) (handoffdelivery.Bundle, error) { return handoffdelivery.Bundle{}, boom })
	_, err := f.CatchUp(context.Background(), 2)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrHandoffPeerNotReady)
	require.EqualValues(t, 1, calls.Load(), "an unrelated failure is not retried")
	require.Empty(t, history.order)
}

// A refusal followed by an unverifiable bundle is still refused for verification: the retry never installs unverified data.
func TestCatchUpNeverInstallsAnUnverifiedBundleWhileRetrying(t *testing.T) {
	t.Parallel()
	f, history, calls := retryFollower(t, BundleRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: 300 * time.Millisecond},
		func(attempt int64) (handoffdelivery.Bundle, error) {
			if attempt == 1 {
				return handoffdelivery.Bundle{}, notReady()
			}
			wrong := epochTwoBundle()
			wrong.Body.Epoch = 3 // not the epoch asked for: the follower's own check refuses it before any install
			return wrong, nil
		})
	_, err := f.CatchUp(context.Background(), 2)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrHandoffPeerNotReady, "the second answer was a bundle, not a refusal")
	require.Empty(t, history.order, "a bundle for another epoch is never installed")
	require.EqualValues(t, 2, calls.Load())
}

func TestCatchUpRetryStopsOnContextCancel(t *testing.T) {
	t.Parallel()
	f, _, _ := retryFollower(t, BundleRetry{Initial: 5 * time.Millisecond, Max: 20 * time.Millisecond, Total: time.Hour},
		func(int64) (handoffdelivery.Bundle, error) { return handoffdelivery.Bundle{}, notReady() })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := f.CatchUp(ctx, 2)
	require.Error(t, err)
	require.Less(t, time.Since(started), 5*time.Second)
	require.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled), "got %v", err)
}
