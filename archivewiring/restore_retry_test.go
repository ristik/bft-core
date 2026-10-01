package archivewiring

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// saturatedHost fails the first failures CreateStream calls the way a source validator whose global
// archive stream limit is reached does (a stream reset with ErrPendingLimit), then delegates. A negative
// failures value never recovers.
type saturatedHost struct {
	shardnode.EvidenceHost
	failures int64
	calls    atomic.Int64
}

func (h *saturatedHost) CreateStream(ctx context.Context, id peer.ID, protocol string) (libp2pnetwork.Stream, error) {
	n := h.calls.Add(1)
	if h.failures < 0 || n <= h.failures {
		return nil, &StreamResetError{Peer: id, Operation: "fetch", Reason: ErrPendingLimit}
	}
	return h.EvidenceHost.CreateStream(ctx, id, protocol)
}

type retryRestoreFixture struct {
	restore  *ArchiveRestore
	host     *saturatedHost
	journal  *configuredprogress.Store
	local    *archive.Store
	wf       *wiringFixture
	limits   configuredprogress.JournalLimits
	executor *restoreExecutorFixture
}

func newRetryRestoreFixture(t *testing.T, failures int64, retry FetchRetry) *retryRestoreFixture {
	t.Helper()
	f := newWiringFixture(t, 5)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var replicas []*peer.ID
	for range 2 {
		remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		store, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		for _, entry := range f.entries {
			q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, entry)
			require.NoError(t, err)
			require.NoError(t, store.Put(q, rec))
		}
		server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), remote)
		id := remote.ID()
		replicas = append(replicas, &id)
	}
	journal, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/restored.db", configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	_, _, err = journal.Initialize(context.Background(), f.context)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 3, Observations: 4, Bytes: 16 << 20}
	require.NoError(t, journal.EnableJournal(context.Background(), f.context, limits))
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	last := f.entries[len(f.entries)-1]
	for _, entry := range f.entries {
		if entry.Candidate.Number > last.Candidate.Number {
			last = entry
		}
	}
	genesis := shardnode.BlockRef{Number: 0, Hash: f.context.Origin.BlockHash().Bytes(), StateRoot: f.context.Origin.StateRoot().Bytes()}
	executor := newRestoreExecutorFixture(genesis)
	host := &saturatedHost{EvidenceHost: sender, failures: failures}
	return &retryRestoreFixture{
		restore: &ArchiveRestore{Journal: journal, Context: f.context, JournalLimits: limits, Archive: local,
			Subject: f.subject, Replicas: [2]peer.ID{*replicas[0], *replicas[1]}, Host: host,
			Limits: DefaultLimits(), Retry: retry, Adapter: executor, Genesis: genesis, TipUC: last.ResultingUC, TipTR: last.ResultingTR},
		host: host, journal: journal, local: local, wf: f, limits: limits, executor: executor,
	}
}

// Replicas that cannot serve a record while their global archive stream limit is reached must not fail the
// restore: it backs off and completes once they answer, and everything it retains is still verified.
func TestArchiveRestoreRetriesWhileReplicasAreSaturated(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, 7, FetchRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: 20 * time.Second})
	require.NoError(t, fx.restore.Restore(context.Background()))
	require.Greater(t, fx.host.calls.Load(), int64(7), "the restore must have retried past the saturated attempts")
	require.EqualValues(t, 5, fx.executor.head.Number)
	require.True(t, sameBlockRef(fx.executor.head, fx.executor.finalized))
	image, err := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, err)
	require.NotNil(t, image.Restored)
}

// A record that stays unavailable fails after the bounded total wait with a clear error that still
// identifies both the restore refusal and the unavailable record, and nothing unverified is retained.
func TestArchiveRestoreFailsAfterTheBoundedWaitWhenRecordsStayUnavailable(t *testing.T) {
	t.Parallel()
	const total = 300 * time.Millisecond
	fx := newRetryRestoreFixture(t, -1, FetchRetry{Initial: 5 * time.Millisecond, Max: 20 * time.Millisecond, Total: total})
	started := time.Now()
	err := fx.restore.Restore(context.Background())
	elapsed := time.Since(started)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRestore)
	require.ErrorIs(t, err, archive.ErrUnavailable)
	require.False(t, errors.Is(err, context.DeadlineExceeded))
	require.ErrorContains(t, err, "attempts over")
	require.GreaterOrEqual(t, elapsed, total, "the restore must wait out the bounded total before giving up")
	require.Less(t, elapsed, 10*time.Second, "the wait must stay bounded")
	require.Greater(t, fx.host.calls.Load(), int64(2), "it must have retried, not failed on the first refusal")
	image, loadErr := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, loadErr)
	require.Nil(t, image.Restored, "a failed restore must not leave a restore pin")
	require.Empty(t, image.Observations)
	require.EqualValues(t, 0, fx.executor.head.Number, "the EL head must stay at the checked genesis")
}

// Cancelling the context ends the wait immediately instead of sleeping out the budget.
func TestArchiveRestoreRetryStopsOnContextCancel(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, -1, FetchRetry{Initial: 5 * time.Millisecond, Max: 20 * time.Millisecond, Total: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := fx.restore.Restore(ctx)
	require.Error(t, err)
	require.Less(t, time.Since(started), 5*time.Second)
	require.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled), "got %v", err)
}
