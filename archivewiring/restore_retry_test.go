package archivewiring

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/unicitynetwork/bft-go-base/types"
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
	return newRetryRestoreFixtureT(t, failures, retry, false)
}

func newRetryRestoreFixtureT(t *testing.T, failures int64, retry FetchRetry, tamper bool) *retryRestoreFixture {
	return buildRetryRestoreFixture(t, failures, retry, tamper, nil)
}

// buildRetryRestoreFixture is the fixture with, optionally, replicas whose peer authorizer refuses the next *refusals requests
// (decremented per request) before admitting the restoring node: the real server-side refusal of a retained validator that has not
// installed the assignment step yet, which reaches the client as a reset frame carrying ErrPeerNotAllowed.
func buildRetryRestoreFixture(t *testing.T, failures int64, retry FetchRetry, tamper bool, refusals *atomic.Int64) *retryRestoreFixture {
	var mutate func(*wiringFixture, *types.UnicityCertificate)
	if tamper {
		mutate = func(_ *wiringFixture, uc *types.UnicityCertificate) { uc.InputRecord.Hash[0] ^= 1 }
	}
	return buildRetryRestoreFixtureMutating(t, failures, retry, mutate, refusals)
}

// buildRetryRestoreFixtureMutating serves every archived record from both replicas with its resulting UC altered by mutate (nil
// serves them unchanged); the pinned tip stays the genuine certificate.
func buildRetryRestoreFixtureMutating(t *testing.T, failures int64, retry FetchRetry, mutate func(*wiringFixture, *types.UnicityCertificate), refusals *atomic.Int64) *retryRestoreFixture {
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
			if mutate != nil {
				var uc types.UnicityCertificate
				require.NoError(t, types.Cbor.Unmarshal(rec.ResultingUC, &uc))
				mutate(f, &uc)
				rec.ResultingUC, err = types.Cbor.Marshal(&uc)
				require.NoError(t, err)
			}
			require.NoError(t, store.Put(q, rec))
		}
		server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		if refusals != nil {
			server.SetPeerAuthorizer(func(peer.ID) bool { return refusals.Add(-1) < 0 })
		}
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

func TestArchiveRestoreVerificationFailureIsNotRetried(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixtureT(t, 0, FetchRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: time.Hour}, true)
	started := time.Now()
	err := fx.restore.Restore(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRestore)
	require.Less(t, time.Since(started), 3*time.Second)
	require.Less(t, fx.host.calls.Load(), int64(8))
	image, loadErr := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, loadErr)
	require.Nil(t, image.Restored)
}

// A joiner whose restore reaches a retained validator before that validator has installed the assignment step is refused with
// ErrPeerNotAllowed (a reset frame from the replica's peer authorizer). The restore retries that refusal with bounded backoff and
// completes once the replicas admit it.
func TestArchiveRestoreRetriesWhileReplicasHaveNotAdmittedThisNodeYet(t *testing.T) {
	t.Parallel()
	var refusals atomic.Int64
	refusals.Store(6)
	fx := buildRetryRestoreFixture(t, 0, FetchRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: 20 * time.Second}, false, &refusals)
	require.NoError(t, fx.restore.Restore(context.Background()))
	require.Less(t, refusals.Load(), int64(0), "the replicas refused first and then admitted the node")
	require.EqualValues(t, 5, fx.executor.head.Number)
}

// If no replica ever admits it, the restore ends after the bounded wait and says why: the final error names the restore refusal,
// the unavailable record AND the replicas' refusal, all reachable with errors.Is.
func TestArchiveRestoreEndsWithAClearErrorWhenNoReplicaEverAdmitsThisNode(t *testing.T) {
	t.Parallel()
	var refusals atomic.Int64
	refusals.Store(1 << 40)
	fx := buildRetryRestoreFixture(t, 0, FetchRetry{Initial: 5 * time.Millisecond, Max: 20 * time.Millisecond, Total: 300 * time.Millisecond}, false, &refusals)
	started := time.Now()
	err := fx.restore.Restore(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRestore)
	require.ErrorIs(t, err, archive.ErrUnavailable)
	require.ErrorIs(t, err, ErrPeerNotAllowed, "the final error says the replicas refused this node, not just that a record was missing")
	require.ErrorContains(t, err, "refusing this node")
	require.GreaterOrEqual(t, time.Since(started), 300*time.Millisecond)
	require.Less(t, time.Since(started), 10*time.Second)
	image, loadErr := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, loadErr)
	require.Nil(t, image.Restored, "nothing is retained from a refused restore")
}

// A restore whose context ends during an attempt used to return the replica's failure alone: transientFetchError answers false once the
// context is done, so retryFetch returned the attempt's error and errors.Is(err, context.Canceled/DeadlineExceeded) did not hold
// (TestArchiveRestoreRetryStopsOnContextCancel failed once under load). Cancellation is now always visible, with the replica failure
// kept for diagnosis; a non-transient failure on a live context is returned as before.
func TestRetryFetchKeepsTheContextCauseWhenTheContextEndsDuringAnAttempt(t *testing.T) {
	r := &ArchiveRestore{Retry: FetchRetry{Initial: time.Millisecond, Max: 2 * time.Millisecond, Total: time.Hour}}
	replica := errors.Join(ErrPendingLimit, errors.New("replica saturated"))
	for _, tc := range []struct {
		name  string
		setup func() (context.Context, func())
		cause error
	}{
		{"cancelled", func() (context.Context, func()) {
			ctx, cancel := context.WithCancel(context.Background())
			return ctx, cancel
		}, context.Canceled},
		{"deadline exceeded", func() (context.Context, func()) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			return ctx, func() { time.Sleep(60 * time.Millisecond); cancel() }
		}, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, end := tc.setup()
			defer end()
			err := r.retryFetch(ctx, "record", func() (bool, error) {
				end() // the context ends while the replica fetch is in flight, which then fails
				return transientFetchError(ctx, replica), replica
			})
			require.ErrorIs(t, err, tc.cause)
			require.ErrorIs(t, err, ErrPendingLimit, "the replica failure is kept")
			require.NotErrorIs(t, err, archive.ErrUnavailable, "this is a stop, not an exhausted wait")
		})
	}
	t.Run("a non-transient failure on a live context is returned unchanged", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		bad := fmt.Errorf("%w: forged", archive.ErrInvalid)
		err := r.retryFetch(ctx, "record", func() (bool, error) { return transientFetchError(ctx, bad), bad })
		require.ErrorIs(t, err, archive.ErrInvalid)
		require.NotErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, context.DeadlineExceeded)
	})
}
