package archivewiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

// A replica at its global stream limit says so by name. The refusal used to reach the client as a bare stream reset, which it could
// not tell from a broken connection.
func TestABusyReplicaNamesItsRefusal(t *testing.T) {
	f := newWiringFixture(t, 2)
	replica := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	writer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	reader := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	writer.Network().Peerstore().AddAddrs(replica.ID(), replica.MultiAddresses(), peerstore.PermanentAddrTTL)
	reader.Network().Peerstore().AddAddrs(replica.ID(), replica.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	q0, rec0, err := FromJournal(context.Background(), f.context, f.subject, nil, f.entries[0])
	require.NoError(t, err)
	require.NoError(t, store.Put(q0, rec0))
	q1, rec1, err := FromJournal(context.Background(), f.context, f.subject, nil, f.entries[1])
	require.NoError(t, err)

	// the replica's one slot is held by a put whose verification is in progress
	entered, release := make(chan struct{}), make(chan struct{})
	verify := func(context.Context, archive.Request, *archive.Record) error {
		close(entered)
		<-release
		return nil
	}
	limits := Limits{Deadline: 10 * time.Second, Pending: 1, PerPeer: 1}
	server, err := NewServer(store, f.subject, verify, []peer.ID{writer.ID(), reader.ID()}, limits)
	require.NoError(t, err)
	server.Register(context.Background(), replica)
	putDone := make(chan error, 1)
	go func() { putDone <- PutAndReadBack(context.Background(), writer, replica.ID(), q1, rec1, limits) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the put never reached the replica")
	}

	_, err = Fetch(context.Background(), reader, replica.ID(), q0, limits)
	require.ErrorIs(t, err, ErrPendingLimit, "the refusal names the limit")
	var reset *StreamResetError
	require.ErrorAs(t, err, &reset)
	require.Equal(t, replica.ID(), reset.Peer)
	require.True(t, replicaBusy(err), "and the restore treats it as a busy replica")
	require.NotErrorIs(t, err, ErrTransport, "not as a transport failure")

	close(release)
	require.NoError(t, <-putDone)
	got, err := Fetch(context.Background(), reader, replica.ID(), q0, limits)
	require.NoError(t, err, "with the slot free the same fetch is served")
	require.Equal(t, rec0.Header, got.Header)
}

// The restore waits a short, flat time after a busy refusal and keeps its doubling backoff for every other failure. Busy refusals
// do not advance the doubling.
func TestRestoreWaitsBrieflyForABusyReplicaAndBacksOffForOtherFailures(t *testing.T) {
	busyErr := &StreamResetError{Peer: "replica", Operation: "fetch", Reason: ErrPendingLimit}
	otherErr := errors.Join(ErrTransport, errors.New("connection refused"))
	run := func(policy FetchRetry, failures []error) (time.Duration, int) {
		r := &ArchiveRestore{Retry: policy}
		tries := 0
		start := time.Now()
		err := r.retryFetch(context.Background(), "a record", func() (bool, error) {
			tries++
			if tries <= len(failures) {
				return true, failures[tries-1]
			}
			return false, nil
		})
		require.NoError(t, err)
		return time.Since(start), tries
	}
	repeat := func(err error, n int) []error {
		out := make([]error, n)
		for i := range out {
			out[i] = err
		}
		return out
	}
	policy := FetchRetry{Initial: 40 * time.Millisecond, Max: 2 * time.Second, Total: time.Minute, Busy: 2 * time.Millisecond}

	// thirty busy refusals: thirty flat waits of 2 ms. Doubling from 40 ms would have waited 40+80+160+... = far more than 10 s.
	elapsed, tries := run(policy, repeat(busyErr, 30))
	require.Equal(t, 31, tries)
	require.Less(t, elapsed, time.Second, "a busy replica is asked again after the flat wait")
	require.GreaterOrEqual(t, elapsed, 30*policy.Busy-time.Millisecond, "but not without waiting at all")

	// three other failures: 40 + 80 + 160 ms
	elapsed, _ = run(policy, repeat(otherErr, 3))
	require.GreaterOrEqual(t, elapsed, 280*time.Millisecond-time.Millisecond, "other failures double the wait")

	// busy refusals in between do not advance the doubling: the one other failure after them still waits Initial, not more
	elapsed, _ = run(policy, append(repeat(busyErr, 10), otherErr))
	require.GreaterOrEqual(t, elapsed, policy.Initial)
	require.Less(t, elapsed, policy.Initial+10*policy.Busy+250*time.Millisecond, "40 ms plus ten flat waits, not a doubled wait")

	// a per-peer limit is the same kind of refusal; a zero Busy means the default
	require.True(t, replicaBusy(&StreamResetError{Reason: ErrPeerLimit}))
	require.False(t, replicaBusy(otherErr))
	require.Equal(t, DefaultFetchRetry.Busy, FetchRetry{Initial: time.Second}.busy())
}
