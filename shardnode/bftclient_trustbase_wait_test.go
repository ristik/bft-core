package shardnode

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/q3install"
)

// errIncomplete is what a trust store answers while its installation of the epoch is incomplete (q3active.ErrNotActive wraps the sentinel).
var errIncomplete = fmt.Errorf("q3active: activation is not installed: %w", q3install.ErrIncomplete)

// flakyTrustStore serves no trust base for its first `missing` lookups, as a node's trust store does until its own installation of the
// epoch completes.
type flakyTrustStore struct {
	tb      *types.RootTrustBaseV1
	missing int32
	calls   atomic.Int32
	err     error
}

func (s *flakyTrustStore) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	if s.calls.Add(1) <= s.missing {
		return nil, s.err
	}
	return s.tb, nil
}

func shortTrustBaseWait(t *testing.T, wait time.Duration) {
	t.Helper()
	oldWait, oldRetry := initialHandshakeTrustBaseWait, initialHandshakeTrustBaseRetry
	initialHandshakeTrustBaseWait, initialHandshakeTrustBaseRetry = wait, 5*time.Millisecond
	t.Cleanup(func() { initialHandshakeTrustBaseWait, initialHandshakeTrustBaseRetry = oldWait, oldRetry })
}

func newTrustWaitClient(t *testing.T, f *confBindingFixture, store TrustBaseStore) (*BFTClient, *lateRootNet, *firstUCDriver) {
	t.Helper()
	net := &lateRootNet{received: make(chan any, 4), response: f.respond(f.ucMine)}
	net.ready = true
	driver := &firstUCDriver{got: make(chan struct{})}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		store, driver, nil, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: time.Hour})
	require.NoError(t, err)
	return client, net, driver
}

// A node restarting into an epoch whose installation is still completing must wait for the trust base, not exit (#748).
func TestInitialHandshakeWaitsForTheTrustBaseOfItsEpoch(t *testing.T) {
	shortTrustBaseWait(t, 5*time.Second)
	f := newConfBindingFixture(t)
	store := &flakyTrustStore{tb: f.tb, missing: 5, err: errIncomplete}
	client, _, driver := newTrustWaitClient(t, f, store)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(cancel)
	select {
	case <-driver.got:
	case err := <-done:
		t.Fatalf("the client exited while the trust base was still being installed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("no certificate after the trust base became available")
	}
	require.Greater(t, store.calls.Load(), int32(5), "the handshake asked again after each refusal")
}

// A trust base that never arrives still ends the start, with the cause, after the wait.
func TestInitialHandshakeGivesUpWhenTheTrustBaseNeverArrives(t *testing.T) {
	shortTrustBaseWait(t, 50*time.Millisecond)
	cause := errIncomplete
	client, net, _ := newTrustWaitClient(t, newConfBindingFixture(t), &flakyTrustStore{missing: 1 << 30, err: cause})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Run(ctx)
	require.ErrorContains(t, err, "initial handshake")
	require.ErrorIs(t, err, cause)
	net.mu.Lock()
	defer net.mu.Unlock()
	require.Zero(t, net.handshakes, "no handshake was sent without a trust base")
}

// Only an incomplete installation is waited for: a trust store that fails any other way ends the start at once, not after the wait.
func TestInitialHandshakeDoesNotWaitForOtherTrustBaseErrors(t *testing.T) {
	shortTrustBaseWait(t, time.Minute)
	cause := errors.New("trust store: database closed")
	store := &flakyTrustStore{missing: 1 << 30, err: cause}
	client, net, _ := newTrustWaitClient(t, newConfBindingFixture(t), store)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Run(ctx)
	require.ErrorIs(t, err, cause)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, int32(1), store.calls.Load(), "asked once, not retried")
	net.mu.Lock()
	defer net.mu.Unlock()
	require.Zero(t, net.handshakes)
}
