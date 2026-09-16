package parentwitness

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type lifecycleOpener struct {
	started     chan struct{}
	release     chan struct{}
	honorCancel bool
	mu          sync.Mutex
	calls       int
	releaseOnce sync.Once
}

func (o *lifecycleOpener) CreateStream(ctx context.Context, _ peer.ID, _ string) (libp2pnetwork.Stream, error) {
	o.mu.Lock()
	o.calls++
	o.mu.Unlock()
	select {
	case o.started <- struct{}{}:
	default:
	}
	if o.honorCancel {
		select {
		case <-o.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	} else {
		<-o.release
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("released")
}

func (o *lifecycleOpener) count() int { o.mu.Lock(); defer o.mu.Unlock(); return o.calls }

func (o *lifecycleOpener) unblock() { o.releaseOnce.Do(func() { close(o.release) }) }

func lifecycleWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle barrier timed out")
	}
}

type waiterContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *waiterContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func lifecycleBudget() RequesterBudget {
	return RequesterBudget{MaxAttempts: 2, MaxProviders: 2, Overall: time.Second, PerAttempt: time.Second, MaxDownloadedBytes: 1024, Backoff: time.Hour}
}

func lifecycleRequester(t *testing.T, o StreamOpener, providers []peer.ID) (*Requester, Target, Target) {
	t.Helper()
	c, first := fixtureTarget(t)
	second, err := NewTarget(TargetConfig{NetworkID: first.Request().Context.NetworkID, PartitionID: first.Request().Context.PartitionID, ShardID: first.Request().Context.ShardID, FullShardConfHash: first.Request().Context.FullShardConfHash, Registry: first.registry, BlockHash: c.Blocks[2].Hash})
	require.NoError(t, err)
	r, err := NewRequester(context.Background(), RequesterConfig{Opener: o, Providers: providers, Budget: lifecycleBudget()})
	require.NoError(t, err)
	t.Cleanup(func() {
		if blocked, ok := o.(*lifecycleOpener); ok {
			blocked.unblock()
		}
		r.Close()
	})
	return r, first, second
}

func TestRequesterLifecycleCoalescesWaiterAndOwnerCancellationJoins(t *testing.T) {
	o := &lifecycleOpener{started: make(chan struct{}, 2), release: make(chan struct{}), honorCancel: true}
	r, target, _ := lifecycleRequester(t, o, []peer.ID{"a"})
	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	ownerDone := make(chan RequesterResult, 1)
	go func() { got, _ := r.Request(ownerCtx, target); ownerDone <- got }()
	lifecycleWait(t, o.started)
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	trackedWaiter := &waiterContext{Context: waiterCtx, entered: make(chan struct{})}
	waiterDone := make(chan RequesterResult, 1)
	go func() { got, _ := r.Request(trackedWaiter, target); waiterDone <- got }()
	lifecycleWait(t, trackedWaiter.entered)
	cancelWaiter()
	select {
	case got := <-waiterDone:
		require.Equal(t, RequesterStopped, got.Outcome)
	case <-time.After(time.Second):
		t.Fatal("coalesced waiter did not stop")
	}
	require.Equal(t, 1, o.count())
	cancelOwner()
	select {
	case got := <-ownerDone:
		require.Equal(t, RequesterStopped, got.Outcome)
	case <-time.After(time.Second):
		t.Fatal("owner did not join cancellation")
	}
	r.Close()
}

func TestRequesterLifecycleSupersessionBackoffAndCanceledChanger(t *testing.T) {
	o := &lifecycleOpener{started: make(chan struct{}, 2), release: make(chan struct{}), honorCancel: true}
	r, first, second := lifecycleRequester(t, o, []peer.ID{"a"})
	ownerDone := make(chan RequesterResult, 1)
	go func() { got, _ := r.Request(context.Background(), first); ownerDone <- got }()
	lifecycleWait(t, o.started)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := r.Request(canceled, second)
	require.Error(t, err)
	require.Equal(t, RequesterStopped, got.Outcome)
	require.Equal(t, 1, o.count())
	changerDone := make(chan RequesterResult, 1)
	go func() { got, _ := r.Request(context.Background(), second); changerDone <- got }()
	select {
	case got := <-ownerDone:
		require.Equal(t, RequesterSuperseded, got.Outcome)
	case <-time.After(time.Second):
		t.Fatal("owner was not superseded")
	}
	select {
	case got := <-changerDone:
		require.Equal(t, RequesterBudgetExhausted, got.Outcome)
	case <-time.After(time.Second):
		t.Fatal("superseding request did not observe backoff")
	}
	require.Equal(t, 1, o.count())
	r.Close()
}

func TestRequesterLifecycleConcurrentCloseJoinsBlockedOpener(t *testing.T) {
	o := &lifecycleOpener{started: make(chan struct{}, 1), release: make(chan struct{}), honorCancel: false}
	r, target, _ := lifecycleRequester(t, o, []peer.ID{"a"})
	requestDone := make(chan struct{})
	go func() { _, _ = r.Request(context.Background(), target); close(requestDone) }()
	lifecycleWait(t, o.started)
	closeDone := make(chan struct{}, 2)
	go func() { r.Close(); closeDone <- struct{}{} }()
	go func() { r.Close(); closeDone <- struct{}{} }()
	select {
	case <-closeDone:
		t.Fatal("Close returned before blocked opener released")
	case <-time.After(20 * time.Millisecond):
	}
	o.unblock()
	for range 2 {
		select {
		case <-closeDone:
		case <-time.After(time.Second):
			t.Fatal("concurrent Close did not join")
		}
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not finish after Close")
	}
}
