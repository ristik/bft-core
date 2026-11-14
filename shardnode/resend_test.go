package shardnode

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// flakyNet fails the first `fail` sends, then records every request like swallowingNet.
type flakyNet struct {
	swallowingNet
	mu   sync.Mutex
	fail int
}

func (n *flakyNet) Send(ctx context.Context, msg any, to ...peer.ID) error {
	n.mu.Lock()
	if n.fail > 0 {
		n.fail--
		n.mu.Unlock()
		return errors.New("stream reset")
	}
	n.mu.Unlock()
	return n.swallowingNet.Send(ctx, msg, to...)
}

// timedClient is a client of the conf-binding fixture holding ucMine, with a timed re-send interval the test controls and the duplicate-triggered
// re-send effectively off (its minimum interval is an hour), so that every re-send seen here is a timed one.
func timedClient(t *testing.T, opts BFTClientOptions) (*confBindingFixture, *BFTClient, *swallowingNet, *atomic.Uint64) {
	t.Helper()
	f := newConfBindingFixture(t)
	if opts.ResendInterval == 0 {
		opts.ResendInterval = 100 * time.Millisecond
	}
	if opts.ResubmitMinInterval == 0 {
		opts.ResubmitMinInterval = time.Hour
	}
	c, net := resubmitClient(t, f, opts)
	var installed atomic.Uint64
	installed.Store(f.ucMine.GetRootEpoch())
	c.trustBaseStore = epochTrustStore{TrustBaseStore: c.trustBaseStore, installed: &installed}
	require.NoError(t, c.handleCertificationResponse(context.Background(), f.respond(f.ucMine)))
	return f, c, net, &installed
}

// due is a moment past any timed re-send's delay (interval plus at most half of it of jitter) after the attempt's last send.
func due(c *BFTClient) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.outstanding.lastSent.Add(c.resendInterval()*3/2 + time.Millisecond)
}

func sameBytes(t *testing.T, want *certification.BlockCertificationRequest, sent []*certification.BlockCertificationRequest) {
	t.Helper()
	w, err := types.Cbor.Marshal(want)
	require.NoError(t, err)
	for i, s := range sent {
		g, err := types.Cbor.Marshal(s)
		require.NoError(t, err)
		require.True(t, bytes.Equal(w, g), "send %d carries the signed bytes unchanged", i)
	}
}

// The timed re-send puts the same signed bytes on the wire again once the interval and its jitter have passed without progress, not before,
// and at most MaxResubmits times.
func TestTheTimedResendSendsTheSameBytesWhenDueAndBounded(t *testing.T) {
	ctx := context.Background()
	f, c, net, _ := timedClient(t, BFTClientOptions{MaxResubmits: 3})
	req := pendingRequest(f)
	require.NoError(t, c.Submit(ctx, req))
	require.Len(t, net.sent(), 1)

	c.mu.Lock()
	early := c.outstanding.lastSent.Add(c.resendInterval() - time.Millisecond)
	c.mu.Unlock()
	c.resendStale(ctx, early)
	require.Len(t, net.sent(), 1, "not before the interval")

	for i := 0; i < 6; i++ {
		c.resendStale(ctx, due(c))
	}
	require.Len(t, net.sent(), 1+3, "MaxResubmits bounds the timed re-sends")
	sameBytes(t, req, net.sent())

	_, c2, net2, _ := timedClient(t, BFTClientOptions{ResendInterval: -1})
	require.NoError(t, c2.Submit(ctx, pendingRequest(f)))
	c2.resendStale(ctx, time.Now().Add(time.Hour))
	require.Len(t, net2.sent(), 1, "a negative interval disables the timed re-send")
}

// Progress (any adopted certificate: here a repeat at a later root round) ends the attempt's generation: it is never re-sent.
func TestTheTimedResendStopsOnProgress(t *testing.T) {
	ctx := context.Background()
	f, c, net, _ := timedClient(t, BFTClientOptions{})
	require.NoError(t, c.Submit(ctx, pendingRequest(f)))
	when := due(c)

	c.mu.Lock()
	later := *c.luc
	seal := *later.UnicitySeal
	seal.RootChainRoundNumber++
	later.UnicitySeal = &seal
	c.luc = &later
	c.noteAdoptedLocked(UCRepeat) // what both adoption paths do with an adopted certificate
	c.mu.Unlock()

	c.resendStale(ctx, when)
	require.Len(t, net.sent(), 1, "the attempt of an earlier certificate is not re-sent")

	// the generation alone is enough: the same held certificate, adopted again after a failed apply, still ends the attempt
	require.NoError(t, c.Submit(ctx, pendingRequest(f)))
	c.mu.Lock()
	c.noteAdoptedLocked(UCValid)
	c.mu.Unlock()
	c.resendStale(ctx, due(c))
	require.Len(t, net.sent(), 2, "only the second Submit's own send")
}

// An installed root activation cancels the attempt (it was built on a certificate of the closed epoch, #1036); a new shard epoch's configuration
// (an assignment change) ends its generation. A configuration installed again, unchanged, does not.
func TestTheTimedResendStopsOnActivationAndAssignmentChange(t *testing.T) {
	ctx := context.Background()
	t.Run("activation", func(t *testing.T) {
		f, c, net, installed := timedClient(t, BFTClientOptions{})
		require.NoError(t, c.Submit(ctx, pendingRequest(f)))
		installed.Add(1)
		c.resendStale(ctx, due2(c))
		require.Len(t, net.sent(), 1)
		c.mu.Lock()
		require.Nil(t, c.outstanding, "cancelled, never re-sent across the activation")
		c.mu.Unlock()
	})
	t.Run("assignment change", func(t *testing.T) {
		f, c, net, _ := timedClient(t, BFTClientOptions{})
		require.NoError(t, c.Submit(ctx, pendingRequest(f)))
		when := due(c)
		require.NoError(t, c.InstallShardConf(0, f.confMine), "the genesis configuration again: not a change")
		c.resendStale(ctx, when)
		require.Len(t, net.sent(), 2, "an unchanged configuration keeps the attempt")
		when = due(c)
		require.NoError(t, c.InstallShardConf(7, f.confOther))
		c.resendStale(ctx, when)
		require.Len(t, net.sent(), 2, "a new shard epoch's configuration ends the attempt")
	})
}

// due2 is due for a client whose attempt may be gone already.
func due2(c *BFTClient) time.Time {
	c.mu.Lock()
	o := c.outstanding
	c.mu.Unlock()
	if o == nil {
		return time.Now()
	}
	return due(c)
}

// A failed first send is still the pending attempt: Submit reports the failure, and the timer sends the request later. A first send refused
// across an activation is never pending.
func TestTheTimedResendCoversAFailedFirstSend(t *testing.T) {
	ctx := context.Background()
	f, c, _, installed := timedClient(t, BFTClientOptions{})
	net := &flakyNet{fail: 1}
	c.net = net
	req := pendingRequest(f)
	require.Error(t, c.Submit(ctx, req), "the first send failed")
	require.Empty(t, net.sent())
	c.resendStale(ctx, due(c))
	require.Len(t, net.sent(), 1, "the timer delivered it")
	sameBytes(t, req, net.sent())

	installed.Add(1)
	c.mu.Lock()
	c.outstanding = nil
	c.mu.Unlock()
	require.ErrorIs(t, c.Submit(withRequestOrigin(ctx, installed.Load()-1), pendingRequest(f)), ErrRequestAcrossActivation)
	c.mu.Lock()
	require.Nil(t, c.outstanding, "a request refused across an activation is never pending")
	c.mu.Unlock()
}

// supersedingStore runs hook inside the trust-base lookup of a send: the event lands after the timed re-send's own checks and before the request
// leaves.
type supersedingStore struct {
	epochTrustStore
	hook func()
}

func (s supersedingStore) GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	if s.hook != nil {
		s.hook()
	}
	return s.TrustBaseStore.GetByEpoch(ctx, epoch)
}

// The generation is checked again immediately before the network send: progress, a new attempt or an activation that lands while the timed
// re-send is being prepared stops it.
func TestTheTimedResendIsAdmittedLastAgainstItsGenerationAndOrigin(t *testing.T) {
	ctx := context.Background()
	for name, event := range map[string]func(c *BFTClient, installed *atomic.Uint64){
		"progress": func(c *BFTClient, _ *atomic.Uint64) { c.mu.Lock(); c.noteAdoptedLocked(UCValid); c.mu.Unlock() },
		"a new attempt": func(c *BFTClient, _ *atomic.Uint64) {
			c.mu.Lock()
			c.outstanding = c.newAttemptLocked(c.outstanding.req, c.luc, c.outstanding.rootEpoch, time.Now())
			c.mu.Unlock()
		},
		"an activation": func(_ *BFTClient, installed *atomic.Uint64) { installed.Add(1) },
	} {
		t.Run(name, func(t *testing.T) {
			f, c, net, installed := timedClient(t, BFTClientOptions{})
			require.NoError(t, c.Submit(ctx, pendingRequest(f)))
			var once atomic.Bool
			store := c.trustBaseStore.(epochTrustStore)
			c.trustBaseStore = supersedingStore{epochTrustStore: store, hook: func() {
				if once.CompareAndSwap(false, true) {
					event(c, installed)
				}
			}}
			c.resendStale(ctx, due(c))
			require.Len(t, net.sent(), 1, "nothing left after %s", name)
		})
	}
}

// Run drives the timer: a pending request whose root did not answer is sent again by the client loop alone.
func TestRunResendsAPendingRequestOnItsTimer(t *testing.T) {
	f, c, net, _ := timedClient(t, BFTClientOptions{ResendInterval: 50 * time.Millisecond})
	c.opts.HeartbeatInterval, c.opts.InactivityTimeout, c.opts.HandshakeNodes = time.Hour, time.Hour, 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.Submit(ctx, pendingRequest(f)))
	c.mu.Lock()
	o := c.outstanding
	c.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	require.Eventually(t, func() bool {
		select {
		case err := <-done:
			t.Fatalf("Run returned: %v", err)
		default:
		}
		return len(net.sent()) >= 2
	}, 5*time.Second, 10*time.Millisecond)
	c.mu.Lock()
	require.Same(t, o, c.outstanding, "the same attempt, re-sent")
	c.mu.Unlock()
}

// The re-send is due only once delivery has stalled for the interval, by the same clock the UC relay reads: a delivery recorded without
// ending the attempt (as a relay-fed clock may) postpones it.
func TestTheTimedResendWaitsForAStalledDelivery(t *testing.T) {
	ctx := context.Background()
	f, c, net, _ := timedClient(t, BFTClientOptions{})
	require.NoError(t, c.Submit(ctx, pendingRequest(f)))
	when := due(c)
	c.delivered.stamp(when.Add(-c.resendInterval() / 2))
	c.resendStale(ctx, when)
	require.Len(t, net.sent(), 1, "delivery is not stalled for the interval yet")
	c.resendStale(ctx, when.Add(c.resendInterval()))
	require.Len(t, net.sent(), 2, "once it is, the attempt is re-sent")
}
