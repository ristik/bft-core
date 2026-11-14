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

// sameBytes checks that every send carried exactly the first send's encoding, as the network serialized each one when it was sent.
func sameBytes(t *testing.T, net *swallowingNet) {
	t.Helper()
	wire := net.sentWire()
	require.NotEmpty(t, wire)
	for i, w := range wire {
		require.True(t, bytes.Equal(wire[0], w), "send %d carries the first send's bytes", i)
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
	sameBytes(t, net)
	want, err := types.Cbor.Marshal(req)
	require.NoError(t, err)
	require.Equal(t, want, net.sentWire()[0], "the signed request as Submit got it")

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
	want, err := types.Cbor.Marshal(req)
	require.NoError(t, err)
	require.Equal(t, want, net.sentWire()[0])

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

// hookNet runs hook inside the first send it is asked for (after the client's final admission), then fails that send or not.
type hookNet struct {
	swallowingNet
	mu   sync.Mutex
	hook func()
	fail bool
}

func (n *hookNet) Send(ctx context.Context, msg any, to ...peer.ID) error {
	n.mu.Lock()
	hook, fail := n.hook, n.fail
	n.hook, n.fail = nil, false
	n.mu.Unlock()
	if hook != nil {
		hook()
		if fail {
			return errors.New("stream reset")
		}
	}
	return n.swallowingNet.Send(ctx, msg, to...)
}

// An assignment change installed while the first send is under way ends the attempt: whether it lands before the final admission (nothing
// is sent) or during a write that then fails, the attempt is never re-stamped as current, the timer never sends it and Round does not retry it.
func TestAnAssignmentChangeDuringTheFirstSendEndsTheAttempt(t *testing.T) {
	ctx := context.Background()
	t.Run("before the final admission", func(t *testing.T) {
		f, c, net, _ := timedClient(t, BFTClientOptions{})
		store := c.trustBaseStore.(epochTrustStore)
		var once atomic.Bool
		c.trustBaseStore = supersedingStore{epochTrustStore: store, hook: func() {
			if once.CompareAndSwap(false, true) {
				require.NoError(t, c.InstallShardConf(7, f.confOther))
			}
		}}
		err := c.Submit(ctx, pendingRequest(f))
		require.ErrorIs(t, err, errAttemptSuperseded)
		require.True(t, neverPending(err), "Round does not retry it")
		c.resendStale(ctx, time.Now().Add(time.Hour))
		require.Empty(t, net.sent())
	})
	t.Run("during a failed write", func(t *testing.T) {
		f, c, _, _ := timedClient(t, BFTClientOptions{})
		net := &hookNet{fail: true}
		net.hook = func() { require.NoError(t, c.InstallShardConf(7, f.confOther)) }
		c.net = net
		err := c.Submit(ctx, pendingRequest(f))
		require.Error(t, err)
		require.True(t, neverPending(err), "invalidated while it failed: Round does not retry it")
		c.mu.Lock()
		require.Nil(t, c.outstanding, "not kept pending under the new generation")
		c.mu.Unlock()
		c.resendStale(ctx, time.Now().Add(time.Hour))
		require.Empty(t, net.sent(), "the timer never sends it")
	})
}

// An older Submit that completes after a newer one never replaces it: the first send is admitted against its own attempt, and its completion
// updates only that attempt while it is still the published one.
func TestALateFirstSendNeverReplacesANewerAttempt(t *testing.T) {
	ctx := context.Background()
	newer := func(f *confBindingFixture) *certification.BlockCertificationRequest {
		r := pendingRequest(f)
		r.InputRecord.Hash = bytes.Repeat([]byte{7}, 32)
		return r
	}
	t.Run("the newer one lands before the older one's admission", func(t *testing.T) {
		f, c, net, _ := timedClient(t, BFTClientOptions{})
		store := c.trustBaseStore.(epochTrustStore)
		var once atomic.Bool
		c.trustBaseStore = supersedingStore{epochTrustStore: store, hook: func() {
			if once.CompareAndSwap(false, true) {
				require.NoError(t, c.Submit(ctx, newer(f)))
			}
		}}
		require.ErrorIs(t, c.Submit(ctx, pendingRequest(f)), errAttemptSuperseded)
		require.Len(t, net.sent(), 1, "only the newer one left")
		c.mu.Lock()
		require.True(t, bytes.Equal(c.outstanding.req.InputRecord.Hash, newer(f).InputRecord.Hash), "the newer attempt is the pending one")
		c.mu.Unlock()
	})
	t.Run("the newer one lands during the older one's failing write", func(t *testing.T) {
		f, c, _, _ := timedClient(t, BFTClientOptions{})
		net := &hookNet{fail: true}
		net.hook = func() { require.NoError(t, c.Submit(ctx, newer(f))) }
		c.net = net
		require.Error(t, c.Submit(ctx, pendingRequest(f)))
		c.mu.Lock()
		o := c.outstanding
		c.mu.Unlock()
		require.NotNil(t, o)
		require.True(t, bytes.Equal(o.req.InputRecord.Hash, newer(f).InputRecord.Hash), "the older completion left the newer attempt alone")
		c.resendStale(ctx, due(c))
		require.Len(t, net.sent(), 2, "the newer request's send and its timed re-send")
		require.True(t, bytes.Equal(net.sentWire()[0], net.sentWire()[1]))
	})
}

// The duplicate-triggered re-send has the timed one's admission: an attempt whose generation an assignment change ended is never re-sent on a
// duplicate of the held certificate either.
func TestTheDuplicateTriggerRespectsTheGeneration(t *testing.T) {
	ctx := context.Background()
	f, c, net, _ := timedClient(t, BFTClientOptions{ResubmitMinInterval: time.Millisecond, ResendInterval: -1})
	require.NoError(t, c.Submit(ctx, pendingRequest(f)))
	time.Sleep(3 * time.Millisecond)
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	require.Len(t, net.sent(), 2, "control: a duplicate re-sends the pending request")
	require.NoError(t, c.InstallShardConf(7, f.confOther))
	time.Sleep(3 * time.Millisecond)
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	require.Len(t, net.sent(), 2, "not after the assignment change")
	c.mu.Lock()
	require.Nil(t, c.outstanding)
	c.mu.Unlock()
}

// The attempt owns its bytes: changing the caller's request after Submit changes nothing any later send puts on the wire, on either trigger.
func TestTheAttemptOwnsItsSignedBytes(t *testing.T) {
	ctx := context.Background()
	f, c, net, _ := timedClient(t, BFTClientOptions{ResubmitMinInterval: time.Millisecond})
	req := pendingRequest(f)
	require.NoError(t, c.Submit(ctx, req))
	first := net.sentWire()[0]
	req.InputRecord.RoundNumber++
	req.InputRecord.Hash = bytes.Repeat([]byte{9}, 32)
	req.Signature = []byte("other")
	time.Sleep(3 * time.Millisecond)
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	c.resendStale(ctx, due(c))
	require.Len(t, net.sent(), 3, "the first send, a duplicate-triggered and a timed re-send")
	for i, w := range net.sentWire() {
		require.True(t, bytes.Equal(first, w), "send %d is the first send's bytes", i)
	}
}

// Round's retries of the same signed request on the same certificate are the same logical attempt: it keeps its retry budget.
func TestARepeatedSubmitKeepsTheAttemptAndItsBudget(t *testing.T) {
	ctx := context.Background()
	f, c, net, _ := timedClient(t, BFTClientOptions{MaxResubmits: 2})
	req := pendingRequest(f)
	require.NoError(t, c.Submit(ctx, req))
	c.mu.Lock()
	o := c.outstanding
	c.mu.Unlock()
	c.resendStale(ctx, due(c))
	require.NoError(t, c.Submit(ctx, pendingRequest(f)), "Round's retry: the same bytes again")
	c.mu.Lock()
	require.Same(t, o, c.outstanding, "the same attempt")
	require.Equal(t, 1, o.resent, "its budget is kept")
	c.mu.Unlock()
	for i := 0; i < 4; i++ {
		c.resendStale(ctx, due(c))
	}
	require.Len(t, net.sent(), 1+1+1+1, "first send, one timed re-send, the retry's send, the last re-send of the budget")
	sameBytes(t, net)
}

// afterFirstSubmit is the client as Round's submitter, running after once the first Submit has returned: an event between two Submits of
// the same request.
type afterFirstSubmit struct {
	c     *BFTClient
	calls int
	after func()
}

func (s *afterFirstSubmit) Submit(ctx context.Context, req *certification.BlockCertificationRequest) error {
	err := s.c.Submit(ctx, req)
	s.calls++
	if s.calls == 1 && s.after != nil {
		s.after()
	}
	return err
}

// Between two Submits of one request (Round's retry after a failed first send, or a re-delivery's re-send): an attempt invalidated in between
// stays refused for that request through its handle, even once a timer has removed the pending pointer. It never becomes a fresh attempt in
// the later generation.
func TestAnAttemptInvalidatedBetweenSubmitsIsNeverRetriedAsANewOne(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		event       func(f *confBindingFixture, c *BFTClient)
		sent, calls int
	}{
		"control: nothing in between, the retry is sent": {nil, 1, 2},
		"an assignment change in between":                {func(f *confBindingFixture, c *BFTClient) { require.NoError(t, c.InstallShardConf(7, f.confOther)) }, 0, 2},
		"an assignment change, then the timer dropped the attempt": {func(f *confBindingFixture, c *BFTClient) {
			require.NoError(t, c.InstallShardConf(7, f.confOther))
			c.resendStale(ctx, time.Now().Add(time.Hour))
			c.mu.Lock()
			require.Nil(t, c.outstanding, "premise: the pending pointer is gone")
			c.mu.Unlock()
		}, 0, 2},
		"progress in between": {func(_ *confBindingFixture, c *BFTClient) { c.mu.Lock(); c.noteAdoptedLocked(UCValid); c.mu.Unlock() }, 0, 2},
	} {
		t.Run(name, func(t *testing.T) {
			f, c, _, _ := timedClient(t, BFTClientOptions{})
			net := &flakyNet{fail: 1}
			c.net = net
			w := &afterFirstSubmit{c: c}
			if tc.event != nil {
				w.after = func() { tc.event(f, c) }
			}
			r := &Round{submitter: w}
			err := r.send(withAttemptHandle(ctx, &attemptHandle{}), f.ucMine, pendingRequest(f), 5)
			require.Equal(t, tc.calls, w.calls, "Round retried once and stopped")
			require.Len(t, net.sent(), tc.sent)
			if tc.sent == 0 {
				require.ErrorIs(t, err, errAttemptSuperseded)
				c.resendStale(ctx, time.Now().Add(time.Hour))
				require.Empty(t, net.sent(), "and the timer never sends it")
				c.mu.Lock()
				require.Nil(t, c.outstanding, "no fresh attempt was published")
				c.mu.Unlock()
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("a re-delivery's re-send after an assignment change", func(t *testing.T) {
		f, c, net, _ := timedClient(t, BFTClientOptions{})
		r := &Round{submitter: c}
		h := &attemptHandle{} // the completed round's handle, kept for its re-deliveries
		req := pendingRequest(f)
		require.NoError(t, r.send(withAttemptHandle(ctx, h), f.ucMine, req, 5))
		require.Len(t, net.sent(), 1)
		require.NoError(t, r.send(withAttemptHandle(ctx, h), f.ucMine, req, 5), "control: re-sent within its generation")
		require.Len(t, net.sent(), 2)
		require.NoError(t, c.InstallShardConf(7, f.confOther))
		require.ErrorIs(t, r.send(withAttemptHandle(ctx, h), f.ucMine, req, 5), errAttemptSuperseded)
		require.Len(t, net.sent(), 2, "the request of the invalidated attempt is never sent again")
	})
}

// roleClient is timedClient with phase 1's role lease: active under token 1. bound is a context of a request produced under token 1, with
// its own attempt handle (one Round request).
func roleClient(t *testing.T, opts BFTClientOptions) (*confBindingFixture, *BFTClient, *swallowingNet, *tokenRole, func(token uint64) context.Context) {
	t.Helper()
	f, c, net, _ := timedClient(t, opts)
	role := &tokenRole{}
	role.token.Store(1)
	role.active.Store(true)
	c.SetRole(role)
	h := &attemptHandle{}
	bound := func(token uint64) context.Context {
		return withAttemptHandle(withRoleToken(context.Background(), token), h)
	}
	return f, c, net, role, bound
}

// A retirement while the first send fails ends the attempt: it is not kept pending, the timer never sends it, Round's retry of it is refused,
// and a re-promotion, under a later token, never revives or re-creates it.
func TestARetirementDuringAFailedFirstSendEndsTheAttempt(t *testing.T) {
	f, c, _, role, bound := roleClient(t, BFTClientOptions{})
	net := &hookNet{fail: true}
	net.hook = func() { role.active.Store(false) }
	c.net = net
	req := pendingRequest(f)
	err := c.Submit(bound(1), req)
	require.Error(t, err)
	require.True(t, neverPending(err), "Round does not retry it")
	c.mu.Lock()
	require.Nil(t, c.outstanding, "not kept pending under the ended role")
	c.mu.Unlock()
	c.resendStale(context.Background(), time.Now().Add(time.Hour))
	require.ErrorIs(t, c.Submit(bound(1), req), errAttemptSuperseded, "Round's retry is refused")

	role.token.Store(2)
	role.active.Store(true) // re-promoted, without any certificate progress
	c.resendStale(context.Background(), time.Now().Add(time.Hour))
	require.ErrorIs(t, c.Submit(bound(1), req), errAttemptSuperseded, "not revived after the re-promotion")
	require.ErrorIs(t, c.Submit(bound(2), req), errAttemptSuperseded, "nor re-created under the later token")
	require.Empty(t, net.sent())
}

// A retirement and a re-promotion without any certificate progress: the attempt of the ended role is dropped by the next trigger, and neither
// trigger nor Round's re-send of the request sends it under the later role.
func TestARetirementAndRepromotionWithoutProgressNeverReviveTheAttempt(t *testing.T) {
	ctx := context.Background()
	for _, trigger := range []string{"timer", "duplicate"} {
		t.Run(trigger, func(t *testing.T) {
			f, c, net, role, bound := roleClient(t, BFTClientOptions{ResubmitMinInterval: time.Millisecond})
			req := pendingRequest(f)
			require.NoError(t, c.Submit(bound(1), req))
			require.Len(t, net.sent(), 1)
			role.active.Store(false)
			role.token.Store(2)
			role.active.Store(true) // retired and re-promoted before any trigger looked
			fire := func() {
				if trigger == "timer" {
					c.resendStale(ctx, due2(c))
					return
				}
				time.Sleep(3 * time.Millisecond)
				require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
			}
			fire()
			require.Len(t, net.sent(), 1, "the attempt of the ended role is never re-sent")
			c.mu.Lock()
			require.Nil(t, c.outstanding, "it is dropped")
			c.mu.Unlock()
			fire()
			require.ErrorIs(t, c.Submit(bound(1), req), errAttemptSuperseded, "Round's re-send under the old token is refused")
			require.ErrorIs(t, c.Submit(bound(2), req), errAttemptSuperseded, "and the request is never re-created under the new one")
			require.Len(t, net.sent(), 1)
		})
	}
}

// Both triggers check the attempt's own token: after a role change, an attempt of the earlier token is dropped and not sent, while a new
// request of the new role (another Round request, its own handle) is sent and re-sent normally. Only the matching attempt is cancelled.
func TestBothTriggersAdmitOnlyUnderTheAttemptsRole(t *testing.T) {
	ctx := context.Background()
	for _, trigger := range []string{"timer", "duplicate"} {
		t.Run(trigger, func(t *testing.T) {
			f, c, net, role, bound := roleClient(t, BFTClientOptions{ResubmitMinInterval: time.Millisecond})
			fire := func() {
				if trigger == "timer" {
					c.resendStale(ctx, due2(c))
					return
				}
				time.Sleep(3 * time.Millisecond)
				require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
			}
			require.NoError(t, c.Submit(bound(1), pendingRequest(f)))
			role.token.Store(2) // a new publication of the role: still active, another token
			fire()
			require.Len(t, net.sent(), 1, "not re-sent under the new token")

			newer := pendingRequest(f)
			newer.InputRecord.Hash = bytes.Repeat([]byte{5}, 32)
			ctx2 := withAttemptHandle(withRoleToken(ctx, 2), &attemptHandle{})
			require.NoError(t, c.Submit(ctx2, newer))
			fire()
			require.Len(t, net.sent(), 3, "the new role's own request is sent and re-sent")
			require.True(t, bytes.Equal(net.sentWire()[1], net.sentWire()[2]))
		})
	}
}
