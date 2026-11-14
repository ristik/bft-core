package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The timed exact re-send (#1032). A request a lagging or restarting root dropped, or one lost on the way, is otherwise recovered only by the
// duplicate-triggered re-send (resubmitPending), which needs the roots to answer with the held certificate, or by T2. The timed re-send puts
// the SAME signed bytes on the wire again after ResendInterval plus a jitter without progress. It is the contract #1033 deferred:
//
//   - owned: an attempt is created and published as c.outstanding BEFORE its first send (beginAttemptLocked), with the held certificate and
//     the generation captured together under c.mu, and every send of it, the first included, is admitted against it (currentAttempt). A
//     send's completion only ever updates that same attempt while it is still current; a superseded one is dropped, never re-stamped;
//   - immutable: the signed request is frozen at creation, as its canonical encoding (wire); every send decodes a private copy of those exact
//     bytes, so nothing the caller does to its request afterwards reaches the wire. The certificate, root-epoch origin and generation are
//     fixed too; only the send counters change, under c.mu;
//   - generation-bound: c.attemptGen advances on every adopted certificate (progress or a repeat, on both adoption paths) and on an installed
//     configuration of a new shard epoch (an assignment change, published together with the invalidation under c.mu). An attempt of an older
//     generation is never sent again, by either re-send trigger (resendPending is their one admission), and is checked again immediately
//     before the network send (sendRequest's final admission). A Round retry of an attempt that was superseded during its first send stops;
//   - role-bound (phase 1's role lease): the attempt keeps the role token it was produced under, every send of it, both re-send triggers and
//     the first send alike, is admitted last under that token (sendRequest), and the end of the role drops exactly that attempt (ErrFollower is
//     never pending). Through its attemptHandle, a request whose attempt ended with its role is refused for good: a later role, a
//     re-promotion included, never revives or re-creates it;
//   - cancelled on activation (and, through sendRequest, on whatever final checks a build adds): every send is admitted last against the
//     attempt's root-epoch origin (#1036), and an attempt built before the installed root activation is cancelled. As in #1051's policy, a send
//     admitted before an activation or an invalidation may still complete: the network queues an admitted write asynchronously. The roots
//     refuse such a request (storage.ErrRequestBeforeActivation); the client keeps an honest shard from starting one;
//   - a failed first send: the attempt stays pending, so the timer sends it, unless the send was refused for good (neverPending) or the
//     attempt was superseded meanwhile. Repeated Submits of the same logical attempt (Round's retries of the same signed request on the same
//     certificate and generation) keep the attempt and its retry budget.
//
// It is due once both the attempt's last send and the last delivery (deliveryClock) are older than the interval, the send plus its jitter: the
// first paces the re-sends, the second is the stall the UC relay also reads. The re-sends of both kinds count toward MaxResubmits. The roots
// take a byte-identical request as idempotent (rootchain.Node.countRequest).
const (
	// DefaultResendInterval is the base of the timed re-send's delay (see BFTClientOptions.ResendInterval).
	DefaultResendInterval = 1500 * time.Millisecond
	// resendCheckEvery is how often Run looks for an attempt due for a timed re-send.
	resendCheckEvery = 250 * time.Millisecond
)

// deliveryClock is when the client last adopted a new certificate, a repeat included, never an invalid or duplicate one. It is the narrow part
// of follower-phase2's progress clock (UsefulProgress.Delivered, #1054) that the timed re-send consumes: that clock satisfies it, so the
// re-send and the UC relay read one definition of a stalled delivery. The re-send is due only once delivery is stalled for the interval.
type deliveryClock interface{ Delivered() time.Time }

// lastDelivery is the client's own deliveryClock until #1054's progress clock replaces it (deliveries): noteAdoptedLocked stamps it on both
// adoption paths. Zero is "nothing delivered yet", which is stalled.
type lastDelivery struct{ at atomic.Int64 }

func (d *lastDelivery) stamp(t time.Time) { d.at.Store(t.UnixNano()) }

func (d *lastDelivery) Delivered() time.Time {
	if n := d.at.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// deliveries is the clock the timed re-send reads.
func (c *BFTClient) deliveries() deliveryClock { return &c.delivered }

// errAttemptSuperseded refuses the send of an attempt that is no longer the current one of the current generation.
var errAttemptSuperseded = errors.New("shardnode: the pending attempt was superseded before its send")

// neverPending reports whether a send failed in a way that makes the request unsendable for good: it is not kept as the pending attempt, and
// Round does not retry it.
func neverPending(err error) bool {
	return errors.Is(err, ErrRequestAcrossActivation) || errors.Is(err, errAttemptSuperseded) || errors.Is(err, ErrFollower)
}

// resendInterval is the configured base of the timed re-send, or a negative value when it is disabled.
func (c *BFTClient) resendInterval() time.Duration {
	if d := c.opts.ResendInterval; d != 0 {
		return d
	}
	return DefaultResendInterval
}

// resendJitter draws the random part of a timed re-send's delay: up to half the interval, so that the validators of a shard, which all submit
// on the same certificate, do not re-send in step.
func (c *BFTClient) resendJitter() time.Duration {
	d := c.resendInterval()
	if d <= 1 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d / 2)))
}

// maxResubmits is the bound on the re-sends of one attempt, or a negative value when re-sending is disabled.
func (c *BFTClient) maxResubmits() int {
	if c.opts.MaxResubmits == 0 {
		return DefaultMaxResubmits
	}
	return c.opts.MaxResubmits
}

// freeze is the canonical encoding of req, checked to decode back to exactly those bytes: what every send of the attempt puts on the wire.
func freeze(req *certification.BlockCertificationRequest) ([]byte, error) {
	if req == nil {
		return nil, errors.New("shardnode: no certification request")
	}
	wire, err := types.Cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding the certification request: %w", err)
	}
	back, err := thaw(wire)
	if err != nil {
		return nil, err
	}
	if again, err := types.Cbor.Marshal(back); err != nil || !bytes.Equal(again, wire) {
		return nil, errors.New("shardnode: the certification request has no canonical encoding")
	}
	return wire, nil
}

// thaw decodes a private copy of a frozen request.
func thaw(wire []byte) (*certification.BlockCertificationRequest, error) {
	var req certification.BlockCertificationRequest
	if err := types.Cbor.Unmarshal(wire, &req); err != nil {
		return nil, fmt.Errorf("decoding the frozen certification request: %w", err)
	}
	return &req, nil
}

// beginAttemptLocked is the owned attempt of req on luc, bound to the root-epoch origin of the certificate that authorised it, to the role
// token it was produced under (token, bound: phase 1's role lease, Round.sendUnder) and to the current generation, published as c.outstanding
// before anything is sent. The same logical attempt again (Round's retry: the same bytes on the same certificate and origin, under the same
// token, in the same generation) is the current attempt, kept with its retry budget. c.mu must be held.
func (c *BFTClient) beginAttemptLocked(req *certification.BlockCertificationRequest, luc *types.UnicityCertificate, origin uint64, token uint64, bound bool,
	now time.Time) (*outstandingRequest, error) {
	wire, err := freeze(req)
	if err != nil {
		return nil, err
	}
	on := deliveryAttempt{partitionRound: luc.GetRoundNumber(), rootRound: luc.GetRootRoundNumber()}
	if o := c.outstanding; o != nil && o.gen == c.attemptGen && o.on == on && o.rootEpoch == origin && o.token == token && o.bound == bound &&
		bytes.Equal(o.wire, wire) {
		return o, nil
	}
	o := &outstandingRequest{wire: wire, on: on, gen: c.attemptGen, jitter: c.resendJitter(), firstSent: now, lastSent: now, rootEpoch: origin,
		token: token, bound: bound}
	if o.req, err = thaw(wire); err != nil {
		return nil, err
	}
	c.outstanding = o
	return o, nil
}

// newAttemptLocked is beginAttemptLocked for a caller that knows its request encodes (tests): it panics otherwise.
func (c *BFTClient) newAttemptLocked(req *certification.BlockCertificationRequest, luc *types.UnicityCertificate, origin uint64, now time.Time) *outstandingRequest {
	c.outstanding = nil
	o, err := c.beginAttemptLocked(req, luc, origin, 0, false, now)
	if err != nil {
		panic(err)
	}
	return o
}

// attemptHandle is one request's hold on its attempt across every Submit of it: Round makes one per completed round (completedRound.handle)
// and binds it to each send of that round's request, its retries and a re-delivery's re-send alike (withAttemptHandle). The first Submit
// through a handle binds the attempt it publishes; every later Submit through it is admitted only while that attempt is still the current
// one of its generation. An invalidated attempt therefore stays refused for that request, even when the pending pointer is already gone (a
// timer, an assignment change): an invalidated retry never becomes a fresh attempt in a later generation. Its fields are under c.mu.
type attemptHandle struct{ o *outstandingRequest }

type attemptHandleKey struct{}

// withAttemptHandle binds the Submits under ctx to h.
func withAttemptHandle(ctx context.Context, h *attemptHandle) context.Context {
	if h == nil {
		return ctx
	}
	return context.WithValue(ctx, attemptHandleKey{}, h)
}

func attemptHandleOf(ctx context.Context) *attemptHandle {
	h, _ := ctx.Value(attemptHandleKey{}).(*attemptHandle)
	return h
}

// submitAttemptLocked is Submit's attempt: the one its handle already holds while that is still current (the same logical attempt keeps its
// budget), errAttemptSuperseded once that attempt was invalidated, and otherwise a new owned attempt bound to the handle. c.mu must be held.
func (c *BFTClient) submitAttemptLocked(ctx context.Context, req *certification.BlockCertificationRequest, luc *types.UnicityCertificate, origin uint64,
	now time.Time) (*outstandingRequest, error) {
	h := attemptHandleOf(ctx)
	if h != nil && h.o != nil && !c.currentLocked(h.o) {
		return nil, fmt.Errorf("%w: the attempt of this request was invalidated (generation %d, now %d)", errAttemptSuperseded, h.o.gen, c.attemptGen)
	}
	token, bound := roleTokenOf(ctx)
	o, err := c.beginAttemptLocked(req, luc, origin, token, bound, now)
	if err != nil {
		return nil, err
	}
	if h != nil {
		h.o = o
	}
	return o, nil
}

// roleEndedLocked reports whether the role o was produced under has ended (a retirement, a revocation or a new publication of the role): o is
// then never sent again, and a later role, a re-promotion included, never revives it. An attempt bound to no token (a caller that binds none)
// is judged by sendRequest's follower check alone. c.mu must be held.
func (c *BFTClient) roleEndedLocked(o *outstandingRequest) bool {
	return o.bound && !c.role.Load().admits(o.token)
}

// currentLocked reports whether o is still the client's attempt, in the current generation. c.mu must be held.
func (c *BFTClient) currentLocked(o *outstandingRequest) bool {
	return c.outstanding == o && c.attemptGen == o.gen
}

// currentAttempt is the final admission of a send of attempt o: nil only while o is still the client's attempt in its own generation.
func (c *BFTClient) currentAttempt(o *outstandingRequest) func() error {
	return func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.currentLocked(o) {
			return errAttemptSuperseded
		}
		return nil
	}
}

// sendAttempt sends a private copy of o's frozen bytes to the roots selected from held, under o's own role token, admitted last against that
// token (sendRequest's role check), its origin and its currency. Both re-send triggers and the first send go through it.
func (c *BFTClient) sendAttempt(ctx context.Context, o *outstandingRequest, held *types.UnicityCertificate) error {
	msg, err := thaw(o.wire)
	if err != nil {
		return err
	}
	if o.bound {
		ctx = withRoleToken(ctx, o.token) // a re-send stays bound to the role the request was produced under
	}
	return c.sendRequest(ctx, msg, held, o.rootEpoch, c.currentAttempt(o))
}

// settleLocked applies the outcome of a send of o: an attempt refused for good, or no longer current, is dropped if it is still the published
// one; nothing else of it changes. It reports whether o is still the current attempt. c.mu must be held.
func (c *BFTClient) settleLocked(ctx context.Context, o *outstandingRequest, err error) bool {
	switch {
	case errors.Is(err, ErrRequestAcrossActivation):
		if c.outstanding == o {
			c.cancelAcrossActivationLocked(ctx, o)
		}
		return false
	case !c.currentLocked(o) || neverPending(err) || c.roleEndedLocked(o):
		// superseded, refused for good (ErrFollower among them), or its role ended meanwhile: only this attempt is dropped
		if c.outstanding == o {
			c.outstanding = nil
		}
		return false
	}
	return true
}

// firstSend is Submit's send of the attempt it published, and its completion: a sent request refills the subscription, a send that failed
// keeps the attempt pending only while it is still current.
func (c *BFTClient) firstSend(ctx context.Context, o *outstandingRequest, held *types.UnicityCertificate) error {
	err := c.sendAttempt(ctx, o, held)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		// A submitted request refills this node's subscription at the root chain, so nothing else needs to ask for one this round.
		c.submittedSinceHandshake = true
	}
	current := c.settleLocked(ctx, o, err)
	if current && err == nil {
		o.lastSent = time.Now()
	}
	if err != nil && !current && !neverPending(err) {
		// invalidated while its send failed: never re-stamped, and Round does not retry it under a later generation
		err = errors.Join(err, errAttemptSuperseded)
	}
	return err
}

// resendPending is the one admission, send and cancellation of both re-send triggers: the current attempt, of the current generation, still
// pending on held (the certificate held now, when held is nil), within its budget and due by the trigger's own pacing, is sent again, its
// frozen bytes, to the roots selected from held. An attempt of an older generation, or one built before the installed root activation, is
// dropped instead.
func (c *BFTClient) resendPending(ctx context.Context, held *types.UnicityCertificate, trigger string, now time.Time, due func(*outstandingRequest) bool) {
	limit := c.maxResubmits()
	if limit < 0 {
		return
	}
	// an early sample only spares a doomed re-send; the admission that counts is sendRequest's, immediately before the network send
	installed, knows := c.installedRootEpoch()
	c.mu.Lock()
	o := c.outstanding
	if held == nil {
		held = c.luc
	}
	if o == nil || held == nil {
		c.mu.Unlock()
		return
	}
	if knows && installed > o.rootEpoch {
		c.cancelAcrossActivationLocked(ctx, o)
		c.mu.Unlock()
		return
	}
	if o.gen != c.attemptGen || c.roleEndedLocked(o) {
		c.outstanding = nil // invalidated by progress, an assignment change or the end of its role: never re-sent
		c.mu.Unlock()
		return
	}
	if o.on != (deliveryAttempt{partitionRound: held.GetRoundNumber(), rootRound: held.GetRootRoundNumber()}) || o.resent >= limit || !due(o) {
		c.mu.Unlock()
		return
	}
	o.resent++
	o.lastSent, o.jitter = now, c.resendJitter()
	attempt := o.resent
	c.mu.Unlock()

	err := c.sendAttempt(ctx, o, held)
	c.mu.Lock()
	c.settleLocked(ctx, o, err)
	c.mu.Unlock()
	switch {
	case err == nil:
		if c.log != nil {
			c.log.InfoContext(ctx, "certification request still outstanding, re-sent unchanged", slog.String("trigger", trigger),
				slog.Uint64("round", o.req.InputRecord.RoundNumber), slog.Int("attempt", attempt), slog.Uint64("heldRootRound", held.GetRootRoundNumber()))
		}
	case errors.Is(err, ErrRequestAcrossActivation), errors.Is(err, errAttemptSuperseded), errors.Is(err, ErrFollower):
		// cancelled (activation, the end of its role), or superseded during the send's preparation: nothing was sent
	default:
		if c.log != nil {
			c.log.WarnContext(ctx, "re-sending the pending certification request failed", slog.String("trigger", trigger), slog.Int("attempt", attempt),
				slog.String("err", err.Error()))
		}
	}
}

// resendStale is the timed re-send: due once both the attempt's last send (plus its jitter) and the last delivery are older than the interval.
func (c *BFTClient) resendStale(ctx context.Context, now time.Time) {
	every := c.resendInterval()
	if every < 0 {
		return
	}
	c.resendPending(ctx, nil, "timer", now, func(o *outstandingRequest) bool {
		return now.Sub(o.lastSent) >= every+o.jitter && now.Sub(c.deliveries().Delivered()) >= every
	})
}
