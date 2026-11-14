package shardnode

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The timed exact re-send (#1032). A request a lagging or restarting root dropped, or one lost on the way, is otherwise recovered only by the
// duplicate-triggered re-send (resubmitPending), which needs the roots to answer with the held certificate, or by T2. The timed re-send puts
// the SAME signed bytes on the wire again after ResendInterval plus a jitter without progress. It is the contract #1033 deferred:
//
//   - owned: it acts only on the client's current attempt (c.outstanding, by identity), and drops it only while it is still that attempt;
//   - immutable: an attempt's request bytes, certificate, root-epoch origin and generation are fixed when it is made (newAttemptLocked) and
//     never change; only its send counters do, under c.mu;
//   - generation-bound: every event that can make the attempt wrong advances c.attemptGen (a new attempt, any adopted certificate, which
//     is progress or a repeat, and an installed shard configuration, which is an assignment change). An attempt of an older generation is
//     never sent, and the generation is checked again immediately before the network send (sendRequest's final admission);
//   - cancelled on fencing and activation: sendRequest admits every send last against the attempt's root-epoch origin (#1036); an attempt
//     built before the installed root activation is cancelled, never re-sent;
//   - a failed first send: Submit keeps the attempt even when its first send failed (except one refused across an activation), so the timer
//     sends it; Round's own short retries are not the only ones.
//
// The re-sends of both kinds count toward MaxResubmits. The roots take a byte-identical request as idempotent (rootchain.Node.countRequest).
const (
	// DefaultResendInterval is the base of the timed re-send's delay (see BFTClientOptions.ResendInterval).
	DefaultResendInterval = 1500 * time.Millisecond
	// resendCheckEvery is how often Run looks for an attempt due for a timed re-send.
	resendCheckEvery = 250 * time.Millisecond
)

// errAttemptSuperseded refuses the send of an attempt that is no longer the current one of the current generation.
var errAttemptSuperseded = errors.New("shardnode: the pending attempt was superseded before its send")

// neverPending reports whether a first send failed in a way that makes the request unsendable for good: it is not kept as the pending attempt.
func neverPending(err error) bool { return errors.Is(err, ErrRequestAcrossActivation) }

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

// newAttemptLocked makes the attempt of req on luc, bound to the root-epoch origin of the certificate that authorised it, in a new generation.
// c.mu must be held.
func (c *BFTClient) newAttemptLocked(req *certification.BlockCertificationRequest, luc *types.UnicityCertificate, origin uint64, now time.Time) *outstandingRequest {
	c.attemptGen++
	return &outstandingRequest{req: req, on: deliveryAttempt{partitionRound: luc.GetRoundNumber(), rootRound: luc.GetRootRoundNumber()}, gen: c.attemptGen,
		jitter: c.resendJitter(), firstSent: now, lastSent: now, rootEpoch: origin}
}

// currentAttempt is the final admission of a send of attempt o of generation gen: nil only while o is still the client's attempt and nothing
// advanced the generation since.
func (c *BFTClient) currentAttempt(o *outstandingRequest, gen uint64) func() error {
	return func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.outstanding != o || c.attemptGen != gen {
			return errAttemptSuperseded
		}
		return nil
	}
}

// resendStale is the timed re-send: the current attempt, still pending on the held certificate in its own generation, with no progress for
// the interval plus its jitter since its last send, is sent again, the same signed bytes, to the roots selected from the held certificate.
func (c *BFTClient) resendStale(ctx context.Context, now time.Time) {
	every, limit := c.resendInterval(), c.maxResubmits()
	if every < 0 || limit < 0 {
		return
	}
	// an early sample only spares a doomed re-send; the admission that counts is sendRequest's, immediately before the network send
	installed, knows := c.installedRootEpoch()
	c.mu.Lock()
	o, held, gen := c.outstanding, c.luc, c.attemptGen
	if o == nil || held == nil {
		c.mu.Unlock()
		return
	}
	if knows && installed > o.rootEpoch {
		c.cancelAcrossActivationLocked(ctx, o)
		c.mu.Unlock()
		return
	}
	if o.gen != gen || o.on != (deliveryAttempt{partitionRound: held.GetRoundNumber(), rootRound: held.GetRootRoundNumber()}) ||
		o.resent >= limit || now.Sub(o.lastSent) < every+o.jitter {
		c.mu.Unlock()
		return
	}
	o.resent++
	o.lastSent, o.jitter = now, c.resendJitter()
	req, origin, attempt := o.req, o.rootEpoch, o.resent
	c.mu.Unlock()

	err := c.sendRequest(ctx, req, held, origin, c.currentAttempt(o, gen))
	switch {
	case err == nil:
		if c.log != nil {
			c.log.InfoContext(ctx, "certification request still outstanding, re-sent unchanged (timed)", slog.Uint64("round", req.InputRecord.RoundNumber),
				slog.Int("attempt", attempt), slog.Uint64("heldRootRound", held.GetRootRoundNumber()))
		}
	case errors.Is(err, ErrRequestAcrossActivation):
		c.mu.Lock()
		if c.outstanding == o {
			c.cancelAcrossActivationLocked(ctx, o)
		}
		c.mu.Unlock()
	case errors.Is(err, errAttemptSuperseded):
		// progress, a new attempt or an assignment change landed during the send's preparation: nothing was sent
	default:
		if c.log != nil {
			c.log.WarnContext(ctx, "timed re-send of the pending certification request failed", slog.Int("attempt", attempt), slog.String("err", err.Error()))
		}
	}
}
