package shardnode

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"
)

/*
Block pacing (bft-core#1167): a per-node, best-effort minimum interval between the blocks this
validator takes part in.

Without it the shard runs one block per certification round trip: a certificate arrives, the leader
builds on it at once, the followers verify, and the root chain certifies the result in its next
round. On the testnet that is one EVM block every 1.6 to 2 s, empty or not. The pacer only ever
DELAYS: the leader does not start building a round's block until the interval has passed since it
started the previous one, and a follower extends its wait for the leader's block by the same
remainder, measured from when it received the previous one. Nothing else changes:

  - the block, its timestamp, the input record and what a follower verifies are exactly what they
    would have been had the leader built the block late for any other reason, so the interval is not
    part of validity and no peer, root or replay checks it;
  - a certificate re-delivery that re-sends an answered authorization does not pass through here;
  - a node with no previous block in this process (startup, restore) does not delay.

The pacer's reference is local and monotonic, so it needs no clock agreement between validators. The
root chain still applies T2 to the shard: while the leader waits nothing is submitted, so T2 must
cover the interval (see CheckBlockInterval) or the root chain times the round out and issues repeat
certificates instead of blocks.
*/
type blockPacer struct {
	interval time.Duration
	// from is when the previous block this node took part in started: the leader's build start, or
	// the moment a follower received the leader's block. Zero until the first one.
	from time.Time
}

// remaining is how much longer a round starting at now waits before its block is built.
func (p *blockPacer) remaining(now time.Time) time.Duration {
	if p.interval <= 0 || p.from.IsZero() {
		return 0
	}
	if d := p.from.Add(p.interval).Sub(now); d > 0 {
		return d
	}
	return 0
}

// mark records that a block started at t. A clock reading earlier than the last mark is ignored.
func (p *blockPacer) mark(t time.Time) {
	if t.After(p.from) {
		p.from = t
	}
}

// SetBlockInterval sets the target minimum interval between this node's blocks; zero (the default)
// disables pacing. See blockPacer. Call before Run.
func (r *Round) SetBlockInterval(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d < 0 {
		d = 0
	}
	r.pacer.interval = d
}

// paceLeader holds the leader until the block interval has passed since its previous block. A repeat
// UC of the certificate being handled ends the wait early with errAwaitSuperseded (the authorization
// was replaced; the repeat is handled next), and a cancelled context ends it with the context's error.
func (r *Round) paceLeader(ctx context.Context, held *types.UnicityCertificate, round uint64) error {
	d := r.pacer.remaining(time.Now())
	if d <= 0 {
		return nil
	}
	if r.log != nil {
		r.log.LogAttrs(ctx, slog.LevelDebug, "round: pacing the leader's build to the block interval",
			slog.Uint64("round", round), slog.Duration("delay", d), slog.Duration("interval", r.pacer.interval))
	}
	waitCtx, cut := context.WithCancelCause(ctx)
	defer cut(nil)
	if watch := r.watchSupersession; watch != nil {
		defer watch(held, func() { cut(errAwaitSuperseded) })()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-waitCtx.Done():
		if cause := context.Cause(waitCtx); cause == errAwaitSuperseded {
			return errAwaitSuperseded
		}
		return fmt.Errorf("pacing round %d: %w", round, waitCtx.Err())
	}
}

// MinT2ForBlockInterval is the smallest shard T2 under which a block interval keeps the shard
// certifying blocks rather than timing out rounds. With pacing, no request reaches the root chain for
// up to the interval after a certificate, and a follower whose leader is silent waits that long plus
// its await budget (AwaitTimeoutForT2, itself derived from T2) before it abstains. Both must end before
// the root chain's T2 repeat certificate, with one root round to spare; otherwise every paced round
// becomes a timeout and a follower consumes certificates more slowly than they arrive.
//
// That is T2 >= interval + min(T2/2, DefaultAwaitTimeout) + rootBlockRate, solved for T2.
func MinT2ForBlockInterval(interval, rootBlockRate time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	if t2 := 2 * (interval + rootBlockRate); t2/2 <= DefaultAwaitTimeout {
		return t2
	}
	return interval + DefaultAwaitTimeout + rootBlockRate
}

// CheckBlockInterval refuses a block interval the shard's T2 cannot accommodate. Zero always passes.
func CheckBlockInterval(interval, t2, rootBlockRate time.Duration) error {
	if interval < 0 {
		return fmt.Errorf("block interval %s is negative", interval)
	}
	if interval == 0 {
		return nil
	}
	if need := MinT2ForBlockInterval(interval, rootBlockRate); t2 < need {
		return fmt.Errorf("block interval %s needs a shard T2 of at least %s (the interval, the follower await budget and one root round of %s), but T2 is %s",
			interval, need, rootBlockRate, t2)
	}
	return nil
}

// InactivityWarnMargin is the least headroom CheckInactivityMargin accepts between a paced node's longest healthy wait for a certificate and
// its inactivity re-handshake.
const InactivityWarnMargin = 10 * time.Second

// CheckInactivityMargin warns (it is advice, not a refusal) when a block interval brings the longest healthy gap between certificates
// close to the client's inactivity timeout: the interval, the follower's await budget and one root round. Past the timeout a healthy node
// re-handshakes with the roots for nothing (BFTClient's heartbeat); no block is rejected. Zero intervals and timeouts are not checked.
func CheckInactivityMargin(interval, t2, rootBlockRate, inactivity time.Duration) error {
	if interval <= 0 || inactivity <= 0 {
		return nil
	}
	gap := interval + AwaitTimeoutForT2(t2) + rootBlockRate
	if margin := inactivity - gap; margin < InactivityWarnMargin {
		return fmt.Errorf("block interval %s: a healthy gap between certificates reaches %s (the interval, the follower await budget and one root round), %s below the %s inactivity timeout; a slower round makes the node re-handshake",
			interval, gap, margin, inactivity)
	}
	return nil
}
