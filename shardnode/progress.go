package shardnode

import (
	"sync"
	"time"
)

// UsefulProgress is the common admission/progress clock of a shard node (phase 2). It moves only when a certificate is ADOPTED: verified,
// admitted, and new (a duplicate of the held certificate, a stale one, or one that failed verification moves nothing). Every
// "no progress" deadline of the node is measured from it, so irrelevant or invalid input can never postpone a failover:
//
//   - Delivered is when the node last adopted any new certificate, a repeat included: the roots (or a relay) are delivering. The
//     inactivity re-handshake, the UC relay backup and a timed exact resend measure their "nothing arrived" interval from it.
//   - Advanced is when the node last adopted a non-repeat certificate: the shard made progress. The pending-work diagnostics use it.
//
// Both start at the client's construction, so a node that starts into silence has an age. A timed resend (#1032, deferred to its own PR)
// consumes this interface: it re-sends the pending request's exact bytes once Delivered is older than its interval, never earlier, and
// the same clock is what the relay backup reads, so the two never disagree about whether delivery is stalled.
type UsefulProgress interface {
	Delivered() time.Time
	Advanced() time.Time
}

// progressClock is the client's UsefulProgress.
type progressClock struct {
	mu                  sync.Mutex
	delivered, advanced time.Time
	now                 func() time.Time
}

func newProgressClock(now func() time.Time) *progressClock {
	if now == nil {
		now = time.Now
	}
	t := now()
	return &progressClock{delivered: t, advanced: t, now: now}
}

// adopted records an adopted certificate: always a delivery, and an advance unless it is a repeat.
func (p *progressClock) adopted(repeat bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.now()
	p.delivered = t
	if !repeat {
		p.advanced = t
	}
}

func (p *progressClock) Delivered() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.delivered
}

func (p *progressClock) Advanced() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.advanced
}

// clock is the client's progress clock, started on first use (construction, for a client built by NewBFTClient).
func (c *BFTClient) clock() *progressClock {
	c.progressInit.Do(func() { c.progress = newProgressClock(nil) })
	return c.progress
}

// Progress is the client's common progress clock (see UsefulProgress).
func (c *BFTClient) Progress() UsefulProgress { return c.clock() }
