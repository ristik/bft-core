package shardnode

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

/*
FinalityGate serializes every executor operation that can change what the executor considers
canonical or final.

WHY IT EXISTS AS ITS OWN THING. Until recovery was wired, one lock did this job by accident:
`Round.mu` is held across `HandleCertificate`, and every finality-changing call happened inside it.
That was never a statement about finality — it is a round lock — and it stopped being sufficient the
moment a second thing could commit. `TargetApplier` (§6.4) commits an evidence-verified block, and
whether it happens to be driven from inside a round is a wiring decision that can change; the
executor's answer to "what is canonical" must not depend on that decision being remembered.

WHAT MUST HOLD IT. Every call that makes the executor treat a block as canonical or final:

  - `Commit`, wherever it is issued from — the round's own commit of what it just certified,
    reconcile's recovery commit, and the applier's;
  - `Build`, because starting a block sets head, safe and finalized on its parent before any
    payload exists.

Standalone reads (`Head`, `GenesisBlock`) and `Verify` do not acquire the gate: `newPayload` tells the
executor about a block without making it canonical. A head read used to confirm a commit or decide
certified-record publication stays inside that operation's gate. A validator's per-round Verify
must not queue behind a recovery commit.

WHY BOTH FLAVOURS OF ACQUISITION. The round MUST proceed, so it waits (with its context). The
applier must NOT wait: it is called from a round loop and its whole contract is to make one bounded
attempt and answer, so it takes the gate only if it is free and reports being turned away otherwise.
Retrying is what the next certificate is for.
*/
type FinalityGate struct {
	mu sync.Mutex // guards the fields below

	held   bool
	holder string
	since  time.Time
	// waiting is how many callers are parked on the gate. It is a diagnostic — a queue that only
	// grows is what a stuck executor looks like from here — and it is what lets a fixture establish
	// that every waiter really is waiting before the holder releases.
	waiting int
	// ready is closed and replaced on each release, so waiters learn about it without polling.
	ready chan struct{}

	now func() time.Time
}

// ErrFinalityBusy is reported to a caller that will not wait for the gate.
var ErrFinalityBusy = errors.New("shardnode: another finality-changing executor operation is in progress")

func NewFinalityGate() *FinalityGate {
	return &FinalityGate{ready: make(chan struct{}), now: time.Now}
}

/*
Hold waits for the gate, or for ctx to end, and returns its idempotent release. It is for a decision outside
this package that must not interleave with a commit or a build: publishing the certified record for the
executor's current head (#14 W2) reads the head and commits the store transaction while holding it. Hold it only
for local, bounded work; a network acquisition or signature verification does not belong inside.
*/
func (g *FinalityGate) Hold(ctx context.Context, who string) (func(), error) {
	return g.acquire(ctx, who)
}

// acquire waits for the gate, or for the context to end. The returned release is idempotent.
func (g *FinalityGate) acquire(ctx context.Context, who string) (func(), error) {
	for {
		g.mu.Lock()
		if !g.held {
			return g.takeLocked(who), nil
		}
		holder, since, ready := g.holder, g.since, g.ready
		g.waiting++
		g.mu.Unlock()

		select {
		case <-ready:
			// Someone released it; go round again — another waiter may have taken it first.
			g.mu.Lock()
			g.waiting--
			g.mu.Unlock()
		case <-ctx.Done():
			g.mu.Lock()
			g.waiting--
			g.mu.Unlock()
			return nil, fmt.Errorf("%w: %q has held it for %s: %w",
				ErrFinalityBusy, holder, g.now().Sub(since).Round(time.Millisecond), ctx.Err())
		}
	}
}

// tryAcquire takes the gate only if it is free. It never blocks, so a caller that must answer
// promptly — the applier, called from a round loop — can report being turned away instead of
// parking behind whatever is inside the executor.
func (g *FinalityGate) tryAcquire(who string) (func(), error) {
	g.mu.Lock()
	if g.held {
		holder, since := g.holder, g.since
		g.mu.Unlock()
		return nil, fmt.Errorf("%w: %q has held it for %s",
			ErrFinalityBusy, holder, g.now().Sub(since).Round(time.Millisecond))
	}
	return g.takeLocked(who), nil
}

// takeLocked is called with g.mu held and releases it.
func (g *FinalityGate) takeLocked(who string) func() {
	g.held, g.holder, g.since = true, who, g.now()
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.held, g.holder = false, ""
			// Wake EVERY waiter and install a fresh channel for the next holder.
			//
			// Closing rather than sending is deliberate and is the standard broadcast: a send wakes
			// one, and a waiter that has been counted but has not yet reached its select is not
			// there to receive it — a lost wakeup that leaves it parked with nothing left to wake
			// it. That interleaving is not reproducible by any fixture here without a hook inside
			// acquire, so it is stated rather than asserted: the fixtures below establish that
			// every waiter is woken, not that this particular race is closed.
			close(g.ready)
			g.ready = make(chan struct{})
			g.mu.Unlock()
		})
	}
}

// Waiting is how many callers are parked on the gate.
func (g *FinalityGate) Waiting() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.waiting
}

// Holder reports who holds the gate and for how long, for diagnostics and for tests that need to
// assert the state rather than infer it from a later effect.
func (g *FinalityGate) Holder() (string, time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.held {
		return "", 0, false
	}
	return g.holder, g.now().Sub(g.since), true
}
