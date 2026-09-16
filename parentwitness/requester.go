package parentwitness

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	ErrRequesterClosed  = errors.New("parent witness requester: closed")
	ErrRequesterBackoff = errors.New("parent witness requester: backoff")
)

type RequesterOutcome uint8

const (
	RequesterVerified RequesterOutcome = iota
	RequesterUnavailable
	RequesterInvalid
	RequesterBudgetExhausted
	RequesterStopped
	RequesterSuperseded
)

type RequesterBudget struct {
	MaxAttempts        int
	MaxProviders       int
	Overall            time.Duration
	PerAttempt         time.Duration
	MaxDownloadedBytes int64
	Backoff            time.Duration
}

func (b RequesterBudget) validate() error {
	if b.MaxAttempts <= 0 || b.MaxProviders <= 0 || b.Overall <= 0 || b.PerAttempt <= 0 || b.MaxDownloadedBytes <= 0 || b.Backoff <= 0 {
		return fmt.Errorf("%w: all limits must be positive and finite", ErrTransport)
	}
	if b.Overall <= 0 || b.PerAttempt <= 0 || b.Backoff <= 0 || b.Overall > 100*365*24*time.Hour || b.PerAttempt > 100*365*24*time.Hour || b.Backoff > 100*365*24*time.Hour {
		return fmt.Errorf("%w: duration out of range", ErrTransport)
	}
	return nil
}

type RequesterConfig struct {
	Opener    StreamOpener
	Providers []peer.ID
	Budget    RequesterBudget
}

type RequesterResult struct {
	Outcome    RequesterOutcome
	Response   VerifiedResponse
	Attempts   int
	Providers  int
	Downloaded int64
	Detail     string
}

type requesterEpisode struct {
	target Target
	cancel context.CancelFunc
	done   chan struct{}
	result RequesterResult
	marked RequesterOutcome
	mu     sync.Mutex
}

func (e *requesterEpisode) mark(outcome RequesterOutcome) {
	e.mu.Lock()
	e.marked = outcome
	e.mu.Unlock()
}
func (e *requesterEpisode) markValue() RequesterOutcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.marked
}

type Requester struct {
	opener    StreamOpener
	providers []peer.ID
	budget    RequesterBudget
	ctx       context.Context
	cancel    context.CancelFunc

	mu        sync.Mutex
	closed    bool
	active    *requesterEpisode
	nextTry   time.Time
	closeDone chan struct{}
	closeOnce sync.Once
}

func NewRequester(parent context.Context, cfg RequesterConfig) (*Requester, error) {
	if parent == nil || cfg.Opener == nil || len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("%w: incomplete requester configuration", ErrTransport)
	}
	if err := cfg.Budget.validate(); err != nil {
		return nil, err
	}
	if len(cfg.Providers) > cfg.Budget.MaxProviders {
		return nil, fmt.Errorf("%w: provider list exceeds MaxProviders", ErrTransport)
	}
	providers := append([]peer.ID(nil), cfg.Providers...)
	seen := make(map[peer.ID]struct{}, len(providers))
	for _, p := range providers {
		if p == "" {
			return nil, fmt.Errorf("%w: empty provider", ErrTransport)
		}
		if _, ok := seen[p]; ok {
			return nil, fmt.Errorf("%w: duplicate provider", ErrTransport)
		}
		seen[p] = struct{}{}
	}
	ctx, cancel := context.WithCancel(parent)
	return &Requester{opener: cfg.Opener, providers: providers, budget: cfg.Budget, ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}, nil
}

// Request runs one bounded episode. The first caller owns episode cancellation; later callers
// waiting on the same target may cancel only their own wait. Calls for the same target coalesce.
// A changed target supersedes the current episode and requires an explicit new request after
// cancellation and backoff; no pending automatic restart is performed.
func (r *Requester) Request(ctx context.Context, target Target) (RequesterResult, error) {
	if ctx == nil || !target.Valid() {
		return RequesterResult{}, ErrContext
	}
	for {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return RequesterResult{Outcome: RequesterStopped, Detail: ErrRequesterClosed.Error()}, ErrRequesterClosed
		}
		if r.active != nil {
			ep := r.active
			if sameRequest(ep.target.Request(), target.Request()) {
				done := ep.done
				r.mu.Unlock()
				select {
				case <-done:
					return ep.result, nil
				case <-ctx.Done():
					return RequesterResult{Outcome: RequesterStopped, Detail: ctx.Err().Error()}, ctx.Err()
				}
			}
			ep.mark(RequesterSuperseded)
			ep.cancel()
			done := ep.done
			r.mu.Unlock()
			select {
			case <-done:
			case <-ctx.Done():
				return RequesterResult{Outcome: RequesterStopped, Detail: ctx.Err().Error()}, ctx.Err()
			}
			continue
		}
		if until := r.nextTry.Sub(time.Now()); until > 0 {
			r.mu.Unlock()
			return RequesterResult{Outcome: RequesterBudgetExhausted, Detail: ErrRequesterBackoff.Error()}, ErrRequesterBackoff
		}
		epctx, cancel := context.WithCancel(ctx)
		watchStop := make(chan struct{})
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			select {
			case <-r.ctx.Done():
				cancel()
			case <-watchStop:
			}
		}()
		ep := &requesterEpisode{target: target, cancel: cancel, done: make(chan struct{})}
		r.active = ep
		r.mu.Unlock()
		res := r.run(epctx, ep)
		close(watchStop)
		<-watchDone
		r.mu.Lock()
		if res.Outcome == RequesterVerified && (ep.markValue() != RequesterVerified || epctx.Err() != nil || r.ctx.Err() != nil || r.closed || r.active != ep) {
			if ep.markValue() == RequesterSuperseded {
				res = RequesterResult{Outcome: RequesterSuperseded, Attempts: res.Attempts, Providers: res.Providers, Downloaded: res.Downloaded, Detail: "target superseded"}
			} else {
				res = RequesterResult{Outcome: RequesterStopped, Attempts: res.Attempts, Providers: res.Providers, Downloaded: res.Downloaded, Detail: "requester stopped"}
			}
		}
		ep.result = res
		if res.Outcome != RequesterVerified {
			r.nextTry = time.Now().Add(r.budget.Backoff)
		}
		if r.active == ep {
			r.active = nil
		}
		close(ep.done)
		r.mu.Unlock()
		cancel()
		return res, nil
	}
}

func (r *Requester) run(ctx context.Context, ep *requesterEpisode) RequesterResult {
	started := time.Now()
	deadline := started.Add(r.budget.Overall)
	var out RequesterResult
	for i, p := range r.providers {
		if i >= r.budget.MaxProviders || out.Attempts >= r.budget.MaxAttempts {
			out.Outcome = RequesterBudgetExhausted
			out.Detail = "attempt/provider limit"
			return out
		}
		if err := ctx.Err(); err != nil {
			return stoppedResult(ep, out, err)
		}
		if err := r.ctx.Err(); err != nil {
			return stoppedResult(ep, out, err)
		}
		remaining := time.Until(deadline)
		if d := r.budget.PerAttempt; remaining > d {
			remaining = d
		}
		if remaining <= 0 {
			out.Outcome, out.Detail = RequesterBudgetExhausted, "overall deadline"
			return out
		}
		attemptCtx, cancel := context.WithTimeout(ctx, remaining)
		resp, bytes, err := requestVerifiedBudgeted(attemptCtx, r.opener, p, ep.target, remaining, r.budget.MaxDownloadedBytes-out.Downloaded)
		cancel()
		out.Attempts++
		out.Providers++
		out.Downloaded += bytes
		if err == nil {
			if resp.Found() {
				out.Outcome, out.Response, out.Detail = RequesterVerified, resp, "verified"
				return out
			}
			if resp.Outcome() == OutcomeUnavailable || resp.Outcome() == OutcomeBusy {
				out.Outcome, out.Detail = RequesterUnavailable, resp.Detail()
				continue
			}
			out.Outcome, out.Detail = RequesterInvalid, resp.Detail()
			continue
		}
		if errors.Is(err, ErrDownloadedBytes) || out.Downloaded >= r.budget.MaxDownloadedBytes {
			out.Outcome, out.Detail = RequesterBudgetExhausted, ErrDownloadedBytes.Error()
			return out
		}
		if errors.Is(err, context.Canceled) {
			return stoppedResult(ep, out, err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			if ctx.Err() != nil || time.Now().After(deadline) {
				return stoppedResult(ep, out, err)
			}
			out.Detail = err.Error()
			continue
		}
		out.Outcome, out.Detail = RequesterInvalid, err.Error()
	}
	if out.Outcome == 0 {
		out.Outcome, out.Detail = RequesterBudgetExhausted, "provider budget exhausted"
	}
	return out
}

func stoppedResult(ep *requesterEpisode, out RequesterResult, err error) RequesterResult {
	out.Detail = err.Error()
	if ep.markValue() == RequesterSuperseded {
		out.Outcome = RequesterSuperseded
		out.Detail = "target superseded"
	} else {
		out.Outcome = RequesterStopped
	}
	return out
}

func (r *Requester) Close() {
	r.mu.Lock()
	if r.closed {
		done := r.closeDone
		r.mu.Unlock()
		<-done
		return
	}
	r.closed = true
	r.cancel()
	ep := r.active
	if ep != nil {
		ep.mark(RequesterStopped)
		ep.cancel()
	}
	r.mu.Unlock()
	if ep != nil {
		<-ep.done
	}
	r.closeOnce.Do(func() { close(r.closeDone) })
}
