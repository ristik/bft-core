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
	if b.MaxAttempts <= 0 || b.MaxProviders <= 0 || b.Overall <= 0 || b.PerAttempt <= 0 || b.MaxDownloadedBytes <= 0 || b.Backoff < 0 {
		return fmt.Errorf("%w: all limits must be positive and finite", ErrTransport)
	}
	if b.Overall <= 0 || b.PerAttempt <= 0 || b.Backoff < 0 || b.Overall > 100*365*24*time.Hour || b.PerAttempt > 100*365*24*time.Hour || b.Backoff > 100*365*24*time.Hour {
		return fmt.Errorf("%w: duration out of range", ErrTransport)
	}
	return nil
}

type RequesterConfig struct {
	Opener    StreamOpener
	Providers []peer.ID
	Target    Target
	Budget    RequesterBudget
	Now       func() time.Time
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
	now       func() time.Time
	ctx       context.Context
	cancel    context.CancelFunc

	mu      sync.Mutex
	closed  bool
	active  *requesterEpisode
	nextTry time.Time
	last    RequesterResult
}

func NewRequester(parent context.Context, cfg RequesterConfig) (*Requester, error) {
	if parent == nil || cfg.Opener == nil || !cfg.Target.Valid() || len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("%w: incomplete requester configuration", ErrTransport)
	}
	if err := cfg.Budget.validate(); err != nil {
		return nil, err
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
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ctx, cancel := context.WithCancel(parent)
	return &Requester{opener: cfg.Opener, providers: providers, budget: cfg.Budget, now: cfg.Now, ctx: ctx, cancel: cancel}, nil
}

// Request runs one bounded episode. Calls for the same target coalesce. A changed target
// supersedes the current episode and starts the explicitly requested target after cancellation.
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
					return cloneRequesterResult(ep.result), nil
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
		if until := r.nextTry.Sub(r.now()); until > 0 {
			r.mu.Unlock()
			return RequesterResult{Outcome: RequesterBudgetExhausted, Detail: ErrRequesterBackoff.Error()}, ErrRequesterBackoff
		}
		epctx, cancel := context.WithCancel(ctx)
		watchStop := make(chan struct{})
		go func() {
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
		cancel()
		r.mu.Lock()
		ep.result = cloneRequesterResult(res)
		if res.Outcome != RequesterVerified && res.Outcome != RequesterSuperseded && res.Outcome != RequesterStopped {
			r.nextTry = r.now().Add(r.budget.Backoff)
		}
		r.last = ep.result
		if r.active == ep {
			r.active = nil
		}
		close(ep.done)
		r.mu.Unlock()
		return res, nil
	}
}

func (r *Requester) run(ctx context.Context, ep *requesterEpisode) RequesterResult {
	started := r.now()
	deadline := started.Add(r.budget.Overall)
	var out RequesterResult
	for i, p := range r.providers {
		if i >= r.budget.MaxProviders || out.Attempts >= r.budget.MaxAttempts {
			out.Outcome = RequesterBudgetExhausted
			out.Detail = "attempt/provider limit"
			return out
		}
		if ep.markValue() == RequesterSuperseded {
			return RequesterResult{Outcome: RequesterSuperseded, Attempts: out.Attempts, Providers: out.Providers, Downloaded: out.Downloaded, Detail: "target superseded"}
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
		resp, bytes, err := RequestVerifiedBudgeted(attemptCtx, r.opener, p, ep.target, remaining, r.budget.MaxDownloadedBytes-out.Downloaded)
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
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if ep.markValue() == RequesterSuperseded {
				return RequesterResult{Outcome: RequesterSuperseded, Attempts: out.Attempts, Providers: out.Providers, Downloaded: out.Downloaded, Detail: "target superseded"}
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

func (r *Requester) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
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
}

func cloneRequesterResult(in RequesterResult) RequesterResult {
	out := in
	out.Response = in.Response
	return out
}
