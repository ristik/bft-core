package parentwitness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/registrywitness"
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
	// LocalRPC, when set, is tried once before peers. That source attempt performs
	// at most debug_getRawHeader and eth_getProof and shares every episode budget.
	LocalRPC registrywitness.MeteredCaller
	Budget   RequesterBudget
}

type RequesterResult struct {
	Outcome       RequesterOutcome
	Response      VerifiedResponse
	Attempts      int
	LocalAttempts int
	Providers     int
	Downloaded    int64
	Detail        string
}

type requesterEpisode struct {
	target Target
	owner  context.Context
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
	localRPC  registrywitness.MeteredCaller
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
	if parent == nil || (cfg.LocalRPC == nil && len(cfg.Providers) == 0) || (len(cfg.Providers) > 0 && cfg.Opener == nil) {
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
	return &Requester{opener: cfg.Opener, providers: providers, localRPC: cfg.LocalRPC, budget: cfg.Budget, ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}, nil
}

// Request runs one bounded episode. The first caller owns episode cancellation; later callers
// waiting on the same target may cancel only their own wait. Calls for the same target coalesce.
// A changed target supersedes the current episode and requires an explicit new request after
// cancellation and backoff; no pending automatic restart is performed.
func (r *Requester) Request(ctx context.Context, target Target) (RequesterResult, error) {
	if ctx == nil || !target.Valid() {
		return RequesterResult{}, ErrContext
	}
	if err := ctx.Err(); err != nil {
		return RequesterResult{Outcome: RequesterStopped, Detail: err.Error()}, err
	}
	for {
		r.mu.Lock()
		if err := ctx.Err(); err != nil {
			r.mu.Unlock()
			return RequesterResult{Outcome: RequesterStopped, Detail: err.Error()}, err
		}
		if err := r.ctx.Err(); err != nil && !r.closed {
			r.mu.Unlock()
			return RequesterResult{Outcome: RequesterStopped, Detail: err.Error()}, err
		}
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
		epctx, cancel := context.WithTimeout(ctx, r.budget.Overall)
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
		ep := &requesterEpisode{target: target, owner: ctx, cancel: cancel, done: make(chan struct{})}
		r.active = ep
		r.mu.Unlock()
		res := r.run(epctx, ep)
		close(watchStop)
		<-watchDone
		r.mu.Lock()
		if res.Outcome == RequesterVerified && (ep.markValue() != RequesterVerified || contextResult(epctx) != nil || r.ctx.Err() != nil || r.closed || r.active != ep) {
			if ep.markValue() == RequesterSuperseded {
				res = RequesterResult{Outcome: RequesterSuperseded, Attempts: res.Attempts, LocalAttempts: res.LocalAttempts, Providers: res.Providers, Downloaded: res.Downloaded, Detail: "target superseded"}
			} else if ep.owner.Err() == nil && r.ctx.Err() == nil && errors.Is(contextResult(epctx), context.DeadlineExceeded) {
				res = RequesterResult{Outcome: RequesterBudgetExhausted, Attempts: res.Attempts, LocalAttempts: res.LocalAttempts, Providers: res.Providers, Downloaded: res.Downloaded, Detail: "overall deadline"}
			} else {
				res = RequesterResult{Outcome: RequesterStopped, Attempts: res.Attempts, LocalAttempts: res.LocalAttempts, Providers: res.Providers, Downloaded: res.Downloaded, Detail: "requester stopped"}
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
	deadline, _ := ctx.Deadline()
	var out RequesterResult
	if r.localRPC != nil {
		if out.Attempts >= r.budget.MaxAttempts {
			return budgetResult(out, "attempt limit")
		}
		remaining, ok := r.attemptRemaining(deadline, out.Downloaded)
		if !ok {
			return budgetResult(out, budgetDetail(deadline, out.Downloaded, r.budget.MaxDownloadedBytes))
		}
		attemptCtx, cancel := context.WithTimeout(ctx, remaining)
		meter := &localRPCMeter{rpc: r.localRPC, left: r.budget.MaxDownloadedBytes - out.Downloaded}
		witness, err := registrywitness.Acquire(attemptCtx, meter, ep.target.registry, ep.target.request.BlockHash)
		out.Attempts++
		out.LocalAttempts++
		out.Downloaded += meter.downloaded
		if err == nil {
			resp, verifyErr := verifyEvidence(ep.target, witness.Evidence(), "verified from local execution RPC")
			attemptErr := contextResult(attemptCtx)
			if verifyErr == nil && attemptErr == nil {
				cancel()
				out.Outcome, out.Response, out.Detail = RequesterVerified, resp, "verified"
				return out
			}
			if verifyErr != nil {
				err = verifyErr
			} else {
				err = attemptErr
			}
		}
		attemptErr := contextResult(attemptCtx)
		cancel()
		if attemptErr != nil || ctx.Err() != nil || r.ctx.Err() != nil {
			if episodeBudgetExpired(ep, r.ctx, deadline) {
				return budgetResult(out, "overall deadline")
			}
			if ctx.Err() != nil || r.ctx.Err() != nil || errors.Is(attemptErr, context.Canceled) {
				return stoppedResult(ep, out, firstError(ctx.Err(), r.ctx.Err(), attemptErr))
			}
			if !time.Now().Before(deadline) {
				return budgetResult(out, "overall deadline")
			}
			out.Outcome, out.Detail = RequesterUnavailable, err.Error()
		} else if errors.Is(err, registrywitness.ErrResponseBytes) || out.Downloaded >= r.budget.MaxDownloadedBytes {
			return budgetResult(out, ErrDownloadedBytes.Error())
		} else if errors.Is(err, registrywitness.ErrUnavailable) {
			out.Outcome, out.Detail = RequesterUnavailable, err.Error()
		} else {
			out.Outcome, out.Detail = RequesterInvalid, err.Error()
		}
	}
	for i, p := range r.providers {
		if i >= r.budget.MaxProviders || out.Attempts >= r.budget.MaxAttempts {
			out.Outcome = RequesterBudgetExhausted
			out.Detail = "attempt/provider limit"
			return out
		}
		if err := ctx.Err(); err != nil {
			if episodeBudgetExpired(ep, r.ctx, deadline) {
				return budgetResult(out, "overall deadline")
			}
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
		if out.Downloaded >= r.budget.MaxDownloadedBytes {
			out.Outcome, out.Detail = RequesterBudgetExhausted, ErrDownloadedBytes.Error()
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
			if time.Now().After(deadline) {
				out.Outcome, out.Detail = RequesterBudgetExhausted, "overall deadline"
				return out
			}
			if ctx.Err() != nil {
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

func episodeBudgetExpired(ep *requesterEpisode, requesterCtx context.Context, deadline time.Time) bool {
	return ep.markValue() != RequesterSuperseded && ep.owner.Err() == nil && requesterCtx.Err() == nil && !time.Now().Before(deadline)
}

func (r *Requester) attemptRemaining(deadline time.Time, downloaded int64) (time.Duration, bool) {
	if downloaded >= r.budget.MaxDownloadedBytes {
		return 0, false
	}
	remaining := time.Until(deadline)
	if remaining > r.budget.PerAttempt {
		remaining = r.budget.PerAttempt
	}
	return remaining, remaining > 0
}

func budgetDetail(deadline time.Time, downloaded, max int64) string {
	if downloaded >= max {
		return ErrDownloadedBytes.Error()
	}
	if !time.Now().Before(deadline) {
		return "overall deadline"
	}
	return "attempt limit"
}

func budgetResult(out RequesterResult, detail string) RequesterResult {
	out.Outcome, out.Detail = RequesterBudgetExhausted, detail
	return out
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return context.Canceled
}

type localRPCMeter struct {
	rpc        registrywitness.MeteredCaller
	left       int64
	downloaded int64
	calls      int
}

func (m *localRPCMeter) Call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	if m.calls >= 2 || m.left <= 0 {
		return nil, registrywitness.ErrResponseBytes
	}
	m.calls++
	result, downloaded, err := m.rpc.CallMetered(ctx, method, params, m.left)
	if downloaded < 0 || downloaded > m.left {
		return nil, registrywitness.ErrResponseBytes
	}
	m.downloaded += downloaded
	m.left -= downloaded
	if err == nil && (len(result) > registrywitness.MaxResponseBytes || int64(len(result)) > downloaded) {
		return nil, fmt.Errorf("%w: local RPC returned unmetered result", registrywitness.ErrInvalid)
	}
	return result, err
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
