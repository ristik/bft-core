package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

/*
Authenticated execution-anchor recovery across a quiet tail — the APPLICATION half.

WHERE THIS SITS. `evidencerequester.go` obtains a verified anchor and holds it as a READY TARGET;
this decides whether and how that target reaches the executor. They are separate because §5's cursors
are separate: a target can be verified long before an executor can act on it, and the whole point of
the "payload unavailable" case is that both facts are true at once. Collapsing them would mean either
discarding proven evidence because a client is still syncing, or reporting a node recovered because
its evidence was good.

WHAT IT DECIDES, AND WHAT IT REFUSES TO CONFLATE. Three executor situations that look alike from a
distance and call for three different operator responses:

  - the executor could not be REACHED — an RPC error. Nothing at all is known: not whether it has the
    block, not whether it applied anything. Retryable, and the target is kept.
  - the executor was reached and does not have the PAYLOAD yet — SYNCING or ACCEPTED. A positive
    answer about availability, and the ordinary state after an execution-client restart (§1.1).
    Retryable, and the target is kept: the authority to retry is exactly what dropping it would lose.
  - the executor was reached and REJECTED the payload — INVALID. A fault, not a wait. Retrying cannot
    fix it and asking another provider cannot either, because the evidence already authenticated;
    the disagreement is between an authenticated certificate and this node's own executor.

WHAT IT NEVER DOES. It does not sign, and it does not make a node eligible to (P-sign, #105). It does
not re-verify evidence — `VerifyAnchorEvidence` did that, and doing it again here would be a second
place where evidence is judged. It does not fetch payloads: the executor's own ancestor acquisition
is what obtained the missing block in every run measured so far (§8), and that stays its business.
*/

// Named outcomes. Each is a different situation with a different answer, and the taxonomy is the
// reason this file exists — a single "recovery failed" would erase it.
var (
	// ErrApplyNoTarget — nothing verified for the certificate this node is being asked to build on.
	ErrApplyNoTarget = errors.New("anchor application: no verified target for the certificate held")
	// ErrApplyStaleTarget — the target explains a different state than this round builds on. It is
	// not applied, and it is not discarded either: it is simply not an answer to this question.
	ErrApplyStaleTarget = errors.New("anchor application: the verified target explains another state")
	// ErrApplyExecutorUnreachable — the RPC failed. Nothing is known about the executor.
	ErrApplyExecutorUnreachable = errors.New("anchor application: the executor could not be reached")
	// ErrApplyPayloadUnavailable — the executor answered, and does not have the block yet.
	ErrApplyPayloadUnavailable = errors.New("anchor application: the executor does not have the certified block yet")
	// ErrApplyPayloadInvalid — the executor answered, and rejected the block. A fault.
	ErrApplyPayloadInvalid = errors.New("anchor application: the executor rejected the certified block")
	// ErrApplyHeadMismatch — the commit reported success and the executor's head is not the certified
	// block at the certified state. P-id's whole subject, so it is a fault rather than a retry.
	ErrApplyHeadMismatch = errors.New("anchor application: the executor head is not the certified block after a successful commit")
	// ErrApplyBackoff — the previous attempt failed and its interval has not elapsed.
	ErrApplyBackoff = errors.New("anchor application: the previous attempt failed and its interval has not elapsed")
	// ErrApplyExhausted — this certified state has had its attempts. The target is kept; the next
	// certificate brings a fresh budget.
	ErrApplyExhausted = errors.New("anchor application: the attempts for this certified state are spent")
	// ErrApplyBudgetInvalid — a caller bug, reported the way the rest of #92 reports its own.
	ErrApplyBudgetInvalid = errors.New("anchor application: the configured budget is not usable")
)

// ApplyOutcome names what one attempt did, for diagnostics and for tests that assert the transition
// rather than infer it from a later effect.
type ApplyOutcome int

const (
	ApplyNotAttempted ApplyOutcome = iota
	ApplyApplied
	ApplyNoTarget
	ApplyStaleTarget
	ApplyExecutorUnreachable
	ApplyPayloadUnavailable
	ApplyPayloadInvalid
	ApplyHeadMismatch
	ApplyBackoff
	ApplyExhausted
)

func (o ApplyOutcome) String() string {
	switch o {
	case ApplyApplied:
		return "applied"
	case ApplyNoTarget:
		return "no-target"
	case ApplyStaleTarget:
		return "stale-target"
	case ApplyExecutorUnreachable:
		return "executor-unreachable"
	case ApplyPayloadUnavailable:
		return "payload-unavailable"
	case ApplyPayloadInvalid:
		return "payload-invalid"
	case ApplyHeadMismatch:
		return "head-mismatch"
	case ApplyBackoff:
		return "backoff"
	case ApplyExhausted:
		return "exhausted"
	default:
		return "not-attempted"
	}
}

// Retryable says whether another attempt at the SAME target could plausibly succeed. It is the
// application-side counterpart of the predicate's Retryable (§4.1), and the rule is the same shape:
// an outcome may be terminal only if it is a conclusion this node drew from something it
// authenticated itself. An executor that cannot be reached, or that says it is still syncing, has
// told this node nothing about the evidence.
func (o ApplyOutcome) Retryable() bool {
	switch o {
	case ApplyExecutorUnreachable, ApplyPayloadUnavailable, ApplyBackoff, ApplyExhausted:
		return true
	default:
		return false
	}
}

// ApplyBudget bounds what applying one target may cost.
type ApplyBudget struct {
	// MaxAttempts is how many attempts one CERTIFIED STATE may spend. It is deliberately not a
	// lifetime cap on a target: an unavailable payload is the expected state after an
	// execution-client restart, and a node that stopped trying for good would have turned a
	// recoverable situation into a permanent one. Each new certificate resets it, which is the same
	// rhythm the live path already has ("retaining the anchor and retrying on the next certificate").
	MaxAttempts int
	// Backoff spaces attempts within one certified state, so a fast round cadence cannot turn into a
	// tight loop against an executor that is busy syncing.
	Backoff time.Duration
	// Timeout bounds ONE executor call. An executor that never answers must not hold the caller.
	Timeout time.Duration
}

// DefaultApplyBudget are starting values, to be revisited against a measured quiet tail. Three
// attempts per certified state with a second between them fits comfortably inside a round, and a
// five-second per-call bound matches the transport's.
var DefaultApplyBudget = ApplyBudget{MaxAttempts: 3, Backoff: time.Second, Timeout: 5 * time.Second}

func (b ApplyBudget) validate() error {
	switch {
	case b.MaxAttempts <= 0:
		return fmt.Errorf("%w: MaxAttempts=%d", ErrApplyBudgetInvalid, b.MaxAttempts)
	case b.Backoff < 0:
		return fmt.Errorf("%w: Backoff=%s", ErrApplyBudgetInvalid, b.Backoff)
	case b.Timeout <= 0:
		return fmt.Errorf("%w: Timeout=%s", ErrApplyBudgetInvalid, b.Timeout)
	}
	return nil
}

// TargetSource is what holds a verified anchor — `*EvidenceRequester` in production. Behind an
// interface so the application policy can be tested without a network, and so the two halves stay
// separable: this one never asks the source to fetch anything.
type TargetSource interface {
	Target() (*ExecutionAnchor, bool)
}

// ApplyResult is one attempt, reported in full.
type ApplyResult struct {
	Outcome ApplyOutcome
	// Head is the executor's head AFTER the attempt when one was read, and the head passed in
	// otherwise. It is never a guess: an attempt that could not read a head reports the one it was
	// given, and Outcome says why.
	Head    BlockRef
	Target  *ExecutionAnchor
	Attempt int
	Err     error
}

/*
TargetApplier commits a verified anchor to the executor, once the target is an answer to the question
this round is actually asking.

One attempt at a time and never concurrently with itself: an executor commit is not a read, and two
in flight would make "what did the executor do" unanswerable.
*/
type TargetApplier struct {
	executor Executor
	source   TargetSource
	budget   ApplyBudget
	now      func() time.Time
	log      *slog.Logger

	mu sync.Mutex
	// forState is the certified state the counters below belong to. A new certified state is a new
	// question, and gets a new budget.
	forState    Hash
	attempts    int
	nextAttempt time.Time
	last        ApplyOutcome
	lastErr     error
	// faultedFor is the block hash an attempt concluded this node cannot apply — a rejected payload,
	// or a head that did not become the certified block after a successful commit. Kept by BLOCK
	// HASH, so a later, different target is not refused for it.
	faultedFor Hash
	faultErr   error
	applied    int
}

// ApplyConfig is what the applier needs that it cannot observe for itself.
type ApplyConfig struct {
	Executor Executor
	Source   TargetSource
	Budget   ApplyBudget
	// Now is the clock, injectable so the backoff is testable without sleeping.
	Now func() time.Time
	Log *slog.Logger
}

func NewTargetApplier(cfg ApplyConfig) (*TargetApplier, error) {
	if cfg.Executor == nil {
		return nil, fmt.Errorf("%w: no executor", ErrApplyBudgetInvalid)
	}
	if cfg.Source == nil {
		return nil, fmt.Errorf("%w: no target source", ErrApplyBudgetInvalid)
	}
	if err := cfg.Budget.validate(); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &TargetApplier{
		executor: cfg.Executor, source: cfg.Source, budget: cfg.Budget,
		now: cfg.Now, log: cfg.Log,
	}, nil
}

/*
Apply makes one bounded attempt to bring the executor to the certified block for certifiedState.

certifiedState is what the round being built builds on — `Expectation.PreviousHash` — and it is
RECHECKED against the target before anything is committed. That recheck is the point of taking it as
an argument rather than reading it from the target: a target verified against a certificate this node
has since moved past may name a block that is no longer the last certified one, and a state root that
happens to match is not an argument (§3.3.1). If the target does not explain THIS state, nothing is
sent to the executor.

The head passed in is the executor's head as the caller already read it. Apply does not re-read it
first: the caller has it, a second read would be a second RPC, and the answer that matters is the one
taken AFTER the commit.
*/
func (a *TargetApplier) Apply(ctx context.Context, certifiedState Hash, head BlockRef) ApplyResult {
	target, ok := a.source.Target()
	if !ok || target == nil {
		return a.record(ApplyNoTarget, head, nil, fmt.Errorf("%w: state %x", ErrApplyNoTarget, certifiedState))
	}
	// THE RECHECK. Not "the target is recent" — the target must be about the state this node is
	// being asked to build on. A verified anchor for another state is not stale in the sense of
	// being wrong; it is an answer to a question nobody asked.
	if !bytes.Equal(target.StateRoot, certifiedState) {
		return a.record(ApplyStaleTarget, head, target,
			fmt.Errorf("%w: target produces state %x for round %d, this round builds on %x",
				ErrApplyStaleTarget, target.StateRoot, target.Round, certifiedState))
	}

	if err := a.admit(certifiedState, target); err != nil {
		var outcome ApplyOutcome
		switch {
		case errors.Is(err, ErrApplyBackoff):
			outcome = ApplyBackoff
		case errors.Is(err, ErrApplyExhausted):
			outcome = ApplyExhausted
		case errors.Is(err, ErrApplyPayloadInvalid):
			outcome = ApplyPayloadInvalid
		default:
			outcome = ApplyHeadMismatch
		}
		return a.record(outcome, head, target, err)
	}

	attempt := a.attemptNumber()

	// Idempotent by contract (see Round.reconcile): Commit on an already-canonical hash is a no-op
	// returning VALID, so an attempt after a failed one does not double-execute anything.
	status, err := a.commit(ctx, target.BlockHash)
	if err != nil {
		// UNREACHABLE, not unavailable and not invalid. The executor said nothing, so nothing is
		// known — including whether it applied the block. The target is kept.
		return a.retryable(ApplyExecutorUnreachable, head, target, attempt,
			fmt.Errorf("%w: committing certified block %x: %w", ErrApplyExecutorUnreachable, target.BlockHash, err))
	}
	switch status {
	case StatusValid:
		// on, to the post-conditions
	case StatusSyncing, StatusAccepted:
		return a.retryable(ApplyPayloadUnavailable, head, target, attempt,
			fmt.Errorf("%w: certified block %x reported %s", ErrApplyPayloadUnavailable, target.BlockHash, status))
	default:
		return a.fault(ApplyPayloadInvalid, head, target, attempt,
			fmt.Errorf("%w: certified block %x reported %s — this is a fault, not an availability problem",
				ErrApplyPayloadInvalid, target.BlockHash, status))
	}

	newHead, err := a.head(ctx)
	if err != nil {
		// The commit reported VALID and the head could not be read, so whether this node is
		// recovered is unknown. Unknown is retryable, and the next attempt's commit is a no-op.
		return a.retryable(ApplyExecutorUnreachable, head, target, attempt,
			fmt.Errorf("%w: reading head after committing %x: %w", ErrApplyExecutorUnreachable, target.BlockHash, err))
	}

	// P-id, and by the SAME comparison the live path uses — anchorHeadIdentity, not a second copy of
	// it written here. A commit that reports success while the head is another block is exactly what
	// P-id exists to catch, so it is a fault rather than something to wait through.
	var genesis *BlockRef
	if target.fromGenesisRound {
		// Read only when the exception could apply. It is one round per shard, and an executor that
		// cannot answer for its own block zero must not silently widen the check.
		g, gerr := a.genesis(ctx)
		if gerr != nil {
			return a.retryable(ApplyExecutorUnreachable, newHead, target, attempt,
				fmt.Errorf("%w: reading the executor genesis block: %w", ErrApplyExecutorUnreachable, gerr))
		}
		genesis = &g
	}
	if idErr := anchorHeadIdentity(target, newHead, genesis); idErr != nil {
		return a.fault(ApplyHeadMismatch, newHead, target, attempt,
			fmt.Errorf("%w: %w", ErrApplyHeadMismatch, idErr))
	}
	// And the state, which is the other half of P-id: the same block hash at another state would
	// mean the executor and the certificate disagree about what that block produced.
	if !bytes.Equal(newHead.StateRoot, certifiedState) {
		return a.fault(ApplyHeadMismatch, newHead, target, attempt,
			fmt.Errorf("%w: head block %x is at state %x, the certified state is %x",
				ErrApplyHeadMismatch, newHead.Hash, newHead.StateRoot, certifiedState))
	}

	a.mu.Lock()
	a.applied++
	a.attempts = 0
	a.nextAttempt = time.Time{}
	a.mu.Unlock()
	if a.log != nil {
		a.log.LogAttrs(ctx, slog.LevelInfo, "recovered from authenticated evidence: the certified block is committed",
			slog.String("blockHash", fmt.Sprintf("%x", target.BlockHash)),
			slog.String("stateRoot", fmt.Sprintf("%x", target.StateRoot)),
			slog.Uint64("anchorRound", target.Round))
	}
	return a.record(ApplyApplied, newHead, target, nil)
}

// admit applies everything that can refuse an attempt before the executor is touched: a target this
// node has already concluded it cannot apply, the attempt budget for this certified state, and the
// backoff. It also rolls the budget over when the certified state changes.
func (a *TargetApplier) admit(certifiedState Hash, target *ExecutionAnchor) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.faultedFor != nil && bytes.Equal(a.faultedFor, target.BlockHash) {
		return a.faultErr
	}
	if !bytes.Equal(a.forState, certifiedState) {
		// A new certified state is a new question. The counters belong to the question, not to the
		// process, so the shard advancing is what gives a stuck node its next attempts.
		a.forState = bytes.Clone(certifiedState)
		a.attempts = 0
		a.nextAttempt = time.Time{}
	}
	if a.attempts >= a.budget.MaxAttempts {
		return fmt.Errorf("%w: %d attempts spent on state %x", ErrApplyExhausted, a.attempts, certifiedState)
	}
	if now := a.now(); !a.nextAttempt.IsZero() && now.Before(a.nextAttempt) {
		return fmt.Errorf("%w: %s remaining", ErrApplyBackoff, a.nextAttempt.Sub(now).Round(time.Millisecond))
	}
	a.attempts++
	return nil
}

func (a *TargetApplier) attemptNumber() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.attempts
}

// commit, head and genesis each bound ONE executor call. A context that is already done is passed
// through rather than replaced, so a caller cancelling still cancels.
func (a *TargetApplier) commit(ctx context.Context, hash Hash) (Status, error) {
	cctx, cancel := context.WithTimeout(ctx, a.budget.Timeout)
	defer cancel()
	return a.executor.Commit(cctx, hash)
}

func (a *TargetApplier) head(ctx context.Context) (BlockRef, error) {
	cctx, cancel := context.WithTimeout(ctx, a.budget.Timeout)
	defer cancel()
	return a.executor.Head(cctx)
}

func (a *TargetApplier) genesis(ctx context.Context) (BlockRef, error) {
	cctx, cancel := context.WithTimeout(ctx, a.budget.Timeout)
	defer cancel()
	return a.executor.GenesisBlock(cctx)
}

// retryable records an outcome that another attempt could resolve, and schedules the next one. The
// target is deliberately untouched: dropping it is what would remove the authority to retry.
func (a *TargetApplier) retryable(o ApplyOutcome, head BlockRef, target *ExecutionAnchor, attempt int, err error) ApplyResult {
	a.mu.Lock()
	a.nextAttempt = a.now().Add(a.budget.Backoff)
	a.mu.Unlock()
	res := a.record(o, head, target, err)
	res.Attempt = attempt
	return res
}

// fault records an outcome no further attempt at this target can resolve. It is recorded against the
// BLOCK HASH rather than the state, so a later target for the same state — a different block, which
// is exactly what §3.3.1 describes — is not refused for it.
func (a *TargetApplier) fault(o ApplyOutcome, head BlockRef, target *ExecutionAnchor, attempt int, err error) ApplyResult {
	a.mu.Lock()
	a.faultedFor = bytes.Clone(target.BlockHash)
	a.faultErr = err
	a.mu.Unlock()
	if a.log != nil {
		a.log.LogAttrs(context.Background(), slog.LevelError, "the executor cannot be brought to the certified block",
			slog.String("outcome", o.String()),
			slog.String("blockHash", fmt.Sprintf("%x", target.BlockHash)),
			slog.String("err", err.Error()))
	}
	res := a.record(o, head, target, err)
	res.Attempt = attempt
	return res
}

func (a *TargetApplier) record(o ApplyOutcome, head BlockRef, target *ExecutionAnchor, err error) ApplyResult {
	a.mu.Lock()
	a.last, a.lastErr = o, err
	attempt := a.attempts
	a.mu.Unlock()
	return ApplyResult{Outcome: o, Head: head, Target: copyAnchor(target), Attempt: attempt, Err: err}
}

// ApplyStatus is a diagnostic snapshot.
type ApplyStatus struct {
	Last        ApplyOutcome
	LastErr     error
	Attempts    int
	Applied     int
	NextAttempt time.Time
	ForState    Hash
	FaultedFor  Hash
}

func (a *TargetApplier) Status() ApplyStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ApplyStatus{
		Last: a.last, LastErr: a.lastErr, Attempts: a.attempts, Applied: a.applied,
		NextAttempt: a.nextAttempt,
		ForState:    Hash(bytes.Clone(a.forState)),
		FaultedFor:  Hash(bytes.Clone(a.faultedFor)),
	}
}
