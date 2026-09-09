package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"
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
	// ErrApplyInFlight — another attempt is inside the executor right now. A commit is not a read,
	// and two of them in flight would make "what did the executor do" unanswerable.
	ErrApplyInFlight = errors.New("anchor application: another attempt is already in the executor")
	// ErrApplyTargetMoved — the verified target changed while this attempt was in the executor, so
	// what was committed is no longer what this node is being asked to build on.
	ErrApplyTargetMoved = errors.New("anchor application: the verified target moved while the attempt was in flight")
	// ErrApplyBusy — another finality-changing executor operation is in progress. Distinct from
	// ErrApplyInFlight, which is another APPLICATION: this one is the round itself committing, and
	// the applier waits for no round.
	ErrApplyBusy = errors.New("anchor application: the executor is busy with another finality-changing operation")
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
	ApplyInFlight
	ApplyTargetMoved
	ApplyBusy
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
	case ApplyInFlight:
		return "in-flight"
	case ApplyTargetMoved:
		return "target-moved"
	case ApplyBusy:
		return "busy"
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
	case ApplyExecutorUnreachable, ApplyPayloadUnavailable, ApplyBackoff, ApplyExhausted,
		ApplyInFlight, ApplyTargetMoved, ApplyBusy:
		return true
	default:
		return false
	}
}

// ApplyBudget bounds what applying one target may cost.
type ApplyBudget struct {
	// MaxAttempts is how many attempts one CERTIFICATE may spend, and a new certificate renews it.
	//
	// Keyed on the certificate and NOT on the certified state, which is the correction review
	// found: across a quiet tail every certificate carries the same state root — that is what quiet
	// MEANS — so a state-keyed budget never renews for exactly the node this design exists for. A
	// node whose executor was still syncing spent its attempts, and then no number of quiet
	// certificates could give it another, however available the payload had since become. That is
	// the permanent failure the cap was supposed to avoid, reached by the cap itself.
	//
	// Renewing per certificate is the rhythm the live path already has ("retaining the anchor and
	// retrying on the next certificate"), and it is still bounded: a certificate arrives at the
	// shard's cadence, not at a retry loop's.
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

/*
CertificateBinding names the exact certificate an application attempt is for.

It is a CERTIFICATE, not a state root, and that distinction is the whole of it. Across a quiet tail
every certificate carries the same state root — that is what "quiet" means — so state equality cannot
say which certificate an anchor was verified against, cannot say whether the certificate has advanced
since, and cannot renew anything. Every one of those questions is answered here instead.

Identity is `InputRecord.Bytes()`, the canonical encoding the root chain's signatures cover, the same
identity the predicate binds to (§2.2) and the requester pins its requests with. RootRound is carried
because it is the one field that advances even for a REPEAT — same round, same input record, a later
root round — and a repeat is a new certificate, so it is a new opportunity to try.
*/
type CertificateBinding struct {
	Round     uint64 // partition round
	RootRound uint64 // the root round that certified it
	Identity  []byte // InputRecord.Bytes()
	State     Hash   // InputRecord.Hash — the state the next round builds on
}

// BindingFor derives the binding from a certificate this node has verified.
func BindingFor(uc *types.UnicityCertificate) (CertificateBinding, error) {
	if uc == nil || uc.InputRecord == nil {
		return CertificateBinding{}, fmt.Errorf("%w: certificate carries no input record", ErrEvidenceMalformed)
	}
	identity, err := uc.InputRecord.Bytes()
	if err != nil {
		return CertificateBinding{}, fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
	}
	return CertificateBinding{
		Round:     uc.InputRecord.RoundNumber,
		RootRound: uc.GetRootRoundNumber(),
		Identity:  identity,
		State:     Hash(bytes.Clone(uc.InputRecord.Hash)),
	}, nil
}

func bindingOf(w witnessEntry) CertificateBinding {
	return CertificateBinding{
		Round:     w.round,
		RootRound: w.link.UC.GetRootRoundNumber(),
		Identity:  bytes.Clone(w.identity),
		State:     Hash(bytes.Clone(w.link.UC.InputRecord.Hash)),
	}
}

// same reports whether two bindings name the same certificate.
func (b CertificateBinding) same(o CertificateBinding) bool {
	return b.Round == o.Round && b.RootRound == o.RootRound && bytes.Equal(b.Identity, o.Identity)
}

func (b CertificateBinding) valid() bool { return len(b.Identity) != 0 }

func (b CertificateBinding) clone() CertificateBinding {
	b.Identity = bytes.Clone(b.Identity)
	b.State = Hash(bytes.Clone(b.State))
	return b
}

// VerifiedTarget is an anchor together with the certificate it was verified against. The two travel
// together because neither is usable without the other: an anchor says which block, and the binding
// says which question that block is the answer to.
type VerifiedTarget struct {
	Anchor *ExecutionAnchor
	For    CertificateBinding
}

// TargetSource is what holds a verified anchor — `*EvidenceRequester` in production. Behind an
// interface so the application policy can be tested without a network, and so the two halves stay
// separable: this one never asks the source to fetch anything.
type TargetSource interface {
	Target() (VerifiedTarget, bool)
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
	gate     *FinalityGate
	now      func() time.Time
	log      *slog.Logger

	mu sync.Mutex
	// inFlight is set while an attempt is inside the executor. Not a mutex held across the call: a
	// slow executor would then hold whatever goroutine asked next, and the caller is a round loop.
	inFlight bool
	// forCert is the certificate the counters below belong to. A new certificate is a new
	// opportunity, and gets a new budget.
	forCert     CertificateBinding
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
	// Gate serializes this commit against every other finality-changing executor operation. Nil is
	// allowed and means "this applier is the only thing that commits", which is true in fixtures
	// and false in a wired node — see finality.go.
	Gate *FinalityGate
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
		executor: cfg.Executor, source: cfg.Source, budget: cfg.Budget, gate: cfg.Gate,
		now: cfg.Now, log: cfg.Log,
	}, nil
}

/*
Apply makes one bounded attempt to bring the executor to the certified block for `held`.

`held` is the certificate this node is being asked to build on, named in full — round, root round,
canonical identity and state. It is a certificate rather than a state root because state equality
cannot answer any of the questions this function has to answer:

  - Was this target verified against THIS certificate? Across a quiet tail every certificate carries
    the same state root, so "the target explains this state" is true of a target verified three
    rounds ago against a certificate this node has since moved past — and §3.3.1 is why that is not
    good enough. The requester returns the binding WITH the target; the two are compared directly.
  - Is this a new opportunity to try? Only a new certificate is, and across a quiet tail the state
    does not change while certificates keep arriving.
  - Did the answer go stale while the attempt was in the executor? Re-read afterwards and compare.

The head passed in is the executor's head as the caller already read it. Apply does not re-read it
first: the caller has it, a second read would be a second RPC, and the answer that matters is the one
taken AFTER the commit.
*/
func (a *TargetApplier) Apply(ctx context.Context, held CertificateBinding, head BlockRef) ApplyResult {
	if !held.valid() {
		return a.record(ApplyNoTarget, head, nil,
			fmt.Errorf("%w: no certificate was named to apply against", ErrApplyNoTarget))
	}
	vt, ok := a.source.Target()
	if !ok || vt.Anchor == nil {
		return a.record(ApplyNoTarget, head, nil, fmt.Errorf("%w: round %d", ErrApplyNoTarget, held.Round))
	}
	target := vt.Anchor

	// THE BINDING CHECK. Not "the target explains this state" — the target must have been VERIFIED
	// against the certificate this node is being asked to build on. Anything weaker is inferring
	// what a target is about from a hash it happens to share.
	if !vt.For.same(held) {
		return a.record(ApplyStaleTarget, head, target,
			fmt.Errorf("%w: the target was verified against round %d (root round %d), this node holds round %d (root round %d)",
				ErrApplyStaleTarget, vt.For.Round, vt.For.RootRound, held.Round, held.RootRound))
	}
	// And the two must agree about what that certificate says. A disagreement here is a bug on this
	// node, not a peer's doing, so it is named separately rather than folded into staleness.
	if !bytes.Equal(target.StateRoot, held.State) {
		return a.record(ApplyStaleTarget, head, target,
			fmt.Errorf("%w: target produces state %x for round %d, the certificate for that round builds on %x",
				ErrApplyStaleTarget, target.StateRoot, target.Round, held.State))
	}

	release, err := a.admit(held, target)
	if err != nil {
		return a.record(outcomeForAdmission(err), head, target, err)
	}
	defer release()

	attempt := a.attemptNumber()

	/*
	   THE GATE COVERS THE WHOLE SEQUENCE, not just the commit.

	   Review found it held for the Commit alone and released before the head was read, which made
	   the confirmation meaningless in the one case it exists for: between the two calls the round
	   could commit something of its own, the head would then be that other block, and this code
	   treats a head that is not the committed block as a FAULT — recorded against the block hash and
	   never retried. Interference by a correct round therefore permanently refused a target that was
	   correct too.

	   "Commit this block and confirm the executor is now at it" is one operation. It is held across
	   the commit, the head read and the genesis read, and released when the answer is known.
	*/
	if a.gate != nil {
		gateRelease, gerr := a.gate.tryAcquire("recovery-apply")
		if gerr != nil {
			// The round is doing something of its own. Not an answer about the executor and not an
			// attempt spent against it — the next certificate is the next opportunity.
			return a.retryable(ApplyBusy, head, target, attempt,
				fmt.Errorf("%w: %w", ErrApplyBusy, gerr))
		}
		defer gateRelease()
	}

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

	// TIME PASSED INSIDE THE EXECUTOR. A commit is not instantaneous, and the requester may have
	// installed a target for a newer certificate while this one was in flight — that is its ordinary
	// behaviour across a quiet tail, not a fault. Committing the block was still correct if the
	// target still names the same block; what must not happen is reporting this node RECOVERED for a
	// certificate the answer was never about.
	if now, ok := a.source.Target(); !ok || now.Anchor == nil || !bytes.Equal(now.Anchor.BlockHash, target.BlockHash) {
		return a.retryable(ApplyTargetMoved, newHead, target, attempt,
			fmt.Errorf("%w: %x was committed for round %d", ErrApplyTargetMoved, target.BlockHash, held.Round))
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
	if !bytes.Equal(newHead.StateRoot, held.State) {
		return a.fault(ApplyHeadMismatch, newHead, target, attempt,
			fmt.Errorf("%w: head block %x is at state %x, the certified state is %x",
				ErrApplyHeadMismatch, newHead.Hash, newHead.StateRoot, held.State))
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
			slog.Uint64("anchorRound", target.Round),
			slog.Uint64("heldRound", held.Round))
	}
	return a.record(ApplyApplied, newHead, target, nil)
}

func outcomeForAdmission(err error) ApplyOutcome {
	switch {
	case errors.Is(err, ErrApplyInFlight):
		return ApplyInFlight
	case errors.Is(err, ErrApplyBackoff):
		return ApplyBackoff
	case errors.Is(err, ErrApplyExhausted):
		return ApplyExhausted
	case errors.Is(err, ErrApplyPayloadInvalid):
		return ApplyPayloadInvalid
	default:
		return ApplyHeadMismatch
	}
}

/*
admit applies everything that can refuse an attempt before the executor is touched, and returns the
release for the in-flight slot it takes.

The slot is the answer to concurrency: two callers were previously both admitted and both entered
Commit, because the lock was released between counting the attempt and making the call. A commit is
not a read — two in flight make "what did the executor do" unanswerable, and the head read afterwards
belongs to neither of them. It is a NON-BLOCKING slot rather than a mutex held across the call: a
mutex would park whichever goroutine asked next behind a slow executor, and the caller is a round
loop.
*/
func (a *TargetApplier) admit(held CertificateBinding, target *ExecutionAnchor) (func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.faultedFor != nil && bytes.Equal(a.faultedFor, target.BlockHash) {
		return nil, a.faultErr
	}
	if a.inFlight {
		return nil, fmt.Errorf("%w: round %d", ErrApplyInFlight, held.Round)
	}
	if !a.forCert.same(held) {
		// A NEW CERTIFICATE is a new opportunity — not a new certified state, which across a quiet
		// tail never comes. The counters belong to the certificate, so the shard advancing at all is
		// what gives a node whose executor was syncing its next attempts.
		a.forCert = held.clone()
		a.attempts = 0
		a.nextAttempt = time.Time{}
	}
	if a.attempts >= a.budget.MaxAttempts {
		return nil, fmt.Errorf("%w: %d attempts spent on round %d", ErrApplyExhausted, a.attempts, held.Round)
	}
	if now := a.now(); !a.nextAttempt.IsZero() && now.Before(a.nextAttempt) {
		return nil, fmt.Errorf("%w: %s remaining", ErrApplyBackoff, a.nextAttempt.Sub(now).Round(time.Millisecond))
	}
	a.attempts++
	a.inFlight = true
	return func() {
		a.mu.Lock()
		a.inFlight = false
		a.mu.Unlock()
	}, nil
}

func (a *TargetApplier) attemptNumber() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.attempts
}

// commit, head and genesis each bound ONE executor call. The gate is taken by Apply around all
// three — see the comment there for why holding it for the commit alone was not enough.
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
	ForCert     CertificateBinding
	FaultedFor  Hash
	InFlight    bool
}

func (a *TargetApplier) Status() ApplyStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ApplyStatus{
		Last: a.last, LastErr: a.lastErr, Attempts: a.attempts, Applied: a.applied,
		NextAttempt: a.nextAttempt,
		ForCert:     a.forCert.clone(),
		FaultedFor:  Hash(bytes.Clone(a.faultedFor)),
		InFlight:    a.inFlight,
	}
}
