package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
Authenticated execution-anchor recovery across a quiet tail — the REQUESTER half.

WHAT THIS FILE IS. The coordinator: it decides WHEN to ask for evidence, WHO to ask, HOW MANY times,
and what a returned bundle is worth. `evidencetransport.go` asks one provider once and carries bytes;
`anchorevidence.go` decides whether a bundle authenticates an anchor. Neither of them decides policy,
deliberately (§6.2), and this is where that policy lives, in one reviewable place.

WHAT IT IS NOT. It applies nothing. A verified anchor is stored as a READY TARGET and handed to a
caller that asks for it; committing it to an executor, and the RPC-unreachable / payload-missing /
payload-invalid distinctions that come with doing so, belong to the application side and are the next
unit (§5's Applied cursor, kept separate from Verified anchor for exactly this reason). It authorises
no signing: P-sign (#105) is untouched, and a recovered executor is not a licence to vote.

WHAT IT REFUSES TO SHORTCUT. Three things, each of which was cheap to get wrong:

  - Transport success is not evidence. A bundle that arrives intact from a well-behaved peer means
    nothing until `VerifyAnchorEvidence` accepts it against this node's OWN configuration; a peer's
    refusal TEXT means nothing at all, and is never the reason a decision is made.
  - A result verified against an OLDER held certificate does not authorise the newer one merely
    because the state roots match. A missed non-quiet interval can return to the same state root by
    a different block (§3.3.1), so the result is carried forward only by re-verifying it, extended
    with the certificates this node itself observed in the meantime, against the certificate it now
    holds. Anything else would be inferring history from state equality.
  - A refusal decided from bundle content says something about that CANDIDATE, not about the shard's
    history: it costs one attempt out of a bounded budget. Only a contradiction with this node's own
    authenticated certificate is terminal (§4.1, `Retryable`).
*/

// Named outcomes of a recovery attempt. Every one of them is a different operator situation, and
// collapsing any two costs the word that says what to do about it.
var (
	// ErrRecoveryNoProvider — nobody to ask. Not a failure of recovery; a failure to start one.
	ErrRecoveryNoProvider = errors.New("anchor recovery: no provider is available to ask")
	// ErrRecoveryUnavailable — the attempt budget was spent and no provider produced a bundle that
	// verifies. Retryable after the backoff, and the ordinary outcome while a shard is partitioned.
	ErrRecoveryUnavailable = errors.New("anchor recovery: no provider produced evidence that verifies")
	// ErrRecoveryStale — every result obtained was for a certificate this node has since moved
	// past, and none could be carried forward. Retryable after the backoff.
	ErrRecoveryStale = errors.New("anchor recovery: the held certificate moved past every result obtained")
	// ErrRecoveryConflict — an authenticated chain and this node's own authenticated certificate
	// make different statements about one round. TERMINAL for this held certificate: no third party
	// can adjudicate it, and asking another provider cannot make it go away.
	ErrRecoveryConflict = errors.New("anchor recovery: an authenticated chain contradicts this node's own certificate")
	// ErrRecoveryBackoff — a previous attempt failed and its backoff has not elapsed. Refusing here
	// is the point: a shard delivering a certificate every round would otherwise refetch on every
	// delivery, which turns one node's recovery into a load pattern on all the others.
	ErrRecoveryBackoff = errors.New("anchor recovery: the previous attempt failed and its backoff has not elapsed")
	// ErrRecoveryNoObservation — this node has verified no certificate yet, so there is nothing to
	// pin a request to. A request naming only a round is refused by the provider anyway (§2.2).
	ErrRecoveryNoObservation = errors.New("anchor recovery: this node has observed no certificate to recover for")
	// ErrRecoveryClosed — the requester has been shut down.
	ErrRecoveryClosed = errors.New("anchor recovery: the requester is closed")
	// ErrRecoveryBudgetInvalid — a caller bug, reported the way the predicate reports its own.
	ErrRecoveryBudgetInvalid = errors.New("anchor recovery: the configured budget is not usable")
)

// EvidenceFetcher is one bounded attempt at one provider: exactly what the transport offers, behind
// an interface so the coordinator's policy can be tested without a network and so the transport
// stays replaceable. `RequestAnchorEvidence` satisfies it through a two-line adapter.
type EvidenceFetcher interface {
	Fetch(ctx context.Context, provider peer.ID, req EvidenceRequest) (AnchorEvidence, error)
}

// ProviderSource names the peers worth asking, in the order they should be asked. It is consulted
// once per fetch rather than cached, so a membership change takes effect at the next attempt.
type ProviderSource interface {
	EvidenceProviders() []peer.ID
}

// RecoveryBudget bounds what one recovery may cost. Every field is a bound on something an
// adversary — or an unlucky partition — could otherwise make unbounded.
type RecoveryBudget struct {
	// MaxProviders is how many providers one fetch may consult. Bounded across providers rather
	// than per provider, so a supply of retryable refusals cannot keep an attempt alive (§4).
	MaxProviders int
	// Overall is the deadline for the WHOLE recovery, restarts included. One budget, not one per
	// attempt: a recovery that has already spent it is over, however it spent it.
	Overall time.Duration
	// PerAttempt bounds one provider's share of that budget, so the first silent peer cannot spend
	// all of it. Zero means "whatever is left of Overall".
	PerAttempt time.Duration
	// Backoff is how long a failed recovery waits before another may start. See ErrRecoveryBackoff.
	Backoff time.Duration
	// MaxRestarts bounds how many times a recovery may begin again because the held certificate
	// moved under it. A shard certifying rounds faster than a fetch completes would otherwise
	// restart forever, which is a livelock that looks like progress.
	MaxRestarts int
	// MaxWitness is how many observed certificates are retained to carry a result forward across a
	// moving held certificate. It bounds memory; exceeding it costs a refetch, never a shortcut.
	MaxWitness int
}

// DefaultRecoveryBudget are starting values, to be revisited against a measured quiet tail. Four
// providers is the same order as the transport's serving concurrency; 30 s is well inside the
// interval over which #111 measured a node sitting a block behind; 64 witnessed certificates covers
// far more quiet rounds than a fetch has ever taken.
var DefaultRecoveryBudget = RecoveryBudget{
	MaxProviders: 4,
	Overall:      30 * time.Second,
	PerAttempt:   5 * time.Second,
	Backoff:      10 * time.Second,
	MaxRestarts:  2,
	MaxWitness:   64,
}

func (b RecoveryBudget) validate() error {
	switch {
	case b.MaxProviders <= 0:
		return fmt.Errorf("%w: MaxProviders=%d", ErrRecoveryBudgetInvalid, b.MaxProviders)
	case b.Overall <= 0:
		return fmt.Errorf("%w: Overall=%s", ErrRecoveryBudgetInvalid, b.Overall)
	case b.PerAttempt < 0:
		return fmt.Errorf("%w: PerAttempt=%s", ErrRecoveryBudgetInvalid, b.PerAttempt)
	case b.Backoff < 0:
		return fmt.Errorf("%w: Backoff=%s", ErrRecoveryBudgetInvalid, b.Backoff)
	case b.MaxRestarts < 0:
		return fmt.Errorf("%w: MaxRestarts=%d", ErrRecoveryBudgetInvalid, b.MaxRestarts)
	case b.MaxWitness <= 0:
		return fmt.Errorf("%w: MaxWitness=%d", ErrRecoveryBudgetInvalid, b.MaxWitness)
	}
	return nil
}

// RecoveryConfig is everything the coordinator needs that it cannot observe for itself. The
// partition, shard, configuration hash and trust-base store are the RUNNING NODE's own, and are the
// only context any bundle is ever judged against — nothing travelling with evidence contributes.
type RecoveryConfig struct {
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardConfHash []byte
	TrustBases    TrustBaseStore

	Fetcher   EvidenceFetcher
	Providers ProviderSource

	Limits AnchorEvidenceLimits
	Budget RecoveryBudget

	// Now is the clock, injectable so backoff is testable without sleeping.
	Now func() time.Time
	Log *slog.Logger
}

// RecoveryState is what the coordinator is doing, for diagnostics and for callers deciding whether
// to trigger. It is NOT a substitute for Target: readiness is answered by asking for the target
// against the certificate actually held.
type RecoveryState int

const (
	RecoveryIdle RecoveryState = iota
	RecoveryFetching
	RecoveryReady
	RecoveryFailed
	RecoveryRefused // terminal for the held certificate that produced it
)

func (s RecoveryState) String() string {
	switch s {
	case RecoveryFetching:
		return "fetching"
	case RecoveryReady:
		return "ready"
	case RecoveryFailed:
		return "failed"
	case RecoveryRefused:
		return "refused"
	default:
		return "idle"
	}
}

/*
Contradiction is an authenticated disagreement, kept rather than logged away.

Both halves verified against this node's own trust base, so this is not a peer misbehaving in a way
the protocol tolerates — it is evidence that two conflicting statements about one round were signed.
The bundle is retained as it arrived so the disagreement can be examined after the fact; discarding
it would leave only a log line asserting that something unprovable had happened.

Bounded on purpose: the FIRST contradiction of a recovery is kept and later ones are counted, so a
provider cannot make a node retain memory by disagreeing repeatedly.
*/
type Contradiction struct {
	Provider  peer.ID
	HeldRound uint64
	Err       error
	Evidence  AnchorEvidence
	At        time.Time
	Count     int
}

// RecoveryStatus is a snapshot for logs and tests: enough to reconstruct what the coordinator did
// without inferring it from a later effect.
type RecoveryStatus struct {
	State       RecoveryState
	HeldRound   uint64
	Attempts    int
	Restarts    int
	Fetches     int
	LastErr     error
	NextAttempt time.Time
	TargetRound uint64 // the SOURCE round the ready target names, zero if none
	TargetFor   uint64 // the held round the target was verified against, zero if none
	// Contradictions counts the authenticated disagreements seen. The disagreement ITSELF is behind
	// Contradiction(), which copies it: a status snapshot is taken often and cheaply, and a bundle
	// of up to MaxCertificates certificates does not belong in one — nor does a pointer into the
	// retained record, which would let a reader rewrite the evidence it came to read.
	Contradictions int
	Witness        int
}

// witnessEntry is one certificate this node observed, kept so that a result obtained for an older
// held certificate can be RE-VERIFIED against the current one rather than assumed still to apply.
type witnessEntry struct {
	link     EvidenceLink
	round    uint64
	identity []byte // InputRecord.Bytes(), the identity the predicate binds to
	// seq numbers this observation within the process, monotonically and without reuse. It is what
	// a snapshot is taken OF, and content is not a substitute for it: a repeat certificate has the
	// same round AND the same identity as the certificate it repeats — that is what makes it a
	// repeat — so a snapshot keyed on either names two different observations, and extending from
	// the wrong one either drops a link or appends one twice.
	seq uint64
}

// EvidenceRequester is the coordinator. One fetch at a time, by construction: `Need` is idempotent
// and coalescing, so a shard delivering the same certificate to several call sites — or a certificate
// per round while a fetch runs — cannot spawn parallel recoveries.
type EvidenceRequester struct {
	cfg RecoveryConfig

	// life is cancelled by Close, and every fetch derives from it. The Round's per-call context is
	// deliberately NOT the parent: background work must not be bounded by the lifetime of whichever
	// call happened to trigger it, and no network I/O may run under the Round lock.
	life   context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	closed  bool
	state   RecoveryState
	witness []witnessEntry
	nextSeq uint64

	// retained is the last bundle that VERIFIED, with the held identity it verified against. It is
	// kept after success so that a held certificate advancing over a quiet tail can be answered by
	// extending it locally instead of refetching, and so a target survives an application that has
	// not completed.
	retained    *AnchorEvidence
	retainedFor witnessEntry // the certificate the retained bundle was VERIFIED against
	target      *ExecutionAnchor
	// targetBinding is the certificate the retained target was verified against, IN FULL. Readiness
	// and coalescing are decided from it rather than from the identity alone — see Target.
	targetBinding CertificateBinding
	// targetSource and targetSourceTechnical are the certificate that certified the retained
	// target's block and its bound technical record, copied from the evidence VerifyAnchorEvidence
	// authenticated. They are what a recovery commit's record is bound to: across a quiet tail the
	// held certificate names no block, so it cannot be the certificate the recovered block's record
	// cites. Retained alongside the target as its own copy, like every other retained certificate.
	targetSource          *types.UnicityCertificate
	targetSourceTechnical *certification.TechnicalRecord
	// refusedFor is the held IDENTITY a terminal conflict was decided for — deliberately a narrower
	// key than the binding above, because the two answer different questions. Readiness asks which
	// certificate a target was verified against, and a repeat is a different certificate. A conflict
	// asks what was SIGNED, and a repeat re-certifies the byte-identical input record: it is the
	// same contradiction, and re-deriving it would spend attempts to reach the conclusion already
	// reached.
	refusedFor    []byte
	nextAttempt   time.Time
	lastErr       error
	attempts      int
	restarts      int
	fetches       int
	contradiction *Contradiction
}

func NewEvidenceRequester(cfg RecoveryConfig) (*EvidenceRequester, error) {
	if cfg.Fetcher == nil {
		return nil, fmt.Errorf("%w: no fetcher", ErrRecoveryBudgetInvalid)
	}
	if cfg.Providers == nil {
		return nil, fmt.Errorf("%w: no provider source", ErrRecoveryBudgetInvalid)
	}
	if cfg.TrustBases == nil {
		return nil, fmt.Errorf("%w: no trust base store", ErrRecoveryBudgetInvalid)
	}
	if cfg.Limits.MaxCertificates <= 0 || cfg.Limits.MaxBytes <= 0 {
		return nil, fmt.Errorf("%w: MaxCertificates=%d MaxBytes=%d",
			ErrEvidenceLimitsInvalid, cfg.Limits.MaxCertificates, cfg.Limits.MaxBytes)
	}
	if err := cfg.Budget.validate(); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &EvidenceRequester{cfg: cfg, life: ctx, cancel: cancel}, nil
}

// Close cancels any fetch in flight and waits for it to release its work. It is idempotent, and it
// is the only thing that ends background work: a fetch is not abandoned to finish unobserved,
// because a goroutine still holding a stream after its owner is gone is exactly the leak the
// transport's cancellation contract exists to prevent (§6.2).
func (r *EvidenceRequester) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
}

/*
Observe records one certificate this node has verified. It is the same feed as the serving buffer's,
and for the same reason: what a node has itself authenticated is the only history it may reason
from.

It never fails a round, and it never triggers a fetch. Deciding that recovery is needed is the
caller's — Round's — business, because only Round knows whether its executor is actually behind.
*/
func (r *EvidenceRequester) Observe(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	if uc == nil || uc.InputRecord == nil || tr == nil {
		return fmt.Errorf("%w: observation is structurally incomplete", ErrEvidenceMalformed)
	}
	identity, err := uc.InputRecord.Bytes()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
	}
	entryRound := uc.InputRecord.RoundNumber
	// Copied, for the same reason the buffer copies: the caller keeps a pointer to a certificate it
	// may mutate, and evidence that changes after it was witnessed is not evidence.
	ucCopy, trCopy, _, err := copyPair(uc, tr)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// An exact re-delivery of the certificate just observed is not new information, and appending it
	// would make the witness unrepresentable as a chain: repeat normalisation requires a STRICTLY
	// later root round (§2.3), so a duplicate would read as a gap. A genuine repeat — same input
	// record, later root round, new assignment — is not a duplicate and is kept.
	if last, ok := r.current(); ok && last.round == entryRound &&
		bytes.Equal(last.identity, identity) && last.link.UC.GetRootRoundNumber() == uc.GetRootRoundNumber() {
		return nil
	}
	r.nextSeq++
	r.witness = append(r.witness, witnessEntry{
		link:     EvidenceLink{UC: ucCopy, Technical: trCopy},
		round:    ucCopy.InputRecord.RoundNumber,
		identity: identity,
		seq:      r.nextSeq,
	})
	for len(r.witness) > r.cfg.Budget.MaxWitness {
		r.witness[0] = witnessEntry{}
		r.witness = r.witness[1:]
	}
	return nil
}

// current is the certificate this node is being asked to build on, with its identity.
func (r *EvidenceRequester) current() (witnessEntry, bool) {
	if len(r.witness) == 0 {
		return witnessEntry{}, false
	}
	return r.witness[len(r.witness)-1], true
}

/*
Target returns a verified anchor for the certificate this node currently holds, if one is ready.

The identity check is the whole of it, and it is not a formality: a target verified against an older
certificate is returned only after it has been RE-VERIFIED against the current one (see carry), so
what this returns is never "an anchor whose state root happens to match". A target that no longer
matches is retained, not discarded — the caller's next Need can usually carry it forward locally —
which is what lets a target outlive an application that has not finished.

The target is returned WITH the certificate binding it was verified against, so a consumer never has
to reconstruct that from a state root. Across a quiet tail every certificate carries the same state
root, so state equality cannot say which certificate an anchor was verified for.

It does no I/O and takes only the coordinator's own lock, so it is safe to call under the Round lock.
*/
func (r *EvidenceRequester) Target() (VerifiedTarget, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	held, ok := r.current()
	if !ok || r.target == nil || !r.targetBinding.same(bindingOf(held)) {
		return VerifiedTarget{}, false
	}
	out := VerifiedTarget{Anchor: copyAnchor(r.target), For: r.targetBinding.clone()}
	// The source pair is copied out for the same reason the anchor is: it points into the retained
	// evidence, and a caller that edited what it was handed would be editing what this node
	// authenticated. It was already a decoded copy, so a refusal here would mean something this node
	// owns is unreadable, and refusing the target is safer than sharing that memory.
	if r.targetSource != nil && r.targetSourceTechnical != nil {
		uc, tr, _, err := copyPair(r.targetSource, r.targetSourceTechnical)
		if err != nil {
			if r.cfg.Log != nil {
				r.cfg.Log.WarnContext(context.Background(), "not handing out a recovery target: its source certificate could not be copied",
					slog.String("err", err.Error()))
			}
			return VerifiedTarget{}, false
		}
		out.Source, out.SourceTechnical = uc, tr
	}
	return out, true
}

// copyAnchor returns an anchor that shares nothing with the retained one. ExecutionAnchor's fields
// are byte SLICES, so a struct copy hands the caller the same backing arrays: a caller that trims,
// re-slices or overwrites a returned hash would be editing this node's own verified target, and the
// next call would return the edited value as though it had been verified. The struct copy was
// exactly that defect.
func copyAnchor(a *ExecutionAnchor) *ExecutionAnchor {
	if a == nil {
		return nil
	}
	out := *a
	out.BlockHash = Hash(bytes.Clone(a.BlockHash))
	out.StateRoot = Hash(bytes.Clone(a.StateRoot))
	return &out
}

// Status is a diagnostic snapshot. The contradiction, if there is one, is returned by pointer to the
// retained record: it is immutable once written.
func (r *EvidenceRequester) Status() RecoveryStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := RecoveryStatus{
		State:       r.state,
		Attempts:    r.attempts,
		Restarts:    r.restarts,
		Fetches:     r.fetches,
		LastErr:     r.lastErr,
		NextAttempt: r.nextAttempt,
		TargetFor:   r.targetBinding.Round,
		Witness:     len(r.witness),
	}
	if r.contradiction != nil {
		st.Contradictions = r.contradiction.Count
	}
	if held, ok := r.current(); ok {
		st.HeldRound = held.round
	}
	if r.target != nil {
		st.TargetRound = r.target.Round
	}
	return st
}

/*
Need asks for an anchor for the certificate this node holds, and returns as soon as it has decided
whether to start one — never after the network.

It is the deduplication point, and each refusal below is a distinct reason not to start:

  - a fetch is already running: one recovery at a time, whatever the held certificate has done in
    the meantime, because the running one re-checks the current certificate when it completes;
  - a target is already ready for this certificate: nothing to obtain;
  - a terminal conflict was decided for this certificate: no provider can change it;
  - the backoff has not elapsed: an explicit failure, not a silent refetch.

Returning nil means a fetch was started or the target is already there; the outcome arrives through
Target and Status, because a caller under the Round lock must not wait for one.
*/
func (r *EvidenceRequester) Need() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrRecoveryClosed
	}
	held, ok := r.current()
	if !ok {
		return ErrRecoveryNoObservation
	}
	if r.state == RecoveryFetching {
		return nil
	}
	// READY means ready for the certificate held NOW, compared as a whole certificate. Identity
	// alone was not enough and a repeat is the counterexample: same round, same input record — so
	// the same identity — certified at a LATER root round. On identity alone this returned "already
	// ready" and did nothing, while the applier compared the full binding and correctly refused the
	// target as stale, and the node sat between the two making no progress. The two halves must
	// answer the same question, and a repeat is a new certificate.
	if r.target != nil && r.targetBinding.same(bindingOf(held)) {
		return nil
	}
	if r.refusedFor != nil && bytes.Equal(r.refusedFor, held.identity) {
		return fmt.Errorf("%w: round %d", ErrRecoveryConflict, held.round)
	}
	if now := r.cfg.Now(); !r.nextAttempt.IsZero() && now.Before(r.nextAttempt) {
		return fmt.Errorf("%w: %s remaining", ErrRecoveryBackoff, r.nextAttempt.Sub(now).Round(time.Millisecond))
	}
	r.state = RecoveryFetching
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run()
	}()
	return nil
}

/*
Refresh carries an already-verified bundle onto the certificate this node holds NOW, using only what
this node has itself observed. No network, no provider, no attempt budget — so it is bounded work
that is safe to call under the round lock, and it is the difference between recovering and
permanently trailing by one certificate.

WHY IT EXISTS. Wiring made a lag visible that the unit fixtures could not: a certificate is observed
at the top of a round, and the recovery attempt happens inside the same round. An asynchronous carry
completes microseconds later — long before the next certificate, and still after the attempt that
needed it. So every attempt found a target for the PREVIOUS certificate, refused it as stale
(correctly), started a carry, and the next attempt found a target for the certificate before it. The
node would have gone on doing that forever on a shard that was doing nothing wrong.

The cost is re-verifying a bounded chain — the predicate over at most MaxCertificates certificates,
which is what carrying means (§6.3) — against a certificate arriving at the shard's cadence. That is
the right trade against never recovering.
*/
func (r *EvidenceRequester) Refresh(ctx context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrRecoveryClosed
	}
	held, ok := r.current()
	if !ok {
		r.mu.Unlock()
		return ErrRecoveryNoObservation
	}
	if r.target != nil && r.targetBinding.same(bindingOf(held)) {
		r.mu.Unlock()
		return nil // already an answer to this question
	}
	if r.refusedFor != nil && bytes.Equal(r.refusedFor, held.identity) {
		r.mu.Unlock()
		return fmt.Errorf("%w: round %d", ErrRecoveryConflict, held.round)
	}
	bundle, from, ok := r.retainedLocked()
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: nothing verified has been retained to carry", ErrRecoveryUnavailable)
	}
	if err := r.carry(ctx, bundle, from); err != nil {
		if errors.Is(err, ErrEvidenceConflict) {
			return fmt.Errorf("%w: %w", ErrRecoveryConflict, err)
		}
		return err
	}
	return nil
}

// run is the whole recovery, off the caller's goroutine and outside any lock the caller holds.
func (r *EvidenceRequester) run() {
	ctx, cancel := context.WithTimeout(r.life, r.cfg.Budget.Overall)
	defer cancel()

	err := r.recover(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastErr = err
	switch {
	case err == nil:
		r.state = RecoveryReady
		r.nextAttempt = time.Time{}
	case errors.Is(err, ErrRecoveryConflict):
		// Terminal, and terminal for a NAMED certificate: a later held certificate is a different
		// question, and must not inherit this refusal.
		r.state = RecoveryRefused
		r.nextAttempt = time.Time{}
	default:
		r.state = RecoveryFailed
		r.nextAttempt = r.cfg.Now().Add(r.cfg.Budget.Backoff)
	}
	if r.cfg.Log != nil {
		r.cfg.Log.LogAttrs(context.Background(), slog.LevelInfo, "anchor recovery finished",
			slog.String("state", r.state.String()),
			slog.String("err", errText(err)),
			slog.Int("attempts", r.attempts),
			slog.Int("restarts", r.restarts))
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// recover runs the restart loop: carry what is already held forward if it can be, otherwise fetch,
// and begin again if the held certificate moved past the result — a bounded number of times.
func (r *EvidenceRequester) recover(ctx context.Context) error {
	var last error
	// The retained bundle is worth one try per recovery, not one per restart: it is extended from a
	// fixed point through what has been observed, so a second attempt at it would re-decide exactly
	// the same question at the cost of re-verifying the whole chain.
	carried := false
	for restart := 0; ; restart++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %w", ErrRecoveryUnavailable, err)
		}
		if restart > r.cfg.Budget.MaxRestarts {
			if last != nil {
				return fmt.Errorf("%w after %d restarts: %w", ErrRecoveryStale, restart-1, last)
			}
			return fmt.Errorf("%w after %d restarts", ErrRecoveryStale, restart-1)
		}
		if restart > 0 {
			r.mu.Lock()
			r.restarts++
			r.mu.Unlock()
		}

		held, ok := r.snapshot()
		if !ok {
			return ErrRecoveryNoObservation
		}

		// 1. What is already held may already answer the question. This costs no network, and it is
		//    the ordinary case for a node whose recovery completed one quiet round ago.
		if bundle, from, ok := r.retainedBundle(); ok && !carried {
			carried = true
			if err := r.carry(ctx, bundle, from); err == nil {
				return nil
			} else if errors.Is(err, ErrEvidenceConflict) {
				return fmt.Errorf("%w: %w", ErrRecoveryConflict, err)
			}
		}

		// 2. Ask, pinned to the certificate held at THIS moment.
		bundle, err := r.fetch(ctx, held)
		if err != nil {
			return err
		}
		// 3. Time passed. The certificate this node is being asked to build on may no longer be the
		//    one the bundle was fetched for, and a bundle for an older one authorises nothing about
		//    the newer one on its own.
		if err := r.carry(ctx, bundle, held); err == nil {
			return nil
		} else if errors.Is(err, ErrEvidenceConflict) {
			return fmt.Errorf("%w: %w", ErrRecoveryConflict, err)
		} else {
			last = err
		}
	}
}

func (r *EvidenceRequester) snapshot() (witnessEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current()
}

// retainedBundle returns the last bundle that verified TOGETHER WITH the certificate it verified
// against. The pair is what makes it reusable: carrying it forward means extending it from THAT
// point through what has been observed since, and a bundle without the point it was anchored at
// would be extended from the wrong place — which reads as a chain that stops short.
func (r *EvidenceRequester) retainedBundle() (AnchorEvidence, witnessEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.retainedLocked()
}

// retainedLocked is retainedBundle with the lock already held.
func (r *EvidenceRequester) retainedLocked() (AnchorEvidence, witnessEntry, bool) {
	if r.retained == nil {
		return AnchorEvidence{}, witnessEntry{}, false
	}
	return *r.retained, r.retainedFor, true
}

/*
fetch spends the attempt budget across providers, pinned to one candidate at a time.

The pinning is the requester's half of §2.2: a request names the round AND the canonical identity of
the certificate held, so a provider cannot answer about a differently-certified round that happens to
share a number, and a disagreement surfaces as a named refusal one round trip earlier.

What ends the loop, and what does not:

  - a bundle the predicate ACCEPTS ends it, successfully;
  - a contradiction with this node's own certificate ends it, terminally — everything else about the
    budget is irrelevant once a statement this node made is one half of the disagreement;
  - everything else — a transport failure, a peer refusal, a bundle that fails any content check —
    costs one attempt and moves to the next provider. The peer's DETAIL string is never consulted:
    it is diagnostic, and a decision made from it would be a decision made by the peer (§6.2).
*/
func (r *EvidenceRequester) fetch(ctx context.Context, held witnessEntry) (AnchorEvidence, error) {
	providers := r.cfg.Providers.EvidenceProviders()
	if len(providers) == 0 {
		return AnchorEvidence{}, fmt.Errorf("%w: round %d", ErrRecoveryNoProvider, held.round)
	}
	req := EvidenceRequest{HeldRound: held.round, HeldIdentity: held.identity}
	vctx := r.verifyContext(held.link.UC)

	var last error
	spent := 0
	for _, p := range providers {
		if spent >= r.cfg.Budget.MaxProviders {
			break
		}
		if err := ctx.Err(); err != nil {
			return AnchorEvidence{}, fmt.Errorf("%w: %w", ErrRecoveryUnavailable, err)
		}
		spent++
		r.mu.Lock()
		r.attempts++
		r.fetches++
		r.mu.Unlock()

		bundle, err := r.fetchOne(ctx, p, req)
		if err != nil {
			last = fmt.Errorf("provider %s: %w", p, err)
			continue
		}
		// The transport delivered bytes. Whether they mean anything is decided here, and only here.
		if _, err := VerifyAnchorEvidence(ctx, bundle, vctx, r.cfg.Limits); err != nil {
			if isContradiction(err) {
				r.recordContradiction(p, held.round, bundle, err)
			}
			if !Retryable(err) {
				if !isContradiction(err) {
					// The only other non-retryable refusal is a caller bug about the bounds
					// (§4.1), and calling that a conflict would blame a peer for it.
					return AnchorEvidence{}, fmt.Errorf("provider %s: %w", p, err)
				}
				r.markRefused(held.identity)
				return AnchorEvidence{}, fmt.Errorf("%w: provider %s: %w", ErrRecoveryConflict, p, err)
			}
			last = fmt.Errorf("provider %s: %w", p, err)
			continue
		}
		return bundle, nil
	}
	if last == nil {
		return AnchorEvidence{}, fmt.Errorf("%w: round %d", ErrRecoveryUnavailable, held.round)
	}
	return AnchorEvidence{}, fmt.Errorf("%w: round %d, %d attempts: %w", ErrRecoveryUnavailable, held.round, spent, last)
}

// fetchOne applies this attempt's share of the overall budget. PerAttempt never EXTENDS the overall
// deadline — the derived context keeps whichever is sooner — so one budget still bounds the whole
// recovery no matter how the per-attempt value is configured.
func (r *EvidenceRequester) fetchOne(ctx context.Context, p peer.ID, req EvidenceRequest) (AnchorEvidence, error) {
	if r.cfg.Budget.PerAttempt > 0 {
		attemptCtx, cancel := context.WithTimeout(ctx, r.cfg.Budget.PerAttempt)
		defer cancel()
		return r.cfg.Fetcher.Fetch(attemptCtx, p, req)
	}
	return r.cfg.Fetcher.Fetch(ctx, p, req)
}

/*
carry decides whether a bundle verified for `from` authorises an anchor for the certificate this node
holds NOW, and installs the target if it does.

The rule is that there is no rule of its own: the bundle is EXTENDED with the certificates this node
itself observed after `from`, and handed back to `VerifyAnchorEvidence` against the current
certificate. Every property that made the original bundle acceptable is therefore re-decided —
contiguity by assigned round, quietness at the source's state, the terminal binding to the exact
certificate held — over the longer chain. A second, weaker rule written here ("the state roots still
match", say) would be a second place where history is inferred, and §3.3.1 is the counterexample to
every version of it.

A failure is not a verdict on the shard: the observed interval may simply contain a new certified
block, in which case the caller restarts and the next fetch names it. Only a contradiction with this
node's own certificate is passed up as terminal.
*/
func (r *EvidenceRequester) carry(ctx context.Context, bundle AnchorEvidence, from witnessEntry) error {
	held, links, ok := r.extension(from)
	if !ok {
		return fmt.Errorf("%w: the interval from round %d is no longer witnessed", ErrRecoveryStale, from.round)
	}
	extended := bundle
	if len(links) > 0 {
		tail := make([]EvidenceLink, 0, len(bundle.Tail)+len(links))
		tail = append(tail, bundle.Tail...)
		tail = append(tail, links...)
		extended = AnchorEvidence{Source: bundle.Source, SourceTechnical: bundle.SourceTechnical, Tail: tail}
	}

	// CLONE FIRST, then verify the clone, then retain the clone. The order is the point, and getting
	// it wrong is subtle in a way that survives review: a bundle arrives through a decoder whose
	// buffers this node does not own, and ExecutionAnchor's hashes are SLICES INTO the certificate
	// the anchor was derived from. Retaining what was handed over therefore left both the verified
	// target and the bundle future extensions are built on aliasing memory a provider could still be
	// writing to — Target cloning on the way out does not help, because what it clones is already
	// the provider's.
	//
	// Cloning AFTER verifying would be no better in kind, only smaller: the window between the two
	// is a window in which the bytes that were verified and the bytes that are kept can differ. So
	// what is verified is the copy this node owns, and that same copy is what it keeps.
	owned, err := copyEvidence(extended)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
	}
	anchor, err := VerifyAnchorEvidence(ctx, owned, r.verifyContext(held.link.UC), r.cfg.Limits)
	if err != nil {
		if errors.Is(err, ErrEvidenceConflict) {
			r.markRefused(held.identity)
		}
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// The held certificate can move between the verification above and this line. Installing the
	// target for the certificate it was VERIFIED against — not for whatever is current now — is what
	// keeps Target honest: a caller asking with a newer certificate is told there is no target, and
	// the next Need carries this bundle forward properly rather than silently reusing it.
	kept := owned
	r.retained = &kept
	r.retainedFor = held
	r.target = anchor
	// The source pair travels WITH the target. It is the one VerifyAnchorEvidence authenticated and
	// guaranteed non-quiet, and it is owned: `owned` was re-decoded before verification, so these
	// pointers do not alias a provider's buffers. A consumer reports a recovery commit against it.
	r.targetSource = owned.Source
	r.targetSourceTechnical = owned.SourceTechnical
	// The binding travels WITH the target. What the anchor was verified against is a fact about the
	// anchor, and a consumer that had to re-derive it from a state root would be inferring history
	// from state equality — the one thing this whole design refuses (§3.3.1).
	r.targetBinding = bindingOf(held)
	r.refusedFor = nil
	return nil
}

// extension returns the certificate held now, and the links observed strictly after `from`.
//
// `from` is located by POSITION rather than by round number, so a repeat certificate — same round,
// same input record, a later root round and a new assignment — is carried into the extension instead
// of being dropped, which is what makes an honest repeat representable (§2.3).
func (r *EvidenceRequester) extension(from witnessEntry) (witnessEntry, []EvidenceLink, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	held, ok := r.current()
	if !ok {
		return witnessEntry{}, nil, false
	}
	// By SEQUENCE — the exact observation the snapshot was taken of. Matching on round and identity
	// instead was wrong in both directions, and a repeat certificate is what exposes it: it carries
	// the same round and the same input record as the certificate it repeats, and a NEW assignment.
	// Taking the first content match appends a later repeat to evidence that already ends at it,
	// and the duplicate is refused as a gap (a repeat must be at a STRICTLY later root round), so a
	// correct answer is discarded and the retry budget is spent re-obtaining it. Taking the last
	// content match instead drops the repeat that supplies the assignment the rest of the interval
	// follows. There is no content key that separates the two; the version is the answer.
	at := -1
	for i := range r.witness {
		if r.witness[i].seq == from.seq {
			at = i
			break
		}
	}
	if at < 0 {
		// The snapshot has been evicted from the witness, so this node can no longer say what
		// happened between it and now. Refetching is the only sound answer.
		return witnessEntry{}, nil, false
	}
	rest := r.witness[at+1:]
	links := make([]EvidenceLink, 0, len(rest))
	for _, w := range rest {
		links = append(links, w.link)
	}
	return held, links, true
}

// markRefused records that a terminal conflict was decided for ONE certificate. It is deliberately
// keyed by identity rather than by round: a later certificate for the same round is a different
// authenticated statement, and it must be allowed its own attempt rather than inheriting a refusal.
func (r *EvidenceRequester) markRefused(identity []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refusedFor = identity
}

func (r *EvidenceRequester) verifyContext(held *types.UnicityCertificate) AnchorEvidenceContext {
	return AnchorEvidenceContext{
		PartitionID:   r.cfg.PartitionID,
		ShardID:       r.cfg.ShardID,
		ShardConfHash: r.cfg.ShardConfHash,
		TrustBases:    r.cfg.TrustBases,
		Held:          held,
	}
}

// isContradiction names the two refusals that mean two AUTHENTICATED certificates disagree — one
// with this node's own, one inside a single bundle. Both are worth keeping; only the first is
// terminal (§4.1), and that distinction is made by Retryable, not here.
func isContradiction(err error) bool {
	return errors.Is(err, ErrEvidenceConflict) || errors.Is(err, ErrEvidenceCandidateSplit)
}

// Contradiction returns the first authenticated disagreement this requester saw, as an independent
// copy: the certificates are re-decoded rather than shared, so examining the evidence — or handing
// it to something that writes to it — cannot change what this node retained as the record of it.
func (r *EvidenceRequester) Contradiction() (Contradiction, bool) {
	// The RECORD is copied under the lock and the BUNDLE outside it. Taking the pointer under the
	// lock and dereferencing after was a data race on every scalar field: Count is incremented under
	// this lock by a recovery still running, so a reader that unlocked first read it concurrently.
	// The lock is released before the re-decode because that is the expensive part and it touches
	// only memory this node already owns.
	r.mu.Lock()
	if r.contradiction == nil {
		r.mu.Unlock()
		return Contradiction{}, false
	}
	out := *r.contradiction
	r.mu.Unlock()

	// The bundle was copied when it was recorded, so this cannot fail on anything a provider chose.
	// If it somehow does, the bundle is DROPPED rather than shared: sharing it is the defect this
	// copy exists to prevent, and a caller that finds no evidence attached has been told the truth.
	if ev, err := copyEvidence(out.Evidence); err == nil {
		out.Evidence = ev
	} else {
		out.Evidence = AnchorEvidence{}
	}
	return out, true
}

// copyEvidence re-decodes a bundle so the copy shares no memory with it. It is the same mechanism
// the serving buffer uses for the same reason: evidence that can change after it was recorded is not
// evidence of anything.
// A failure is REPORTED rather than skipped: silently omitting a link would turn a chain into a
// shorter one that is still structurally a chain, and a shortened chain is not evidence of anything
// (§4). Callers treat it as a malformed bundle, which is retryable against another provider.
func copyEvidence(ev AnchorEvidence) (AnchorEvidence, error) {
	out := AnchorEvidence{}
	if ev.Source != nil && ev.SourceTechnical != nil {
		uc, tr, _, err := copyPair(ev.Source, ev.SourceTechnical)
		if err != nil {
			return AnchorEvidence{}, fmt.Errorf("copying evidence source: %w", err)
		}
		out.Source, out.SourceTechnical = uc, tr
	}
	out.Tail = make([]EvidenceLink, 0, len(ev.Tail))
	for i, l := range ev.Tail {
		if l.UC == nil || l.Technical == nil {
			return AnchorEvidence{}, fmt.Errorf("copying evidence: tail[%d] is structurally incomplete", i)
		}
		uc, tr, _, err := copyPair(l.UC, l.Technical)
		if err != nil {
			return AnchorEvidence{}, fmt.Errorf("copying evidence tail[%d]: %w", i, err)
		}
		out.Tail = append(out.Tail, EvidenceLink{UC: uc, Technical: tr})
	}
	return out, nil
}

func (r *EvidenceRequester) recordContradiction(p peer.ID, heldRound uint64, ev AnchorEvidence, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.contradiction != nil {
		r.contradiction.Count++
		return
	}
	// Copied on the way IN as well: the bundle came from a provider through a decoder this node does
	// not own the buffers of, and the record is meant to outlive the attempt that produced it.
	owned, cerr := copyEvidence(ev)
	if cerr != nil {
		// The disagreement still happened, and saying so without the bundle is better than either
		// losing the record or retaining a bundle that can change under it.
		owned, err = AnchorEvidence{}, fmt.Errorf("%w (the bundle could not be retained: %w)", err, cerr)
	}
	r.contradiction = &Contradiction{
		Provider: p, HeldRound: heldRound, Err: err, Evidence: owned, At: r.cfg.Now(), Count: 1,
	}
	if r.cfg.Log != nil {
		r.cfg.Log.LogAttrs(context.Background(), slog.LevelError, "authenticated certificates disagree",
			slog.String("provider", p.String()),
			slog.Uint64("heldRound", heldRound),
			slog.String("err", err.Error()))
	}
}
