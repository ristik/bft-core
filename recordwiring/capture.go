package recordwiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// CaptureOutcome is what one capture attempt established. Only CapturePublished leaves a new durable record.
type CaptureOutcome int

const (
	// CapturePublished: witness(B) verified and bound, the executor was still at B, and the record was
	// published in one store transaction.
	CapturePublished CaptureOutcome = iota
	// CaptureDuplicate: the same block and round is in flight, pending or already published by this capturer.
	CaptureDuplicate
	// CaptureSuperseded: a newer committed block replaced this attempt before it started.
	CaptureSuperseded
	// CaptureMalformed: the commit could not be snapshotted; nothing was attempted.
	CaptureMalformed
	// CaptureWitnessUnavailable: the client did not provide witness(B), including a block behind its proof
	// window. Obtaining it later is #15.
	CaptureWitnessUnavailable
	// CaptureWitnessInvalid: the client answered with something that is not a valid witness for B's hash.
	CaptureWitnessInvalid
	// CaptureWitnessMismatch: the witness verified for B's hash but does not prove the certified state root
	// and executed round.
	CaptureWitnessMismatch
	// CaptureExecutorUnavailable: the executor's head could not be read before publication.
	CaptureExecutorUnavailable
	// CaptureExecutorMoved: the executor's head is no longer exactly B, so B is not published.
	CaptureExecutorMoved
	// CaptureStale: the store's head already names this round or a later one, or changed between preparation
	// and the store transaction; it is not replaced.
	CaptureStale
	// CapturePublishFailed: the store refused or failed the publication.
	CapturePublishFailed
	// CaptureStopped: the capturer stopped before the attempt completed.
	CaptureStopped
)

func (o CaptureOutcome) String() string {
	switch o {
	case CapturePublished:
		return "published"
	case CaptureDuplicate:
		return "duplicate"
	case CaptureSuperseded:
		return "superseded"
	case CaptureMalformed:
		return "malformed"
	case CaptureWitnessUnavailable:
		return "witness-unavailable"
	case CaptureWitnessInvalid:
		return "witness-invalid"
	case CaptureWitnessMismatch:
		return "witness-mismatch"
	case CaptureExecutorUnavailable:
		return "executor-unavailable"
	case CaptureExecutorMoved:
		return "executor-moved"
	case CaptureStale:
		return "stale"
	case CapturePublishFailed:
		return "publish-failed"
	case CaptureStopped:
		return "stopped"
	default:
		return fmt.Sprintf("capture(%d)", int(o))
	}
}

var (
	ErrDuplicateCapture = errors.New("recordwiring: this block is already being captured or was published")
	ErrSuperseded       = errors.New("recordwiring: a newer committed block replaced this attempt before it started")
	ErrWitnessMismatch  = errors.New("recordwiring: the witness does not prove the certified state root and round")
	ErrExecutorMoved    = errors.New("recordwiring: the executor's head is no longer the captured block")
	ErrCaptureStopped   = errors.New("recordwiring: the capturer stopped before the attempt completed")
)

// Attempt is the immutable snapshot one capture works from: the certificate and technical record as
// canonical CBOR taken when the round reported the commit, and the block, state and round they certify.
type Attempt struct {
	ID        uint64
	BlockHash common.Hash
	StateRoot common.Hash
	Round     uint64

	certificate []byte
	technical   []byte
}

func (a *Attempt) sameBlock(o Attempt) bool {
	return a != nil && a.BlockHash == o.BlockHash && a.Round == o.Round
}

// CaptureResult is one attempt, reported in full.
type CaptureResult struct {
	Attempt Attempt
	Outcome CaptureOutcome
	// BlockNumber is the number the verified witness proves, when the witness verified.
	BlockNumber uint64
	Err         error
}

// FinalityLock serializes the publication decision with every finality-changing executor operation.
// *shardnode.FinalityGate implements it.
type FinalityLock interface {
	Hold(ctx context.Context, who string) (func(), error)
}

// DefaultAcquireTimeout bounds one witness acquisition.
const DefaultAcquireTimeout = 10 * time.Second

const (
	DefaultCaptureAttempts = 3
	DefaultRetryDelay      = 250 * time.Millisecond
)

// CaptureConfig is what a Capturer works with.
type CaptureConfig struct {
	Deployment Deployment
	Store      *certifiedstore.Store
	// RPC answers debug_getRawHeader and eth_getProof for the execution client the node commits to.
	RPC registrywitness.Caller
	// Executor is read with Head only; no call that changes finality is made.
	Executor shardnode.Executor
	// Finality is the node's finality gate (Node.FinalityGate). The final head read and the store transaction
	// run while holding it.
	Finality       FinalityLock
	AcquireTimeout time.Duration
	// MaxAttempts bounds acquisition attempts for a transient unavailable witness. Proof-window
	// expiry and authenticated invalid evidence are terminal for one episode and are not burst-retried.
	MaxAttempts int
	RetryDelay  time.Duration
	Metrics     *Metrics
	Log         *slog.Logger
	// OnResult, when set, receives every attempt's result. It is called from the round for duplicate,
	// superseded and malformed attempts and from Run otherwise, so it must not block.
	OnResult func(CaptureResult)
}

/*
Capturer captures witness(B) for each block the round commits and publishes B's certified record (#14 W2).

ObserveCommit, called with the round lock held, only snapshots the commit and hands it to Run: one attempt is
in flight at a time, and a single pending slot keeps only the newest committed block, so an attempt a newer
block overtook before it started is superseded. Run acquires witness(B) by B's exact hash, verifies it under the
deployment's proof context, binds it to the certificate's state root and round, re-reads the executor's head
and requires it to be exactly B, and publishes. The store refuses inside its transaction to replace a head
naming this or a later round, so a late completion cannot replace a newer durable record.

States stay separate: the commit reported is executor-applied, a verified witness is witness-verified, and
only a publication that returned nil is durable. A failed attempt leaves the prior record in place.
*/
type Capturer struct {
	cfg CaptureConfig
	log *slog.Logger

	mu        sync.Mutex
	nextID    uint64
	pending   *Attempt
	inflight  *Attempt
	published *Attempt
	retryable *Attempt // last exhausted unavailable witness; retried only on an explicit later trigger

	wake chan struct{}
}

// HTTPWitnessCaller is the JSON-RPC caller for an execution client's plain endpoint.
func HTTPWitnessCaller(url string, timeout time.Duration) registrywitness.Caller {
	return registrywitness.NewHTTPCaller(url, timeout)
}

// NewCapturer checks cfg and returns a capturer that does nothing until Run.
func NewCapturer(cfg CaptureConfig) (*Capturer, error) {
	switch {
	case !cfg.Deployment.Valid():
		return nil, errors.New("recordwiring: capture needs a checked deployment")
	case cfg.Store == nil:
		return nil, errors.New("recordwiring: capture needs a record store")
	case cfg.RPC == nil:
		return nil, errors.New("recordwiring: capture needs an execution client RPC caller")
	case cfg.Executor == nil:
		return nil, errors.New("recordwiring: capture needs the executor")
	case cfg.Finality == nil:
		return nil, errors.New("recordwiring: capture needs the node's finality gate")
	}
	if cfg.AcquireTimeout <= 0 {
		cfg.AcquireTimeout = DefaultAcquireTimeout
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultCaptureAttempts
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = DefaultRetryDelay
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Capturer{cfg: cfg, log: log, wake: make(chan struct{}, 1)}, nil
}

// ObserveCommit implements shardnode.CommitObserver.
func (c *Capturer) ObserveCommit(cc shardnode.CertifiedCommit) {
	a, err := snapshot(cc)
	c.mu.Lock()
	c.nextID++
	a.ID = c.nextID
	var superseded *Attempt
	accepted := false
	result := CaptureResult{Attempt: a}
	switch {
	case err != nil:
		result.Outcome, result.Err = CaptureMalformed, err
	case c.inflight.sameBlock(a) || c.pending.sameBlock(a) || c.published.sameBlock(a):
		result.Outcome, result.Err = CaptureDuplicate, ErrDuplicateCapture
	case c.pending != nil && c.pending.Round >= a.Round:
		result.Outcome, result.Err = CaptureSuperseded, fmt.Errorf("%w: round %d is pending", ErrSuperseded, c.pending.Round)
	default:
		superseded, c.pending, accepted = c.pending, &a, true
		if c.retryable != nil && a.Round >= c.retryable.Round {
			c.retryable = nil
		}
	}
	c.mu.Unlock()

	if superseded != nil {
		c.report(CaptureResult{Attempt: *superseded, Outcome: CaptureSuperseded, Err: fmt.Errorf("%w: round %d", ErrSuperseded, a.Round)})
	}
	if !accepted {
		c.report(result)
		return
	}
	c.log.Debug("certified record: observed a committed block", "attempt", a.ID, "round", a.Round, "block", a.BlockHash.String())
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func snapshot(cc shardnode.CertifiedCommit) (Attempt, error) {
	if cc.Certificate == nil || cc.Certificate.InputRecord == nil || cc.Technical == nil {
		return Attempt{}, errors.New("recordwiring: the commit carries no certificate, input record or technical record")
	}
	ir := cc.Certificate.InputRecord
	if len(ir.BlockHash) != common.HashLength || !bytes.Equal(ir.BlockHash, cc.BlockHash) || len(ir.Hash) != common.HashLength {
		return Attempt{}, fmt.Errorf("recordwiring: the committed block %x is not the 32-byte block the certificate names (%x) at a 32-byte state", cc.BlockHash, ir.BlockHash)
	}
	uc, err := types.Cbor.Marshal(cc.Certificate)
	if err != nil {
		return Attempt{}, fmt.Errorf("recordwiring: encoding the certificate: %w", err)
	}
	tr, err := types.Cbor.Marshal(cc.Technical)
	if err != nil {
		return Attempt{}, fmt.Errorf("recordwiring: encoding the technical record: %w", err)
	}
	return Attempt{
		BlockHash: common.BytesToHash(ir.BlockHash), StateRoot: common.BytesToHash(ir.Hash), Round: ir.RoundNumber,
		certificate: uc, technical: tr,
	}, nil
}

// Run processes attempts until ctx ends. An attempt pending when it ends is reported as stopped.
func (c *Capturer) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			c.stop()
			return nil
		case <-c.wake:
		}
		for {
			c.mu.Lock()
			a := c.pending
			c.pending, c.inflight = nil, a
			c.mu.Unlock()
			if a == nil {
				break
			}
			res := c.captureWithRetry(ctx, *a)
			c.mu.Lock()
			c.inflight = nil
			if res.Outcome == CapturePublished {
				c.published = a
			}
			if res.Outcome == CaptureWitnessUnavailable {
				retry := *a
				c.retryable = &retry
			} else if c.retryable.sameBlock(*a) {
				c.retryable = nil
			}
			c.mu.Unlock()
			c.report(res)
			if ctx.Err() != nil {
				c.stop()
				return nil
			}
		}
	}
}

// RetryPending starts one later bounded episode for the last attempt whose witness remained
// unavailable after its finite burst. It reuses the immutable certificate/TR snapshot and therefore
// needs no new transaction or commit notification. Scheduling/backoff policy belongs to W3b; calls
// while that block is already pending or in flight coalesce.
func (c *Capturer) RetryPending() bool {
	c.mu.Lock()
	if c.retryable == nil || c.pending != nil || c.inflight != nil {
		c.mu.Unlock()
		return false
	}
	a := *c.retryable
	c.nextID++
	a.ID = c.nextID
	c.pending = &a
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return true
}

func (c *Capturer) captureWithRetry(ctx context.Context, a Attempt) CaptureResult {
	var res CaptureResult
	for n := 1; n <= c.cfg.MaxAttempts; n++ {
		res = c.capture(ctx, a)
		if res.Outcome != CaptureWitnessUnavailable || errors.Is(res.Err, registrywitness.ErrProofWindow) || n == c.cfg.MaxAttempts {
			return res
		}
		c.log.Debug("certified record: transient witness acquisition failed; retrying",
			"attempt", a.ID, "captureTry", n, "round", a.Round, "block", a.BlockHash.String(), "err", res.Err)
		t := time.NewTimer(c.cfg.RetryDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			return CaptureResult{Attempt: a, Outcome: CaptureStopped, Err: fmt.Errorf("%w: %w", ErrCaptureStopped, ctx.Err())}
		case <-t.C:
		}
	}
	return res
}

func (c *Capturer) stop() {
	c.mu.Lock()
	a := c.pending
	c.pending = nil
	c.mu.Unlock()
	if a != nil {
		c.report(CaptureResult{Attempt: *a, Outcome: CaptureStopped, Err: ErrCaptureStopped})
	}
}

func (c *Capturer) capture(ctx context.Context, a Attempt) CaptureResult {
	res := CaptureResult{Attempt: a}
	fail := func(o CaptureOutcome, err error) CaptureResult {
		if ctx.Err() != nil {
			o, err = CaptureStopped, fmt.Errorf("%w: %w", ErrCaptureStopped, err)
		}
		res.Outcome, res.Err = o, err
		return res
	}

	// witness(B), by B's exact hash, verified under the deployment's proof context.
	actx, cancel := context.WithTimeout(ctx, c.cfg.AcquireTimeout)
	w, err := registrywitness.Acquire(actx, c.cfg.RPC, c.cfg.Deployment.ProofContext(), a.BlockHash)
	cancel()
	if err != nil {
		if errors.Is(err, registrywitness.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fail(CaptureWitnessUnavailable, err)
		}
		return fail(CaptureWitnessInvalid, err)
	}
	s := w.Snapshot()
	res.BlockNumber = s.Number()
	if s.StateRoot() != a.StateRoot || s.Fields().RoundAuthorized != a.Round {
		return fail(CaptureWitnessMismatch, fmt.Errorf("%w: witness proves state %s round %d, certificate names state %s round %d",
			ErrWitnessMismatch, s.StateRoot(), s.Fields().RoundAuthorized, a.StateRoot, a.Round))
	}
	c.log.Debug("certified record: witness verified", "attempt", a.ID, "round", a.Round, "block", a.BlockHash.String(), "number", s.Number())

	var uc types.UnicityCertificate
	var tr certification.TechnicalRecord
	if err := types.Cbor.Unmarshal(a.certificate, &uc); err != nil {
		return fail(CaptureMalformed, err)
	}
	if err := types.Cbor.Unmarshal(a.technical, &tr); err != nil {
		return fail(CaptureMalformed, err)
	}

	// The expensive part of publication runs here, still off the round lock and outside the finality gate: the
	// store verifies the record and the head it would replace, and decides staleness.
	prepared, err := c.cfg.Store.Prepare(ctx, c.cfg.Deployment.StoreContext(), certifiedstore.Record{
		BlockHash: a.BlockHash, BlockNumber: s.Number(), StateRoot: a.StateRoot, PartitionRound: a.Round,
		Certificate: &uc, Technical: &tr, Witness: w.Evidence(),
	})
	switch {
	case errors.Is(err, certifiedstore.ErrStaleRecord):
		return fail(CaptureStale, err)
	case err != nil:
		return fail(CapturePublishFailed, err)
	}

	// THE DECISION IS SERIALIZED WITH FINALITY (review of #162). Every executor call that changes what is
	// canonical, the round's commits and builds and recovery's commit, takes this gate. Holding it across the
	// head read and the store transaction means the executor cannot move between "the head is exactly B" and
	// "B's record is durable": a commit that arrives meanwhile waits, and one already in progress is seen by the
	// read. Only the head read and the store transaction happen under it.
	release, err := c.cfg.Finality.Hold(ctx, "certified-record-publication")
	if err != nil {
		return fail(CaptureStopped, fmt.Errorf("%w: waiting for the finality gate: %w", ErrCaptureStopped, err))
	}
	defer release()

	// The executor must still be exactly B: a record claims no more than the node established.
	head, err := c.cfg.Executor.Head(ctx)
	if err != nil {
		return fail(CaptureExecutorUnavailable, fmt.Errorf("%w: head: %w", ErrExecutorUnavailable, err))
	}
	if head.Number != s.Number() || !bytes.Equal(head.Hash, a.BlockHash.Bytes()) || !bytes.Equal(head.StateRoot, a.StateRoot.Bytes()) {
		return fail(CaptureExecutorMoved, fmt.Errorf("%w: executor at %d hash %x state %x, captured %d hash %s state %s",
			ErrExecutorMoved, head.Number, head.Hash, head.StateRoot, s.Number(), a.BlockHash, a.StateRoot))
	}

	err = c.cfg.Store.Commit(prepared)
	switch {
	case errors.Is(err, certifiedstore.ErrHeadChanged):
		return fail(CaptureStale, err)
	case err != nil:
		return fail(CapturePublishFailed, err)
	}
	res.Outcome = CapturePublished
	return res
}

func (c *Capturer) report(r CaptureResult) {
	attrs := []any{"attempt", r.Attempt.ID, "outcome", r.Outcome.String(), "round", r.Attempt.Round, "block", r.Attempt.BlockHash.String()}
	switch r.Outcome {
	case CapturePublished:
		c.log.Info("certified record published", append(attrs, "number", r.BlockNumber)...)
	case CaptureDuplicate, CaptureSuperseded:
		c.log.Debug("certified record: attempt not started", append(attrs, "err", r.Err)...)
	default:
		c.log.Warn("certified record not published; the prior record is unchanged", append(attrs, "err", r.Err)...)
	}
	if c.cfg.OnResult != nil {
		c.cfg.OnResult(r)
	}
}
