// Package posreject is every root validator's side of the RejectResult of an abandoned election result (contracts#73,
// briefs/73-reject-result-design.md): at each candidate proposal parent it discovers Election's open result at the EVM state the parent
// certified, collects the three-account witness, and once the proven facts make the result due (lost, or reserved
// storage.ResultReservationLifetimeProgress rounds ago) it hands the leader the control for exactly that parent and offers it to the other
// roots through the signed submission path. Nothing here decides anything: every voter judges the control by the full rule
// (storage/pos_control.go). RPC answers are discovery hints; only the witness verified against the certified state root counts.
//
// Nothing blocks the consensus loop, and nothing is persisted: Prepare starts bounded background work, Ready only reads the cache, and a
// restart rediscovers everything from chain state.
package posreject

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
)

// Bounds. Every one of them is a cap on work or memory, never a correctness rule.
const (
	MaxCache      = 16  // prepared rejections retained
	MaxNegative   = 256 // contexts remembered as "nothing to reject here"
	MaxResolved   = 64  // results the committed root resolved
	MaxInflight   = 2   // witnesses being collected at once
	ProofBudget   = 5 * time.Second
	maxRootBlocks = 256 // state root -> block hash memory (for quiet parents)
	// Resubmit is how long a submitted rejection waits before the same one is offered again: a submission expires from the leaders'
	// queue after posSubmissionTTL rounds, and on a quiet chain the context it was built for can outlive it.
	Resubmit = time.Minute
)

// Proofs returns the eth_getProof source for one EVM block.
type Proofs func(blockHash [32]byte) evmstate.ProofSource

// Config wires a Service.
type Config struct {
	Deployment storage.PosDeployment
	Pins       evmstate.Pins
	Proofs     Proofs
	// Submit offers a ready rejection to every root (ConsensusManager.SubmitPosControl); nil only offers it to this root's own proposals.
	Submit func(ctx context.Context, control rctypes.PosControl, witness []byte) error
	// Open and Build are seams for tests (defaults evmstate.OpenResult and evmstate.BuildRejectWitness).
	Open  func(ctx context.Context, src evmstate.ProofSource, pins evmstate.Pins) ([32]byte, error)
	Build func(ctx context.Context, src evmstate.ProofSource, pins evmstate.Pins, resultID [32]byte) ([]byte, storage.RejectFacts, error)
	Log   *slog.Logger
	Now   func() time.Time
}

type entry struct {
	ctx       storage.RejectionContext
	prepared  storage.PreparedRejection
	submitted time.Time
}

// Service implements storage.RejectProposer.
type Service struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	cache    []*entry
	negative []storage.RejectionContext
	inflight map[storage.RejectionContext]struct{}
	resolved [][32]byte
	roots    map[[32]byte][32]byte
	rootsOrd [][32]byte
	slots    chan struct{}
	wg       sync.WaitGroup
}

var _ storage.RejectProposer = (*Service)(nil)

// New makes the service. It needs a proof source and the pinned election.
func New(cfg Config) (*Service, error) {
	if cfg.Proofs == nil || cfg.Pins.Election == ([20]byte{}) {
		return nil, errors.New("posreject: a proof source and a pinned election are required")
	}
	if cfg.Open == nil {
		cfg.Open = evmstate.OpenResult
	}
	if cfg.Build == nil {
		cfg.Build = evmstate.BuildRejectWitness
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg, log: cfg.Log.With("component", "posreject"), inflight: map[storage.RejectionContext]struct{}{},
		roots: map[[32]byte][32]byte{}, slots: make(chan struct{}, MaxInflight)}, nil
}

// Wait waits for the collections in flight.
func (s *Service) Wait() { s.wg.Wait() }

// blockHashFor returns the EVM block hash proofs for the parent are fetched at: the certified block's, or for a quiet parent (no block hash
// in the input record) the block that certified the same state root earlier. The control still names the parent's own (zero) hash.
func (s *Service) blockHashFor(parent storage.EVMParent) ([32]byte, bool) {
	if parent.BlockHash != ([32]byte{}) {
		if _, known := s.roots[parent.StateRoot]; !known {
			if len(s.rootsOrd) >= maxRootBlocks {
				delete(s.roots, s.rootsOrd[0])
				s.rootsOrd = s.rootsOrd[1:]
			}
			s.roots[parent.StateRoot] = parent.BlockHash
			s.rootsOrd = append(s.rootsOrd, parent.StateRoot)
		}
		return parent.BlockHash, true
	}
	h, ok := s.roots[parent.StateRoot]
	return h, ok
}

func (s *Service) cachedLocked(ctx storage.RejectionContext) *entry {
	for _, e := range s.cache {
		if e.ctx == ctx {
			return e
		}
	}
	return nil
}

// Prepare implements storage.RejectProposer.
func (s *Service) Prepare(ctx storage.RejectionContext) {
	s.mu.Lock()
	// always learn the root -> block mapping: a later quiet parent carries the same root
	fetchAt, ok := s.blockHashFor(ctx.Parent)
	if !ok {
		s.mu.Unlock()
		return // a quiet parent whose state root this root never saw certified with a block: nothing to fetch proofs at
	}
	if e := s.cachedLocked(ctx); e != nil {
		resubmit := s.cfg.Submit != nil && s.cfg.Now().Sub(e.submitted) >= Resubmit
		if resubmit {
			e.submitted = s.cfg.Now()
		}
		prepared := e.prepared
		s.mu.Unlock()
		if resubmit {
			s.submit(prepared)
		}
		return
	}
	defer s.mu.Unlock()
	if _, busy := s.inflight[ctx]; busy || slices.Contains(s.negative, ctx) {
		return
	}
	select {
	case s.slots <- struct{}{}:
	default:
		return // MaxInflight collections are running: a later parent tries again
	}
	s.inflight[ctx] = struct{}{}
	s.wg.Add(1)
	go s.collect(ctx, fetchAt)
}

// collect discovers the open result at the parent's EVM state and, when the witness shows it due, caches and offers the rejection. A source
// that fails leaves nothing behind (the next Prepare of the same context tries again); a result that is not due, or no result, is remembered
// for the context only: a newer EVM state is a new context.
func (s *Service) collect(ctx storage.RejectionContext, fetchAt [32]byte) {
	defer s.wg.Done()
	defer func() { <-s.slots }()
	cctx, cancel := context.WithTimeout(context.Background(), ProofBudget)
	defer cancel()
	src := s.cfg.Proofs(fetchAt)
	prepared, negative, err := s.build(cctx, src, ctx)

	s.mu.Lock()
	delete(s.inflight, ctx)
	switch {
	case err != nil:
		s.mu.Unlock()
		s.log.Debug("rejection witness not collected; retried at a later parent", "error", err)
		return
	case negative:
		if len(s.negative) >= MaxNegative {
			s.negative = s.negative[1:]
		}
		s.negative = append(s.negative, ctx)
		s.mu.Unlock()
		return
	}
	if len(s.cache) >= MaxCache {
		s.cache = s.cache[1:]
	}
	e := &entry{ctx: ctx, prepared: prepared, submitted: s.cfg.Now()}
	s.cache = append(s.cache, e)
	s.mu.Unlock()
	s.log.Info("election result due for rejection", "result", prepared.ResultID, "attempt", ctx.Attempt)
	s.submit(prepared)
}

func (s *Service) build(ctx context.Context, src evmstate.ProofSource, rc storage.RejectionContext) (storage.PreparedRejection, bool, error) {
	var out storage.PreparedRejection
	id, err := s.cfg.Open(ctx, src, s.cfg.Pins)
	if err != nil {
		return out, false, err
	}
	if id == ([32]byte{}) || s.isResolved(id) {
		return out, true, nil
	}
	witness, f, err := s.cfg.Build(ctx, src, s.cfg.Pins, id)
	if err != nil {
		return out, false, err
	}
	if f.ResultID != id || !f.Reserved || !f.Unresolved || !f.Bound || !f.NoInstalledSession || !storage.RejectDue(f) {
		return out, true, nil
	}
	dep := s.cfg.Deployment
	c := rctypes.PosControl{Network: dep.RootNetwork, ChainID: dep.ChainID, Custody: dep.Custody, Op: rctypes.OpRejectResult,
		WitnessHash: sha256.Sum256(witness), Data: append([]byte(nil), id[:]...),
		Reject: &rctypes.RejectContext{PredecessorBodyID: rc.Predecessor, Attempt: rc.Attempt, EVMBlockHash: rc.Parent.BlockHash,
			EVMStateRoot: rc.Parent.StateRoot}}
	if err := c.Validate(); err != nil {
		return out, false, err
	}
	return storage.PreparedRejection{ResultID: id, Control: c, Witness: witness}, false, nil
}

func (s *Service) submit(p storage.PreparedRejection) {
	if s.cfg.Submit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), ProofBudget)
	defer cancel()
	if err := s.cfg.Submit(ctx, p.Control, p.Witness); err != nil {
		s.log.Warn("rejection not submitted; offered again later", "result", p.ResultID, "error", err)
	}
}

func (s *Service) isResolved(id [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.resolved, id)
}

// Ready implements storage.RejectProposer.
func (s *Service) Ready(ctx storage.RejectionContext) (storage.PreparedRejection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.cachedLocked(ctx); e != nil && !slices.Contains(s.resolved, e.prepared.ResultID) {
		return e.prepared, true
	}
	return storage.PreparedRejection{}, false
}

// Resolved implements storage.RejectProposer: nothing more is offered for the result, even before the EVM imports its record.
func (s *Service) Resolved(resultID [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains(s.resolved, resultID) {
		if len(s.resolved) >= MaxResolved {
			s.resolved = s.resolved[1:]
		}
		s.resolved = append(s.resolved, resultID)
	}
	s.cache = slices.DeleteFunc(s.cache, func(e *entry) bool { return e.prepared.ResultID == resultID })
}

// Pending reports the results with a prepared rejection, so the caller can tell which of them a committed block has resolved.
func (s *Service) Pending() [][32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][32]byte
	for _, e := range s.cache {
		if !slices.Contains(out, e.prepared.ResultID) {
			out = append(out, e.prepared.ResultID)
		}
	}
	return out
}
