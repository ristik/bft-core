package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// PrimaryWitnessSource is the execution client side of a primary candidate's EVM proof. Nothing it returns is trusted: block admission
// verifies the witness against the frozen parent's certified state root, and the facts only filter what this root accepts into a plan.
type PrimaryWitnessSource interface {
	// PrimaryWitness builds the storage-proof witness of the election and custody state at the frozen parent for a result
	// (evmstate.BuildPrimaryWitness).
	PrimaryWitness(frozenParent []byte, resultID [32]byte) ([]byte, error)
	// PrimaryFacts reads the result's proven facts at the client's current head. A published result's attempt and possession-proof set are
	// fixed, so they are what an arriving plan's proofs are checked against.
	PrimaryFacts(resultID [32]byte) (evmassign.PrimaryFacts, error)
}

const (
	// primaryWitnessBuildTimeout bounds one background build; primaryWitnessRetry spaces the retries after a failed one.
	primaryWitnessBuildTimeout = 60 * time.Second
	primaryWitnessRetry        = 2 * time.Second
)

type primaryWitnessKey struct{ parent, result [32]byte }

// primaryCache holds what the proposal path reads without blocking: the witness of the one (frozen parent, result) in play, built in the
// background, and the facts of published results (immutable once published).
type primaryCache struct {
	mu       sync.Mutex
	facts    map[[32]byte]evmassign.PrimaryFacts
	key      primaryWitnessKey
	witness  []byte
	inflight bool
	failedAt time.Time
}

// SetPrimaryWitnessSource installs the source. A root of a chain that judges primary candidates needs one: to check the proofs of an
// arriving plan, and to lead its Freeze.
func (x *ConsensusManager) SetPrimaryWitnessSource(s PrimaryWitnessSource) {
	if s == nil {
		x.primaryWitness.Store(nil)
		return
	}
	x.primaryWitness.Store(&s)
}

func (x *ConsensusManager) primarySource() (PrimaryWitnessSource, error) {
	src := x.primaryWitness.Load()
	if src == nil {
		return nil, fmt.Errorf("%w: no witness source configured", storage.ErrWitnessUnavailable)
	}
	return *src, nil
}

// primaryFacts returns the published facts of a result, from the cache or the execution client. An unpublished result is not cached.
func (x *ConsensusManager) primaryFacts(result [32]byte) (evmassign.PrimaryFacts, error) {
	x.primaryCache.mu.Lock()
	f, ok := x.primaryCache.facts[result]
	x.primaryCache.mu.Unlock()
	if ok {
		return f, nil
	}
	src, err := x.primarySource()
	if err != nil {
		return f, err
	}
	if f, err = src.PrimaryFacts(result); err != nil {
		return f, errors.Join(storage.ErrWitnessUnavailable, err)
	}
	if f.Published {
		x.primaryCache.mu.Lock()
		if x.primaryCache.facts == nil || len(x.primaryCache.facts) > 8 {
			x.primaryCache.facts = map[[32]byte]evmassign.PrimaryFacts{}
		}
		x.primaryCache.facts[result] = f
		x.primaryCache.mu.Unlock()
	}
	return f, nil
}

// prefetchPrimaryWitness starts the background build of the witness for (parent, result) unless it is cached, in flight, or just failed.
// The cache keeps one entry: the proof of the origin in play, rebuilt only for a new (frozen parent, result).
func (x *ConsensusManager) prefetchPrimaryWitness(parent, result [32]byte) {
	src, err := x.primarySource()
	if err != nil {
		return
	}
	key := primaryWitnessKey{parent: parent, result: result}
	c := &x.primaryCache
	c.mu.Lock()
	if c.key == key && (c.witness != nil || c.inflight || time.Since(c.failedAt) < primaryWitnessRetry) {
		c.mu.Unlock()
		return
	}
	if c.key != key {
		c.key, c.witness, c.failedAt = key, nil, time.Time{}
	}
	c.inflight = true
	c.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), primaryWitnessBuildTimeout)
		defer cancel()
		type built struct {
			w   []byte
			err error
		}
		done := make(chan built, 1)
		go func() {
			w, err := src.PrimaryWitness(parent[:], result)
			done <- built{w, err}
		}()
		var b built
		select {
		case b = <-done:
		case <-ctx.Done():
			b.err = ctx.Err()
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.key != key {
			return // superseded by a newer origin
		}
		c.inflight = false
		if b.err != nil || len(b.w) == 0 {
			c.failedAt = time.Now()
			x.log.Warn("could not build the primary candidate's EVM witness", "err", b.err)
			return
		}
		c.witness = b.w
	}()
}

func (x *ConsensusManager) cachedPrimaryWitness(parent, result [32]byte) ([]byte, bool) {
	c := &x.primaryCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key == (primaryWitnessKey{parent: parent, result: result}) && c.witness != nil {
		return bytes.Clone(c.witness), true
	}
	return nil, false
}

// prefetchForPlan starts the witness build for a primary plan once its frozen parent is known (an endorser knows it from the Prepare), so
// that whichever root leads the Freeze finds it built.
func (x *ConsensusManager) prefetchForPlan(preimage, frozenParent []byte) {
	if len(preimage) == 0 || len(frozenParent) != 32 || !x.blockStore.PosServices().RequiresPrimaryProof() {
		return
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil || c.Kind != evmassign.KindPrimary {
		return
	}
	x.prefetchPrimaryWitness([32]byte(frozenParent), c.ResultID())
}

// primaryFreezeProof returns the canonical PrimaryProof a primary candidate's Freeze must carry, or nil when the chain does not judge
// this candidate. It only reads the cache: a missing witness starts its build and is reported unavailable, so the leader's round never
// waits on the execution client.
func (x *ConsensusManager) primaryFreezeProof(plan *pendingHandoff, frozenParent []byte) ([]byte, error) {
	if len(plan.plan.CandidatePreimage) == 0 || !x.blockStore.PosServices().RequiresPrimaryProof() {
		return nil, nil
	}
	c, err := evmassign.DecodeCandidate(plan.plan.CandidatePreimage)
	if err != nil {
		return nil, errors.Join(ErrHandoffApproval, err)
	}
	return x.primaryProofFor(c, plan.plan.PrimaryPoPs, frozenParent)
}

// primaryProofFor is primaryFreezeProof over a decoded candidate.
func (x *ConsensusManager) primaryProofFor(c evmassign.Candidate, rawPoPs, frozenParent []byte) ([]byte, error) {
	if !x.blockStore.PosServices().RequiresPrimaryProof() || c.Kind != evmassign.KindPrimary {
		return nil, nil
	}
	pops, err := evmassign.DecodePoPs(rawPoPs)
	if err != nil {
		return nil, errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofMissing, err)
	}
	if len(frozenParent) != 32 {
		return nil, ErrHandoffApproval
	}
	parent, result := [32]byte(frozenParent), c.ResultID()
	witness, ok := x.cachedPrimaryWitness(parent, result)
	if !ok {
		x.prefetchPrimaryWitness(parent, result)
		return nil, fmt.Errorf("%w: the witness is being built", storage.ErrWitnessUnavailable)
	}
	return evmassign.PrimaryProof{Witness: witness, PoPs: pops}.Encode()
}

// checkPrimaryPoPs requires the EVM possession proofs exactly where the chain will judge them, and judges them in full on arrival: a
// primary candidate on a chain with the election pinned carries one valid proof per member, and the set is the one the election stored
// (so no member can fix a wrong set in a plan by sending its approval first); nothing else carries any. An EVM client that cannot say is
// a refusal for now, never an acceptance. Freeze admission re-judges everything against the frozen parent's certified state.
func (x *ConsensusManager) checkPrimaryPoPs(msg *abdrc.HandoffApprovalMsg, c evmassign.Candidate) error {
	svc := x.blockStore.PosServices()
	judged := len(msg.CandidatePreimage) != 0 && c.Kind == evmassign.KindPrimary && svc.RequiresPrimaryProof()
	if !judged {
		if len(msg.PrimaryPoPs) != 0 {
			return errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofUnexpected)
		}
		return nil
	}
	pops, err := evmassign.DecodePoPs(msg.PrimaryPoPs)
	if err != nil {
		return errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofMissing, err)
	}
	facts, err := x.primaryFacts(c.ResultID())
	if err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	if !facts.Published {
		return errors.Join(ErrHandoffApproval, evmassign.ErrNotPublished)
	}
	dep := evmassign.ElectionDeployment{Deployment: svc.Deployment.Deployment, Election: svc.Deployment.Election}
	_, set, err := evmassign.AssemblePoPs(c, dep, facts.Attempt, pops)
	if err != nil {
		return errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofRefused, err)
	}
	if set != facts.PopSetDigest {
		return errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofRefused, evmassign.ErrPrimaryPoP)
	}
	return nil
}
