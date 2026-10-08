package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// PrimaryWitnessSource is the execution client side of a primary candidate's EVM proof. Nothing it returns is trusted: block admission
// verifies the witness against the frozen parent's certified state root, and the facts only filter what this root accepts into a plan.
type PrimaryWitnessSource interface {
	// PrimaryWitness builds the storage-proof witness of the election and custody state at the frozen parent for a result
	// (evmstate.BuildPrimaryWitness).
	PrimaryWitness(ctx context.Context, frozenParent []byte, resultID [32]byte) ([]byte, error)
	// PrimaryFacts reads the result's proven facts at the client's current head. A published result's attempt and possession-proof set are
	// fixed, so they are what an arriving plan's proofs are checked against.
	PrimaryFacts(ctx context.Context, resultID [32]byte) (evmassign.PrimaryFacts, error)
}

const (
	// primaryWitnessBuildTimeout bounds one background build; primaryWitnessRetry spaces the retries after a failed one.
	primaryWitnessBuildTimeout = 60 * time.Second
	primaryWitnessRetry        = 2 * time.Second
)

type parkedApproval struct {
	msg    *abdrc.HandoffApprovalMsg
	result [32]byte
	at     time.Time
}

const (
	maxParkedApprovals = 32
	parkedApprovalTTL  = 2 * time.Minute
)

type primaryWitnessKey struct{ parent, result [32]byte }

// primaryCache holds what the proposal path reads without blocking: the witness of the one (frozen parent, result) in play, built in the
// background, and the facts of published results (immutable once published).
//
// INVARIANT the facts cache depends on: the facts are read at the execution client's current head, while Freeze admission judges the result at
// the frozen parent. That is sound because a published result's attempt and possession-proof set (the only facts used here) are written once
// by finalizeCandidate and never change afterwards; only the `lost`/open words can, and those are judged at the parent by the admission itself.
type primaryCache struct {
	mu    sync.Mutex
	facts map[[32]byte]evmassign.PrimaryFacts
	// background fact fetches (single flight per result, with a backoff after a failure) and the approvals that arrived before their
	// result's facts did, one per signer, judged when the facts land
	factsInflight map[[32]byte]bool
	factsFailed   map[[32]byte]time.Time
	parked        map[string]parkedApproval
	key           primaryWitnessKey
	witness       []byte
	inflight      bool
	failedAt      time.Time
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

// cachedPrimaryFacts is the intake's only read: the cache, never the execution client.
func (x *ConsensusManager) cachedPrimaryFacts(result [32]byte) (evmassign.PrimaryFacts, bool) {
	x.primaryCache.mu.Lock()
	defer x.primaryCache.mu.Unlock()
	f, ok := x.primaryCache.facts[result]
	return f, ok
}

func (x *ConsensusManager) storePrimaryFacts(result [32]byte, f evmassign.PrimaryFacts) {
	x.primaryCache.mu.Lock()
	defer x.primaryCache.mu.Unlock()
	if x.primaryCache.facts == nil || len(x.primaryCache.facts) > 8 {
		x.primaryCache.facts = map[[32]byte]evmassign.PrimaryFacts{}
	}
	x.primaryCache.facts[result] = f
}

// primaryFactsSync returns the published facts of a result, from the cache or by asking the execution client in the caller's goroutine.
// Only the operator's own endpoints use it (plan, intent, endorse): never the consensus message loop.
func (x *ConsensusManager) primaryFactsSync(ctx context.Context, result [32]byte) (evmassign.PrimaryFacts, error) {
	if f, ok := x.cachedPrimaryFacts(result); ok {
		return f, nil
	}
	src, err := x.primarySource()
	if err != nil {
		return evmassign.PrimaryFacts{}, err
	}
	f, err := src.PrimaryFacts(ctx, result)
	if err != nil {
		return f, errors.Join(storage.ErrWitnessUnavailable, err)
	}
	if f.Published {
		x.storePrimaryFacts(result, f)
	}
	return f, nil
}

// kickPrimaryFacts starts the background fetch of a result's facts unless they are cached, in flight, or the last try just failed. When
// they land, the approvals parked for the result are judged.
func (x *ConsensusManager) kickPrimaryFacts(result [32]byte) {
	src, err := x.primarySource()
	if err != nil {
		return
	}
	c := &x.primaryCache
	c.mu.Lock()
	if _, ok := c.facts[result]; ok || c.factsInflight[result] || time.Since(c.factsFailed[result]) < primaryWitnessRetry {
		c.mu.Unlock()
		return
	}
	if c.factsInflight == nil {
		c.factsInflight = map[[32]byte]bool{}
	}
	c.factsInflight[result] = true
	c.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), primaryWitnessBuildTimeout)
		defer cancel()
		f, err := src.PrimaryFacts(ctx, result)
		c.mu.Lock()
		delete(c.factsInflight, result)
		ok := err == nil && f.Published
		if !ok {
			if c.factsFailed == nil {
				c.factsFailed = map[[32]byte]time.Time{}
			}
			c.factsFailed[result] = time.Now()
		}
		c.mu.Unlock()
		if !ok {
			x.log.Debug("the primary result's facts are not available yet", "err", err)
			return
		}
		x.storePrimaryFacts(result, f)
		x.releaseParkedApprovals(result)
	}()
}

// parkApproval keeps an approval whose result's facts have not landed, one per signer and bounded, to be judged when they do. An honest
// approval that arrives first is therefore not lost; a flood of them cannot grow the set.
func (x *ConsensusManager) parkApproval(msg *abdrc.HandoffApprovalMsg, result [32]byte) {
	c := &x.primaryCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.parked == nil {
		c.parked = map[string]parkedApproval{}
	}
	for k, p := range c.parked {
		if time.Since(p.at) > parkedApprovalTTL {
			delete(c.parked, k)
		}
	}
	if _, replace := c.parked[msg.Signer]; !replace && len(c.parked) >= maxParkedApprovals {
		return
	}
	c.parked[msg.Signer] = parkedApproval{msg: msg, result: result, at: time.Now()}
}

func (x *ConsensusManager) releaseParkedApprovals(result [32]byte) {
	c := &x.primaryCache
	c.mu.Lock()
	var release []*abdrc.HandoffApprovalMsg
	for k, p := range c.parked {
		if p.result == result {
			release = append(release, p.msg)
			delete(c.parked, k)
		}
	}
	c.mu.Unlock()
	for _, m := range release {
		sink := x.approvalSink
		if sink == nil {
			sink = func(m *abdrc.HandoffApprovalMsg) error { return x.onHandoffApprovalMsg(context.Background(), m) }
		}
		if err := sink(m); err != nil {
			x.log.Debug("a parked handoff approval was refused when its facts landed", "signer", m.Signer, "err", err)
		}
	}
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
		var b struct {
			w   []byte
			err error
		}
		b.w, b.err = src.PrimaryWitness(ctx, parent[:], result)
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

// checkPrimaryPoPsShape requires the EVM possession proofs exactly where the chain will judge them and nothing else: a primary candidate on a
// chain with the election pinned carries a well-formed list, everything else carries none. It needs no EVM state.
func (x *ConsensusManager) checkPrimaryPoPsShape(msg *abdrc.HandoffApprovalMsg, c evmassign.Candidate) error {
	svc := x.blockStore.PosServices()
	judged := len(msg.CandidatePreimage) != 0 && c.Kind == evmassign.KindPrimary && svc.RequiresPrimaryProof()
	if !judged {
		if len(msg.PrimaryPoPs) != 0 {
			return errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofUnexpected)
		}
		return nil
	}
	if _, err := evmassign.DecodePoPs(msg.PrimaryPoPs); err != nil {
		return errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofMissing, err)
	}
	return nil
}

// judgePoPs judges the proofs in full against the election's published facts: one valid proof per member, and the set the election stored (so
// no member can fix a wrong set in a plan by sending its approval first). Freeze admission re-judges everything against the frozen parent.
func (x *ConsensusManager) judgePoPs(msg *abdrc.HandoffApprovalMsg, c evmassign.Candidate, facts evmassign.PrimaryFacts) error {
	svc := x.blockStore.PosServices()
	pops, err := evmassign.DecodePoPs(msg.PrimaryPoPs)
	if err != nil {
		return errors.Join(ErrHandoffApproval, storage.ErrPrimaryProofMissing, err)
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

// checkPrimaryPoPs is the operator-side check (plan, intent): shape, then the proofs against facts read in the caller's own goroutine.
func (x *ConsensusManager) checkPrimaryPoPs(msg *abdrc.HandoffApprovalMsg, c evmassign.Candidate) error {
	if err := x.checkPrimaryPoPsShape(msg, c); err != nil {
		return err
	}
	if len(msg.PrimaryPoPs) == 0 {
		return nil
	}
	facts, err := x.primaryFactsSync(context.Background(), c.ResultID())
	if err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	return x.judgePoPs(msg, c, facts)
}

// errPrimaryFactsPending reports an approval parked until the result's facts land.
var errPrimaryFactsPending = errors.New("the primary result's facts are being fetched; the approval is held")

// judgeApprovalPoPs is the consensus loop's judgement of an arriving approval's proofs, run only AFTER its signatures and Prepare binding
// were verified (so only a real old-committee member can cost anything). It never calls the execution client: it reads the facts cache, and
// on a miss starts the background fetch and parks the approval to be judged when the facts land.
func (x *ConsensusManager) judgeApprovalPoPs(msg *abdrc.HandoffApprovalMsg) error {
	if len(msg.CandidatePreimage) == 0 || !x.blockStore.PosServices().RequiresPrimaryProof() {
		return nil
	}
	c, err := evmassign.DecodeCandidate(msg.CandidatePreimage)
	if err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	if c.Kind != evmassign.KindPrimary {
		return nil
	}
	result := c.ResultID()
	facts, ok := x.cachedPrimaryFacts(result)
	if !ok {
		x.parkApproval(msg, result)
		x.kickPrimaryFacts(result)
		return errors.Join(ErrHandoffApproval, errPrimaryFactsPending)
	}
	return x.judgePoPs(msg, c, facts)
}

// prefetchFactsForPlan starts the background fetch of the result's facts when the operator's own plan is held, before any approval arrives.
func (x *ConsensusManager) prefetchFactsForPlan(preimage []byte) {
	if len(preimage) == 0 || !x.blockStore.PosServices().RequiresPrimaryProof() {
		return
	}
	if c, err := evmassign.DecodeCandidate(preimage); err == nil && c.Kind == evmassign.KindPrimary {
		x.kickPrimaryFacts(c.ResultID())
	}
}

// warmPrimaryFacts reads a primary plan's facts in the operator's own goroutine, so that its own approval (and every approval that follows)
// finds them cached.
func (x *ConsensusManager) warmPrimaryFacts(ctx context.Context, preimage []byte) error {
	if len(preimage) == 0 || !x.blockStore.PosServices().RequiresPrimaryProof() {
		return nil
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil || c.Kind != evmassign.KindPrimary {
		return nil
	}
	if _, err := x.primaryFactsSync(ctx, c.ResultID()); err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	return nil
}

// judgeApproval is judgeApprovalPoPs behind a seam, so a test can observe whether and when intake reaches the proof judgement.
func (x *ConsensusManager) judgeApproval(msg *abdrc.HandoffApprovalMsg) error {
	if x.judgeHook != nil {
		return x.judgeHook(msg)
	}
	return x.judgeApprovalPoPs(msg)
}
