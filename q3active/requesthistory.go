package q3active

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrRequestHistory is returned when the committed request history of a shard cannot be served from the verified history: a
	// missing or conflicting retained candidate, or a shard whose assignment history this source does not serve. It is also
	// storage.ErrAssignmentHistory, so a resolver never falls back to the last committed state.
	ErrRequestHistory = fmt.Errorf("q3active: no verified request history for the shard: %w", storage.ErrAssignmentHistory)
)

// CandidateSource is the root's durable store of retained handoff candidates, by committed body identity (a BlockStore).
type CandidateSource interface {
	HandoffCandidate(bodyID []byte) ([]byte, error)
}

// AnchorSource is the trusted configuration a shard started with, before any committed assignment (the genesis shard config).
type AnchorSource func(partition types.PartitionID, shard types.ShardID) (*types.PartitionDescriptionRecord, error)

// RequestHistoryConfig names everything a request history is built from. Nothing in it selects a policy: the weighted request
// context of an activation comes from the verified history's entry and its committed candidate alone.
type RequestHistoryConfig struct {
	Candidates CandidateSource
	Anchor     AnchorSource
	HashAlg    crypto.Hash
	Network    uint64
	// Version is the certified request protocol version the contexts are labelled with.
	Version uint64
}

// RequestHistory is the storage.RequestHistory of a runtime: the committed activation chain of a shard, derived from the verified
// Q3 history, the retained candidates and the trusted anchor. An activation is minted only by storage.ActivationFromVerifiedV3 from the
// entry the history verified and the candidate the entry's committed record binds: the weighted mirrored context is derived from the
// coupling, not asserted.
//
// The chain of a shard is derived incrementally (#1032): each installed epoch is admitted, its candidate loaded, decoded and verified,
// and its link validated exactly once, and the validated storage.RequestChain is kept per shard together with the claims of the epochs
// it covers. A resolution under the same verified history is then a map lookup; a history extended by an activation only derives the
// new epochs. A history whose covered claims differ from the remembered ones (it is not an extension of the history the chain was
// derived from) discards the shard's chain and derives it again from the anchor; Invalidate discards every chain (recovery).
type RequestHistory struct {
	rt  *Runtime
	cfg RequestHistoryConfig

	mu     sync.Mutex
	chains map[types.PartitionShardID]*shardChain
}

// shardChain is the validated chain of one shard and the verified history entries it was derived from.
type shardChain struct {
	hist   *q3format.History // the immutable history the chain was last checked against
	claims []q3format.Claim  // claims[i] is the claim of epoch i+1, for every epoch the chain covers
	chain  *storage.RequestChain
}

var (
	_ storage.RequestHistory     = (*RequestHistory)(nil)
	_ storage.RequestChainSource = (*RequestHistory)(nil)
)

// RequestHistory is the weighted request-view history of this runtime.
func (r *Runtime) RequestHistory(cfg RequestHistoryConfig) (*RequestHistory, error) {
	if cfg.Candidates == nil || cfg.Anchor == nil || cfg.Network == 0 || cfg.Version == 0 || cfg.HashAlg == 0 {
		return nil, fmt.Errorf("%w: incomplete configuration", ErrRequestHistory)
	}
	return &RequestHistory{rt: r, cfg: cfg, chains: make(map[types.PartitionShardID]*shardChain)}, nil
}

// Invalidate forgets every derived chain: the next resolution of each shard derives it again from the anchor. A recovery that replaces
// the root's committed state calls it, so nothing derived before the recovery is served after it without being derived again.
func (h *RequestHistory) Invalidate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.chains)
}

func (h *RequestHistory) Network() uint64 { return h.cfg.Network }
func (h *RequestHistory) Version() uint64 { return h.cfg.Version }

// RootIdentity is the root epoch and body identity of the assignment that authorises the given root round, from the verified
// history's own intervals. A round before the history's first epoch, or of an epoch whose installation is not complete, is an error.
func (h *RequestHistory) RootIdentity(round uint64) (uint64, []byte, error) {
	e, err := h.rt.History().ForRound(round)
	if err != nil {
		return 0, nil, errors.Join(ErrRequestHistory, err)
	}
	if err := h.rt.Admit(e.Epoch()); err != nil {
		return 0, nil, errors.Join(ErrRequestHistory, err)
	}
	id := e.BodyID()
	return e.Epoch(), id[:], nil
}

// Chain is the shard's committed request-authorization history: its anchor, then, for every root epoch the verified history activated, either the
// real assignment the activation installs for this shard or a continuation of the assignment already in force, whose authorising root
// identity is the activation's. A continuation is issued exactly when the activation leaves this shard unchanged: a root-only activation
// (the commitment of its operator candidate proves it), or a coupled one whose retained candidate designates another shard and replaces none
// of this shard's validators. A candidate that is not retained, or not the committed one, is missing history, never a reason to continue.
// An activation that replaces the validators of this shard is not served (ErrRequestHistory): that history is not derived here.
func (h *RequestHistory) Chain(partition types.PartitionID, shard types.ShardID) ([]*storage.RequestActivation, error) {
	c, err := h.RequestChain(partition, shard)
	if err != nil {
		return nil, err
	}
	return c.Activations(), nil
}

// RequestChain is Chain as the validated storage.RequestChain, maintained incrementally: see RequestHistory. The chain returned is
// immutable and covers every epoch of the verified history; an epoch that cannot be served is the same error Chain returns, and the
// epochs before it stay derived.
func (h *RequestHistory) RequestChain(partition types.PartitionID, shard types.ShardID) (*storage.RequestChain, error) {
	hist := h.rt.History() // one immutable view for the whole derivation
	key := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
	h.mu.Lock()
	defer h.mu.Unlock()
	sc := h.chains[key]
	if sc != nil && sc.hist != hist && !extends(hist, sc.claims) {
		sc = nil // not an extension of what the chain was derived from: derive it again from the anchor
		delete(h.chains, key)
	}
	if sc == nil {
		genesis, chain, err := h.anchor(hist, partition, shard)
		if err != nil {
			return nil, err
		}
		sc = &shardChain{hist: hist, claims: []q3format.Claim{genesis.Claim()}, chain: chain}
		h.chains[key] = sc
	}
	sc.hist = hist
	tip := hist.Tip().Epoch()
	for epoch := uint64(len(sc.claims)) + 1; epoch <= tip; epoch++ {
		e, next, err := h.derive(hist, sc.chain, partition, shard, epoch)
		if err != nil {
			return nil, err
		}
		if sc.chain, err = sc.chain.Extend(next); err != nil {
			return nil, errors.Join(ErrRequestHistory, err)
		}
		sc.claims = append(sc.claims, e.Claim())
	}
	return sc.chain, nil
}

// extends reports whether the history holds exactly the given claims for its first epochs.
func extends(hist *q3format.History, claims []q3format.Claim) bool {
	if hist.Tip().Epoch() < uint64(len(claims)) {
		return false
	}
	for i, c := range claims {
		e, err := hist.ForEpoch(uint64(i) + 1)
		if err != nil || e.Claim() != c {
			return false
		}
	}
	return true
}

// anchor is the validated one-entry chain of the shard's trusted anchor under the history's genesis epoch.
func (h *RequestHistory) anchor(hist *q3format.History, partition types.PartitionID, shard types.ShardID) (q3format.Entry, *storage.RequestChain, error) {
	genesis, err := hist.ForEpoch(1)
	if err != nil {
		return genesis, nil, errors.Join(ErrRequestHistory, err)
	}
	pdr, err := h.cfg.Anchor(partition, shard)
	if err != nil || pdr == nil {
		return genesis, nil, errors.Join(ErrRequestHistory, err)
	}
	if pdr.PartitionID != partition || !pdr.ShardID.Equal(shard) {
		return genesis, nil, fmt.Errorf("%w: the anchor is of shard %s-%s, not %s-%s", ErrRequestHistory, pdr.PartitionID, pdr.ShardID, partition, shard)
	}
	genesisID := genesis.BodyID()
	anchor, err := storage.NewRequestAnchor(pdr, h.cfg.HashAlg, genesis.Epoch(), genesisID[:], h.cfg.Version)
	if err != nil {
		return genesis, nil, err
	}
	chain, err := storage.NewRequestChain(h.cfg.Network, anchor)
	if err != nil {
		return genesis, nil, errors.Join(ErrRequestHistory, err)
	}
	return genesis, chain, nil
}

// derive is the entry of the shard's chain for one activated epoch, following the chain derived so far.
func (h *RequestHistory) derive(hist *q3format.History, chain *storage.RequestChain, partition types.PartitionID, shard types.ShardID, epoch uint64) (q3format.Entry, *storage.RequestActivation, error) {
	last := chain.Tip()
	e, err := hist.ForEpoch(epoch)
	if err != nil {
		// a missing interior epoch is not the end of the history (defense in depth: a verified history is contiguous, so this is
		// unreachable from a real runtime)
		return e, nil, errors.Join(ErrRequestHistory, err)
	}
	if err := h.rt.Admit(epoch); err != nil {
		return e, nil, errors.Join(ErrRequestHistory, err)
	}
	v, _, ok := e.Handoff()
	if !ok {
		return e, nil, fmt.Errorf("%w: epoch %d is not an activation", ErrRequestHistory, epoch)
	}
	bodyID := e.BodyID()
	if e.RootOnly() {
		cont, err := storage.RequestContinuationFromVerifiedV3(last, e, nil, h.cfg.HashAlg, h.cfg.Version)
		if err != nil {
			return e, nil, errors.Join(ErrRequestHistory, err)
		}
		return e, cont, nil
	}
	preimage, err := h.cfg.Candidates.HandoffCandidate(bodyID[:])
	if err != nil {
		return e, nil, errors.Join(ErrRequestHistory, err)
	}
	if len(preimage) == 0 {
		return e, nil, fmt.Errorf("%w: epoch %d committed an assignment whose candidate is not retained", ErrRequestHistory, epoch)
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil {
		return e, nil, errors.Join(ErrRequestHistory, err)
	}
	evm, err := c.Successor()
	if err != nil {
		return e, nil, errors.Join(ErrRequestHistory, err)
	}
	for _, ch := range c.Changes {
		if ch.Kind != evmassign.ChangeReplaceShardValidators {
			return e, nil, errors.Join(ErrRequestHistory, evmassign.ErrUnsupportedChange)
		}
		_, succ, err := evmassign.DecodeReplaceShardValidators(ch.Payload)
		if err != nil {
			return e, nil, errors.Join(ErrRequestHistory, err)
		}
		if succ.PartitionID == partition && succ.ShardID.Equal(shard) {
			return e, nil, fmt.Errorf("%w: epoch %d replaces the validators of this shard", ErrRequestHistory, epoch)
		}
	}
	if evm.PartitionID != partition || !evm.ShardID.Equal(shard) {
		// the assignment of the designated EVM shard is not this shard's: its history continues under this root interval
		cont, err := storage.RequestContinuationFromVerifiedV3(last, e, preimage, h.cfg.HashAlg, h.cfg.Version)
		if err != nil {
			return e, nil, errors.Join(ErrRequestHistory, err)
		}
		return e, cont, nil
	}
	// defense in depth behind the verified q3format history (contiguous and predecessor-linked): unreachable from a verified runtime
	if !bytes.Equal(v.Record.PredecessorBodyID, last.RootBody()) {
		return e, nil, fmt.Errorf("%w: epoch %d does not follow the previous root interval", ErrRequestHistory, epoch)
	}
	act, err := storage.ActivationFromVerifiedV3(e, v.Record, preimage, h.cfg.HashAlg, h.cfg.Version)
	if err != nil {
		return e, nil, errors.Join(ErrRequestHistory, err)
	}
	return e, act, nil
}
