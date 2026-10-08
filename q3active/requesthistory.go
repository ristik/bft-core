package q3active

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
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

// RequestHistory is the storage.RequestHistory of a runtime: the committed activation chain of a shard, rebuilt on every call from
// the verified Q3 history (never cached across an activation), the retained candidates and the trusted anchor. An activation is
// minted only by storage.ActivationFromVerifiedV3 from the entry the history verified and the candidate the entry's committed
// record binds: the weighted mirrored context is derived from the coupling, not asserted.
type RequestHistory struct {
	rt  *Runtime
	cfg RequestHistoryConfig
}

var _ storage.RequestHistory = (*RequestHistory)(nil)

// RequestHistory is the weighted request-view history of this runtime.
func (r *Runtime) RequestHistory(cfg RequestHistoryConfig) (*RequestHistory, error) {
	if cfg.Candidates == nil || cfg.Anchor == nil || cfg.Network == 0 || cfg.Version == 0 || cfg.HashAlg == 0 {
		return nil, fmt.Errorf("%w: incomplete configuration", ErrRequestHistory)
	}
	return &RequestHistory{rt: r, cfg: cfg}, nil
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
	hist := h.rt.History() // one immutable view for the whole traversal
	genesis, err := hist.ForEpoch(1)
	if err != nil {
		return nil, errors.Join(ErrRequestHistory, err)
	}
	pdr, err := h.cfg.Anchor(partition, shard)
	if err != nil || pdr == nil {
		return nil, errors.Join(ErrRequestHistory, err)
	}
	if pdr.PartitionID != partition || !pdr.ShardID.Equal(shard) {
		return nil, fmt.Errorf("%w: the anchor is of shard %s-%s, not %s-%s", ErrRequestHistory, pdr.PartitionID, pdr.ShardID, partition, shard)
	}
	genesisID := genesis.BodyID()
	anchor, err := storage.NewRequestAnchor(pdr, h.cfg.HashAlg, genesis.Epoch(), genesisID[:], h.cfg.Version)
	if err != nil {
		return nil, err
	}
	chain := []*storage.RequestActivation{anchor}
	tip := hist.Tip().Epoch()
	for epoch := uint64(2); epoch <= tip; epoch++ {
		e, err := hist.ForEpoch(epoch)
		if err != nil {
			return nil, errors.Join(ErrRequestHistory, err) // a missing interior epoch is not the end of the history
		}
		if err := h.rt.Admit(epoch); err != nil {
			return nil, errors.Join(ErrRequestHistory, err)
		}
		v, _, ok := e.Handoff()
		if !ok {
			return nil, fmt.Errorf("%w: epoch %d is not an activation", ErrRequestHistory, epoch)
		}
		last := chain[len(chain)-1]
		bodyID := e.BodyID()
		if e.RootOnly() {
			cont, err := storage.RequestContinuationFromVerifiedV3(last, e, nil, h.cfg.HashAlg, h.cfg.Version)
			if err != nil {
				return nil, errors.Join(ErrRequestHistory, err)
			}
			chain = append(chain, cont)
			continue
		}
		preimage, err := h.cfg.Candidates.HandoffCandidate(bodyID[:])
		if err != nil {
			return nil, errors.Join(ErrRequestHistory, err)
		}
		if len(preimage) == 0 {
			return nil, fmt.Errorf("%w: epoch %d committed an assignment whose candidate is not retained", ErrRequestHistory, epoch)
		}
		c, err := evmassign.DecodeCandidate(preimage)
		if err != nil {
			return nil, errors.Join(ErrRequestHistory, err)
		}
		evm, err := c.Successor()
		if err != nil {
			return nil, errors.Join(ErrRequestHistory, err)
		}
		for _, ch := range c.Changes {
			if ch.Kind != evmassign.ChangeReplaceShardValidators {
				return nil, errors.Join(ErrRequestHistory, evmassign.ErrUnsupportedChange)
			}
			_, succ, err := evmassign.DecodeReplaceShardValidators(ch.Payload)
			if err != nil {
				return nil, errors.Join(ErrRequestHistory, err)
			}
			if succ.PartitionID == partition && succ.ShardID.Equal(shard) {
				return nil, fmt.Errorf("%w: epoch %d replaces the validators of this shard", ErrRequestHistory, epoch)
			}
		}
		if evm.PartitionID != partition || !evm.ShardID.Equal(shard) {
			// the assignment of the designated EVM shard is not this shard's: its history continues under this root interval
			cont, err := storage.RequestContinuationFromVerifiedV3(last, e, preimage, h.cfg.HashAlg, h.cfg.Version)
			if err != nil {
				return nil, errors.Join(ErrRequestHistory, err)
			}
			chain = append(chain, cont)
			continue
		}
		if !bytes.Equal(v.Record.PredecessorBodyID, last.RootBody()) {
			return nil, fmt.Errorf("%w: epoch %d does not follow the previous root interval", ErrRequestHistory, epoch)
		}
		act, err := storage.ActivationFromVerifiedV3(e, v.Record, preimage, h.cfg.HashAlg, h.cfg.Version)
		if err != nil {
			return nil, errors.Join(ErrRequestHistory, err)
		}
		chain = append(chain, act)
	}
	return chain, nil
}
