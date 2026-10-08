package storage

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrPosSource reports a root source state that is missing where the chain projects records, undecodable, or inconsistent with the
// committed history it is applied to.
var ErrPosSource = errors.New("invalid P85 root source state")

// posStep is the root source state of the block being executed. It starts from the parent's (carried in its control state) and is
// written back only when an event changed it, so an ordinary or empty block leaves the committed control digest alone. A chain whose
// control state carries no source state (a fixture that predates the projection) projects nothing.
type posStep struct {
	on      bool
	raw     []byte // the parent's encoding, kept so an unchanged state is not re-encoded
	state   rootrecords.State
	changed bool
	records []rootrecords.Record
}

// loadPos reads the source state of a control state.
func loadPos(c *evmroot.ControlState) (posStep, error) {
	if c == nil || len(c.Pos) == 0 {
		return posStep{}, nil
	}
	s, err := rootrecords.DecodeState(c.Pos)
	if err != nil {
		return posStep{}, errors.Join(ErrPosSource, err)
	}
	return posStep{on: true, raw: c.Pos, state: s}, nil
}

// store writes the state into c, which must be this block's private copy of the control state (a record transition builds a new one
// that does not carry the field).
func (p *posStep) store(c *evmroot.ControlState) {
	if !p.on {
		return
	}
	if p.changed {
		p.raw, p.changed = p.state.Bytes(), false
	}
	c.Pos = p.raw
}

func (p *posStep) set(s rootrecords.State) {
	p.state, p.changed = s, true
}

// block applies the ordinary committed block: only the first successor block at or after the activation changes the state.
func (p *posStep) block(epoch, round uint64) error {
	if !p.on {
		return nil
	}
	next, err := p.state.Block(epoch, round)
	if err != nil {
		return errors.Join(ErrPosSource, err)
	}
	if next.Frozen != p.state.Frozen || next.Epoch != p.state.Epoch {
		p.set(next)
	}
	return nil
}

// commit orders H of a committed handoff. assignment reports whether the handoff installs an EVM assignment (a retained candidate).
func (p *posStep) commit(r evmroot.OrderedHandoffRecord, assignment bool) error {
	if !p.on {
		return nil
	}
	var body [32]byte
	copy(body[:], r.NextBodyID)
	next, err := p.state.Commit(r.OrderedRound, r.Epoch+1, r.ActivationRound, assignment, body)
	if err != nil {
		return errors.Join(ErrPosSource, err)
	}
	p.set(next)
	return nil
}

// acknowledges reports whether a request certified for shard key is the EVM acknowledgement a pending handoff waits for: the shard was
// awaiting its installed epoch, its IR epoch has now caught up with the technical record's, and it is the designated EVM shard (another
// shard's epoch change is not an acknowledgement of the assignment).
func (p *posStep) acknowledges(awaiting bool, irEpoch, trEpoch uint64, key, evm types.PartitionShardID, evmFound bool) bool {
	return p.pendingAck() && awaiting && irEpoch == trEpoch && evmFound && key == evm
}

// pendingAck reports whether a committed assignment handoff still waits for the EVM acknowledgement.
func (p *posStep) pendingAck() bool { return p.on && len(p.state.Pending) > 0 }

// ack projects the EVM acknowledgement certified in the block of the given round and timestamp. The election result and the assignment
// ids come from the retained candidates of the pending handoffs, found by the body ids their commits named.
func (p *posStep) ack(candidates candidateSource, round, timestamp, evmEpoch uint64) error {
	if !p.pendingAck() {
		return nil
	}
	if candidates == nil {
		return fmt.Errorf("%w: no retained candidates to project the acknowledgement", ErrPosSource)
	}
	var result, assignment [32]byte
	for i, h := range p.state.Pending {
		preimage, err := candidates.HandoffCandidate(h.BodyID[:])
		if err != nil || len(preimage) == 0 {
			return errors.Join(ErrPosSource, fmt.Errorf("candidate of pending handoff %d unavailable", i), err)
		}
		c, err := evmassign.DecodeCandidate(preimage)
		if err != nil {
			return errors.Join(ErrPosSource, err)
		}
		if i == 0 {
			result = c.ResultID()
		} else if c.ResultID() != result {
			return fmt.Errorf("%w: the recovery names another election result than its primary", ErrPosSource)
		}
		if assignment, err = c.AssignmentID(); err != nil {
			return errors.Join(ErrPosSource, err)
		}
	}
	next, rec, err := p.state.Ack(round, timestamp, result, assignment, evmEpoch)
	if err != nil {
		return errors.Join(ErrPosSource, err)
	}
	p.set(next)
	p.records = append(p.records, rec)
	return nil
}
