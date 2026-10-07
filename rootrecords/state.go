package rootrecords

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"

	"github.com/unicitynetwork/bft-go-base/types"
)

// State is the root's own, copyable, canonically encoded source of the record log: the canonical progress tracker, the committed
// handoffs whose EVM acknowledgement is still pending, and the cursor of the log (count, tip, last anchors). It is a plain value, so every
// executed block carries its own and a fork never shares one, and it is committed by digest in the root's control state so a checkpoint
// can be verified. It changes only at events (an H, the end of a freeze, a projected record): progress at an ordinary block is a function
// of the state and the block's round, and the UC time of a record is the committed timestamp of the block that carried its event, so an
// empty block leaves the committed digest unchanged. The records themselves are not part of it: they are derived once, in order, and
// retained by the store (briefs/p85-pr1c-control-records.md sections 5 and 8).
//
// The registry-side reference model (Projector, Tracker, Clock) is a second implementation of the same progress rules and is compared
// against this one event by event in the tests.
type State struct {
	// Progress tracker. The current epoch advances from Offset on First; Last is its highest ordinary round. After H is ordered the
	// tracker is Frozen at Endpoint = p(e,h) until the successor (NextEpoch, from NextOffset on NextFirst) has an ordinary round.
	Epoch, Offset, First, Last       uint64
	Frozen                           bool
	Endpoint                         uint64
	NextEpoch, NextOffset, NextFirst uint64
	// Time is the committed UC time: the largest block timestamp so far.
	Time uint64
	// Pending are the committed handoffs that installed an assignment and wait for the EVM to acknowledge them, oldest first, at most
	// MaxPending (a primary and its recovery).
	Pending []PendingH
	// Log cursor.
	Count                  uint64
	Tip                    [32]byte
	LastProgress, LastTime uint64
}

// PendingH is one committed handoff that installed an EVM assignment: H was ordered in Epoch at round HRound, the successor starts at
// Offset on First (its activation round A*), and RootEpoch is the root epoch it activates.
type PendingH struct {
	Epoch, HRound, Offset, First, RootEpoch uint64
	// BodyID is the successor body the commit named: how the retained candidate of this handoff is found when it is acknowledged.
	BodyID [32]byte
}

// MaxPending is the longest unacknowledged chain: a primary and its one recovery.
const MaxPending = 2

var (
	// ErrState reports an encoded state that is not the canonical encoding of a consistent state.
	ErrState = errors.New("rootrecords: invalid root source state")
	// ErrNoPending reports an acknowledgement with no committed assignment handoff waiting for it.
	ErrNoPending = errors.New("rootrecords: no committed assignment handoff awaits an acknowledgement")
)

// NewState starts at genesis: offset zero on the epoch's first ordinary round.
func NewState(epoch, firstRound uint64) State {
	return State{Epoch: epoch, First: firstRound}
}

func (s State) clone() State {
	s.Pending = append([]PendingH(nil), s.Pending...)
	return s
}

func progressAt(offset, first, round uint64) (uint64, error) {
	if round < first {
		return 0, fmt.Errorf("%w: round %d precedes first round %d", ErrProgress, round, first)
	}
	p, carry := bits.Add64(offset, round-first, 0)
	if carry != 0 {
		return 0, fmt.Errorf("%w: progress overflows", ErrProgress)
	}
	return p, nil
}

// Progress is the canonical progress at an ordinary block of the current epoch with the given round: p(e,r) = offset + (r - first), or
// the endpoint while the freeze lasts.
func (s State) Progress(round uint64) (uint64, error) {
	if s.Frozen {
		return s.Endpoint, nil
	}
	return progressAt(s.Offset, s.First, round)
}

// Block applies one ordinary committed root block of the given epoch and round. It changes the state only when the block is the first
// of the successor at or after the activation round, which ends the freeze; every other block of the current epoch must lie at or after
// the epoch's first round. A block of the old epoch after H is a suffix block and a block of the successor before its first round
// precedes the activation: neither is ordinary progress and neither changes the state.
func (s State) Block(epoch, round uint64) (State, error) {
	if s.Frozen {
		if epoch != s.NextEpoch || round < s.NextFirst {
			return s, nil
		}
		if _, err := progressAt(s.NextOffset, s.NextFirst, round); err != nil {
			return State{}, err
		}
		s = s.clone()
		s.Epoch, s.Offset, s.First = s.NextEpoch, s.NextOffset, s.NextFirst
		s.Frozen, s.Endpoint, s.NextEpoch, s.NextOffset, s.NextFirst = false, 0, 0, 0, 0
		return s, nil
	}
	if epoch != s.Epoch {
		return State{}, fmt.Errorf("%w: ordinary round %d of epoch %d, the current epoch is %d", ErrProgress, round, epoch, s.Epoch)
	}
	if _, err := progressAt(s.Offset, s.First, round); err != nil {
		return State{}, err
	}
	return s, nil
}

// Commit orders H at round h of the current epoch: it fixes the endpoint p(e,h) and the successor's offset p(e,h)+1 on its activation
// round. A handoff that installs an assignment also waits, in Pending, for the EVM acknowledgement that will project its record.
func (s State) Commit(h, nextEpoch, nextFirst uint64, assignment bool, bodyID [32]byte) (State, error) {
	s = s.clone()
	if s.Frozen {
		return State{}, fmt.Errorf("%w: H of epoch %d is already ordered", ErrProgress, s.Epoch)
	}
	if nextEpoch <= s.Epoch || nextFirst == 0 || nextFirst <= h {
		return State{}, fmt.Errorf("%w: successor epoch %d first round %d after H %d", ErrProgress, nextEpoch, nextFirst, h)
	}
	p, err := progressAt(s.Offset, s.First, h)
	if err != nil {
		return State{}, err
	}
	if p == ^uint64(0) {
		return State{}, fmt.Errorf("%w: the successor offset overflows", ErrProgress)
	}
	if assignment && len(s.Pending) >= MaxPending {
		return State{}, fmt.Errorf("%w: more than %d unacknowledged handoffs", ErrProgress, MaxPending)
	}
	if assignment {
		s.Pending = append(s.Pending, PendingH{Epoch: s.Epoch, HRound: h, Offset: p + 1, First: nextFirst, RootEpoch: nextEpoch, BodyID: bodyID})
	}
	s.Frozen, s.Endpoint = true, p
	s.NextEpoch, s.NextOffset, s.NextFirst = nextEpoch, p+1, nextFirst
	return s, nil
}

// append links one record to the log: next index, the tip as predecessor, anchored now. The anchors may not fall below the last one.
func (s State) append(kind Kind, data []byte, at Anchor) (State, Record, error) {
	if at.UCTime < s.LastTime {
		at.UCTime = s.LastTime // committed times are strictly increasing since #445; the clamp keeps the log's anchors monotone regardless
	}
	if at.Progress < s.LastProgress {
		return State{}, Record{}, fmt.Errorf("%w: (%d,%d) after (%d,%d)", ErrMonotonic, at.Progress, at.UCTime, s.LastProgress, s.LastTime)
	}
	if at.UCTime == 0 {
		return State{}, Record{}, ErrNoUCTime
	}
	if err := checkPayload(kind, data); err != nil {
		return State{}, Record{}, err
	}
	r := Record{Index: s.Count, Predecessor: s.Tip, Kind: kind, Progress: at.Progress, UCTime: at.UCTime, Data: append([]byte(nil), data...)}
	r.ID = RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
	s.Count, s.Tip, s.LastProgress, s.LastTime = s.Count+1, r.ID, at.Progress, at.UCTime
	return s, r, nil
}

// Ack projects the EVM acknowledgement of the pending handoffs: Ack for one, RecoveryAck for a primary and its recovery. The offsets
// are the ones fixed when each H was committed, read here and never derived again. resultID is the election result, assignmentID the
// assignment hash of the last pending step (the recovery's, for two) and evmEpoch the acknowledged EVM assignment epoch. The record is
// anchored at the committed progress and UC time of the block that carried the acknowledgement (its round and timestamp).
func (s State) Ack(round, timestamp uint64, resultID, assignmentID [32]byte, evmEpoch uint64) (State, Record, error) {
	progress, err := s.Progress(round)
	if err != nil {
		return State{}, Record{}, err
	}
	at := Anchor{progress, timestamp}
	s = s.clone()
	switch len(s.Pending) {
	case 1:
		j := s.Pending[0]
		s.Pending = nil
		return s.append(KindAck, concat(resultID[:], word(j.HRound), word(j.Offset), word(j.First)), at)
	case 2:
		j, k := s.Pending[0], s.Pending[1]
		s.Pending = nil
		return s.append(KindRecoveryAck, concat(resultID[:], assignmentID[:], word(j.Offset), word(j.First), word(k.HRound), word(k.Offset), word(k.First),
			word(k.RootEpoch), word(evmEpoch)), at)
	}
	return State{}, Record{}, ErrNoPending
}

const stateDomain = "UNICITY_P85_ROOT_SOURCE_STATE"

// Bytes is the canonical encoding committed by Digest.
func (s State) Bytes() []byte {
	pending := make([]any, 0, len(s.Pending))
	for _, p := range s.Pending {
		pending = append(pending, []any{p.Epoch, p.HRound, p.Offset, p.First, p.RootEpoch, p.BodyID[:]})
	}
	b, err := types.Cbor.Marshal([]any{stateDomain, uint64(1), s.Epoch, s.Offset, s.First, s.Frozen, s.Endpoint, s.NextEpoch, s.NextOffset, s.NextFirst,
		pending, s.Count, s.Tip[:], s.LastProgress, s.LastTime})
	if err != nil {
		panic(err) // fixed shape of scalars and byte strings
	}
	return b
}

// Digest is the SHA-256 of the canonical encoding: what the root control state commits.
func (s State) Digest() [32]byte { return sha256.Sum256(s.Bytes()) }

// DecodeState parses the canonical encoding and refuses anything that is not exactly that or not internally consistent.
func DecodeState(data []byte) (State, error) {
	var f []any
	if err := types.Cbor.Unmarshal(data, &f); err != nil || len(f) != 15 {
		return State{}, fmt.Errorf("%w: shape", ErrState)
	}
	if d, ok := f[0].(string); !ok || d != stateDomain {
		return State{}, fmt.Errorf("%w: domain", ErrState)
	}
	if v, ok := f[1].(uint64); !ok || v != 1 {
		return State{}, fmt.Errorf("%w: version", ErrState)
	}
	u := func(i int) uint64 { v, _ := f[i].(uint64); return v }
	for _, i := range []int{2, 3, 4, 6, 7, 8, 9, 11, 13, 14} {
		if _, ok := f[i].(uint64); !ok {
			return State{}, fmt.Errorf("%w: field %d", ErrState, i)
		}
	}
	frozen, ok := f[5].(bool)
	tip, ok2 := f[12].([]byte)
	pend, ok3 := f[10].([]any)
	if !ok || !ok2 || len(tip) != 32 || !ok3 {
		return State{}, fmt.Errorf("%w: field type", ErrState)
	}
	s := State{Epoch: u(2), Offset: u(3), First: u(4), Frozen: frozen, Endpoint: u(6), NextEpoch: u(7), NextOffset: u(8), NextFirst: u(9),
		Count: u(11), LastProgress: u(13), LastTime: u(14)}
	copy(s.Tip[:], tip)
	for _, pv := range pend {
		pf, isArr := pv.([]any)
		if !isArr || len(pf) != 6 {
			return State{}, fmt.Errorf("%w: pending entry", ErrState)
		}
		var p PendingH
		var good [6]bool
		p.Epoch, good[0] = pf[0].(uint64)
		p.HRound, good[1] = pf[1].(uint64)
		p.Offset, good[2] = pf[2].(uint64)
		p.First, good[3] = pf[3].(uint64)
		p.RootEpoch, good[4] = pf[4].(uint64)
		body, bodyOK := pf[5].([]byte)
		good[5] = bodyOK && len(body) == 32
		copy(p.BodyID[:], body)
		for _, g := range good {
			if !g {
				return State{}, fmt.Errorf("%w: pending field", ErrState)
			}
		}
		s.Pending = append(s.Pending, p)
	}
	if err := s.consistent(); err != nil {
		return State{}, err
	}
	if !bytes.Equal(s.Bytes(), data) {
		return State{}, fmt.Errorf("%w: not canonical", ErrState)
	}
	return s, nil
}

// consistent holds for every state the methods produce: a frozen state names its successor after H, an unfrozen one carries no
// successor, the pending chain is bounded and a log with entries has a tip.
func (s State) consistent() error {
	switch {
	case s.First == 0:
		return fmt.Errorf("%w: epoch %d has no first round", ErrState, s.Epoch)
	case s.Frozen && (s.NextEpoch <= s.Epoch || s.NextFirst == 0 || s.NextOffset != s.Endpoint+1):
		return fmt.Errorf("%w: frozen without a consistent successor", ErrState)
	case !s.Frozen && (s.Endpoint != 0 || s.NextEpoch != 0 || s.NextOffset != 0 || s.NextFirst != 0):
		return fmt.Errorf("%w: successor without H", ErrState)
	case len(s.Pending) > MaxPending:
		return fmt.Errorf("%w: %d pending handoffs", ErrState, len(s.Pending))
	case len(s.Pending) > 0 && !s.Frozen && s.Pending[len(s.Pending)-1].RootEpoch > s.Epoch:
		return fmt.Errorf("%w: pending handoff beyond the current epoch", ErrState)
	case (s.Count == 0) != (s.Tip == [32]byte{}):
		return fmt.Errorf("%w: log count %d with tip %x", ErrState, s.Count, s.Tip)
	}
	return nil
}
