package rootrecords

import (
	"errors"
	"fmt"
)

// The validator-registry projections (design section 4, schema v1 section 7). They extend the P85 ones without changing them: a VR
// generation acknowledges with AckBoundary instead of Ack, rejects with RejectOutput instead of a bare SessionClosed and retires per
// holder with HolderRetire instead of Retire. The root projection guarantees of design section 4.3 are properties of these methods:
//   - an Ack or RecoveryAck is immediately followed by the Boundary of the same result (AckBoundary appends both or neither);
//   - an OutputRejected and its SessionClosed come from one call, in that order (RejectOutput);
//   - a resolved result is never resolved again (both go through resolve);
//   - a holder-scoped retirement key is projected once (HolderRetire), so the SealRegistry's v2 dedup key never sees a second record.

// ErrBoundary reports an acknowledgement whose pending handoffs cannot form a Boundary: a recovery whose K is not exactly one root epoch
// after J (schema v1 section 7: installedRootEpoch = changesEpoch + 1 on recovery).
var ErrBoundary = errors.New("rootrecords: the acknowledged handoffs do not form a boundary")

// AckBoundary projects the acknowledgement of the pending handoffs of a validator-registry generation: the Ack (one pending step) or the
// RecoveryAck (a primary and its recovery) exactly as Ack projects it, followed at the same anchor by the result's Boundary. The Boundary's
// words are read from the same pending handoffs and never supplied: changesEpoch is J's root epoch, installedRootEpoch the root epoch of
// the installed step (J, or K on recovery), installedShardEpoch the acknowledged EVM epoch (K's on recovery), activationRound the
// installed step's first ordinary round. Only rejectedBitmap, the EVM-side verdicts of the committed RegistryChanges (bit i: entry i),
// comes from the caller.
func (s State) AckBoundary(round, timestamp uint64, resultID, assignmentID [32]byte, evmEpoch uint64, rejectedBitmap uint16) (State, []Record, error) {
	if len(s.Pending) == 0 {
		return State{}, nil, ErrNoPending
	}
	j, last := s.Pending[0], s.Pending[len(s.Pending)-1]
	recovered := len(s.Pending) == 2
	payload := BoundaryPayload(resultID, j.RootEpoch, last.RootEpoch, evmEpoch, last.First, recovered, rejectedBitmap)
	if recovered && (j.RootEpoch == ^uint64(0) || last.RootEpoch != j.RootEpoch+1) {
		return State{}, nil, fmt.Errorf("%w: K's root epoch %d after J's %d", ErrBoundary, last.RootEpoch, j.RootEpoch)
	}
	next, ack, err := s.Ack(round, timestamp, resultID, assignmentID, evmEpoch)
	if err != nil {
		return State{}, nil, err
	}
	next, bnd, err := next.append(KindBoundary, payload, Anchor{ack.Progress, ack.UCTime})
	if err != nil {
		return State{}, nil, err
	}
	return next, []Record{ack, bnd}, nil
}

// RejectOutput projects one RejectResult of a validator-registry generation: OutputRejected(resultID, reason, memberID, readyBitmap)
// followed at the same anchor by the result's SessionClosed. The result resolves once, so a second rejection, or a rejection of an
// acknowledged result, is ErrResultResolved and projects nothing; a payload the schema refuses (reason outside 1..3, memberID outside
// Invalid, readyBitmap outside Expired, a zero result id) is ErrPayload and projects nothing either.
func (s State) RejectOutput(resultID [32]byte, reason uint8, memberID uint64, readyBitmap uint16, round, timestamp uint64) (State, []Record, error) {
	return s.RejectOutputMissed(resultID, reason, memberID, readyBitmap, 0, 0, round, timestamp)
}

// RejectOutputMissed is RejectOutput with the certified handoff-PoP misses of an expiry (#1319): with a nonzero missedBitmap, a PoPMissed
// (resultID, deadline, missedBitmap) is projected between the OutputRejected and the SessionClosed, at the same anchor. Misses outside an
// Expired rejection are ErrPayload.
func (s State) RejectOutputMissed(resultID [32]byte, reason uint8, memberID uint64, readyBitmap uint16, deadline uint64, missedBitmap uint16,
	round, timestamp uint64) (State, []Record, error) {
	payload := OutputRejectedPayload(resultID, reason, memberID, readyBitmap)
	if err := checkPayload(KindOutputRejected, payload); err != nil {
		return State{}, nil, err
	}
	var missed []byte
	if missedBitmap != 0 {
		if reason != RejectExpired {
			return State{}, nil, fmt.Errorf("%w: certified misses outside an expiry", ErrPayload)
		}
		missed = PoPMissedPayload(resultID, deadline, missedBitmap)
		if err := checkPayload(KindPoPMissed, missed); err != nil {
			return State{}, nil, err
		}
	}
	progress, err := s.Progress(round)
	if err != nil {
		return State{}, nil, err
	}
	if s, err = s.resolve(resultID); err != nil {
		return State{}, nil, err
	}
	at := Anchor{progress, timestamp}
	s, rej, err := s.append(KindOutputRejected, payload, at)
	if err != nil {
		return State{}, nil, err
	}
	out := []Record{rej}
	if missed != nil {
		var m Record
		if s, m, err = s.append(KindPoPMissed, missed, at); err != nil {
			return State{}, nil, err
		}
		out = append(out, m)
	}
	s, closed, err := s.append(KindSessionClosed, resultID[:], at)
	if err != nil {
		return State{}, nil, err
	}
	return s, append(out, closed), nil
}

func (s State) holderRetiredAt(holder uint8, id, generation uint64) (int, bool) {
	for i, r := range s.HolderRetired {
		if r.Holder == holder && r.ID == id && r.Generation == generation {
			return i, true
		}
		if holderKeyLess(holder, id, generation, r) {
			return i, false
		}
	}
	return len(s.HolderRetired), false
}

// holderKeyLess reports whether (holder, id, generation) orders before r.
func holderKeyLess(holder uint8, id, generation uint64, r HolderRetired) bool {
	if holder != r.Holder {
		return holder < r.Holder
	}
	if id != r.ID {
		return id < r.ID
	}
	return generation < r.Generation
}

// IsHolderRetired reports the holder-scoped marker of a generation and the digest it retired with.
func (s State) IsHolderRetired(holder uint8, id, generation uint64) (ref [32]byte, ok bool) {
	if i, found := s.holderRetiredAt(holder, id, generation); found {
		return s.HolderRetired[i].RefDigest, true
	}
	return [32]byte{}, false
}

// HolderRetire projects the HolderRetirement of one identity generation at a liability holder whose liability anchors end at maxAnchor,
// at the carrying block, under Retire's rules for one key: a repeat with the same digest returns the state unchanged and no record,
// another digest is ErrRetirementConflict, a block below maxAnchor is ErrRetireEarly. The key is (holder, id, generation): the SealRegistry's
// v2 dedup key, so the same (id, generation) at two holders are two retirements.
func (s State) HolderRetire(holder uint8, id, generation uint64, ref [32]byte, maxAnchor, round, timestamp uint64) (State, *Record, error) {
	payload := HolderRetirementPayload(holder, id, generation, ref)
	if err := checkPayload(KindHolderRetirement, payload); err != nil {
		return State{}, nil, err
	}
	i, found := s.holderRetiredAt(holder, id, generation)
	if found {
		if s.HolderRetired[i].RefDigest != ref {
			return State{}, nil, fmt.Errorf("%w: holder %d %d/%d", ErrRetirementConflict, holder, id, generation)
		}
		return s, nil, nil
	}
	progress, err := s.Progress(round)
	if err != nil {
		return State{}, nil, err
	}
	if progress < maxAnchor {
		return State{}, nil, fmt.Errorf("%w: %d < %d", ErrRetireEarly, progress, maxAnchor)
	}
	s = s.clone()
	s.HolderRetired = append(s.HolderRetired, HolderRetired{})
	copy(s.HolderRetired[i+1:], s.HolderRetired[i:])
	s.HolderRetired[i] = HolderRetired{holder, id, generation, ref}
	next, rec, err := s.append(KindHolderRetirement, payload, Anchor{progress, timestamp})
	if err != nil {
		return State{}, nil, err
	}
	return next, &rec, nil
}

func holderRetiredAscending(r []HolderRetired) bool {
	for i := 1; i < len(r); i++ {
		if !holderKeyLess(r[i-1].Holder, r[i-1].ID, r[i-1].Generation, r[i]) {
			return false
		}
	}
	return true
}
