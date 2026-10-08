package rootrecords

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
	"sort"

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
	// Progress tracker. The current epoch advances from Offset on First. After H is ordered the tracker is Frozen at Endpoint = p(e,h)
	// until the successor (NextEpoch, from NextOffset on NextFirst) has an ordinary round.
	Epoch, Offset, First             uint64
	Frozen                           bool
	Endpoint                         uint64
	NextEpoch, NextOffset, NextFirst uint64
	// Pending are the committed handoffs that installed an assignment and wait for the EVM to acknowledge them, oldest first, at most
	// MaxPending (a primary and its recovery).
	Pending []PendingH
	// Awaiting are the closed epochs whose signing liability has no CloseLiability yet, oldest first: an epoch enters when the freeze of
	// an assignment handoff ends (the successor's first ordinary block) and leaves with its closure. The first closure of an epoch is the
	// only one.
	Awaiting []Awaiting
	// Closed are the epochs whose closure the log carries, with the H round each closed at, ascending by epoch and never pruned. A
	// Closure record names its H round (not its epoch, which is no part of the record identity), so this list is what lets a reader of
	// the log authenticate the closed epoch a record is served with.
	Closed []Awaiting
	// Retired are the (id, generation) retirement markers with the reference digest each retired with, ascending by key: a generation
	// retires once, a repeat of the same request is no new record and a conflicting one is refused.
	Retired []Retired
	// Resolved are the Election results the log has closed or acknowledged, ascending. A result resolves once: custody refuses a second
	// SessionClosed, or an Ack, of a session that is no longer open, and its record cursor is strict, so a repeat would block every later
	// record. The list grows by one per resolved election and is never pruned (replay needs it).
	Resolved [][32]byte
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

// Retired is one retirement marker.
type Retired struct {
	ID, Generation uint64
	RefDigest      [32]byte
}

// Awaiting is one closed epoch awaiting its CloseLiability: the epoch H ended and the round H was ordered at.
type Awaiting struct{ Epoch, HRound uint64 }

// MaxPending is the longest unacknowledged chain: a primary and its one recovery.
const MaxPending = 2

var (
	// ErrState reports an encoded state that is not the canonical encoding of a consistent state.
	ErrState = errors.New("rootrecords: invalid root source state")
	// ErrNotAwaiting reports a closure of an epoch that has no closure outstanding: never closed by a handoff, or closed already.
	ErrNotAwaiting = errors.New("rootrecords: no closure is outstanding for the epoch")
	// ErrResultResolved reports a projection for an Election result the log already closed or acknowledged.
	ErrResultResolved = errors.New("rootrecords: the election result is already resolved")
	// ErrRetirementConflict reports a second retirement of a generation with another reference digest.
	ErrRetirementConflict = errors.New("rootrecords: the generation retired with another reference digest")
	// ErrRetireEarly reports a retirement anchored below the generation's last liability anchor.
	ErrRetireEarly = errors.New("rootrecords: retirement progress is below the maximum liability anchor")
	// ErrNoPending reports an acknowledgement with no committed assignment handoff waiting for it.
	ErrNoPending = errors.New("rootrecords: no committed assignment handoff awaits an acknowledgement")
)

// NewState starts at genesis: offset zero on the epoch's first ordinary round.
func NewState(epoch, firstRound uint64) State {
	return State{Epoch: epoch, First: firstRound}
}

func (s State) clone() State {
	s.Pending = append([]PendingH(nil), s.Pending...)
	s.Awaiting = append([]Awaiting(nil), s.Awaiting...)
	s.Closed = append([]Awaiting(nil), s.Closed...)
	s.Retired = append([]Retired(nil), s.Retired...)
	s.Resolved = append([][32]byte(nil), s.Resolved...)
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
		if n := len(s.Pending); n > 0 && s.Pending[n-1].RootEpoch == s.NextEpoch {
			// an assignment handoff ended the epoch: its signing liability waits for the CloseLiability in this first ordinary block
			s.Awaiting = append(s.Awaiting, Awaiting{Epoch: s.Epoch, HRound: s.Pending[n-1].HRound})
		}
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
	// Committed timestamps never decrease (ADR 0013, #479): equal seconds are valid, so successive records may share a UC time. A record's
	// UC time can therefore never fall below the previous record's; if one does, the block is refused rather than its anchor rewritten.
	if at.Progress < s.LastProgress || at.UCTime < s.LastTime {
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
	if len(s.Pending) == 0 {
		return State{}, Record{}, ErrNoPending
	}
	if s, err = s.resolve(resultID); err != nil {
		return State{}, Record{}, err
	}
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

// Close projects the CloseLiability of an awaiting epoch: data is the exact ClosureData payload the root verified. The epoch leaves the
// awaiting list (so a repeat is ErrNotAwaiting, never a second record) and the record is anchored at the progress of the block that
// carries the control and that block's committed timestamp, which fixes p_close and its UC time.
func (s State) Close(epoch uint64, data []byte, round, timestamp uint64) (State, Record, error) {
	i := -1
	for k, a := range s.Awaiting {
		if a.Epoch == epoch {
			i = k
		}
	}
	if i < 0 {
		return State{}, Record{}, fmt.Errorf("%w: epoch %d", ErrNotAwaiting, epoch)
	}
	progress, err := s.Progress(round)
	if err != nil {
		return State{}, Record{}, err
	}
	s = s.clone()
	closed := s.Awaiting[i]
	s.Awaiting = append(s.Awaiting[:i], s.Awaiting[i+1:]...)
	at := sort.Search(len(s.Closed), func(k int) bool { return s.Closed[k].Epoch >= epoch })
	s.Closed = append(s.Closed[:at], append([]Awaiting{closed}, s.Closed[at:]...)...)
	next, rec, err := s.append(KindClosure, data, Anchor{progress, timestamp})
	if err != nil {
		return State{}, Record{}, err
	}
	rec.ClosedEpoch = epoch
	return next, rec, nil
}

// SessionClosed projects the closing of an Election result by a root decision (an Abort of its primary before H, or a RejectResult),
// anchored at the carrying block.
func (s State) SessionClosed(resultID [32]byte, round, timestamp uint64) (State, Record, error) {
	progress, err := s.Progress(round)
	if err != nil {
		return State{}, Record{}, err
	}
	s, err = s.resolve(resultID)
	if err != nil {
		return State{}, Record{}, err
	}
	return s.append(KindSessionClosed, resultID[:], Anchor{progress, timestamp})
}

// IsResolved reports whether the log has closed or acknowledged the result.
func (s State) IsResolved(resultID [32]byte) bool {
	i := sort.Search(len(s.Resolved), func(i int) bool { return bytes.Compare(s.Resolved[i][:], resultID[:]) >= 0 })
	return i < len(s.Resolved) && s.Resolved[i] == resultID
}

// resolve returns a copy of s with the result resolved, or ErrResultResolved.
func (s State) resolve(resultID [32]byte) (State, error) {
	if s.IsResolved(resultID) {
		return State{}, fmt.Errorf("%w: %x", ErrResultResolved, resultID)
	}
	s = s.clone()
	i := sort.Search(len(s.Resolved), func(i int) bool { return bytes.Compare(s.Resolved[i][:], resultID[:]) >= 0 })
	s.Resolved = append(s.Resolved, [32]byte{})
	copy(s.Resolved[i+1:], s.Resolved[i:])
	s.Resolved[i] = resultID
	return s, nil
}

func (s State) retiredAt(id, generation uint64) (int, bool) {
	for i, r := range s.Retired {
		if r.ID == id && r.Generation == generation {
			return i, true
		}
		if r.ID > id || (r.ID == id && r.Generation > generation) {
			return i, false
		}
	}
	return len(s.Retired), false
}

// IsRetired reports the marker of a generation and the digest it retired with.
func (s State) IsRetired(id, generation uint64) (ref [32]byte, ok bool) {
	if i, found := s.retiredAt(id, generation); found {
		return s.Retired[i].RefDigest, true
	}
	return [32]byte{}, false
}

// Retire projects the Retirement of a generation whose liability anchors end at maxAnchor, at the carrying block. A repeat with the
// same digest returns the state unchanged and no record (the existing outcome); another digest is a conflict; a block below maxAnchor
// is too early. Progress is monotonic and is not inferred from request ordering.
func (s State) Retire(id, generation uint64, ref [32]byte, maxAnchor, round, timestamp uint64) (State, *Record, error) {
	i, found := s.retiredAt(id, generation)
	if found {
		if s.Retired[i].RefDigest != ref {
			return State{}, nil, fmt.Errorf("%w: %d/%d", ErrRetirementConflict, id, generation)
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
	s.Retired = append(s.Retired, Retired{})
	copy(s.Retired[i+1:], s.Retired[i:])
	s.Retired[i] = Retired{id, generation, ref}
	next, rec, err := s.append(KindRetirement, concat(word(id), word(generation), ref[:]), Anchor{progress, timestamp})
	if err != nil {
		return State{}, nil, err
	}
	return next, &rec, nil
}

// HRoundAwaiting is the round H was ordered at for an awaiting epoch.
func (s State) HRoundAwaiting(epoch uint64) (uint64, bool) {
	for _, a := range s.Awaiting {
		if a.Epoch == epoch {
			return a.HRound, true
		}
	}
	return 0, false
}

const stateDomain = "UNICITY_P85_ROOT_SOURCE_STATE"

// Bytes is the canonical encoding committed by Digest.
func (s State) Bytes() []byte {
	pending := make([]any, 0, len(s.Pending))
	for _, p := range s.Pending {
		pending = append(pending, []any{p.Epoch, p.HRound, p.Offset, p.First, p.RootEpoch, p.BodyID[:]})
	}
	awaiting := make([]any, 0, len(s.Awaiting))
	for _, a := range s.Awaiting {
		awaiting = append(awaiting, []any{a.Epoch, a.HRound})
	}
	closed := make([]any, 0, len(s.Closed))
	for _, a := range s.Closed {
		closed = append(closed, []any{a.Epoch, a.HRound})
	}
	retired := make([]any, 0, len(s.Retired))
	for _, x := range s.Retired {
		retired = append(retired, []any{x.ID, x.Generation, x.RefDigest[:]})
	}
	resolved := make([]any, 0, len(s.Resolved))
	for _, x := range s.Resolved {
		resolved = append(resolved, x[:])
	}
	b, err := types.Cbor.Marshal([]any{stateDomain, uint64(1), s.Epoch, s.Offset, s.First, s.Frozen, s.Endpoint, s.NextEpoch, s.NextOffset, s.NextFirst,
		pending, awaiting, retired, resolved, s.Count, s.Tip[:], s.LastProgress, s.LastTime, closed})
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
	if err := types.Cbor.Unmarshal(data, &f); err != nil || len(f) != 19 {
		return State{}, fmt.Errorf("%w: shape", ErrState)
	}
	if d, ok := f[0].(string); !ok || d != stateDomain {
		return State{}, fmt.Errorf("%w: domain", ErrState)
	}
	if v, ok := f[1].(uint64); !ok || v != 1 {
		return State{}, fmt.Errorf("%w: version", ErrState)
	}
	u := func(i int) uint64 { v, _ := f[i].(uint64); return v }
	for _, i := range []int{2, 3, 4, 6, 7, 8, 9, 14, 16, 17} {
		if _, ok := f[i].(uint64); !ok {
			return State{}, fmt.Errorf("%w: field %d", ErrState, i)
		}
	}
	frozen, ok := f[5].(bool)
	tip, ok2 := f[15].([]byte)
	pend, ok3 := f[10].([]any)
	await, ok4 := f[11].([]any)
	ret, ok5 := f[12].([]any)
	res, ok6 := f[13].([]any)
	clo, ok7 := f[18].([]any)
	if !ok || !ok2 || len(tip) != 32 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
		return State{}, fmt.Errorf("%w: field type", ErrState)
	}
	s := State{Epoch: u(2), Offset: u(3), First: u(4), Frozen: frozen, Endpoint: u(6), NextEpoch: u(7), NextOffset: u(8), NextFirst: u(9),
		Count: u(14), LastProgress: u(16), LastTime: u(17)}
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
	for _, av := range await {
		af, isArr := av.([]any)
		if !isArr || len(af) != 2 {
			return State{}, fmt.Errorf("%w: awaiting entry", ErrState)
		}
		var a Awaiting
		var e1, e2 bool
		a.Epoch, e1 = af[0].(uint64)
		a.HRound, e2 = af[1].(uint64)
		if !e1 || !e2 {
			return State{}, fmt.Errorf("%w: awaiting field", ErrState)
		}
		s.Awaiting = append(s.Awaiting, a)
	}
	for _, cv := range clo {
		cf, isArr := cv.([]any)
		if !isArr || len(cf) != 2 {
			return State{}, fmt.Errorf("%w: closed entry", ErrState)
		}
		var a Awaiting
		var e1, e2 bool
		a.Epoch, e1 = cf[0].(uint64)
		a.HRound, e2 = cf[1].(uint64)
		if !e1 || !e2 {
			return State{}, fmt.Errorf("%w: closed field", ErrState)
		}
		s.Closed = append(s.Closed, a)
	}
	for _, rv := range ret {
		rf, isArr := rv.([]any)
		if !isArr || len(rf) != 3 {
			return State{}, fmt.Errorf("%w: retired entry", ErrState)
		}
		var x Retired
		var g1, g2 bool
		x.ID, g1 = rf[0].(uint64)
		x.Generation, g2 = rf[1].(uint64)
		ref, g3 := rf[2].([]byte)
		if !g1 || !g2 || !g3 || len(ref) != 32 {
			return State{}, fmt.Errorf("%w: retired field", ErrState)
		}
		copy(x.RefDigest[:], ref)
		s.Retired = append(s.Retired, x)
	}
	for _, rv := range res {
		id, isBytes := rv.([]byte)
		if !isBytes || len(id) != 32 {
			return State{}, fmt.Errorf("%w: resolved entry", ErrState)
		}
		var x [32]byte
		copy(x[:], id)
		s.Resolved = append(s.Resolved, x)
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
	case !awaitingAscending(s.Awaiting):
		return fmt.Errorf("%w: awaiting epochs not strictly ascending", ErrState)
	case !awaitingAscending(s.Closed):
		return fmt.Errorf("%w: closed epochs not strictly ascending", ErrState)
	case !resolvedAscending(s.Resolved):
		return fmt.Errorf("%w: resolved results not strictly ascending", ErrState)
	case !retiredAscending(s.Retired):
		return fmt.Errorf("%w: retired markers not strictly ascending", ErrState)
	case (s.Count == 0) != (s.Tip == [32]byte{}):
		return fmt.Errorf("%w: log count %d with tip %x", ErrState, s.Count, s.Tip)
	}
	return nil
}

func awaitingAscending(a []Awaiting) bool {
	for i := 1; i < len(a); i++ {
		if a[i].Epoch <= a[i-1].Epoch {
			return false
		}
	}
	return true
}

func retiredAscending(r []Retired) bool {
	for i := 1; i < len(r); i++ {
		if r[i].ID < r[i-1].ID || (r[i].ID == r[i-1].ID && r[i].Generation <= r[i-1].Generation) {
			return false
		}
	}
	return true
}

func resolvedAscending(r [][32]byte) bool {
	for i := 1; i < len(r); i++ {
		if bytes.Compare(r[i-1][:], r[i][:]) >= 0 {
			return false
		}
	}
	return true
}

// ClosedEpochOf is the closed epoch a Closure of the given H round belongs to: the epoch of the closed entry that closed at that round.
// An epoch closes once and an H round ends one epoch, so the answer is unique; false when the log has closed no epoch at that round.
func (s State) ClosedEpochOf(hRound uint64) (uint64, bool) {
	for _, c := range s.Closed {
		if c.HRound == hRound {
			return c.Epoch, true
		}
	}
	return 0, false
}
