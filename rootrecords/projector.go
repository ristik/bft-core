package rootrecords

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
)

var (
	// ErrClosureConflict reports a second closure of one (epoch, H record, H round) with a different identity.
	ErrClosureConflict = errors.New("rootrecords: a different closure of the same H is already imported")
	// ErrClosureEarly reports a closure before the successor has ordinary progress, or of an epoch that is not before the current one:
	// the closure rides the successor's first ordinary control record, so none can anchor at H's endpoint or precede every H.
	ErrClosureEarly = errors.New("rootrecords: closure before the successor has ordinary progress")
	// ErrNoUCTime reports a record ordered before any UC time was imported: a record without a time anchor can only fail exits closed.
	ErrNoUCTime = errors.New("rootrecords: no UC time imported")
)

// ClosureKey identifies one closure: the epoch, the H record and the original round of H. Proof encodings, signer subsets and terminal
// seal rounds are not part of it, so no proof can open a second closure or move the first.
type ClosureKey struct {
	Epoch     uint64
	HRecordID [32]byte
	HRound    uint64
}

// Closure is the identity a closure commits to (the contract's ClosureData without the key fields).
type Closure struct {
	AssignmentID     [32]byte
	TerminalRoot     [32]byte
	ExposureDigest   [32]byte
	KeyHistoryDigest [32]byte
}

type closed struct {
	key ClosureKey
	id  Closure
	at  Anchor
}

// Projector turns verified root events into the linked record log. Every anchor comes from its own Tracker and Clock.
type Projector struct {
	Log      Log
	Tracker  *Tracker
	Clock    Clock
	closures map[uint64]closed // by closed epoch: an epoch has exactly one liability closure
}

// NewProjector starts at genesis: offset zero, the epoch's first ordinary round.
func NewProjector(epoch, firstRound uint64) *Projector {
	return &Projector{Tracker: NewGenesis(epoch, firstRound), closures: map[uint64]closed{}}
}

// Anchor is the current canonical progress and UC time.
func (p *Projector) Anchor() Anchor { return Anchor{p.Tracker.Progress(), p.Clock.Time()} }

// Import advances UC time from a verified root certificate's origin.
func (p *Projector) Import(o evmroot.RootOrigin) error { return p.Clock.Import(o) }

func (p *Projector) emit(kind Kind, words ...[]byte) (Record, error) {
	if p.Clock.Time() == 0 {
		return Record{}, ErrNoUCTime
	}
	return p.Log.Append(kind, concat(words...), p.Anchor())
}

// atomically runs a step that moves the tracker and then appends; any failure restores the tracker so a refused record leaves no trace.
func (p *Projector) atomically(step func() (Record, error)) (Record, error) {
	snap := *p.Tracker
	r, err := step()
	if err != nil {
		*p.Tracker = snap
	}
	return r, err
}

// SessionClosed records the exact pre-H abort or ordered rejection of one result.
func (p *Projector) SessionClosed(resultID [32]byte) (Record, error) {
	return p.emit(KindSessionClosed, resultID[:])
}

// Ack records the successor's activation after H was ordered at hRound: the offset is derived, never supplied.
func (p *Projector) Ack(resultID [32]byte, hRound, nextEpoch, firstRound uint64) (Record, error) {
	return p.atomically(func() (Record, error) {
		offset, err := p.Tracker.OrderH(hRound, nextEpoch, firstRound)
		if err != nil {
			return Record{}, err
		}
		return p.emit(KindAck, resultID[:], word(hRound), word(offset), word(firstRound))
	})
}

// RecoveryAck records J's activation and K's H ordered at jHRound of J's epoch, with both offsets derived.
func (p *Projector) RecoveryAck(resultID, recoveryAssignmentID [32]byte, hRound, jEpoch, jFirst, jHRound, kEpoch, kFirst, kEVMEpoch uint64) (Record, error) {
	return p.atomically(func() (Record, error) {
		jOffset, err := p.Tracker.OrderH(hRound, jEpoch, jFirst)
		if err != nil {
			return Record{}, err
		}
		p.Tracker.enter()
		kOffset, err := p.Tracker.OrderH(jHRound, kEpoch, kFirst)
		if err != nil {
			return Record{}, err
		}
		return p.emit(KindRecoveryAck, resultID[:], recoveryAssignmentID[:], word(jOffset), word(jFirst), word(jHRound), word(kOffset), word(kFirst), word(kEpoch), word(kEVMEpoch))
	})
}

// Close imports a liability closure. An epoch closes once: the first closure fixes p_close and its UC time and appends a record; an
// identical repeat (same epoch, H record, H round and value) returns the first anchor and appends nothing; any other closure of the
// epoch, whether another value for the key or another H record or round, is ErrClosureConflict. Custody applies the same rule.
func (p *Projector) Close(k ClosureKey, c Closure) (Anchor, bool, error) {
	// One epoch closes once: the same key and value is a repeat, any other key (another H record or H round) or value is a conflict.
	if first, ok := p.closures[k.Epoch]; ok {
		if first.key != k || first.id != c {
			return Anchor{}, false, fmt.Errorf("%w: epoch %d round %d", ErrClosureConflict, k.Epoch, k.HRound)
		}
		return first.at, false, nil
	}
	// A closure rides the successor's first ordinary control record: some H must have been ordered and its successor must have made
	// ordinary progress, so the closed epoch is strictly before the epoch now advancing and the freeze is over.
	if p.Tracker.Frozen() || k.Epoch >= p.Tracker.Epoch() {
		return Anchor{}, false, ErrClosureEarly
	}
	r, err := p.emit(KindClosure, c.AssignmentID[:], word(k.HRound), k.HRecordID[:], c.TerminalRoot[:], c.ExposureDigest[:], c.KeyHistoryDigest[:])
	if err != nil {
		return Anchor{}, false, err
	}
	at := Anchor{r.Progress, r.UCTime}
	p.closures[k.Epoch] = closed{k, c, at}
	return at, true, nil
}

// Closed reports the anchor of an imported closure; an obligation stays open until one exists.
func (p *Projector) Closed(k ClosureKey) (Anchor, bool) {
	c, ok := p.closures[k.Epoch]
	if !ok || c.key != k {
		return Anchor{}, false
	}
	return c.at, true
}

// Retire records the retirement of an identity generation with the digest of its references.
func (p *Projector) Retire(id, generation uint64, refDigest [32]byte) (Record, error) {
	return p.emit(KindRetirement, word(id), word(generation), refDigest[:])
}
