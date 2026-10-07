package rootrecords

import (
	"errors"
	"fmt"
)

var (
	// ErrProgress reports an ordinary round, epoch or handoff round the canonical progress function does not define.
	ErrProgress = errors.New("rootrecords: round outside the canonical progress function")
)

type epochPos struct{ epoch, offset, first uint64 }

// Tracker is the canonical progress p(e,r) = offset_e + (r - firstRound_e) of ordinary current-epoch rounds. Genesis has offset zero.
// When H is ordered at round h of epoch e, the successor starts at offset p(e,h)+1 on its first round A*; until the successor has an
// ordinary committed round, progress stays at H's endpoint p(e,h). Seal rounds, arrival time and old-epoch rounds above h do not move
// it, and skipped ordinary rounds count (the difference is in rounds, not in blocks).
type Tracker struct {
	cur      epochPos
	last     uint64  // highest ordinary round observed in cur
	endpoint *uint64 // set once H is ordered: progress is frozen here until the successor has progress
	next     *epochPos
}

// NewGenesis starts at offset zero on the epoch's first ordinary round.
func NewGenesis(epoch, firstRound uint64) *Tracker {
	return &Tracker{cur: epochPos{epoch, 0, firstRound}, last: firstRound}
}

func (t *Tracker) at(p epochPos, round uint64) (uint64, error) {
	if round < p.first {
		return 0, fmt.Errorf("%w: round %d precedes first round %d of epoch %d", ErrProgress, round, p.first, p.epoch)
	}
	return p.offset + (round - p.first), nil
}

// At is p(e,r) for the current epoch.
func (t *Tracker) At(epoch, round uint64) (uint64, error) {
	if epoch != t.cur.epoch {
		return 0, fmt.Errorf("%w: epoch %d is not the current epoch %d", ErrProgress, epoch, t.cur.epoch)
	}
	return t.at(t.cur, round)
}

// Progress is the canonical progress now.
func (t *Tracker) Progress() uint64 {
	if t.endpoint != nil {
		return *t.endpoint
	}
	p, _ := t.at(t.cur, t.last)
	return p
}

// Observe records an ordinary committed round. An observation of the pending successor's epoch at or after its first round ends the
// freeze; an observation of the old epoch after H, or any other epoch, changes nothing and is refused so a suffix round is never
// silently absorbed.
func (t *Tracker) Observe(epoch, round uint64) error {
	if t.endpoint != nil {
		if t.next == nil || epoch != t.next.epoch {
			return fmt.Errorf("%w: epoch %d after H of epoch %d", ErrProgress, epoch, t.cur.epoch)
		}
		if round < t.next.first {
			return fmt.Errorf("%w: round %d precedes successor first round %d", ErrProgress, round, t.next.first)
		}
		t.cur, t.last, t.endpoint, t.next = *t.next, round, nil, nil
		return nil
	}
	if epoch != t.cur.epoch || round < t.last {
		return fmt.Errorf("%w: ordinary round %d of epoch %d does not extend (%d,%d)", ErrProgress, round, epoch, t.cur.epoch, t.last)
	}
	t.last = round
	return nil
}

// OrderH orders H at ordinary round h of the current epoch. It fixes the endpoint p(e,h) and the successor's offset p(e,h)+1, and
// returns that offset. The successor epoch must be later; its first round is numbered by its own epoch, so nothing else relates it to h.
func (t *Tracker) OrderH(h, nextEpoch, nextFirst uint64) (uint64, error) {
	if t.endpoint != nil {
		return 0, fmt.Errorf("%w: H of epoch %d is already ordered", ErrProgress, t.cur.epoch)
	}
	if nextEpoch <= t.cur.epoch || nextFirst == 0 {
		return 0, fmt.Errorf("%w: successor epoch %d first round %d", ErrProgress, nextEpoch, nextFirst)
	}
	if h < t.last {
		return 0, fmt.Errorf("%w: H round %d is below observed round %d", ErrProgress, h, t.last)
	}
	p, err := t.at(t.cur, h)
	if err != nil {
		return 0, err
	}
	t.endpoint = &p
	t.next = &epochPos{nextEpoch, p + 1, nextFirst}
	return p + 1, nil
}

// enter makes the pending successor current without ordinary progress; the recovery acknowledgement uses it to order K's H inside J's
// epoch in the same record.
func (t *Tracker) enter() {
	t.cur, t.last, t.endpoint, t.next = *t.next, t.next.first, nil, nil
}

// Frozen reports that H is ordered and the successor has no ordinary progress yet.
func (t *Tracker) Frozen() bool { return t.endpoint != nil }
