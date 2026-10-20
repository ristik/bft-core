package rootevidence

import (
	"bytes"
	"fmt"
)

// Assignment is the part of the certified EVM view of an assignment that decides the evidence cutoff (Evidence.sol _requireTimely).
type Assignment struct {
	OffsetSet  bool
	Offset     uint64 // ordinary progress at the assignment's first round
	FirstRound uint64
	HKnown     bool // the last round the replaced assignment's committee was ordinary-final for is imported
	HRound     uint64
	Closed     bool // the closure is authenticated
	PClose     uint64
}

// Terms are the captured policy windows of the assignment, in ordinary progress rounds.
type Terms struct {
	EvidenceWindow       uint64
	SuffixEvidenceWindow uint64
}

// Retention says whether a statement of the given voting round may be dropped from the service's required archive, from certified values only:
// it must be certain that the contract can no longer admit it. It mirrors the contract's cutoffs and is deliberately never optimistic:
//
//   - the assignment not yet activated, or the round's class not final (H unknown: the contract provisionally classifies every vote as
//     ordinary, but an old suffix vote has no expiry before closure): keep;
//   - a round above H: kept until the closure is authenticated and progress is strictly beyond pClose plus the suffix window;
//   - an ordinary round: dropped once progress is strictly beyond its offence progress plus the evidence window (the cutoff is inclusive);
//   - a round before the assignment's first round can never be admitted.
//
// A pending case, an uncertain submission or an unreconciled prefix are the caller's to add: Retention only answers the time obligation.
func Retention(a Assignment, t Terms, progress, round uint64) (prune bool, reason string) {
	switch {
	case !a.OffsetSet:
		return false, "assignment not activated"
	case round < a.FirstRound:
		return true, "round before the assignment's first round"
	case a.HKnown && round > a.HRound:
		if !a.Closed {
			return false, "suffix round, closure not authenticated"
		}
		if progress > a.PClose+t.SuffixEvidenceWindow {
			return true, "suffix window elapsed after the closure"
		}
		return false, "inside the suffix evidence window"
	case !a.HKnown:
		return false, "class not final: the round may still become a suffix round"
	}
	if progress > a.Offset+(round-a.FirstRound)+t.EvidenceWindow {
		return true, "ordinary evidence window elapsed"
	}
	return false, "inside the ordinary evidence window"
}

// Prune deletes every slot for which decide answers true. An error of decide keeps the slot: an unavailable or unverifiable view is not proof
// that an obligation ended. It returns the number of slots deleted and the first error met.
func (j *Journal) Prune(decide func(*SlotRecord) (bool, error)) (int, error) {
	var slots []Slot
	it := j.db.Find([]byte("s/"))
	for ; it.Valid(); it.Next() {
		k := it.Key()
		if !bytes.HasPrefix(k, []byte("s/")) {
			break
		}
		var rec SlotRecord
		if err := it.Value(&rec); err != nil {
			_ = it.Close()
			return 0, err
		}
		slots = append(slots, Slot{rec.Author, rec.Epoch, rec.Round})
	}
	if err := it.Close(); err != nil {
		return 0, err
	}
	var first error
	n := 0
	for _, s := range slots {
		rec, err := j.Get(s)
		if err != nil || rec == nil {
			continue
		}
		drop, err := decide(rec)
		if err != nil {
			if first == nil {
				first = fmt.Errorf("slot %s epoch %d round %d kept: %w", s.Author, s.Epoch, s.Round, err)
			}
			continue
		}
		if drop {
			if err := j.Delete(s); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, first
}
