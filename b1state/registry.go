package b1state

import (
	"errors"
	"math"
)

// The B1 registry keeps every installed validator epoch forever (briefs/b1-any-age-contract.md section 1): no window, no ring, no pruning,
// no deletion. Entries are looked up directly by epoch. Two cursors are kept apart: I, the imported tip (the greatest contiguously installed
// epoch, the durable import cursor), and the usable origin (U, O) that certificate acceptance reads; preloaded epochs may be ahead of U.
var (
	ErrAppendGap                = errors.New("b1state: append is not the successor of the imported tip")
	ErrImmutable                = errors.New("b1state: an installed entry cannot change")
	ErrTooManyEpochs            = errors.New("b1state: more epochs than the profile admits per block")
	ErrAppendStartNotIncreasing = errors.New("b1state: successor start does not exceed the tip start")
	ErrAppendClosesUsableOrigin = errors.New("b1state: successor start would close the usable epoch at or below the origin round")
	ErrOriginEpochRegression    = errors.New("b1state: usable origin epoch moves backwards")
	ErrOriginBeyondImportedTip  = errors.New("b1state: usable origin epoch is beyond the imported tip")
	ErrOriginRoundRegression    = errors.New("b1state: origin round moves backwards")
	ErrOriginBeforeStart        = errors.New("b1state: origin round precedes the usable epoch's start")
	ErrOriginAtOrAfterEnd       = errors.New("b1state: origin round is at or past the usable epoch's end")
	ErrFirstOriginBeforeGenesis = errors.New("b1state: first usable origin epoch precedes the genesis epoch")
	// ErrImportedUsableMismatch: while a usable origin exists, the usable epoch is the imported tip after every update. There is no preload
	// mode (briefs/b1-any-age-contract.md section preload): the block that installs entries is the block that moves the origin onto the new tip.
	ErrImportedUsableMismatch = errors.New("b1state: the usable epoch is not the imported tip")
)

// Registry is the append-only model of the registry's B1 words.
type Registry struct {
	Genesis uint64 // g: the first epoch of this deployment (zero is a valid epoch)
	Tip     uint64 // I: the imported tip
	Ready   bool   // a usable origin exists
	U, O    uint64 // usable origin epoch and root round, meaningful once Ready
	entries map[uint64]Entry
}

// NewRegistry installs the genesis entry: open, I = g, no usable origin yet.
func NewRegistry(genesis Entry) (*Registry, error) {
	if err := genesis.Validate(); err != nil {
		return nil, err
	}
	if genesis.BodyKind != 1 || genesis.End != nil {
		return nil, ErrHistory
	}
	return &Registry{Genesis: genesis.Epoch, Tip: genesis.Epoch, entries: map[uint64]Entry{genesis.Epoch: clone(genesis)}}, nil
}

// Entry is the direct lookup by epoch.
func (r *Registry) Entry(epoch uint64) (Entry, bool) {
	e, ok := r.entries[epoch]
	return clone(e), ok
}

// Len is the number of installed epochs, derived from the cursors: I - g + 1.
func (r *Registry) Len() uint64 { return r.Tip - r.Genesis + 1 }

func (r *Registry) copy() *Registry {
	c := *r
	c.entries = make(map[uint64]Entry, len(r.entries))
	for k, v := range r.entries {
		c.entries[k] = clone(v)
	}
	return &c
}

func sameImmutable(a, b Entry) bool {
	if a.Epoch != b.Epoch || a.BodyKind != b.BodyKind || a.BodyID != b.BodyID || a.ActivationCommitID != b.ActivationCommitID || a.Start != b.Start ||
		a.SigningScheme != b.SigningScheme || a.SigningConfigHash != b.SigningConfigHash || len(a.Members) != len(b.Members) {
		return false
	}
	for i := range a.Members {
		if a.Members[i] != b.Members[i] {
			return false
		}
	}
	return true
}

// append installs the successor of the tip: closes the tip at the successor's start, writes the entry, advances I. A repeat of an installed
// epoch is an idempotent no-op when every immutable field matches (and any asserted end equals the stored one); otherwise it is refused.
func (r *Registry) append(e Entry, w *Changes) (installed bool, err error) {
	if e.Epoch <= r.Tip {
		have, ok := r.entries[e.Epoch]
		if !ok || !sameImmutable(have, e) {
			return false, ErrImmutable
		}
		if e.End != nil && (have.End == nil || *have.End != *e.End) {
			return false, ErrImmutable
		}
		return false, nil
	}
	if r.Tip == math.MaxUint64 {
		return false, ErrOverflow
	}
	if e.Epoch != r.Tip+1 {
		return false, ErrAppendGap
	}
	if e.BodyKind == 1 {
		return false, ErrHistory
	}
	if err = e.Validate(); err != nil {
		return false, err
	}
	tip := r.entries[r.Tip]
	if tip.End != nil {
		return false, ErrImmutable // only the tip is open
	}
	if e.Start <= tip.Start {
		return false, ErrAppendStartNotIncreasing
	}
	if r.Ready && r.Tip == r.U && e.Start <= r.O {
		return false, ErrAppendClosesUsableOrigin
	}
	end := e.Start
	tip.End = &end
	r.entries[r.Tip] = tip
	w.insert(EntrySlot(tip.Epoch, 5), Word(end))
	w.insert(EntrySlot(tip.Epoch, 6), Word(1))
	open := clone(e)
	open.End = nil // an entry is installed open; its successor closes it, exactly once
	r.entries[e.Epoch] = open
	putEntry(w.insert, open)
	r.Tip = e.Epoch
	return true, nil
}

// advance moves the usable origin to (epoch, round) after the update's appends (I is the post-append tip).
func (r *Registry) advance(epoch, round uint64, w *Changes) error {
	if r.Ready {
		if epoch < r.U {
			return ErrOriginEpochRegression
		}
		if round < r.O {
			return ErrOriginRoundRegression
		}
	} else if epoch < r.Genesis {
		return ErrFirstOriginBeforeGenesis
	}
	target, ok := r.entries[epoch]
	if !ok {
		return ErrOriginBeyondImportedTip
	}
	if round < target.Start {
		return ErrOriginBeforeStart
	}
	if target.End != nil && round >= *target.End {
		return ErrOriginAtOrAfterEnd
	}
	r.U, r.O = epoch, round
	if !r.Ready {
		r.Ready = true
		w.insert(FixedSlot("b1.originReady"), Word(1))
	}
	w.insert(FixedSlot("origin.rootEpoch"), Word(epoch))
	w.insert(FixedSlot("clock.rootRound"), Word(round))
	return nil
}

// Apply is one atomic ordinary update: it appends u.NewEntries (at most b, contiguous after the tip), closes the old tip once, advances the
// imported tip, then moves the usable origin to (u.OriginEpoch, u.OriginRound) under the write-side guards. On any error the receiver is
// unchanged and nothing is written.
func (r *Registry) Apply(u Update, b uint64) (*Registry, *Changes, error) {
	if u.PriorTipEpoch != r.Tip {
		return nil, nil, ErrHistory
	}
	if uint64(len(u.NewEntries)) > b {
		return nil, nil, ErrTooManyEpochs
	}
	next := r.copy()
	w := &Changes{Final: make(map[[32]byte][32]byte)}
	installed := 0
	for _, e := range u.NewEntries {
		ok, err := next.append(e, w)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			installed++
		}
	}
	if installed > 0 {
		w.insert(FixedSlot("b1.importedTipEpoch"), Word(next.Tip))
	}
	if err := next.advance(u.OriginEpoch, u.OriginRound, w); err != nil {
		return nil, nil, err
	}
	if next.Ready && next.U != next.Tip {
		return nil, nil, ErrImportedUsableMismatch
	}
	return next, w, nil
}

// NextEntries is what a builder appends next: the authenticated history's entries after the imported tip, at most b, none beyond upTo.
func NextEntries(history []Entry, tip, upTo, b uint64) []Entry {
	var out []Entry
	for _, e := range history {
		if e.Epoch > tip && e.Epoch <= upTo && uint64(len(out)) < b {
			out = append(out, clone(e))
		}
	}
	return out
}

// ValidateHistory checks an authenticated epoch history as the registry will store it: the first entry is the genesis body, the epochs are
// consecutive, the starts strictly increase and every entry is itself valid.
func ValidateHistory(history []Entry) error {
	if len(history) == 0 || history[0].BodyKind != 1 {
		return ErrHistory
	}
	for i, h := range history {
		if err := h.Validate(); err != nil {
			return err
		}
		if i > 0 && (h.BodyKind == 1 || history[i-1].Epoch == math.MaxUint64 || h.Epoch != history[i-1].Epoch+1 || h.Start <= history[i-1].Start) {
			return ErrHistory
		}
	}
	return nil
}

// ParentRegistry rebuilds the part of a proven parent registry that the write guards read: the cursors, the open tip and the usable origin's
// entry. The caller has authenticated those entries' words against the parent; every epoch below the tip is closed by construction.
func ParentRegistry(genesis, tip uint64, ready bool, u, o uint64, entries ...Entry) (*Registry, error) {
	r := &Registry{Genesis: genesis, Tip: tip, Ready: ready, U: u, O: o, entries: map[uint64]Entry{}}
	for _, e := range entries {
		if err := e.Validate(); err != nil {
			return nil, err
		}
		r.entries[e.Epoch] = clone(e)
	}
	t, ok := r.entries[tip]
	if !ok || t.End != nil || tip < genesis {
		return nil, ErrHistory
	}
	if ready {
		if _, ok := r.entries[u]; !ok || u < genesis || u > tip {
			return nil, ErrHistory
		}
	}
	return r, nil
}
