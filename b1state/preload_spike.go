package b1state

// SPIKE ONLY (spike/b1-preload): a model of the append-only registry the any-age design asks for, to exercise the preload rule against real
// histories. Not wired into admission, not a codec.

import "errors"

var (
	ErrPreloadTip     = errors.New("b1state: preload does not extend the imported tip")
	ErrPreloadClosure = errors.New("b1state: the imported tip is already closed")
	ErrPreloadBatch   = errors.New("b1state: preload batch over the per-update limit")
)

// Permanent is the append-only registry: every imported entry stays; the tip is the last one imported, which may be ahead of the usable origin.
type Permanent struct {
	Entries     []Entry
	UsableEpoch uint64
}

func (r *Permanent) TipEpoch() uint64 { return r.Entries[len(r.Entries)-1].Epoch }

// Preload appends the next batch (at most b entries) of the authenticated history after the imported tip. The old tip's open end is closed
// exactly once, at the successor's start; nothing else is written and the usable origin is untouched.
func (r *Permanent) Preload(history []Entry, batch []Entry, b int) error {
	if len(batch) == 0 || len(batch) > b {
		return ErrPreloadBatch
	}
	tip := r.Entries[len(r.Entries)-1]
	if batch[0].Epoch != tip.Epoch+1 {
		return ErrPreloadTip
	}
	if tip.End != nil {
		return ErrPreloadClosure
	}
	for i, e := range batch {
		want := history[e.Epoch-history[0].Epoch]
		if e.Epoch != want.Epoch || e.BodyID != want.BodyID || e.Start != want.Start || (i > 0 && e.Epoch != batch[i-1].Epoch+1) {
			return ErrHistory
		}
	}
	end := batch[0].Start
	r.Entries[len(r.Entries)-1].End = &end
	for _, e := range batch {
		r.Entries = append(r.Entries, clone(e))
	}
	return nil
}

// NextBatch is what a block builder derives from the parent registry and the authenticated history: the next at most b missing entries.
func NextBatch(history []Entry, tip uint64, b int) []Entry {
	var out []Entry
	for _, e := range history {
		if e.Epoch > tip && len(out) < b {
			out = append(out, clone(e))
		}
	}
	return out
}
