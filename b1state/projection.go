package b1state

import "reflect"

// Select freezes a complete, authenticated genesis-rooted history at origin.
// The caller establishes authentication: exported Entries are pure model input.
// Future-known starts cannot close the origin entry.
func Select(history []Entry, origin, w uint64) ([]Entry, error) {
	if w == ^uint64(0) {
		return nil, ErrOverflow
	}
	if len(history) == 0 || history[0].BodyKind != 1 {
		return nil, ErrHistory
	}
	var live []Entry
	for i, h := range history {
		if err := h.Validate(); err != nil {
			return nil, err
		}
		if i > 0 && (h.BodyKind == 1 || history[i-1].Epoch == ^uint64(0) || h.Epoch != history[i-1].Epoch+1 || h.Start <= history[i-1].Start) {
			return nil, ErrHistory
		}
		if h.Start > origin {
			continue
		}
		e := clone(h)
		e.End = nil
		if i+1 < len(history) && history[i+1].Start <= origin {
			end := history[i+1].Start
			e.End = &end
		}
		if e.End == nil || *e.End > lower(origin, w) {
			live = append(live, e)
		}
	}
	if len(live) == 0 || uint64(len(live)) > w+1 {
		return nil, ErrInterval
	}
	return live, nil
}

// Delta closes the parent tip at its first actual successor even if that
// successor expires. Every intervening link must be authenticated upstream.
func Delta(history, parent []Entry, parentOrigin, origin, w uint64) (oldTipEnd *uint64, newEntries []Entry, err error) {
	if origin < parentOrigin {
		return nil, nil, ErrClock
	}
	expected, err := Select(history, parentOrigin, w)
	if err != nil {
		return nil, nil, err
	}
	if !reflect.DeepEqual(parent, expected) {
		return nil, nil, ErrHistory
	}
	final, err := Select(history, origin, w)
	if err != nil {
		return nil, nil, err
	}
	tip := parent[len(parent)-1]
	for _, e := range history {
		if e.Epoch > tip.Epoch && e.Start <= origin {
			end := e.Start
			oldTipEnd = &end
			break
		}
	}
	for _, e := range final {
		if e.Epoch > tip.Epoch {
			newEntries = append(newEntries, clone(e))
		}
	}
	return
}

type Ring struct {
	Head                      uint64
	OriginRound, GenesisStart uint64
	Entries                   []Entry
}

// Apply models prune-before-append on a disposable ring, with the exact
// addressed writes including zero clears. It does not measure EVM opcode gas.
func (r Ring) Apply(u Update, w uint64) (Ring, *Changes, error) {
	if w == ^uint64(0) {
		return Ring{}, nil, ErrOverflow
	}
	k := w + 1
	if r.Head >= k || len(r.Entries) == 0 || uint64(len(r.Entries)) > k {
		return Ring{}, nil, ErrInterval
	}
	if u.OriginRound < r.OriginRound {
		return Ring{}, nil, ErrClock
	}
	parentLower := lower(r.OriginRound, w)
	if parentLower < r.GenesisStart {
		parentLower = r.GenesisStart
	}
	if r.Entries[0].Start > parentLower {
		return Ring{}, nil, ErrInterval
	}
	for i, e := range r.Entries {
		if err := e.Validate(); err != nil {
			return Ring{}, nil, err
		}
		if e.Start > r.OriginRound || (e.End != nil && *e.End <= lower(r.OriginRound, w)) {
			return Ring{}, nil, ErrInterval
		}
		if i < len(r.Entries)-1 {
			next := r.Entries[i+1]
			if next.Epoch != e.Epoch+1 || e.End == nil || *e.End != next.Start {
				return Ring{}, nil, ErrInterval
			}
		}
	}
	entries := make([]Entry, len(r.Entries))
	for i, e := range r.Entries {
		entries[i] = clone(e)
	}
	tip := &entries[len(entries)-1]
	if tip.Epoch != u.PriorTipEpoch || tip.End != nil {
		return Ring{}, nil, ErrHistory
	}
	if u.OldTipEnd != nil {
		if *u.OldTipEnd <= r.OriginRound || *u.OldTipEnd > u.OriginRound {
			return Ring{}, nil, ErrInterval
		}
		v := *u.OldTipEnd
		tip.End = &v
	}
	writes := &Changes{Final: make(map[[32]byte][32]byte)}
	removed := 0
	for removed < len(entries) && entries[removed].End != nil && *entries[removed].End <= lower(u.OriginRound, w) {
		e := entries[removed]
		clearEntry(writes.clear, e)
		writes.clear(QueueSlot(advance(r.Head, uint64(removed), k)), [32]byte{})
		removed++
	}
	out := Ring{Head: advance(r.Head, uint64(removed), k), OriginRound: u.OriginRound, GenesisStart: r.GenesisStart, Entries: entries[removed:]}
	if len(out.Entries) == 0 {
		out.Head = 0
	}
	if len(out.Entries) > 0 && u.OldTipEnd != nil {
		last := out.Entries[len(out.Entries)-1]
		writes.insert(EntrySlot(last.Epoch, 5), Word(*last.End))
		writes.insert(EntrySlot(last.Epoch, 6), Word(1))
	}
	for _, e := range u.NewEntries {
		if e.BodyKind == 1 || e.Epoch <= u.PriorTipEpoch || u.OldTipEnd == nil || *u.OldTipEnd > e.Start || (e.Epoch == u.PriorTipEpoch+1 && *u.OldTipEnd != e.Start) {
			return Ring{}, nil, ErrHistory
		}
		if err := e.Validate(); err != nil {
			return Ring{}, nil, err
		}
		if uint64(len(out.Entries)) >= k {
			return Ring{}, nil, ErrInterval
		}
		if len(out.Entries) > 0 {
			prev := out.Entries[len(out.Entries)-1]
			if e.Epoch != prev.Epoch+1 || prev.End == nil || *prev.End != e.Start {
				return Ring{}, nil, ErrInterval
			}
		}
		putEntry(writes.insert, e)
		writes.insert(QueueSlot(advance(out.Head, uint64(len(out.Entries)), k)), Word(e.Epoch))
		out.Entries = append(out.Entries, clone(e))
	}
	if len(out.Entries) == 0 {
		return Ring{}, nil, ErrInterval
	}
	targetLower := lower(u.OriginRound, w)
	if targetLower < r.GenesisStart {
		targetLower = r.GenesisStart
	}
	if out.Entries[0].Start > targetLower {
		return Ring{}, nil, ErrInterval
	}
	for i, e := range out.Entries {
		if e.Start > u.OriginRound || (i < len(out.Entries)-1 && (e.End == nil || *e.End != out.Entries[i+1].Start)) || (e.End != nil && *e.End <= lower(u.OriginRound, w)) {
			return Ring{}, nil, ErrInterval
		}
	}
	tail := out.Entries[len(out.Entries)-1]
	if tail.Epoch != u.OriginEpoch || tail.End != nil {
		return Ring{}, nil, ErrInterval
	}
	writes.insert(FixedSlot("b1.head"), Word(out.Head))
	writes.insert(FixedSlot("b1.count"), Word(uint64(len(out.Entries))))
	return out, writes, nil
}

// advance avoids overflow even for synthetic near-u64 ring bounds.
func advance(head, delta, k uint64) uint64 {
	if delta >= k-head {
		return delta - (k - head)
	}
	return head + delta
}
