package q3active

import (
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/b1authority"
	"github.com/unicitynetwork/bft-core/q3format"
)

// B1History freezes one immutable authenticated history and refuses every
// incomplete intervening install, including expired epochs with no EVM block.
// Root installation verifies coupled candidate preimages before completion.
func (r *Runtime) B1History(origin uint64) (*q3format.History, error) {
	if r == nil {
		return nil, ErrHistory
	}
	h := r.History()
	if h == nil {
		return nil, ErrHistory
	}
	entries, err := h.B1Entries(origin)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if err := r.Admit(e.Epoch); err != nil {
			return nil, err
		}
	}
	return h, nil
}

// B1Run is the per-block form of B1History: the entries of epochs from.. up to the one holding origin, at most limit of them (0: no cap), each admitted by
// the journal's completion marker. Epochs before from were admitted when they were imported (the registry holds them), so they are neither converted nor
// admitted again: the cost does not depend on the length of the history. The history is returned for the committee and interval checks.
func (r *Runtime) B1Run(origin, from uint64, limit int) (*q3format.History, []b1state.Entry, error) {
	if r == nil {
		return nil, nil, ErrHistory
	}
	h := r.History()
	if h == nil {
		return nil, nil, ErrHistory
	}
	entries, err := h.B1EntriesFrom(origin, from, limit)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		if err := r.Admit(e.Epoch); err != nil {
			return nil, nil, err
		}
	}
	return h, entries, nil
}

// B1Authority binds an opaque admission capability to this runtime. It keeps
// shared execution-input code independent of root storage consumers.
func (r *Runtime) B1Authority() *b1authority.Source { return b1authority.Bind(r.B1History, r.B1Run) }
