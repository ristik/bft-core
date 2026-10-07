package q3active

import (
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

// B1Authority binds an opaque admission capability to this runtime. It keeps
// shared execution-input code independent of root storage consumers.
func (r *Runtime) B1Authority() *b1authority.Source { return b1authority.Bind(r.B1History) }
