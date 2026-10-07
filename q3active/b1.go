package q3active

import "github.com/unicitynetwork/bft-core/q3format"

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
