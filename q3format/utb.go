package q3format

import (
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utb"
)

// UTBUnsigned derives the unsigned signed-trust-base chain of this history, one entry per epoch from the history's genesis epoch (a zero-predecessor
// genesis entry; its authority is the profile's pin) to the tip. Every entry comes from the one canonical builder, so the root, the shard restore and
// an exporter that hold the same history produce the same bytes and EntryIDs. It carries no signatures: those are the old committee's, collected in
// the commit exchange and retained with the transition.
func (h *History) UTBUnsigned() ([]*types.RootTrustBaseV2, error) {
	out := make([]*types.RootTrustBaseV2, 0, len(h.entries))
	var prev *types.RootTrustBaseV2
	for _, e := range h.entries {
		f := utb.FromProjection(e.tb)
		if e.tb.EpochStart != e.start {
			return nil, fmt.Errorf("%w: epoch %d projection starts at %d, the history at %d", ErrHistory, e.epoch, e.tb.EpochStart, e.start)
		}
		u, err := utb.BuildUnsigned(prev, f)
		if err != nil {
			return nil, fmt.Errorf("%w: epoch %d: %v", ErrHistory, e.epoch, err)
		}
		out, prev = append(out, u), u
	}
	return out, nil
}
