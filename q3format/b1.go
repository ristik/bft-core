package q3format

import (
	"crypto/sha256"
	"sort"

	"github.com/unicitynetwork/bft-core/b1state"
)

// B1Entries returns the complete authenticated prefix, including epochs with no
// execution blocks. No caller-provided committee or activation can enter it.
func (h *History) B1Entries(origin uint64) ([]b1state.Entry, error) {
	if h == nil || len(h.entries) == 0 {
		return nil, ErrHistory
	}
	var out []b1state.Entry
	for _, v := range h.entries {
		if v.start > origin {
			break
		}
		cfg, ok := v.Config()
		var configID [32]byte
		if ok {
			if err := cfg.Validate(); err != nil {
				return nil, err
			}
			configID = cfg.Identity()
		} else {
			// Explicit genesis-only legacy policy. Missing successor configuration is
			// refused rather than interpreted as a legacy epoch.
			if v.epoch != h.entries[0].epoch || v.version != 1 || v.scheme != 1 {
				return nil, ErrConfig
			}
			configID = sha256.Sum256(enc("UNICITY_B1_GENESIS_SIGNING_CONFIG", h.network, h.genesis[:], uint64(1), "unit", "total-(total-1)/3"))
		}
		e := b1state.Entry{Epoch: v.epoch, BodyKind: v.version, BodyID: v.bodyID, ActivationCommitID: v.commitID, Start: v.start, SigningScheme: v.scheme, SigningConfigHash: configID}
		for _, m := range v.tb.RootNodes {
			if m == nil || len(m.SigKey) != 33 {
				return nil, b1state.ErrMembers
			}
			var key [33]byte
			copy(key[:], m.SigKey)
			e.Members = append(e.Members, b1state.Member{NodeID: m.NodeID, Key: key, Weight: m.Stake})
		}
		sort.Slice(e.Members, func(i, j int) bool { return e.Members[i].NodeID < e.Members[j].NodeID })
		if err := e.Validate(); err != nil {
			return nil, err
		}
		total, _ := e.TotalWeight()
		threshold, _ := b1state.Threshold(total)
		if threshold != v.tb.QuorumThreshold {
			return nil, ErrConfig
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, ErrUnknownEpoch
	}
	return out, nil
}
