package storage

import (
	"errors"
	"sync"

	"github.com/unicitynetwork/bft-core/evmroot"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// MaxRetainedCuts is how many control cuts a root keeps hot in memory. It bounds memory only: every cut of a source-state-bearing commit
// is retained durably (CutStore) and read through, so availability does not depend on it.
const MaxRetainedCuts = 512

// ErrCutUnavailable reports a committed block whose control cut this root does not hold: unavailable, not empty.
var ErrCutUnavailable = errors.New("P85 control cut unavailable")

// ControlCut is the control state of one committed root block and the path of its leaf in that block's unicity tree: what a shard needs
// to authenticate the root's source state against the tree root of the certificate it already holds (recordsfeed).
type ControlCut struct {
	Control *evmroot.ControlState
	Path    *basetypes.UnicityTreeCertificate
}

// cutRing is the hot cache of control cuts, the most recent MaxRetainedCuts inserted, oldest evicted first.
type cutRing struct {
	mu    sync.Mutex
	order []CutKey
	byKey map[CutKey]ControlCut
}

func (r *cutRing) put(key CutKey, cut ControlCut) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byKey == nil {
		r.byKey = map[CutKey]ControlCut{}
	}
	if _, seen := r.byKey[key]; !seen {
		r.order = append(r.order, key)
		for len(r.order) > MaxRetainedCuts {
			delete(r.byKey, r.order[0])
			r.order = r.order[1:]
		}
	}
	r.byKey[key] = cut
}

func (r *cutRing) get(key CutKey) (ControlCut, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cut, ok := r.byKey[key]
	return cut, ok
}

// ControlCut is the retained cut of the committed block the key names: from the hot cache, else read through from the durable store.
// What is returned always leads to the key's tree root; a cut that does not is never served.
func (bt *BlockTree) ControlCut(key CutKey) (ControlCut, error) {
	if cut, ok := bt.cuts.get(key); ok {
		return cut, nil
	}
	store, ok := bt.blocksDB.(CutStore)
	if !ok {
		return ControlCut{}, ErrCutUnavailable
	}
	durable, err := store.GetCut(key)
	if err != nil {
		return ControlCut{}, err
	}
	cut := ControlCut{Control: durable.Control, Path: durable.Path}
	bt.cuts.put(key, cut)
	return cut, nil
}
