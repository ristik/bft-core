package storage

import (
	"crypto"
	"errors"
	"sync"

	"github.com/unicitynetwork/bft-core/evmroot"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// MaxRetainedCuts is how many committed blocks' control cuts a root keeps for the shards that pair an EVM with it.
const MaxRetainedCuts = 512

// ErrCutUnavailable reports a committed block whose control cut this root no longer (or never) held: unavailable, not empty.
var ErrCutUnavailable = errors.New("P85 control cut unavailable")

// ControlCut is the control state of one committed root block and the path of its leaf in that block's unicity tree: what a shard needs
// to authenticate the root's source state against the tree root of the certificate it already holds (recordsfeed).
type ControlCut struct {
	Control *evmroot.ControlState
	Path    *basetypes.UnicityTreeCertificate
}

// cutRing keeps the cuts of the last MaxRetainedCuts commits that carried a source state, oldest evicted first. It is memory only: a
// restarted root serves the cuts of the blocks it commits from then on, and a shard whose origin is older asks another root.
type cutRing struct {
	mu      sync.Mutex
	order   []uint64
	byRound map[uint64]ControlCut
}

func (r *cutRing) put(round uint64, cut ControlCut) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byRound == nil {
		r.byRound = map[uint64]ControlCut{}
	}
	if _, seen := r.byRound[round]; !seen {
		r.order = append(r.order, round)
		for len(r.order) > MaxRetainedCuts {
			delete(r.byRound, r.order[0])
			r.order = r.order[1:]
		}
	}
	r.byRound[round] = cut
}

func (r *cutRing) get(round uint64) (ControlCut, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cut, ok := r.byRound[round]
	return cut, ok
}

// captureCut retains the cut of a newly committed block that carries a source state. Best effort: a block whose tree cannot be built is
// simply not served (the commit does not depend on it).
func (bt *BlockTree) captureCut(b *ExecutedBlock) {
	if b == nil || b.ShardState.Control == nil || len(b.ShardState.Control.Pos) == 0 {
		return
	}
	tree, _, err := b.ShardState.UnicityTree(crypto.SHA256)
	if err != nil {
		return
	}
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	if err != nil {
		return
	}
	bt.cuts.put(b.GetRound(), ControlCut{Control: b.ShardState.Control, Path: path})
}

// ControlCut is the retained cut of the committed block of the round.
func (bt *BlockTree) ControlCut(round uint64) (ControlCut, error) {
	if cut, ok := bt.cuts.get(round); ok {
		return cut, nil
	}
	return ControlCut{}, ErrCutUnavailable
}
