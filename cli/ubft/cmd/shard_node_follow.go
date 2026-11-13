package cmd

import (
	"sync"
	"sync/atomic"

	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

// rootFreeRole is the transport-boundary policy of a root-free follower (`--follow-source`): while this node is not a validator of the
// installed assignment, every known root is refused in both directions. Roots are known from the configured bootnodes and every
// verified trust base (the genesis ones at start, each activated epoch's as it activates). Until the active set exists the node counts
// as non-active. Disabled, it refuses nothing.
type rootFreeRole struct {
	enabled bool
	mu      sync.RWMutex
	roots   map[libp2ppeer.ID]struct{}
	member  atomic.Pointer[func() bool]
	mirrors atomic.Pointer[func() []libp2ppeer.ID]
}

// nonActive reports whether the node is a root-free follower that is not active now: it must not ask roots for anything.
func (r *rootFreeRole) nonActive() bool { return r != nil && r.enabled && !r.active() }

// setMirrors installs the non-root evidence holders (follow sources, archive replicas, installed validators).
func (r *rootFreeRole) setMirrors(m func() []libp2ppeer.ID) { r.mirrors.Store(&m) }

// mirrorPeers is the current mirror list; empty before setMirrors.
func (r *rootFreeRole) mirrorPeers() []libp2ppeer.ID {
	if r == nil {
		return nil
	}
	m := r.mirrors.Load()
	if m == nil {
		return nil
	}
	return (*m)()
}

func newRootFreeRole(enabled bool, boot []libp2ppeer.AddrInfo, trust []*types.RootTrustBaseV1) *rootFreeRole {
	r := &rootFreeRole{enabled: enabled, roots: map[libp2ppeer.ID]struct{}{}}
	for _, b := range boot {
		r.roots[b.ID] = struct{}{}
	}
	for _, tb := range trust {
		r.addRoots(tb)
	}
	return r
}

// addRoots records the root committee of a verified trust base.
func (r *rootFreeRole) addRoots(tb *types.RootTrustBaseV1) {
	if r == nil || tb == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range tb.RootNodes {
		if n == nil {
			continue
		}
		if id, err := libp2ppeer.Decode(n.NodeID); err == nil {
			r.roots[id] = struct{}{}
		}
	}
}

// setRole installs the membership predicate (ActivePeers.Member).
func (r *rootFreeRole) setRole(member func() bool) { r.member.Store(&member) }

// active reports whether the node is an active validator; false until the role is known.
func (r *rootFreeRole) active() bool {
	m := r.member.Load()
	return m != nil && (*m)()
}

// deny is the RoleGater predicate.
func (r *rootFreeRole) deny(id libp2ppeer.ID) bool {
	if r == nil || !r.enabled || r.active() {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, root := r.roots[id]
	return root
}

func followSourceIDs(sources []libp2ppeer.AddrInfo) []libp2ppeer.ID {
	out := make([]libp2ppeer.ID, 0, len(sources))
	for _, s := range sources {
		out = append(out, s.ID)
	}
	return out
}
