package cmd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3shard"
	"github.com/unicitynetwork/bft-core/utbstore"
	"github.com/unicitynetwork/bft-go-base/types"
)

// rootFreeRole is the transport-boundary policy of a root-free follower (`--follow-source`): while this node's published role is not
// active (see shardRole), every known root is refused in both directions. Roots are known only from authenticated committee data: every
// verified trust base (the genesis ones at start, each activated epoch's as it activates) and every authenticated UTB entry. A bootnode
// is not a root by being a bootnode: generated joiners list incumbent shard nodes there, and those are its follow sources. Until the role
// exists the node counts as non-active. Disabled, it refuses nothing.
type rootFreeRole struct {
	enabled bool
	mu      sync.RWMutex
	roots   map[libp2ppeer.ID]struct{}
	member  atomic.Pointer[func() bool]
	mirrors atomic.Pointer[func() []libp2ppeer.ID]
	// revoke, when set, closes connections to peers that deny now covers (Peer.RevokeDenied); called on every change of role or roots.
	revoke atomic.Pointer[func()]
}

// setRevoke installs the connection revocation the role calls on every change.
func (r *rootFreeRole) setRevoke(f func()) { r.revoke.Store(&f) }

// changed revokes connections that are denied now. A no-op when disabled or before setRevoke.
func (r *rootFreeRole) changed() {
	if r == nil || !r.enabled {
		return
	}
	if f := r.revoke.Load(); f != nil {
		(*f)()
	}
}

// addRootNodes records the members of an authenticated committee (a verified trust base's or an authenticated UTB entry's).
func (r *rootFreeRole) addRootNodes(nodes []*types.NodeInfo) {
	if r == nil {
		return
	}
	added := false
	r.mu.Lock()
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if id, err := libp2ppeer.Decode(n.NodeID); err == nil {
			if _, ok := r.roots[id]; !ok {
				r.roots[id], added = struct{}{}, true
			}
		}
	}
	r.mu.Unlock()
	if added {
		r.changed()
	}
}

// nonActive reports whether the node is a root-free follower that is not active now: it must not ask roots for anything.
func (r *rootFreeRole) nonActive() bool { return r != nil && r.enabled && !r.active() }

// setMirrors installs the non-root evidence holders (follow sources, archive replicas, installed validators).
func (r *rootFreeRole) setMirrors(m func() []libp2ppeer.ID) { r.mirrors.Store(&m) }

// mirrorPeers is the current mirror list without any known root identity; empty before setMirrors.
func (r *rootFreeRole) mirrorPeers() []libp2ppeer.ID {
	if r == nil {
		return nil
	}
	m := r.mirrors.Load()
	if m == nil {
		return nil
	}
	return r.nonRoot((*m)())
}

// nonRoot drops every known root identity from a source list: a mirror or follow source is a non-root role by definition, so a root
// listed as one (a misconfiguration or a co-located role) is not asked through it, whatever the node's role. The transport gater refuses
// roots too while the node is non-active; this makes the separation explicit at source selection.
func (r *rootFreeRole) nonRoot(ids []libp2ppeer.ID) []libp2ppeer.ID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]libp2ppeer.ID, 0, len(ids))
	seen := make(map[libp2ppeer.ID]struct{}, len(ids))
	for _, id := range ids {
		if _, root := r.roots[id]; root {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func newRootFreeRole(enabled bool, trust []*types.RootTrustBaseV1) *rootFreeRole {
	r := &rootFreeRole{enabled: enabled, roots: map[libp2ppeer.ID]struct{}{}}
	for _, tb := range trust {
		r.addRoots(tb)
	}
	return r
}

// addRoots records the root committee of a verified trust base.
func (r *rootFreeRole) addRoots(tb *types.RootTrustBaseV1) {
	if tb != nil {
		r.addRootNodes(tb.RootNodes)
	}
}

// setRole installs the active predicate (the published role, shardRole).
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

// shardRole is the node's published role (shardnode.RoleLease): active only once the activation that names this node as a validator has
// COMPLETED, every installation step of the installer and the runtime's completion, and non-active at once when an installed assignment
// no longer names it. A suspended or failed activation never opens the role. The token names the completed activation epoch, so work begun
// under an earlier publication ends at its next lease check. Every change runs onChange (connection revocation, the promotion wake).
type shardRole struct {
	anchor          uint64 // the pinned genesis epoch: complete by definition (the runtime reports 0 until its first activation)
	mu              sync.Mutex
	completedEpoch  uint64
	completedMember bool
	revoked         bool
	// activeEpoch is the runtime's completed activation epoch (q3active.Runtime.ActiveEpoch); nil when there is no V3 runtime.
	activeEpoch func() uint64
	onChange    []func()
}

func newShardRole(anchor uint64, member bool, activeEpoch func() uint64) *shardRole {
	return &shardRole{anchor: anchor, completedEpoch: anchor, completedMember: member, activeEpoch: activeEpoch}
}

// Lease implements shardnode.RoleLease.
func (r *shardRole) Lease() (uint64, bool) {
	r.mu.Lock()
	epoch, member, revoked := r.completedEpoch, r.completedMember, r.revoked
	r.mu.Unlock()
	active := member && !revoked && (epoch <= r.anchor || r.activeEpoch == nil || r.activeEpoch() >= epoch)
	token := epoch << 1
	if active {
		token |= 1
	}
	return token, active
}

// active is the lease's active bit.
func (r *shardRole) active() bool { _, a := r.Lease(); return a }

// assignmentInstalled is called when a verified assignment step is installed, before the rest of its activation: an assignment without
// this node revokes the role at once; one with it changes nothing until the activation completes.
func (r *shardRole) assignmentInstalled(member bool) {
	if member {
		return
	}
	r.mu.Lock()
	r.revoked = true
	r.mu.Unlock()
	r.notify()
}

// activationCompleted publishes the role of a completed activation.
func (r *shardRole) activationCompleted(epoch uint64, member bool) {
	r.mu.Lock()
	r.completedEpoch, r.completedMember, r.revoked = epoch, member, false
	r.mu.Unlock()
	r.notify()
}

func (r *shardRole) notify() {
	r.mu.Lock()
	hooks := append([]func(){}, r.onChange...)
	r.mu.Unlock()
	for _, f := range hooks {
		f()
	}
}

// subscribe adds a change hook.
func (r *shardRole) subscribe(f func()) {
	r.mu.Lock()
	r.onChange = append(r.onChange, f)
	r.mu.Unlock()
}

// notifyingActivator is the follower's runtime: after an activation completes in the runtime (its journal completion, which advances the
// active epoch the role waits for), the role is re-published so that a promotion takes effect at once.
type notifyingActivator struct {
	q3shard.Q3Activator
	role *shardRole
}

func (a notifyingActivator) Activate(ctx context.Context, b q3active.Bundle) error {
	err := a.Q3Activator.Activate(ctx, b)
	a.role.notify()
	return err
}

// published is the role's completed epoch and active bit, for health reporting.
// The epoch and the active bit come from ONE lease sample (the token carries the epoch): a completedEpoch read apart from the lease could pair
// a newer epoch with the older epoch's active bit (astra's review of #1060 r2).
func (r *shardRole) published() (uint64, bool) {
	token, active := r.Lease()
	return token >> 1, active
}

// utbEntries is the part of a utbstore.Store root seeding reads.
type utbEntries interface {
	GenesisEpoch() uint64
	Tip() utbstore.Tip
	Entry(epoch uint64) (*types.RootTrustBaseV2, error)
}

// seedRootsFromUTB records the committee of every entry the UTB store holds. The store authenticated each entry from its predecessor when it
// was appended and re-validates the whole chain from the pin when it is opened, so these are authenticated committees.
func seedRootsFromUTB(r *rootFreeRole, store utbEntries) error {
	for e := store.GenesisEpoch(); e <= store.Tip().Epoch; e++ {
		entry, err := store.Entry(e)
		if err != nil {
			return fmt.Errorf("reading retained trust-base entry %d: %w", e, err)
		}
		r.addRootNodes(entry.RootNodes)
	}
	return nil
}

// memberPrewarm keeps the channels a member needs warm before it needs them (phase 2): the shard peers of the installed and staged
// assignments, and, once the role is active, the root committee of the active epoch. Each set is reconciled whole on every change
// (network.MemberProtector): a peer the set no longer names is unprotected, connected or not, and a superseded warm-up cannot re-protect.
type memberPrewarm struct {
	members, committee memberSet
}

// memberSet is the part of network.MemberProtector the prewarm uses.
type memberSet interface {
	Set(ctx context.Context, ids []libp2ppeer.ID)
}

func newMemberPrewarm(p interface {
	NewMemberProtector(tag string) *network.MemberProtector
}) *memberPrewarm {
	return &memberPrewarm{members: p.NewMemberProtector("shard-members"), committee: p.NewMemberProtector("root-committee")}
}

// shard makes ids the protected, warmed shard peer set.
func (w *memberPrewarm) shard(ctx context.Context, ids []libp2ppeer.ID) {
	if w != nil {
		w.members.Set(ctx, ids)
	}
}

// roots makes the committee of tb the protected, warmed root set; nil (a non-active node) protects no root.
func (w *memberPrewarm) roots(ctx context.Context, tb *types.RootTrustBaseV1) {
	if w == nil {
		return
	}
	var ids []libp2ppeer.ID
	if tb != nil {
		for _, n := range tb.RootNodes {
			if n == nil {
				continue
			}
			if id, err := libp2ppeer.Decode(n.NodeID); err == nil {
				ids = append(ids, id)
			}
		}
	}
	w.committee.Set(ctx, ids)
}

// decodePeerIDs decodes node IDs, skipping any that is not a peer ID.
func decodePeerIDs(raw []string) []libp2ppeer.ID {
	out := make([]libp2ppeer.ID, 0, len(raw))
	for _, s := range raw {
		if id, err := libp2ppeer.Decode(s); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// remoteFallbackArchive is the terminal repair's archive: the local store first, then the node's non-root archive sources (follow sources,
// replicas, installed validators). A follower that installed an epoch from its mirrors never executed that epoch's terminal block, so after
// a restart the body is in neither its journal nor its archive; it is fetched here. A fetched record is evidence only: the repair verifies
// it against the terminal certificate (block hash and state root) before anything is written.
type remoteFallbackArchive struct {
	local   handoffArchiveReader
	sources func() []libp2ppeer.ID
	fetch   func(id libp2ppeer.ID, q archive.Request) (*archive.Record, error)
}

func (a remoteFallbackArchive) Get(q archive.Request) (*archive.Record, error) {
	rec, err := a.local.Get(q)
	if err == nil || !errors.Is(err, archive.ErrUnavailable) || a.fetch == nil || a.sources == nil {
		return rec, err
	}
	for _, id := range a.sources() {
		if got, ferr := a.fetch(id, q); ferr == nil && got != nil {
			return got, nil
		}
	}
	return nil, err
}
