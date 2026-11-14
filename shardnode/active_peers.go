package shardnode

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrActivePeersConflict refuses to install a different validator set for a shard epoch that already has one.
var ErrActivePeersConflict = errors.New("shardnode: a different validator set is already installed for this shard epoch")

// ErrActivePeersInvalid refuses a validator set that cannot be a peer set (a nil validator or a node id that is not a peer id).
var ErrActivePeersInvalid = errors.New("shardnode: invalid validator for the active peer set")

// ActivePeers is the set of validator peers this node serves and talks to: the validators of the ACTIVE shard assignment, seeded with
// the genesis set and replaced only from verified committed assignment steps, in the same install path as ShardConfSet. A joiner is a
// peer from the moment its assignment is installed (it must be able to restore from the archive before it can acknowledge); a retired
// validator is a peer no longer once its successor is installed. It never contains this node itself.
type ActivePeers struct {
	mu    sync.RWMutex
	self  peer.ID
	epoch uint64
	set   map[peer.ID]struct{}
	// staged are the validators of the successor assignment this node has STAGED (the candidate its operator handed it for readiness): peers
	// of the next assignment that are not installed yet. They may fetch the archive and records, so a joiner can catch up before its own
	// readiness (it can only stage a candidate that is the successor of the history it has caught up to). Replaced by the next stage and
	// cleared by the next install; never consulted for anything but inbound authorization.
	staged map[peer.ID]struct{}
	// held is set from process start until the persisted verified assignment steps have been replayed into the set: until then the set
	// is only the genesis one, which may still name a validator that a later step retired. A held set authorizes nobody (a peer refused
	// in that window retries; see archivewiring.ErrPeerNotAllowed) rather than authorizing a stale set.
	held bool
	// member is whether this node itself is a validator of the installed set (the set never contains it). A node that is not a member is
	// a non-active party: it takes evidence from blocks and mirrors, never from roots.
	member bool
	// onStage, when set, is told the peers of each accepted stage (outside the lock), so that their channels can be prewarmed.
	onStage func([]peer.ID)
	// selfKey is the signing key the installed set names for this node (nil while it does not name it): health binding evidence only.
	selfKey []byte
}

// OnStage installs the hook told the peers of each accepted stage.
func (a *ActivePeers) OnStage(f func([]peer.ID)) {
	a.mu.Lock()
	a.onStage = f
	a.mu.Unlock()
}

// NewActivePeers starts with the genesis validators as the shard epoch 0 set.
func NewActivePeers(self peer.ID, genesis []*types.NodeInfo) (*ActivePeers, error) {
	a := &ActivePeers{self: self}
	set, err := peerSet(self, genesis)
	if err != nil {
		return nil, err
	}
	a.set, a.member, a.selfKey = set, names(self, genesis), keyOf(self, genesis)
	return a, nil
}

func peerSet(self peer.ID, validators []*types.NodeInfo) (map[peer.ID]struct{}, error) {
	set := make(map[peer.ID]struct{}, len(validators))
	for _, v := range validators {
		if v == nil {
			return nil, fmt.Errorf("%w: nil validator", ErrActivePeersInvalid)
		}
		id, err := peer.Decode(v.NodeID)
		if err != nil {
			return nil, fmt.Errorf("%w: node id %q: %v", ErrActivePeersInvalid, v.NodeID, err)
		}
		if id != self {
			set[id] = struct{}{}
		}
	}
	return set, nil
}

// Install makes the given validators the active set from the given shard epoch. The same set again is a no-op; a different set for the
// active epoch is ErrActivePeersConflict; the set of an older epoch is history and changes nothing (a replayed or out-of-order bundle
// must not move the set backwards, nor fail the handoff it belongs to).
func (a *ActivePeers) Install(epoch uint64, validators []*types.NodeInfo) error {
	set, err := peerSet(a.self, validators)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case epoch < a.epoch:
		return nil
	case epoch == a.epoch:
		// the self-membership bit is part of the set: {self,B} and {B} at one epoch are different assignments
		if !sameSet(a.set, set) || a.member != names(a.self, validators) {
			return fmt.Errorf("%w: shard epoch %d", ErrActivePeersConflict, epoch)
		}
		return nil
	}
	a.epoch, a.set, a.staged, a.member, a.selfKey = epoch, set, nil, names(a.self, validators), keyOf(a.self, validators)
	return nil
}

// names reports whether the validators include self.
func names(self peer.ID, validators []*types.NodeInfo) bool {
	for _, v := range validators {
		if v == nil {
			continue
		}
		if id, err := peer.Decode(v.NodeID); err == nil && id == self {
			return true
		}
	}
	return false
}

// keyOf is the signing key validators name for self, nil when they do not name it.
func keyOf(self peer.ID, validators []*types.NodeInfo) []byte {
	for _, v := range validators {
		if v == nil {
			continue
		}
		if id, err := peer.Decode(v.NodeID); err == nil && id == self {
			return append([]byte(nil), v.SigKey...)
		}
	}
	return nil
}

// Installed is the installed set's shard epoch, whether it names this node, and the signing key it names for it (nil when it does not):
// what the health binding reports (bft-core#1057). It authorizes nothing.
func (a *ActivePeers) Installed() (epoch uint64, member bool, key []byte) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epoch, a.member, append([]byte(nil), a.selfKey...)
}

// Member reports whether this node is a validator of the installed (active) assignment. It is a role fact for source selection only:
// whether the node may sign is decided by its signing gates and authority, never by this.
func (a *ActivePeers) Member() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.member
}

func sameSet(a, b map[peer.ID]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			return false
		}
	}
	return true
}

// Hold makes Allowed refuse every peer until Release. A node that replays persisted assignment steps at startup holds the set from
// construction, so that the genesis set is never used to authorize a peer after a restart that had installed a later step.
func (a *ActivePeers) Hold() {
	a.mu.Lock()
	a.held = true
	a.mu.Unlock()
}

// Release ends the hold: the set now reflects every verified step that was replayed.
func (a *ActivePeers) Release() {
	a.mu.Lock()
	a.held = false
	a.mu.Unlock()
}

// Allowed reports whether the peer is a validator of the active assignment (never this node itself), and false for everyone while the
// set is held.
func (a *ActivePeers) Allowed(id peer.ID) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.held {
		return false
	}
	if _, ok := a.set[id]; ok {
		return true
	}
	_, ok := a.staged[id]
	return ok
}

// Stage records the validators of a staged successor assignment as peers this node serves, in place of any earlier staged set. This node
// itself is never in it. A peer that is not a valid peer ID is ErrActivePeersInvalid and changes nothing.
func (a *ActivePeers) Stage(ids []string) error {
	set := make(map[peer.ID]struct{}, len(ids))
	for _, raw := range ids {
		id, err := peer.Decode(raw)
		if err != nil {
			return fmt.Errorf("%w: node id %q: %v", ErrActivePeersInvalid, raw, err)
		}
		if id != a.self {
			set[id] = struct{}{}
		}
	}
	a.mu.Lock()
	a.staged = set
	hook := a.onStage
	a.mu.Unlock()
	if hook != nil {
		ids := make([]peer.ID, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		hook(ids)
	}
	return nil
}

// Peers is the active assignment's other validators, sorted, never including this node. It is what an OUTBOUND consumer addresses (block
// dissemination recipients, journal suffix providers, evidence providers): the hold does not apply, because holding exists so that a stale
// set never AUTHORIZES an inbound peer, and asking or sending to a validator that a persisted step has since retired may still be answered, but every answer is authenticated independently of who sent it, so it cannot bypass those checks.
func (a *ActivePeers) Peers() []peer.ID {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]peer.ID, 0, len(a.set))
	for id := range a.set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// StagedPeers is the staged successor assignment's peers (never this node), sorted; empty without a stage.
func (a *ActivePeers) StagedPeers() []peer.ID {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]peer.ID, 0, len(a.staged))
	for id := range a.staged {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// EvidenceProviders makes ActivePeers the evidence ProviderSource: who to ask follows the active assignment.
func (a *ActivePeers) EvidenceProviders() []peer.ID { return a.Peers() }

// Epoch is the shard epoch of the installed set (zero for the genesis set).
func (a *ActivePeers) Epoch() uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epoch
}
