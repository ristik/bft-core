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
	// held is set from process start until the persisted verified assignment steps have been replayed into the set: until then the set
	// is only the genesis one, which may still name a validator that a later step retired. A held set authorizes nobody (a peer refused
	// in that window retries; see archivewiring.ErrPeerNotAllowed) rather than authorizing a stale set.
	held bool
}

// NewActivePeers starts with the genesis validators as the shard epoch 0 set.
func NewActivePeers(self peer.ID, genesis []*types.NodeInfo) (*ActivePeers, error) {
	a := &ActivePeers{self: self}
	set, err := peerSet(self, genesis)
	if err != nil {
		return nil, err
	}
	a.set = set
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
		if !sameSet(a.set, set) {
			return fmt.Errorf("%w: shard epoch %d", ErrActivePeersConflict, epoch)
		}
		return nil
	}
	a.epoch, a.set = epoch, set
	return nil
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
	_, ok := a.set[id]
	return ok
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

// EvidenceProviders makes ActivePeers the evidence ProviderSource: who to ask follows the active assignment.
func (a *ActivePeers) EvidenceProviders() []peer.ID { return a.Peers() }
