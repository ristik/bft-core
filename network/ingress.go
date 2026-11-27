package network

import (
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/peer"
)

// IngressBudget reserves the bytes of received frames of a protocol (#1032): a frame's declared length is reserved, globally and for
// its peer, before any of its payload is read or allocated, and the reservation is kept while the decoded message waits in the receive
// queue, until the consumer takes it (LibP2PNetwork.Delivered) or it is dropped. A frame that does not fit is refused and its stream
// reset, so the bytes in flight and queued for the protocol never exceed the budget, whatever lengths senders declare.
//
// A budget with a protected share (NewProtectedIngressBudget, #1113) keeps part of the global budget for the peers its priority function
// names at reservation time: the others together reserve at most global minus protected, so they cannot fill the budget against them.
type IngressBudget struct {
	mu      sync.Mutex
	global  int64
	perPeer int64
	// general is what the peers without priority may hold together: global unless a share is protected
	general     int64
	used        int64
	usedGeneral int64
	priority    atomic.Pointer[func(peer.ID) bool]
	peers       map[peer.ID]int64
	queued      map[any]ingressCharge
}

// ingressCharge is one reservation: its peer, its bytes and whether it was taken from the general share.
type ingressCharge struct {
	peer    peer.ID
	n       int64
	general bool
}

// NewIngressBudget is a budget of global bytes in flight and queued, of which one peer may hold at most perPeer.
func NewIngressBudget(global, perPeer int64) *IngressBudget {
	return &IngressBudget{global: global, perPeer: perPeer, general: global, peers: make(map[peer.ID]int64), queued: make(map[any]ingressCharge)}
}

// NewProtectedIngressBudget is NewIngressBudget with protected of the global bytes kept for the peers SetPriority names: the other peers
// together hold at most global-protected. Until SetPriority is called no peer has priority.
func NewProtectedIngressBudget(global, protected, perPeer int64) *IngressBudget {
	b := NewIngressBudget(global, perPeer)
	b.general = global - max(0, min(protected, global))
	return b
}

// SetPriority sets the peers a protected share is kept for (nil: none). It must be cheap and safe for concurrent use: it is asked for
// every frame, before its payload is read.
func (b *IngressBudget) SetPriority(f func(peer.ID) bool) {
	if f == nil {
		b.priority.Store(nil)
		return
	}
	b.priority.Store(&f)
}

func (b *IngressBudget) prioritized(p peer.ID) bool {
	f := b.priority.Load()
	return f != nil && (*f)(p)
}

// reserve reserves n bytes for a frame of p; ok is false (and nothing is reserved) when they do not fit.
func (b *IngressBudget) reserve(p peer.ID, n int64) (c ingressCharge, ok bool) {
	general := b.general < b.global && !b.prioritized(p) // outside the lock: the priority function may take its own
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.global-b.used || n > b.perPeer-b.peers[p] || (general && n > b.general-b.usedGeneral) {
		return ingressCharge{}, false
	}
	b.used += n
	b.peers[p] += n
	if general {
		b.usedGeneral += n
	}
	return ingressCharge{peer: p, n: n, general: general}, true
}

func (b *IngressBudget) release(c ingressCharge) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releaseLocked(c)
}

func (b *IngressBudget) releaseLocked(c ingressCharge) {
	b.used -= c.n
	if c.general {
		b.usedGeneral -= c.n
	}
	if b.peers[c.peer] -= c.n; b.peers[c.peer] <= 0 {
		delete(b.peers, c.peer)
	}
}

// queue keeps the reservation with the decoded message until it is delivered.
func (b *IngressBudget) queue(msg any, c ingressCharge) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.queued[msg] = c
}

// delivered releases the reservation of a message the consumer took; it reports whether the message was one of the budget's.
func (b *IngressBudget) delivered(msg any) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.queued[msg]
	if ok {
		delete(b.queued, msg)
		b.releaseLocked(c)
	}
	return ok
}

// Used is the number of bytes reserved.
func (b *IngressBudget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}
