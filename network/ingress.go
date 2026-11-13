package network

import (
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
)

// IngressBudget reserves the bytes of received frames of a protocol (#1032): a frame's declared length is reserved, globally and for
// its peer, before any of its payload is read or allocated, and the reservation is kept while the decoded message waits in the receive
// queue, until the consumer takes it (LibP2PNetwork.Delivered) or it is dropped. A frame that does not fit is refused and its stream
// reset, so the bytes in flight and queued for the protocol never exceed the budget, whatever lengths senders declare.
type IngressBudget struct {
	mu      sync.Mutex
	global  int64
	perPeer int64
	used    int64
	peers   map[peer.ID]int64
	queued  map[any]ingressCharge
}

type ingressCharge struct {
	peer peer.ID
	n    int64
}

// NewIngressBudget is a budget of global bytes in flight and queued, of which one peer may hold at most perPeer.
func NewIngressBudget(global, perPeer int64) *IngressBudget {
	return &IngressBudget{global: global, perPeer: perPeer, peers: make(map[peer.ID]int64), queued: make(map[any]ingressCharge)}
}

func (b *IngressBudget) reserve(p peer.ID, n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || b.used+n > b.global || b.peers[p]+n > b.perPeer {
		return false
	}
	b.used += n
	b.peers[p] += n
	return true
}

func (b *IngressBudget) release(p peer.ID, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releaseLocked(p, n)
}

func (b *IngressBudget) releaseLocked(p peer.ID, n int64) {
	b.used -= n
	if b.peers[p] -= n; b.peers[p] <= 0 {
		delete(b.peers, p)
	}
}

// queue keeps the reservation with the decoded message until it is delivered.
func (b *IngressBudget) queue(msg any, p peer.ID, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.queued[msg] = ingressCharge{peer: p, n: n}
}

// delivered releases the reservation of a message the consumer took; it reports whether the message was one of the budget's.
func (b *IngressBudget) delivered(msg any) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.queued[msg]
	if ok {
		delete(b.queued, msg)
		b.releaseLocked(c.peer, c.n)
	}
	return ok
}

// Used is the number of bytes reserved.
func (b *IngressBudget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}
