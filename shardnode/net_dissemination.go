package shardnode

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/network"
)

// ProtocolShardPayload is the shard's own validator-to-validator gossip
// protocol — separate from every root-chain-facing protocol in
// network/root_chain_network.go, since this traffic never touches the root
// chain at all.
const ProtocolShardPayload = "/unicity/shard-payload/1.0.0"

// disseminatedBlock is the wire message NetDisseminator sends: a CBOR
// toarray struct, matching bft-core's own protocol convention (see
// network/protocol/certification for the pattern this follows) rather than
// inventing a different wire format for shard-internal traffic.
type disseminatedBlock struct {
	_          struct{} `cbor:",toarray"`
	Round      uint64
	Number     uint64
	Hash       []byte
	StateRoot  []byte
	ParentHash []byte
	Raw        []byte
	BlockSize  uint64
	StateSize  uint64
}

// NetDisseminator is the multi-validator Disseminator: the leader's Publish
// sends to every other validator over libp2p; every non-leader's Await
// blocks on the corresponding per-round channel until Run — which must be
// started separately and kept running for the node's lifetime — delivers a
// matching message.
//
// It shares an underlying network.Peer (libp2p host) with BFTClient's own
// root-chain connection but registers its own protocol on its own
// LibP2PNetwork instance, so shard-internal gossip and root-chain traffic
// never share a receive channel — see NewNetDisseminator.
type NetDisseminator struct {
	net   *network.LibP2PNetwork
	peers PeerLister // the shard's other validators, excluding this node, as of each publish

	mu      sync.Mutex
	waiters map[uint64]chan Block
	closed  bool
}

// NewNetDisseminator registers ProtocolShardPayload on p (the same peer
// BFTClient uses for the root-chain connection — libp2p hosts support
// multiple protocols on one connection) and returns a Disseminator that
// sends to exactly peers. peers should be every other validator in the
// shard's validator set, resolved from their node IDs — never including
// this node's own ID.
func NewNetDisseminator(p *network.Peer, obs network.Observability, peers []peer.ID) (*NetDisseminator, error) {
	return NewNetDisseminatorFrom(p, obs, StaticPeers(peers))
}

// PeerLister is the shard's other validators at the moment it is asked.
type PeerLister interface{ Peers() []peer.ID }

// StaticPeers is a fixed peer list (a deployment that follows no assignment).
type StaticPeers []peer.ID

func (s StaticPeers) Peers() []peer.ID { return []peer.ID(s) }

// NewNetDisseminatorFrom is NewNetDisseminator for a recipient set that follows the verified, installed assignment: every publish
// addresses the validators the source names then, not the ones the genesis configuration named.
func NewNetDisseminatorFrom(p *network.Peer, obs network.Observability, peers PeerLister) (*NetDisseminator, error) {
	net, err := network.NewLibP2PNetwork(p, 100, obs)
	if err != nil {
		return nil, fmt.Errorf("shardnode: creating dissemination network: %w", err)
	}

	if err := net.RegisterSendProtocols([]network.SendProtocolDescription{
		{ProtocolID: ProtocolShardPayload, MsgType: disseminatedBlock{}, Timeout: 2 * time.Second},
	}); err != nil {
		return nil, fmt.Errorf("shardnode: registering dissemination send protocol: %w", err)
	}
	if err := net.RegisterReceiveProtocols([]network.ReceiveProtocolDescription{
		{ProtocolID: ProtocolShardPayload, TypeFn: func() any { return &disseminatedBlock{} }},
	}); err != nil {
		return nil, fmt.Errorf("shardnode: registering dissemination receive protocol: %w", err)
	}

	return &NetDisseminator{net: net, peers: peers, waiters: make(map[uint64]chan Block)}, nil
}

// Run delivers incoming dissemination messages to whichever Await call is
// waiting on their round, until ctx is done. Must run for the lifetime of
// the node — wire it into the same errgroup as BFTClient.Run (see node.go).
func (d *NetDisseminator) Run(ctx context.Context) error {
	received := d.net.ReceivedChannel()
	for {
		select {
		case <-ctx.Done():
			d.Close()
			return ctx.Err()
		case msg, ok := <-received:
			if !ok {
				return errors.New("shardnode: dissemination network channel closed")
			}
			db, ok := msg.(*disseminatedBlock)
			if !ok {
				continue // not this protocol's message type; ignore rather than fail the whole loop
			}
			d.deliver(db)
		}
	}
}

func (d *NetDisseminator) deliver(db *disseminatedBlock) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	ch := d.chanForLocked(db.Round)
	b := Block{
		Number:     db.Number,
		Hash:       db.Hash,
		StateRoot:  db.StateRoot,
		ParentHash: db.ParentHash,
		Raw:        db.Raw,
		BlockSize:  db.BlockSize,
		StateSize:  db.StateSize,
	}
	select {
	case ch <- b:
	default:
		// A round is only ever published once by an honest leader; a
		// second delivery for the same round (a retransmit, a duplicate
		// route) is dropped rather than blocking or overwriting — matches
		// LoopbackDisseminator's same non-blocking send.
	}
}

func (d *NetDisseminator) Publish(ctx context.Context, round uint64, b Block) error {
	peers := d.peers.Peers()
	if len(peers) == 0 {
		return nil // single-validator shard: nothing to disseminate to
	}
	msg := &disseminatedBlock{
		Round:      round,
		Number:     b.Number,
		Hash:       b.Hash,
		StateRoot:  b.StateRoot,
		ParentHash: b.ParentHash,
		Raw:        b.Raw,
		BlockSize:  b.BlockSize,
		StateSize:  b.StateSize,
	}
	return d.net.Send(ctx, msg, peers...)
}

func (d *NetDisseminator) Await(ctx context.Context, round uint64) (Block, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return Block{}, ErrDisseminationClosed
	}
	ch := d.chanForLocked(round)
	d.mu.Unlock()

	select {
	case b := <-ch:
		return b, nil
	case <-ctx.Done():
		return Block{}, fmt.Errorf("shardnode: awaiting round %d: %w", round, ctx.Err())
	}
}

// chanForLocked must be called with d.mu held.
func (d *NetDisseminator) chanForLocked(round uint64) chan Block {
	ch, ok := d.waiters[round]
	if !ok {
		ch = make(chan Block, 1)
		d.waiters[round] = ch
	}
	return ch
}

func (d *NetDisseminator) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	for _, ch := range d.waiters {
		close(ch)
	}
}

var _ Disseminator = (*NetDisseminator)(nil)
