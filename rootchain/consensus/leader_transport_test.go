package consensus

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// The production settings the transport row keeps: cli/ubft/cmd/root_node.go's default --max-requests and defaultNetworkTimeout. The shard side is
// network.DefaultShardNetworkOptions; the 1 s read deadline and the absent frame limits are in network/network.go and are not parameters.
const (
	transportCapacity = 1000
	transportTimeout  = 300 * time.Millisecond
)

// newRootNode makes the production root node of a manager. rootchain imports this package, so an external test file of this test binary sets it.
var newRootNode func(p *network.Peer, partitionNet *network.LibP2PNetwork, cm *ConsensusManager, obs network.Observability) (interface {
	Run(context.Context) error
}, error)

// tappedNet is the production consensus network. Send also shows the message to the trace; receiving is the production queue itself.
type tappedNet struct {
	*network.LibP2PNetwork
	tap func(any)
}

func (n *tappedNet) Send(ctx context.Context, msg any, receivers ...peer.ID) error {
	if n.tap != nil {
		n.tap(msg)
	}
	return n.LibP2PNetwork.Send(ctx, msg, receivers...)
}

type rootHost struct {
	peer      *network.Peer
	consensus *tappedNet
	partition *network.LibP2PNetwork
	closed    bool
}

type shardHost struct {
	peer *network.Peer
	net  *network.ShardNetwork
}

type certReceipt struct {
	at   time.Time
	node string
	hash []byte
	seal uint64 // the certificate's root round: a later one with the same hash is a T2 repeat
}

// liveTransport puts a live cluster on the production path over same-host TCP: libp2p hosts with the nodes' keys, framing, the receive queues, the
// production root node's ingress in front of each manager and the shard network behind each validator, which submits its own signed request and
// receives its own certificate. Peers learn addresses from the peerstore, not from the DHT. A node not up yet has a host nobody has an address for; a
// node going down closes its host. It is single-host loopback evidence, not separate hosts or a WAN.
type liveTransport struct {
	t      *testing.T
	obs    network.Observability
	tap    func(any)
	mu     sync.Mutex
	roots  map[peer.ID]*rootHost
	shards map[string]*shardHost
	certs  map[string][]certReceipt
	online []*rootHost
	names  map[string]peer.ID
}

func newLiveTransport(t *testing.T) *liveTransport {
	return &liveTransport{t: t, obs: testobservability.Default(t), roots: map[peer.ID]*rootHost{}, shards: map[string]*shardHost{}, certs: map[string][]certReceipt{}, names: map[string]peer.ID{}}
}

func (x *liveTransport) newPeer(conf *network.PeerConfiguration) *network.Peer {
	own, err := network.NewPeerConfiguration("/ip4/127.0.0.1/tcp/0", nil, conf.KeyPair, nil, nil)
	require.NoError(x.t, err)
	p, err := network.NewPeer(context.Background(), own, x.obs.Logger(), nil)
	require.NoError(x.t, err)
	return p
}

// install makes the cluster's nodes run on this transport.
func (x *liveTransport) install(c *q4bLive) {
	x.t.Logf("transport: production libp2p over same-host TCP, receive capacity %d, root send timeout %s, shard %+v", transportCapacity, transportTimeout, network.DefaultShardNetworkOptions)
	c.link = func(_ int, r *q3Replica) RootNet {
		h := x.roots[r.id()]
		if h == nil {
			p := x.newPeer(r.node.PeerConf)
			cons, err := network.NewLibP2RootConsensusNetwork(p, transportCapacity, transportTimeout, x.obs)
			require.NoError(x.t, err)
			partition, err := network.NewLibP2PRootChainNetwork(p, transportCapacity, transportTimeout, x.obs)
			require.NoError(x.t, err)
			h = &rootHost{peer: p, consensus: &tappedNet{LibP2PNetwork: cons}, partition: partition}
			h.consensus.tap = func(msg any) {
				if x.tap != nil {
					x.tap(msg)
				}
			}
			x.roots[r.id()] = h
			x.t.Cleanup(func() { x.closeRoot(h) })
		}
		return h.consensus
	}
	c.run = func(i int, cm *ConsensusManager) func(context.Context) error {
		h := x.roots[c.nodes[i].r.id()]
		node, err := newRootNode(h.peer, h.partition, cm, x.obs)
		require.NoError(x.t, err)
		return node.Run
	}
}

func (x *liveTransport) closeRoot(h *rootHost) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if !h.closed {
		h.closed = true
		_ = h.peer.Close()
	}
}

// addShards starts every shard validator's production shard network and its receipt of certificates.
func (x *liveTransport) addShards(f *q3fixture.Fixture) {
	ctx, cancel := context.WithCancel(context.Background())
	x.t.Cleanup(cancel)
	for id, node := range f.ShardNodes {
		p := x.newPeer(node.PeerConf)
		x.t.Cleanup(func() { _ = p.Close() })
		n, err := network.NewShardNetwork(p, x.obs, network.DefaultShardNetworkOptions)
		require.NoError(x.t, err)
		x.shards[id] = &shardHost{peer: p, net: n}
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case msg := <-n.ReceivedChannel():
					x.receive(id, msg)
				}
			}
		}()
	}
}

func (x *liveTransport) receive(id string, msg any) {
	var cr *certification.CertificationResponse
	switch m := msg.(type) {
	case *certification.CertificationResponse:
		cr = m
	case *certification.CertificationResponseV2:
		cr = &m.Response
	case *certification.CertificationResponseV3:
		cr = &m.Response
	default:
		return
	}
	key := liveShard{partition: cr.Partition, shard: cr.Shard}.String()
	x.mu.Lock()
	defer x.mu.Unlock()
	x.certs[key] = append(x.certs[key], certReceipt{at: time.Now(), node: id, hash: bytes.Clone(cr.UC.InputRecord.Hash), seal: cr.UC.UnicitySeal.RootChainRoundNumber})
}

// up gives the named nodes, and everybody already up, each other's addresses, and the shards theirs.
func (x *liveTransport) up(c *q4bLive, names ...string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, name := range names {
		x.names[name] = c.id(name)
		h := x.roots[c.id(name)]
		for _, other := range x.online {
			if !other.closed {
				h.peer.Network().Peerstore().AddAddrs(other.peer.ID(), other.peer.MultiAddresses(), peerstore.PermanentAddrTTL)
				other.peer.Network().Peerstore().AddAddrs(h.peer.ID(), h.peer.MultiAddresses(), peerstore.PermanentAddrTTL)
			}
		}
		for _, s := range x.shards {
			h.peer.Network().Peerstore().AddAddrs(s.peer.ID(), s.peer.MultiAddresses(), peerstore.PermanentAddrTTL)
			s.peer.Network().Peerstore().AddAddrs(h.peer.ID(), h.peer.MultiAddresses(), peerstore.PermanentAddrTTL)
		}
		x.online = append(x.online, h)
	}
}

func (x *liveTransport) down(c *q4bLive, name string) { x.closeRoot(x.roots[c.id(name)]) }

// receipts are the certificates of a shard its validators received, from the from'th on.
func (x *liveTransport) receipts(s liveShard, from int) []certReceipt {
	x.mu.Lock()
	defer x.mu.Unlock()
	return slices.Clone(x.certs[s.String()][min(from, len(x.certs[s.String()])):])
}

// submit is each validator sending its own signed request to the root over its shard network. The send is asynchronous: its success says nothing about
// delivery, which the trace reads at the receiver.
func (x *liveTransport) submit(name string, req *IRChangeRequest) error {
	to := x.names[name]
	for _, bcr := range req.Requests {
		s := x.shards[bcr.NodeID]
		if s == nil {
			return fmt.Errorf("no shard host for validator %s", bcr.NodeID)
		}
		if err := s.net.Send(context.Background(), bcr, to); err != nil {
			return err
		}
	}
	return nil
}

// reportDelivery requires every shard's fresh certificate at the shard's own validators, not only in a root's store, and logs when it came,
// counted from t0, which origin names ("the stop", "the first send").
func (x *liveTransport) reportDelivery(t0 time.Time, origin string, shards []liveShard, hash func(liveShard) []byte) {
	x.t.Helper()
	for _, s := range shards {
		want := hash(s)
		key := s.String()
		require.Eventually(x.t, func() bool {
			x.mu.Lock()
			defer x.mu.Unlock()
			return slices.ContainsFunc(x.certs[key], func(r certReceipt) bool { return bytes.Equal(r.hash, want) })
		}, 10*time.Second, 5*time.Millisecond, "the certificate of shard %s reaches a validator of the shard", s)
		x.mu.Lock()
		first, n := time.Time{}, 0
		nodes := map[string]bool{}
		for _, r := range x.certs[key] {
			if bytes.Equal(r.hash, want) {
				n++
				nodes[r.node] = true
				if first.IsZero() || r.at.Before(first) {
					first = r.at
				}
			}
		}
		x.mu.Unlock()
		x.t.Logf("shard %s: fresh certificate first received by a validator %s after %s; %d receipts at %d validators", s, first.Sub(t0).Round(time.Millisecond), origin, n, len(nodes))
	}
}

// SetNewRootNode is for the external test file that may import rootchain.
func SetNewRootNode(f func(p *network.Peer, partitionNet *network.LibP2PNetwork, cm *ConsensusManager, obs network.Observability) (interface {
	Run(context.Context) error
}, error)) {
	newRootNode = f
}
