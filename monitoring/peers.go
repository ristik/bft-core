package monitoring

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerSet is a group of peers a node is expected to be connected to: the root committee, the shard's validators.
type PeerSet struct {
	Network  string           // the metric's network label: "root" or "shard"
	Expected func() []peer.ID // the peers it should reach, read at every scrape (the set changes with the committee); may include the node itself
}

// Peers registers unicity_peers_connected{network} and unicity_peers_expected{network} for each set, the node itself excluded, and logs
// node.peers.low when a set has fewer connected peers than expected (see Watch).
type Peers struct {
	net  network.Network
	self peer.ID
	log  *slog.Logger
	sets []PeerSet
	mu   sync.Mutex
	low  map[string]bool
}

// RegisterPeers registers the peer gauges. Call Watch to log the events between scrapes.
func RegisterPeers(r *Registry, log *slog.Logger, net network.Network, self peer.ID, sets ...PeerSet) *Peers {
	p := &Peers{net: net, self: self, log: log, sets: sets, low: map[string]bool{}}
	for _, s := range sets {
		r.GaugeFunc("unicity_peers_connected", "Peers of the network this node is connected to, itself excluded.", func() float64 { c, _ := p.count(s); return float64(c) }, "network", s.Network)
		r.GaugeFunc("unicity_peers_expected", "Peers of the network this node is expected to be connected to, itself excluded.", func() float64 { _, e := p.count(s); return float64(e) }, "network", s.Network)
	}
	return p
}

func (p *Peers) count(s PeerSet) (connected, expected int) {
	for _, id := range s.Expected() {
		if id == p.self {
			continue
		}
		expected++
		if p.net.Connectedness(id) == network.Connected {
			connected++
		}
	}
	return connected, expected
}

// Watch evaluates the sets every interval until ctx ends and logs node.peers.low and node.peers.recovered on the crossings. A set must stay
// low for grace before it is logged (a restart's reconnect is not an event).
func (p *Peers) Watch(ctx context.Context, interval, grace time.Duration) {
	if p == nil || p.log == nil {
		return
	}
	since := map[string]time.Time{}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, s := range p.sets {
				c, e := p.count(s)
				low := e > 0 && c < e
				p.mu.Lock()
				was := p.low[s.Network]
				if low {
					if since[s.Network].IsZero() {
						since[s.Network] = time.Now()
					}
					if !was && time.Since(since[s.Network]) >= grace {
						p.low[s.Network] = true
						p.mu.Unlock()
						p.log.Warn("connected peers are below the committee", "network", s.Network, "connected", c, "expected", e, Event(EvNodePeersLow))
						continue
					}
				} else {
					since[s.Network] = time.Time{}
					if was {
						p.low[s.Network] = false
						p.mu.Unlock()
						p.log.Info("connected peers are back to the committee", "network", s.Network, "connected", c, "expected", e, Event(EvNodePeersRecovered))
						continue
					}
				}
				p.mu.Unlock()
			}
		}
	}
}
