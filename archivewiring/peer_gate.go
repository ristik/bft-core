package archivewiring

import (
	"context"
	"errors"
	"fmt"
	"sync"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/shardnode"
)

var ErrPeerGate = errors.New("archive wiring: invalid peer stream gate")

// PeerGatedHost applies one shared per-peer stream bound to every outbound
// archive operation using the host. Other protocols pass through unchanged.
// Gate entries are removed after their last waiter or stream releases, so the
// map only retains peers with in-flight work.
type PeerGatedHost struct {
	shardnode.EvidenceHost
	limit int
	mu    sync.Mutex
	peers map[peer.ID]*peerGateEntry
}

type peerGateEntry struct {
	active chan struct{}
	refs   int
}

func NewPeerGatedHost(host shardnode.EvidenceHost, limit int) (*PeerGatedHost, error) {
	if host == nil || limit < 1 || limit > 64 {
		return nil, ErrPeerGate
	}
	return &PeerGatedHost{EvidenceHost: host, limit: limit, peers: make(map[peer.ID]*peerGateEntry)}, nil
}

func (h *PeerGatedHost) CreateStream(ctx context.Context, id peer.ID, protocolID string) (libp2pnetwork.Stream, error) {
	if protocolID != ProtocolArchive {
		return h.EvidenceHost.CreateStream(ctx, id, protocolID)
	}
	if id == "" {
		return nil, ErrPeerGate
	}
	release, err := h.acquire(ctx, id)
	if err != nil {
		return nil, err
	}
	stream, err := h.EvidenceHost.CreateStream(ctx, id, protocolID)
	if err != nil {
		release()
		return nil, err
	}
	return &peerGatedStream{Stream: stream, release: release}, nil
}

func (h *PeerGatedHost) acquire(ctx context.Context, id peer.ID) (func(), error) {
	h.mu.Lock()
	entry := h.peers[id]
	if entry == nil {
		entry = &peerGateEntry{active: make(chan struct{}, h.limit)}
		h.peers[id] = entry
	}
	entry.refs++
	h.mu.Unlock()

	var once sync.Once
	releaseRef := func() {
		once.Do(func() {
			h.mu.Lock()
			entry.refs--
			if entry.refs == 0 {
				delete(h.peers, id)
			}
			h.mu.Unlock()
		})
	}
	select {
	case entry.active <- struct{}{}:
		return func() {
			<-entry.active
			releaseRef()
		}, nil
	case <-ctx.Done():
		releaseRef()
		return nil, fmt.Errorf("%w: %v", ErrPeerGate, ctx.Err())
	}
}

type peerGatedStream struct {
	libp2pnetwork.Stream
	release func()
	mu      sync.Once
}

func (s *peerGatedStream) Close() error {
	err := s.Stream.Close()
	s.mu.Do(s.release)
	return err
}

func (s *peerGatedStream) Reset() error {
	err := s.Stream.Reset()
	s.mu.Do(s.release)
	return err
}
