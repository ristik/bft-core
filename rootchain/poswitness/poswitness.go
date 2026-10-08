// Package poswitness is the pull-by-hash protocol that distributes the witnesses of P85 root controls.
//
// A control commits to its witness by SHA-256 only (a closure archive bundle can be tens of megabytes; an EVM storage-proof witness up to
// 1 MiB), so the bytes are not part of the proposal. A node that validates a block carrying a control it does not hold the witness of
// asks the other root nodes for it by hash. The hash is the authentication: a response is accepted only if it hashes to the request, so
// a peer can withhold a witness (the node then does not vote and recovers later) but never substitute one.
//
// The protocol is one request per stream: the 32-byte hash, answered by a 4-byte big-endian length and that many bytes, or length zero
// when the peer does not hold it. It is served only to the root nodes of the current trust base.
package poswitness

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// ProtocolID is the libp2p protocol the witnesses are served on.
	ProtocolID = "/ab/p85-witness/1.0.0"
	// MaxWitnessBytes bounds one witness: the closure archive bundle bound of the witness store.
	MaxWitnessBytes = 64 << 20
	// ClientDeadline bounds one fetch from one peer.
	ClientDeadline = 30 * time.Second
	// ServerDeadline bounds one served stream.
	ServerDeadline = 60 * time.Second
	// MaxPendingStreams bounds the streams served at once, MaxPendingPerPeer those of one peer. At a proposal every voter asks the
	// author at once and a block can carry several controls, so the bounds are those of a committee, not of one peer; a request over
	// them is reset and the client retries with a backoff (see Fetch).
	MaxPendingStreams = 16
	MaxPendingPerPeer = 2
	// FetchRounds is how many times Fetch walks the peer list before giving up, and RetryBackoff the pause before round n (n * backoff).
	FetchRounds  = 3
	RetryBackoff = 100 * time.Millisecond
)

var (
	// ErrUnavailable reports a witness no asked peer could provide.
	ErrUnavailable = errors.New("P85 witness unavailable from the asked peers")
	// ErrWire reports a malformed exchange.
	ErrWire = errors.New("P85 witness exchange malformed")
)

// Source returns the retained witness for a hash, or an error when it holds none.
type Source interface {
	Witness(hash [32]byte) ([]byte, error)
}

// Stream is the part of a libp2p stream the protocol uses.
type Stream interface {
	io.ReadWriter
	SetDeadline(time.Time) error
	CloseWrite() error
	Close() error
	Reset() error
}

// Opener opens a stream to a peer.
type Opener interface {
	CreateStream(ctx context.Context, to peer.ID, protocol string) (Stream, error)
}

// Libp2p adapts a host's stream opener.
type Libp2p interface {
	CreateStream(ctx context.Context, to peer.ID, protocol string) (libp2pnetwork.Stream, error)
}

type libp2pOpener struct{ host Libp2p }

// FromLibp2p is the Opener of a libp2p host.
func FromLibp2p(host Libp2p) Opener { return libp2pOpener{host} }

func (o libp2pOpener) CreateStream(ctx context.Context, to peer.ID, protocol string) (Stream, error) {
	return o.host.CreateStream(ctx, to, protocol)
}

// Server answers witness requests from the root nodes.
type Server struct {
	source  Source
	allowed func(peer.ID) bool

	mu      sync.Mutex
	pending int
	peers   map[peer.ID]*peerState
}

type peerState struct{ active int }

// NewServer serves source to the peers allowed accepts. allowed is consulted per request, so a trust-base change takes effect at once.
func NewServer(source Source, allowed func(peer.ID) bool) *Server {
	return &Server{source: source, allowed: allowed, peers: map[peer.ID]*peerState{}}
}

// Handler is the libp2p stream handler.
func (s *Server) Handler(st libp2pnetwork.Stream) { s.Serve(st.Conn().RemotePeer(), st) }

// Serve answers one request on st. Anything it does not like resets the stream.
func (s *Server) Serve(from peer.ID, st Stream) {
	if !s.admit(from) {
		_ = st.Reset()
		return
	}
	defer s.release(from)
	if err := st.SetDeadline(time.Now().Add(ServerDeadline)); err != nil {
		_ = st.Reset()
		return
	}
	var hash [32]byte
	if _, err := io.ReadFull(st, hash[:]); err != nil {
		_ = st.Reset()
		return
	}
	data, err := s.source.Witness(hash)
	if err != nil || len(data) == 0 || len(data) > MaxWitnessBytes || sha256.Sum256(data) != hash {
		data = nil
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	if _, err := st.Write(prefix[:]); err != nil {
		_ = st.Reset()
		return
	}
	if _, err := st.Write(data); err != nil {
		_ = st.Reset()
		return
	}
	_ = st.Close()
}

func (s *Server) admit(from peer.ID) bool {
	if from == "" || s.allowed == nil || !s.allowed(from) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.peers[from]
	if st == nil {
		st = &peerState{}
		s.peers[from] = st
	}
	if s.pending >= MaxPendingStreams || st.active >= MaxPendingPerPeer {
		return false
	}
	st.active++
	s.pending++
	return true
}

func (s *Server) release(from peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[from].active--
	s.pending--
}

// Fetch asks the peers in order for the witness with the given hash and returns the first response that hashes to it. A peer that is
// unreachable, does not hold it, resets the stream (it is serving its limit of streams) or answers with other bytes is skipped; the
// whole list is walked up to FetchRounds times with a growing pause, so a burst of voters that overran the author's stream limit gets
// the witness once the first streams finish. ctx bounds the whole fetch.
func Fetch(ctx context.Context, opener Opener, peers []peer.ID, hash [32]byte) ([]byte, error) {
	var errs []error
	for round := 0; round < FetchRounds && len(peers) > 0; round++ {
		if round > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(time.Duration(round) * RetryBackoff):
			}
		}
		for _, p := range peers {
			if ctx.Err() != nil {
				return nil, errors.Join(append([]error{ErrUnavailable, ctx.Err()}, errs...)...)
			}
			data, err := fetchOne(ctx, opener, p, hash)
			if err == nil {
				return data, nil
			}
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
		}
	}
	return nil, errors.Join(append([]error{ErrUnavailable}, errs...)...)
}

func fetchOne(ctx context.Context, opener Opener, to peer.ID, hash [32]byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, ClientDeadline)
	defer cancel()
	st, err := opener.CreateStream(ctx, to, ProtocolID)
	if err != nil {
		return nil, err
	}
	return exchange(ctx, st, hash)
}

func exchange(ctx context.Context, st Stream, hash [32]byte) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		if err := st.SetDeadline(dl); err != nil {
			_ = st.Reset()
			return nil, err
		}
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = st.Reset()
		case <-stop:
		}
	}()
	if _, err := st.Write(hash[:]); err != nil {
		_ = st.Reset()
		return nil, err
	}
	_ = st.CloseWrite()
	var prefix [4]byte
	if _, err := io.ReadFull(st, prefix[:]); err != nil {
		_ = st.Reset()
		return nil, fmt.Errorf("%w: length: %v", ErrWire, err)
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 {
		_ = st.Close()
		return nil, errors.New("the peer does not hold the witness")
	}
	if n > MaxWitnessBytes {
		_ = st.Reset()
		return nil, fmt.Errorf("%w: %d bytes exceed the bound", ErrWire, n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(st, data); err != nil {
		_ = st.Reset()
		return nil, fmt.Errorf("%w: body: %v", ErrWire, err)
	}
	_ = st.Close()
	if sha256.Sum256(data) != hash {
		return nil, fmt.Errorf("%w: the bytes are not the requested witness", ErrWire)
	}
	return data, nil
}
