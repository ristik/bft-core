package poswitness

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type pipeStream struct {
	net.Conn
	closeWrite func()
}

func (p pipeStream) CloseWrite() error { p.closeWrite(); return nil }
func (p pipeStream) Reset() error      { return p.Conn.Close() }

// halfPipe is a net.Pipe whose CloseWrite is a no-op: the requests are fixed-size, so the server never waits for EOF.
func pipePair() (client, server Stream) {
	c, s := net.Pipe()
	return pipeStream{Conn: c, closeWrite: func() {}}, pipeStream{Conn: s, closeWrite: func() {}}
}

type memSource map[[32]byte][]byte

func (m memSource) Witness(h [32]byte) ([]byte, error) {
	if d, ok := m[h]; ok {
		return d, nil
	}
	return nil, errors.New("not held")
}

// network connects openers to servers by peer id.
type network struct {
	servers map[peer.ID]*Server
	self    peer.ID
	dialled []peer.ID
	mu      sync.Mutex
	wrap    func(Stream) Stream
}

func (n *network) CreateStream(_ context.Context, to peer.ID, protocol string) (Stream, error) {
	n.mu.Lock()
	n.dialled = append(n.dialled, to)
	n.mu.Unlock()
	srv, ok := n.servers[to]
	if !ok || protocol != ProtocolID {
		return nil, errors.New("unreachable")
	}
	c, s := pipePair()
	go srv.Serve(n.self, s)
	if n.wrap != nil {
		c = n.wrap(c)
	}
	return c, nil
}

func witness(seed byte) ([32]byte, []byte) {
	data := make([]byte, 1000+int(seed))
	for i := range data {
		data[i] = seed + byte(i)
	}
	return sha256.Sum256(data), data
}

func allowAll(peer.ID) bool { return true }

func TestFetchReturnsTheWitnessAnyAllowedPeerHolds(t *testing.T) {
	h, data := witness(1)
	net := &network{self: "asker", servers: map[peer.ID]*Server{
		"empty":  NewServer(memSource{}, allowAll),
		"holder": NewServer(memSource{h: data}, allowAll),
	}}
	got, err := Fetch(context.Background(), net, []peer.ID{"gone", "empty", "holder"}, h)
	require.NoError(t, err)
	require.Equal(t, data, got)
	require.Equal(t, []peer.ID{"gone", "empty", "holder"}, net.dialled, "peers are asked in the given order")
}

func TestFetchStopsAtTheFirstHolder(t *testing.T) {
	h, data := witness(2)
	net := &network{self: "asker", servers: map[peer.ID]*Server{
		"a": NewServer(memSource{h: data}, allowAll), "b": NewServer(memSource{h: data}, allowAll)}}
	_, err := Fetch(context.Background(), net, []peer.ID{"a", "b"}, h)
	require.NoError(t, err)
	require.Equal(t, []peer.ID{"a"}, net.dialled)
}

func TestFetchNeverAcceptsBytesThatAreNotTheRequestedWitness(t *testing.T) {
	h, data := witness(3)
	_, other := witness(4)
	// a lying peer serves other bytes under the hash (its source is not hash-checked on the wire from the client's view)
	lying := &lyingServer{answer: other}
	net := &network{self: "asker", servers: map[peer.ID]*Server{"holder": NewServer(memSource{h: data}, allowAll)},
		wrap: nil}
	got, err := fetchOneStream(context.Background(), lying, h)
	require.ErrorIs(t, err, ErrWire)
	require.Nil(t, got)
	// and the honest path still works
	got, err = Fetch(context.Background(), net, []peer.ID{"holder"}, h)
	require.NoError(t, err)
	require.Equal(t, data, got)
}

// lyingServer answers any request with a fixed frame.
type lyingServer struct{ answer []byte }

func fetchOneStream(ctx context.Context, l *lyingServer, hash [32]byte) ([]byte, error) {
	c, s := pipePair()
	go func() {
		var req [32]byte
		_, _ = s.Read(req[:])
		prefix := []byte{byte(len(l.answer) >> 24), byte(len(l.answer) >> 16), byte(len(l.answer) >> 8), byte(len(l.answer))}
		_, _ = s.Write(prefix)
		_, _ = s.Write(l.answer)
		_ = s.Close()
	}()
	return exchange(ctx, c, hash)
}

func TestFetchRefusesAnOversizedAnnouncement(t *testing.T) {
	c, s := pipePair()
	go func() {
		var req [32]byte
		_, _ = s.Read(req[:])
		_, _ = s.Write([]byte{0xff, 0xff, 0xff, 0xff})
		_ = s.Close()
	}()
	_, err := exchange(context.Background(), c, [32]byte{1})
	require.ErrorIs(t, err, ErrWire)
	require.ErrorContains(t, err, "exceed the bound", "refused for its announced size, before any body is read")
}

func TestFetchNamesTheUnavailableWitness(t *testing.T) {
	h, _ := witness(5)
	net := &network{self: "asker", servers: map[peer.ID]*Server{"a": NewServer(memSource{}, allowAll)}}
	_, err := Fetch(context.Background(), net, []peer.ID{"a", "b"}, h)
	require.ErrorIs(t, err, ErrUnavailable)
	_, err = Fetch(context.Background(), net, nil, h)
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestTheServerServesOnlyAllowedPeers(t *testing.T) {
	h, data := witness(6)
	srv := NewServer(memSource{h: data}, func(p peer.ID) bool { return p == "root" })
	for peerID, want := range map[peer.ID]bool{"root": true, "stranger": false} {
		net := &network{self: peerID, servers: map[peer.ID]*Server{"srv": srv}}
		_, err := Fetch(context.Background(), net, []peer.ID{"srv"}, h)
		require.Equal(t, want, err == nil, peerID)
	}
}

func TestTheServerNeverServesBytesThatDoNotHashToTheRequest(t *testing.T) {
	h, _ := witness(7)
	_, wrong := witness(8)
	srv := NewServer(memSource{h: wrong}, allowAll) // a corrupt store
	c, s := pipePair()
	go srv.Serve("asker", s)
	_, err := c.Write(h[:])
	require.NoError(t, err)
	var prefix [4]byte
	_, err = io.ReadFull(c, prefix[:])
	require.NoError(t, err)
	require.Equal(t, [4]byte{}, prefix, "the server answers 'not held' rather than serve bytes that are not the witness")
}

func TestTheServerConcurrencyGates(t *testing.T) {
	srv := NewServer(memSource{}, allowAll)
	for i := 0; i < MaxPendingPerPeer; i++ {
		require.True(t, srv.admit("p"), i)
	}
	require.False(t, srv.admit("p"), "a peer's streams are bounded")
	srv.release("p")
	require.True(t, srv.admit("p"))
	// the global bound
	var held []peer.ID
	for i := 0; i < MaxPendingStreams-MaxPendingPerPeer; i++ {
		id := peer.ID(string(rune('a' + i)))
		require.True(t, srv.admit(id), i)
		held = append(held, id)
	}
	require.False(t, srv.admit("overflow"))
	srv.release(held[0])
	require.True(t, srv.admit("overflow"))
}

// a fake that resets the first streams (a server at its limit) and serves afterwards
func TestFetchRetriesAfterAReset(t *testing.T) {
	h, data := witness(9)
	srv := NewServer(memSource{h: data}, allowAll)
	resets := 2
	op := openerFunc(func(_ context.Context, _ peer.ID, _ string) (Stream, error) {
		c, s := pipePair()
		if resets > 0 {
			resets--
			_ = s.Reset()
			return c, nil
		}
		go srv.Serve("asker", s)
		return c, nil
	})
	got, err := Fetch(context.Background(), op, []peer.ID{"author"}, h)
	require.NoError(t, err)
	require.Equal(t, data, got)
	require.Zero(t, resets)
}

func TestFetchGivesUpWhenTheContextEnds(t *testing.T) {
	h, _ := witness(10)
	slow := openerFunc(func(ctx context.Context, _ peer.ID, _ string) (Stream, error) {
		c, _ := pipePair() // the peer accepts and never answers
		return c, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Fetch(ctx, slow, []peer.ID{"slow1", "slow2", "slow3"}, h)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Less(t, time.Since(start), 2*time.Second, "one deadline bounds the fetch over every peer and round")
}

type openerFunc func(ctx context.Context, to peer.ID, protocol string) (Stream, error)

func (f openerFunc) CreateStream(ctx context.Context, to peer.ID, protocol string) (Stream, error) {
	return f(ctx, to, protocol)
}
