package recordsfeed

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	p2p "github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

type serverFake struct {
	cuts    map[uint64]Cut
	records []rootrecords.Record
}

func (s serverFake) ControlCut(round uint64) (Cut, error) {
	if c, ok := s.cuts[round]; ok {
		return c, nil
	}
	return Cut{}, errors.New("pruned")
}

func (s serverFake) Records(from uint64, max int) ([]rootrecords.Record, error) {
	end := min(from+uint64(max), uint64(len(s.records)))
	if from >= end {
		return nil, nil
	}
	return s.records[from:end], nil
}

// The whole route over two real libp2p hosts: a shard pairs with a root, derives the cursor from a cut it verifies against its own
// certificate's tree root, and fetches and verifies the log.
func TestTheShardDerivesTheCursorAndTheLogFromARootOverLibp2p(t *testing.T) {
	root := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shard := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	stranger := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, p := range []*p2p.Peer{shard, stranger} {
		p.Network().Peerstore().AddAddrs(root.ID(), root.MultiAddresses(), peerstore.PermanentAddrTTL)
	}
	c := buildChain(t, 300)
	cut, origin := c.cutOf(t, 500, 9_000)
	server := NewServer(serverFake{cuts: map[uint64]Cut{500: cut}, records: c.records}, func(id peer.ID) bool { return id == shard.ID() })
	root.RegisterProtocolHandler(ProtocolID, server.Handler)
	t.Cleanup(func() { root.RemoveProtocolHandler(ProtocolID) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	src := NewSource(P2PRemote{Opener: FromLibp2p(shard), Roots: []peer.ID{root.ID()}})
	cursor, err := src.Cursor(ctx, origin)
	require.NoError(t, err)
	require.EqualValues(t, 301, cursor.TargetCount)
	require.Equal(t, c.records[300].ID, cursor.TargetTip)
	for _, i := range []uint64{0, 1, 255, 256, 300} {
		r, err := src.Record(i)
		require.NoError(t, err)
		require.Equal(t, c.records[i], r)
	}
	closure, _ := src.Record(0)
	require.EqualValues(t, 1, closure.ClosedEpoch, "the served closed epoch is the one the cut's state authenticates")

	// a round the root no longer holds is unavailable
	late := origin
	late.RootRound = 501
	_, err = NewSource(P2PRemote{Opener: FromLibp2p(shard), Roots: []peer.ID{root.ID()}}).Cursor(ctx, late)
	require.ErrorIs(t, err, ErrUnavailable)

	// a peer outside the allow-list gets nothing
	_, err = NewSource(P2PRemote{Opener: FromLibp2p(stranger), Roots: []peer.ID{root.ID()}}).Cursor(ctx, origin)
	require.ErrorIs(t, err, ErrUnavailable)

	// a root that lies about the cut is caught by the shard's own certificate
	forged := cut
	forgedCtl := *cut.Control
	forgedCtl.Pos = append([]byte(nil), cut.Control.Pos...)
	forgedCtl.Pos[len(forgedCtl.Pos)-1] ^= 1
	forged.Control = &forgedCtl
	liar := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shard.Network().Peerstore().AddAddrs(liar.ID(), liar.MultiAddresses(), peerstore.PermanentAddrTTL)
	liarServer := NewServer(serverFake{cuts: map[uint64]Cut{500: forged}, records: c.records}, func(peer.ID) bool { return true })
	liar.RegisterProtocolHandler(ProtocolID, liarServer.Handler)
	t.Cleanup(func() { liar.RemoveProtocolHandler(ProtocolID) })
	_, err = NewSource(P2PRemote{Opener: FromLibp2p(shard), Roots: []peer.ID{liar.ID()}}).Cursor(ctx, origin)
	require.ErrorIs(t, err, ErrAuth)
	// the next root in the list is asked when the first has nothing, never trusted when it lies
	good, err := NewSource(
		P2PRemote{Opener: FromLibp2p(shard), Roots: []peer.ID{liar.ID()}},
		P2PRemote{Opener: FromLibp2p(shard), Roots: []peer.ID{root.ID()}},
	).Cursor(ctx, origin)
	require.NoError(t, err, "a lying root is skipped for the honest one")
	require.EqualValues(t, 301, good.TargetCount)
}

type pipeStream struct{ net.Conn }

func (pipeStream) CloseWrite() error { return nil }
func (p pipeStream) Reset() error    { return p.Conn.Close() }

type pipeOpener map[peer.ID]*Server

func (o pipeOpener) CreateStream(_ context.Context, to peer.ID, protocol string) (Stream, error) {
	srv, ok := o[to]
	if !ok || protocol != ProtocolID {
		return nil, errors.New("unreachable")
	}
	c, s := net.Pipe()
	go srv.Serve("shard", pipeStream{s})
	return pipeStream{c}, nil
}

func TestTheClientAsksTheNextRootWhenOneHasNothingAndBoundsEveryResponse(t *testing.T) {
	c := buildChain(t, 3)
	cut, origin := c.cutOf(t, 200, 5_000)
	empty := NewServer(serverFake{}, func(peer.ID) bool { return true })
	full := NewServer(serverFake{cuts: map[uint64]Cut{200: cut}, records: c.records}, func(peer.ID) bool { return true })
	src := NewSource(P2PRemote{Opener: pipeOpener{"a": empty, "b": full}, Roots: []peer.ID{"gone", "a", "b"}})
	cursor, err := src.Cursor(context.Background(), origin)
	require.NoError(t, err)
	require.EqualValues(t, 4, cursor.TargetCount)

	// a request is bounded: the server resets an oversized frame instead of reading it
	cl, sv := net.Pipe()
	go empty.Serve("shard", pipeStream{sv})
	big := make([]byte, 4096)
	_ = pipeStream{cl}.SetDeadline(time.Now().Add(time.Second))
	_, _ = cl.Write(append([]byte{0, 0, 16, 0}, big...))
	buf := make([]byte, 4)
	_, err = cl.Read(buf)
	require.Error(t, err, "the server hung up")

	// a malformed request gets no answer
	cl2, sv2 := net.Pipe()
	go full.Serve("shard", pipeStream{sv2})
	_ = cl2.SetDeadline(time.Now().Add(time.Second))
	_ = writeFrame(cl2, []byte{0xff, 0xff})
	_, err = cl2.Read(buf)
	require.Error(t, err)

	// an announcement above the client's bound is refused before it is read
	tooBig, peerEnd := net.Pipe()
	go func() {
		_, _ = peerEnd.Write([]byte{0xff, 0xff, 0xff, 0xff})
		_ = peerEnd.Close()
	}()
	_ = tooBig.SetDeadline(time.Now().Add(time.Second))
	_, err = readFrame(tooBig, MaxCutBytes)
	require.ErrorIs(t, err, ErrWire)
}

func TestTheServersAdmissionGates(t *testing.T) {
	srv := NewServer(serverFake{}, func(id peer.ID) bool { return id != "banned" })
	require.False(t, srv.admit("banned"))
	require.False(t, srv.admit(""))
	for i := 0; i < MaxPendingPerPeer; i++ {
		require.True(t, srv.admit("p"), i)
	}
	require.False(t, srv.admit("p"), "a peer's streams are bounded")
	srv.release("p")
	require.True(t, srv.admit("p"))
	var held []peer.ID
	for i := 0; srv.pending < MaxPendingStreams; i++ {
		id := peer.ID("x" + string(rune(0x61+i)))
		require.True(t, srv.admit(id))
		held = append(held, id)
	}
	require.False(t, srv.admit("overflow"))
	srv.release(held[0])
	require.True(t, srv.admit("overflow"))
}

func TestTheServerNeverReturnsMoreThanABatchWhateverIsAsked(t *testing.T) {
	c := buildChain(t, 400)
	srv := NewServer(serverFake{records: c.records}, func(peer.ID) bool { return true })
	cl, sv := net.Pipe()
	go srv.Serve("shard", pipeStream{sv})
	_ = cl.SetDeadline(time.Now().Add(2 * time.Second))
	raw, err := types.Cbor.Marshal(request{Kind: kindRecords, From: 0, Max: 1 << 30})
	require.NoError(t, err)
	require.NoError(t, writeFrame(cl, raw))
	body, err := readFrame(cl, MaxBatchBytes)
	require.NoError(t, err)
	var wire []wireRecord
	require.NoError(t, types.Cbor.Unmarshal(body, &wire))
	require.Len(t, wire, MaxBatch)
}
