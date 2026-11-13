package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"runtime"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// A declared length alone allocates no more than the first chunk: the payload buffer grows with the bytes that actually arrive (#1032).
func TestAFrameHeaderAloneDoesNotAllocateTheDeclaredLength(t *testing.T) {
	hdr := binary.AppendUvarint(nil, certification.MaxBlockCertificationRequestFrame)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var req certification.BlockCertificationRequest
	err := deserializeMsgLimited(bufio.NewReader(bytes.NewReader(hdr)), &req, certification.MaxBlockCertificationRequestFrame)
	runtime.ReadMemStats(&after)
	require.Error(t, err, "the payload never arrives")
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20), "a 64 MiB declaration with no payload allocates under 1 MiB")
}

// The budget reserves globally and per peer, refuses what does not fit, and releases on delivery.
func TestIngressBudgetReservesAndReleases(t *testing.T) {
	b := NewIngressBudget(100, 60)
	a, c := peer.ID("a"), peer.ID("c")
	require.True(t, b.reserve(a, 50))
	require.False(t, b.reserve(a, 20), "per peer")
	require.True(t, b.reserve(c, 50))
	require.False(t, b.reserve(c, 1), "global")
	msg := &testStrMsg{Info: "x"}
	b.queue(msg, a, 50)
	require.True(t, b.delivered(msg))
	require.False(t, b.delivered(msg), "released once")
	require.EqualValues(t, 50, b.Used())
	b.release(c, 50)
	require.Zero(t, b.Used())
}

// End to end: a protocol with a budget refuses a frame larger than the peer's share before reading it, delivers one that fits, and
// releases the reservation once the consumer takes the message.
func TestIngressBudgetOnAProtocol(t *testing.T) {
	obs := observability.Default(t)
	peer1 := createPeer(t)
	t.Cleanup(func() { _ = peer1.Close() })
	nw1, err := NewLibP2PNetwork(peer1, 1, obs)
	require.NoError(t, err)
	peer2 := createPeer(t)
	t.Cleanup(func() { _ = peer2.Close() })
	nw2, err := NewLibP2PNetwork(peer2, 8, obs)
	require.NoError(t, err)
	peer1.Network().Peerstore().AddAddrs(peer2.ID(), peer2.MultiAddresses(), peerstore.PermanentAddrTTL)
	require.NoError(t, nw1.registerSendProtocol(SendProtocolDescription{ProtocolID: "test/i", MsgType: testStrMsg{}, Timeout: 100 * time.Millisecond}))
	budget := NewIngressBudget(1<<10, 64)
	require.NoError(t, nw2.registerReceiveProtocol(ReceiveProtocolDescription{
		ProtocolID: "test/i", TypeFn: func() any { return &testStrMsg{} }, MaxFrameSize: 1 << 10, Ingress: budget,
	}))
	in := nw2.ReceivedChannel()

	require.NoError(t, nw1.Send(context.Background(), &testStrMsg{Info: string(make([]byte, 100))}, nw2.self.ID()))
	select {
	case <-in:
		t.Fatal("a frame over the peer's share was delivered")
	case <-time.After(300 * time.Millisecond):
	}
	require.Zero(t, budget.Used(), "a refused frame reserves nothing")

	require.NoError(t, nw1.Send(context.Background(), &testStrMsg{Info: "fits"}, nw2.self.ID()))
	select {
	case m := <-in:
		require.Equal(t, "fits", m.(*testStrMsg).Info)
	case <-time.After(time.Second):
		t.Fatal("a frame that fits was not delivered")
	}
	require.Eventually(t, func() bool { return budget.Used() == 0 }, time.Second, 5*time.Millisecond, "released once taken")
}

// Close stops the forwarder even while the consumer has stopped reading: the message it holds and everything still queued are dropped,
// each reservation released exactly once, the consumer's channel is closed, and later frames are not queued.
func TestCloseReleasesForwardedAndQueuedReservations(t *testing.T) {
	obs := observability.Default(t)
	p := createPeer(t)
	t.Cleanup(func() { _ = p.Close() })
	nw, err := NewLibP2PNetwork(p, 8, obs)
	require.NoError(t, err)
	budget := NewIngressBudget(1<<20, 1<<20)
	require.NoError(t, nw.registerReceiveProtocol(ReceiveProtocolDescription{
		ProtocolID: "test/c", TypeFn: func() any { return &testStrMsg{} }, MaxFrameSize: 1 << 10, Ingress: budget,
	}))
	out := nw.ReceivedChannel()
	from := peer.ID("sender")
	for i := range 3 { // the forwarder takes the first and blocks handing it over; two stay queued
		msg := &testStrMsg{Info: string(rune('a' + i))}
		require.True(t, budget.reserve(from, 10))
		budget.queue(msg, from, 10)
		require.NoError(t, nw.receivedMsg(from, "test/c", msg))
	}
	require.EqualValues(t, 30, budget.Used())
	nw.Close()
	require.Eventually(t, func() bool { return budget.Used() == 0 }, time.Second, 5*time.Millisecond, "every reservation released")
	select {
	case _, ok := <-out:
		require.False(t, ok, "the consumer's channel is closed")
	case <-time.After(time.Second):
		t.Fatal("the consumer's channel was not closed")
	}
	late := &testStrMsg{Info: "late"}
	require.True(t, budget.reserve(from, 10))
	budget.queue(late, from, 10)
	require.Error(t, nw.receivedMsg(from, "test/c", late), "nothing is queued after Close")
	budget.delivered(late) // the stream handler's release on a refused enqueue
	require.Zero(t, budget.Used())
	nw.Close() // idempotent
}

// Without an ingress budget the documented contract (review r4/r5): Close drops what is queued and refuses later messages, but the consumer's
// channel, the buffered receive queue itself, is neither replaced nor closed; its consumer stops through its own context.
func TestReview1033UnbudgetedCloseLeavesConsumerOpen(t *testing.T) {
	p := createPeer(t)
	t.Cleanup(func() { _ = p.Close() })
	nw, err := NewLibP2PNetwork(p, 8, observability.Default(t))
	require.NoError(t, err)
	out := nw.ReceivedChannel()
	require.Equal(t, 8, cap(out), "the buffered receive queue itself: a consumer sees its backlog")
	from := peer.ID("sender")
	for _, s := range []string{"a", "b"} {
		require.NoError(t, nw.receivedMsg(from, "test/u", &testStrMsg{Info: s}))
	}
	require.Equal(t, 2, len(out))
	nw.Close()
	require.Zero(t, len(out), "queued messages are dropped")
	require.Error(t, nw.receivedMsg(from, "test/u", &testStrMsg{Info: "late"}), "nothing is queued after Close")
	select {
	case m, ok := <-out:
		t.Fatalf("the unbudgeted consumer channel delivered %v (open %v) after Close", m, ok)
	case <-time.After(100 * time.Millisecond): // open and empty, as documented
	}
	nw.Close() // idempotent
}

// Close before the consumer of a budgeted network asked for its channel: the channel it gets afterwards is closed.
func TestBudgetedCloseBeforeReceivedChannel(t *testing.T) {
	p := createPeer(t)
	t.Cleanup(func() { _ = p.Close() })
	nw, err := NewLibP2PNetwork(p, 8, observability.Default(t))
	require.NoError(t, err)
	budget := NewIngressBudget(1<<20, 1<<20)
	require.NoError(t, nw.registerReceiveProtocol(ReceiveProtocolDescription{
		ProtocolID: "test/b", TypeFn: func() any { return &testStrMsg{} }, MaxFrameSize: 1 << 10, Ingress: budget,
	}))
	msg := &testStrMsg{Info: "a"}
	require.True(t, budget.reserve(peer.ID("s"), 10))
	budget.queue(msg, peer.ID("s"), 10)
	require.NoError(t, nw.receivedMsg(peer.ID("s"), "test/b", msg))
	nw.Close()
	require.Zero(t, budget.Used(), "the queued message is dropped and released")
	select {
	case _, ok := <-nw.ReceivedChannel():
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("not closed")
	}
}
