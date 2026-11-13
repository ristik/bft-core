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
