package vrschedule

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	p2p "github.com/unicitynetwork/bft-core/network"
)

// The peer protocol over two real libp2p hosts: a pushed message reaches the receiving root's verification queue and its service, a
// restarted root rebuilds its stage set with GetStage, and a peer the receiver does not admit is reset.
func TestThePeerProtocolOverRealHosts(t *testing.T) {
	w := newWorld(t)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	receiver := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	stranger := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, p := range []*p2p.Peer{sender, stranger} {
		p.Network().Peerstore().AddAddrs(receiver.ID(), receiver.MultiAddresses(), peerstore.PermanentAddrTTL)
	}
	svc := w.service("x")
	svc.Update(w.committed(0))
	q := NewQueue(svc, 0)
	server := NewServer(svc, q, func(id peer.ID) bool { return id == sender.ID() })
	receiver.RegisterProtocolHandler(ProtocolID, server.Handler)
	t.Cleanup(func() { receiver.RemoveProtocolHandler(ProtocolID) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go q.Run(ctx)

	for _, m := range w.messages(0) {
		require.NoError(t, Push(ctx, FromLibp2p(sender), []peer.ID{receiver.ID()}, m))
	}
	require.Eventually(t, func() bool { _, ok := svc.Plan(); return ok }, 20*time.Second, 50*time.Millisecond, "the pushed messages complete the view")

	set, err := GetStage(ctx, FromLibp2p(sender), receiver.ID(), w.d, 0)
	require.NoError(t, err)
	require.Len(t, set.PoPs, len(w.J))
	require.Len(t, set.Assemblies, 1)
	require.Len(t, set.Readiness, len(w.J))
	restarted := w.service("y")
	restarted.Update(w.committed(0))
	offerAll(t, restarted, set.Offers())
	_, ok := restarted.Plan()
	require.True(t, ok, "a restarted root rebuilds from the stage set")

	_, err = GetStage(ctx, FromLibp2p(stranger), receiver.ID(), w.d, 0)
	require.Error(t, err, "a peer outside the members and the committee is reset")
}

// PV (design 8.3): the adequacy condition D + delta + Q_max < 4 T, and the serial completion times of the acceptance trace (two slow valid
// messages at 2 s and 11 s, 100 s each on one verifier: completion at 102 and 202).
func TestThePVPremise(t *testing.T) {
	require.Equal(t, []uint64{102, 202}, SerialCompletions([]uint64{2, 11}, 100))
	require.True(t, PVAdequate(10, 1, 300, 80), "10 + 1 + 300 < 320")
	require.False(t, PVAdequate(10, 1, 300, 20), "at T = 20 the premise fails")
}
