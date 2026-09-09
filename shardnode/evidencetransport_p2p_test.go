package shardnode

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
)

// network.Peer is the production host. Asserted rather than assumed, so that narrowing EvidenceHost
// to two methods cannot silently drift away from what a real node provides.
var _ EvidenceHost = (*network.Peer)(nil)

/*
TestEvidenceTransport_TwoRealPeers runs the whole exchange over two independent libp2p hosts on
loopback TCP — the same transport a deployment uses, only the addresses are local. It follows
net_dissemination_test.go's pattern for the same reason: the pipe tests above pin the framing and the
bounds, and this one pins that the protocol registers, dials, and carries a bundle the predicate then
accepts, which no in-process test can establish.
*/
func TestEvidenceTransport_TwoRealPeers(t *testing.T) {
	f := newEvidenceFixture(t)
	obs := quietTailObserved(t, f)
	held := obs[2].UC

	buffer := newTestBuffer(t)
	mustObserve(t, buffer, obs...)

	providerHost := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	requesterHost := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	requesterHost.Network().Peerstore().AddAddrs(providerHost.ID(), providerHost.MultiAddresses(), peerstore.PermanentAddrTTL)

	server, err := NewEvidenceServer(buffer, DefaultEvidenceTransportLimits, nil)
	require.NoError(t, err)
	server.Register(providerHost)

	ctx := context.Background()

	t.Run("a returning node recovers its anchor from a peer that stayed up", func(t *testing.T) {
		ev, err := RequestAnchorEvidence(ctx, requesterHost, providerHost.ID(), requestFor(t, held), DefaultEvidenceTransportLimits)
		require.NoError(t, err)

		anchor, err := verifyAssembled(t, f, ev, held)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
		require.EqualValues(t, 10, anchor.Round)
	})

	t.Run("a second request on a fresh stream is answered too", func(t *testing.T) {
		// One request per stream is the protocol; the provider must therefore still be serving
		// after the first exchange closed, rather than having consumed a one-shot handler.
		ev, err := RequestAnchorEvidence(ctx, requesterHost, providerHost.ID(), requestFor(t, obs[3].UC), DefaultEvidenceTransportLimits)
		require.NoError(t, err)
		_, err = verifyAssembled(t, f, ev, obs[3].UC)
		require.NoError(t, err)
	})

	t.Run("a refusal arrives as a refusal, over the wire", func(t *testing.T) {
		other := newEvidenceFixture(t)
		unknown := other.cert(99, 900, h32(0x0a), h32(0x0b), h32(0xbb), 100)
		_, err := RequestAnchorEvidence(ctx, requesterHost, providerHost.ID(), requestFor(t, unknown.UC), DefaultEvidenceTransportLimits)
		require.ErrorIs(t, err, ErrProviderBehind)
	})

	t.Run("a peer that serves nobody is a transport failure, not a statement about history", func(t *testing.T) {
		// A node without a buffer never registers the protocol, so the dial itself fails — which is
		// a correct "ask somebody else" without this file being involved.
		silent := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		requesterHost.Network().Peerstore().AddAddrs(silent.ID(), silent.MultiAddresses(), peerstore.PermanentAddrTTL)
		_, err := RequestAnchorEvidence(ctx, requesterHost, silent.ID(), requestFor(t, held), DefaultEvidenceTransportLimits)
		require.ErrorIs(t, err, ErrEvidenceTransport)
	})
}
