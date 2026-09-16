package parentwitness

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

func TestTransportRealLibp2pLoopback(t *testing.T) {
	clientHost := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	serverHost := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	clientHost.Network().Peerstore().AddAddrs(serverHost.ID(), serverHost.MultiAddresses(), peerstore.PermanentAddrTTL)
	c, target := fixtureTarget(t)
	provider, err := NewProvider(target, &providerReader{evidence: c.Blocks[1].Evidence, found: true})
	require.NoError(t, err)
	server, err := NewServer(context.Background(), provider, []peer.ID{clientHost.ID()}, testLimits())
	require.NoError(t, err)
	defer server.Close()
	// Registration is intentionally test-owned; production transport exposes only the handler.
	serverHost.RegisterProtocolHandler(ProtocolID, server.Handler)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := RequestVerified(ctx, clientHost, serverHost.ID(), target, time.Second)
	require.NoError(t, err)
	require.True(t, got.Found())
}
