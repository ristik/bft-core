package poswitness

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	p2p "github.com/unicitynetwork/bft-core/network"
)

// The transport over two real libp2p hosts on loopback: protocol negotiation, the half-close of the request, the remote peer id the
// allow-list reads, and a multi-megabyte body.
func TestWitnessesOverTwoRealHosts(t *testing.T) {
	author := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	voter := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	stranger := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, p := range []*p2p.Peer{voter, stranger} {
		p.Network().Peerstore().AddAddrs(author.ID(), author.MultiAddresses(), peerstore.PermanentAddrTTL)
	}

	big := make([]byte, 5<<20)
	for i := range big {
		big[i] = byte(i*7 + i>>9)
	}
	held := sha256.Sum256(big)
	server := NewServer(memSource{held: big}, func(id peer.ID) bool { return id == voter.ID() })
	author.RegisterProtocolHandler(ProtocolID, server.Handler)
	t.Cleanup(func() { author.RemoveProtocolHandler(ProtocolID) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := Fetch(ctx, FromLibp2p(voter), []peer.ID{author.ID()}, held, MaxWitnessBytes)
	require.NoError(t, err)
	require.Equal(t, big, got, "a multi-megabyte witness arrives whole")

	absent := sha256.Sum256([]byte("nobody holds this"))
	_, err = Fetch(ctx, FromLibp2p(voter), []peer.ID{author.ID()}, absent, MaxWitnessBytes)
	require.ErrorIs(t, err, ErrUnavailable, "a witness the peer does not hold")

	// a peer outside the allow-list is reset, however many times it asks
	_, err = Fetch(ctx, FromLibp2p(stranger), []peer.ID{author.ID()}, held, MaxWitnessBytes)
	require.ErrorIs(t, err, ErrUnavailable)
}
