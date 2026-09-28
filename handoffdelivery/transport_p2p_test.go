package handoffdelivery

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
)

var _ Host = (*network.Peer)(nil)

func TestBundleTransportOverRootPeerStream(t *testing.T) {
	root := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shard := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shard.Network().Peerstore().AddAddrs(root.ID(), root.MultiAddresses(), peerstore.PermanentAddrTTL)
	bundle := &Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 1}},
		Body: evmroot.TrustBaseBodyV2{Epoch: 2}}
	server, err := NewServer(testProvider{bundle: bundle})
	require.NoError(t, err)
	server.Register(root)
	got, err := Request(context.Background(), shard, root.ID(), 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, got.Body.Epoch)
	_, err = Request(context.Background(), shard, root.ID(), 3)
	require.ErrorIs(t, err, ErrBundle)
}
