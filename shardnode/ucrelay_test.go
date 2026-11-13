package shardnode

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// The backup path (phase 2): the roots push nothing (every handshake is dropped), and the node's active peers hold the certificate. One
// peer relays a forged pair, another the genuine one: the forged one is refused by the same admission as a root's response and does not
// move the progress clock; the genuine one is delivered to the driver. A follower does not use the relay.
func TestTheUCRelayBacksUpTheRootPushWithVerifiedPairs(t *testing.T) {
	f := newConfBindingFixture(t)
	good := f.respond(f.ucMine)
	raw, err := types.Cbor.Marshal(&good.UC)
	require.NoError(t, err)
	var forged types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(raw, &forged))
	forged.UnicitySeal.RootChainRoundNumber += 3

	node := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	serve := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) peer.ID {
		p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		p.RegisterProtocolHandler(UCRelayProtocol, NewUCRelayServer(func() (*types.UnicityCertificate, *certification.TechnicalRecord) { return uc, tr },
			func(id peer.ID) bool { return id == node.ID() }).Handler)
		node.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
		return p.ID()
	}
	liar, honest := serve(&forged, &good.Technical), serve(&good.UC, &good.Technical)

	net := &lateRootNet{received: make(chan any, 4)} // a root that never answers
	driver := &firstUCDriver{got: make(chan struct{})}
	client, err := NewBFTClient(node, net, f.signer, authPartitionID, types.ShardID{}, f.confMine, stubTrustBaseStore{tb: f.tb}, driver, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: time.Hour})
	require.NoError(t, err)
	client.SetRelay(node, func() []peer.ID { return []peer.ID{liar, honest} }, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-driver.got:
	case <-time.After(10 * time.Second):
		t.Fatal("the relayed genuine certificate was not delivered")
	}
	uc, _ := client.Held()
	require.Equal(t, good.UC.GetRootRoundNumber(), uc.GetRootRoundNumber(), "the genuine pair is held, never the forged one")
}

func TestAFollowerDoesNotUseTheUCRelay(t *testing.T) {
	f := newConfBindingFixture(t)
	node := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client, err := NewBFTClient(node, &lateRootNet{received: make(chan any, 1)}, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, &firstUCDriver{got: make(chan struct{})}, nil, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1})
	require.NoError(t, err)
	client.SetRelay(node, func() []peer.ID { return nil }, time.Millisecond)
	client.SetFollowerRole(func() bool { return true })
	require.False(t, client.relayDue(time.Now().Add(time.Hour)), "a non-active node takes its certificates from its follow sources")
	client.SetFollowerRole(func() bool { return false })
	require.True(t, client.relayDue(time.Now().Add(time.Hour)))
}

// The server answers only the peers it admits, at most two streams of one peer at a time.
func TestTheUCRelayServerAdmitsOnlyItsPeers(t *testing.T) {
	f := newConfBindingFixture(t)
	good := f.respond(f.ucMine)
	server := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	member := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	stranger := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	s := NewUCRelayServer(func() (*types.UnicityCertificate, *certification.TechnicalRecord) { return &good.UC, &good.Technical },
		func(id peer.ID) bool { return id == member.ID() })
	server.RegisterProtocolHandler(UCRelayProtocol, s.Handler)
	member.Network().Peerstore().AddAddrs(server.ID(), server.MultiAddresses(), peerstore.PermanentAddrTTL)
	stranger.Network().Peerstore().AddAddrs(server.ID(), server.MultiAddresses(), peerstore.PermanentAddrTTL)
	uc, tr, err := FetchHeldPair(context.Background(), member, server.ID())
	require.NoError(t, err)
	require.Equal(t, good.UC.GetRootRoundNumber(), uc.GetRootRoundNumber())
	require.Equal(t, good.Technical.Round, tr.Round)
	_, _, err = FetchHeldPair(context.Background(), stranger, server.ID())
	require.Error(t, err, "a peer that is not admitted gets nothing")
	require.True(t, s.reserve("p") && s.reserve("p"))
	require.False(t, s.reserve("p"), "two concurrent requests per peer")
}
