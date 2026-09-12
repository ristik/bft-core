package network

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	test "github.com/unicitynetwork/bft-core/internal/testutils"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
)

const randomTestAddressStr = "/ip4/127.0.0.1/tcp/0"

// --- discovery diagnostics (issue #100) --------------------------------------
//
// These tests assert an EXACT routing-table size, and until now a failure reported only
// "Condition never satisfied": no routing-table membership, no connection state, nothing to
// distinguish "the peer was never reached" from "the table converged to a different size".
// #100 asks that the negative case show routing/connection/query state, so every wait below goes
// through requireRoutingTable, which dumps that state on failure.

// peerLabel gives short, stable names to the peers a test cares about, so a dump reads as
// "bootstrap, peer1, peer2" rather than as base58 keys.
type peerLabel struct {
	id   peer.ID
	name string
}

func shortID(id peer.ID) string {
	s := id.String()
	if len(s) > 8 {
		return s[len(s)-8:]
	}
	return s
}

// describePeer renders everything that decides whether the assertion below can ever hold.
func describePeer(p *Peer, name string, known []peerLabel) string {
	rt := p.dht.RoutingTable()
	members := rt.ListPeers()
	seen := make(map[peer.ID]bool, len(members))
	for _, m := range members {
		seen[m] = true
	}

	var b strings.Builder
	fmt.Fprintf(&b, "  %s (%s): routingTable size=%d mode=%v\n", name, shortID(p.host.ID()), rt.Size(), p.dht.Mode())
	for _, m := range members {
		label := shortID(m)
		for _, k := range known {
			if k.id == m {
				label = k.name + "/" + shortID(m)
			}
		}
		fmt.Fprintf(&b, "      in table: %s connectedness=%v\n", label, p.host.Network().Connectedness(m))
	}
	// An expected peer that is absent from the table is the interesting case: say whether we are
	// even connected to it, which separates "never dialled" from "dialled but not admitted".
	for _, k := range known {
		if k.id == p.host.ID() || seen[k.id] {
			continue
		}
		fmt.Fprintf(&b, "      MISSING:  %s/%s connectedness=%v addrsKnown=%d\n",
			k.name, shortID(k.id), p.host.Network().Connectedness(k.id), len(p.host.Peerstore().Addrs(k.id)))
	}
	// Peers this host is connected to but which are NOT in its routing table, and peers in the
	// table that no test created: either one means this test is not running in isolation.
	for _, c := range p.host.Network().Peers() {
		if !seen[c] {
			fmt.Fprintf(&b, "      connected but not in table: %s\n", shortID(c))
		}
	}
	return b.String()
}

// requireRoutingTable waits for p's routing table to reach exactly want entries, and on failure
// prints the routing/connection state of every peer the test knows about.
func requireRoutingTable(t *testing.T, p *Peer, name string, want int, budget time.Duration, all map[string]*Peer) {
	t.Helper()
	known := make([]peerLabel, 0, len(all))
	for n, q := range all {
		known = append(known, peerLabel{id: q.host.ID(), name: n})
	}
	sort.Slice(known, func(i, j int) bool { return known[i].name < known[j].name })

	if assert.Eventually(t, func() bool { return p.dht.RoutingTable().Size() == want }, budget, test.WaitTick) {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s routing table never reached exactly %d entries within %s\n", name, want, budget)
	for _, k := range known {
		b.WriteString(describePeer(all[k.name], k.name, known))
	}
	t.Fatal(b.String())
}

func TestNewPeer_PeerConfigurationIsNil(t *testing.T) {
	p, err := NewPeer(context.Background(), nil, nil, nil)
	require.ErrorIs(t, err, ErrPeerConfigurationIsNil)
	require.Nil(t, p)
}

func TestNewPeer_NewPeerCanBeCreated(t *testing.T) {
	p := createPeer(t)
	require.NotNil(t, p)
	require.NotNil(t, p.ID())
	require.True(t, len(p.MultiAddresses()) > 0)
	require.Equal(t, 1, len(p.host.Peerstore().Peers()))
}

func TestNewPeer_InvalidPrivateKey(t *testing.T) {
	conf := &PeerConfiguration{
		KeyPair: &PeerKeyPair{
			PrivateKey: test.RandomBytes(30),
		},
	}

	_, err := NewPeer(context.Background(), conf, logger.New(t), nil)
	require.ErrorContains(t, err, "invalid private key: expected secp256k1 data size to be 32")
}

func TestNewPeer_InvalidPublicKey(t *testing.T) {
	privKey, _, _ := crypto.GenerateSecp256k1Key(rand.Reader)
	privKeyBytes, _ := privKey.Raw()
	conf := &PeerConfiguration{
		KeyPair: &PeerKeyPair{
			PrivateKey: privKeyBytes,
			PublicKey:  test.RandomBytes(30),
		},
	}
	_, err := NewPeer(context.Background(), conf, logger.New(t), nil)
	require.ErrorContains(t, err, "invalid public key: malformed public key: invalid length: 30")
}

func TestNewPeer_LoadsKeyPairCorrectly(t *testing.T) {
	privateKey, pubKey, _ := crypto.GenerateSecp256k1Key(rand.Reader)
	keyBytes, err := privateKey.Raw()
	require.NoError(t, err)
	pubKeyBytes, err := pubKey.Raw()
	require.NoError(t, err)
	conf := &PeerConfiguration{
		KeyPair: &PeerKeyPair{
			PrivateKey: keyBytes,
			PublicKey:  pubKeyBytes,
		},
		Address: randomTestAddressStr,
	}
	peer, err := NewPeer(context.Background(), conf, logger.New(t), nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, peer.Close()) }()
	p := peer.host.Peerstore().PeersWithKeys()[0]
	pub, _ := p.ExtractPublicKey()
	raw, _ := pub.Raw()
	require.Equal(t, pubKeyBytes, raw)
	// test stringer
	idStr := peer.ID().String()
	require.EqualValues(t, fmt.Sprintf("NodeID:%s*%s", idStr[:2], idStr[len(idStr)-6:]), peer.String())
	pubKeyFromID, err := peer.ID().ExtractPublicKey()
	require.NoError(t, err)
	require.Equal(t, pubKey, pubKeyFromID)
}

func TestBootstrapNodes(t *testing.T) {
	log := logger.New(t)
	// Scoped, not Background: the DHT and its background workers are built from this context
	// (NewPeer passes it to newDHT), so a package-lifetime context leaves them running after the
	// test returns. Cancelling on cleanup bounds them to the test that created them (#100).
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bootStrapPeerConf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
	require.NoError(t, err)

	bootstrapNode, err := NewPeer(ctx, bootStrapPeerConf, log, nil)
	require.NoError(t, err)
	// The bootstrap node was created and never closed, unlike peer1/peer2 (#100 item 2). A leaked
	// libp2p host keeps its listener, its peerstore and its DHT workers alive for the rest of the
	// package run.
	t.Cleanup(func() { _ = bootstrapNode.Close() })
	bootstrapNodeAddrInfo := []peer.AddrInfo{{ID: bootstrapNode.ID(), Addrs: bootstrapNode.MultiAddresses()}}

	peerConf1, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)

	peer1, err := NewPeer(ctx, peerConf1, log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer1.Close() })

	all := map[string]*Peer{"bootstrap": bootstrapNode, "peer1": peer1}
	requireRoutingTable(t, peer1, "peer1", 1, test.WaitDuration, all)

	peerConf2, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)

	peer2, err := NewPeer(ctx, peerConf2, log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer2.Close() })
	all["peer2"] = peer2

	requireRoutingTable(t, peer2, "peer2", 2, test.WaitDuration, all)
	requireRoutingTable(t, peer1, "peer1", 2, test.WaitDuration, all)
	require.Eventually(t, func() bool { return peer2.dht.RoutingTable().Find(peer1.dht.Host().ID()) != "" }, test.WaitDuration, test.WaitTick)
	require.Eventually(t, func() bool { return peer1.dht.RoutingTable().Find(peer2.dht.Host().ID()) != "" }, test.WaitDuration, test.WaitTick)
}

func TestBootstrap_OneBootStrapConnectionFails_StillOK(t *testing.T) {
	log := logger.New(t)
	ctx := context.Background()
	bootStrapPeer1Conf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
	require.NoError(t, err)
	bootstrap1NodeAddr, err := ma.NewMultiaddr("/ip4/127.0.0.2/tcp/10")
	require.NoError(t, err)

	bootStrapPeer2Conf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
	require.NoError(t, err)
	bootstrapNode2, err := NewPeer(ctx, bootStrapPeer2Conf, log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bootstrapNode2.Close() }) // was leaked (#100)
	// set bootstrap info
	bootstrapNodeAddrInfo := []peer.AddrInfo{
		{ID: bootStrapPeer1Conf.ID, Addrs: []ma.Multiaddr{bootstrap1NodeAddr}},
		{ID: bootstrapNode2.ID(), Addrs: bootstrapNode2.MultiAddresses()},
	}

	peerConf1, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)

	peer1, err := NewPeer(ctx, peerConf1, log, nil)
	require.NoError(t, err)
	defer func() { _ = peer1.Close() }()
	require.Eventually(t, func() bool { return peer1.dht.RoutingTable().Size() == 1 }, 2*test.WaitDuration, test.WaitTick)

	peerConf2, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)

	peer2, err := NewPeer(ctx, peerConf2, log, nil)
	require.NoError(t, err)
	defer func() { _ = peer2.Close() }()

	require.Eventually(t, func() bool { return peer2.dht.RoutingTable().Size() == 2 }, 2*test.WaitDuration, test.WaitTick)
	require.Eventually(t, func() bool { return peer1.dht.RoutingTable().Size() == 2 }, 2*test.WaitDuration, test.WaitTick)
	require.Eventually(t, func() bool { return peer2.dht.RoutingTable().Find(peer1.dht.Host().ID()) != "" }, 2*test.WaitDuration, test.WaitTick)
	require.Eventually(t, func() bool { return peer1.dht.RoutingTable().Find(peer2.dht.Host().ID()) != "" }, 2*test.WaitDuration, test.WaitTick)
}

func TestBootstrap_AllConnectionsFail(t *testing.T) {
	log := logger.New(t)
	ctx := context.Background()
	bootStrapPeer1Conf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
	require.NoError(t, err)
	addr, err := ma.NewMultiaddr("/ip4/127.0.0.2/tcp/10")
	require.NoError(t, err)

	bootstrapNodeAddrInfo := []peer.AddrInfo{{ID: bootStrapPeer1Conf.ID, Addrs: []ma.Multiaddr{addr}}}

	peerConf1, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)

	peer1, err := NewPeer(ctx, peerConf1, log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer1.Close() }) // was leaked (#100)
	require.NotNil(t, peer1)
	err = peer1.BootstrapConnect(ctx, log)
	require.ErrorContains(t, err, fmt.Sprintf("failed to bootstrap: failed to dial: failed to dial %s: all dials failed", bootStrapPeer1Conf.ID))
}

func TestBootstrapConnect_OnlySelf(t *testing.T) {
	log := logger.New(t)
	ctx := context.Background()

	bootnode1AddrStr := randomTestAddressStr
	bootnode1Addr, err := ma.NewMultiaddr(bootnode1AddrStr)
	require.NoError(t, err)
	bootnode1KeyPair := generateKeyPair(t)
	bootnode1Conf, err := NewPeerConfiguration(bootnode1AddrStr, nil, bootnode1KeyPair, nil, nil)
	require.NoError(t, err)

	bootstrapNodeAddrInfo := []peer.AddrInfo{{ID: bootnode1Conf.ID, Addrs: []ma.Multiaddr{bootnode1Addr}}}

	peerConf, err := NewPeerConfiguration(bootnode1AddrStr, nil, bootnode1KeyPair, bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)
	// Create the test peer
	testPeer, err := NewPeer(ctx, peerConf, log, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, testPeer.Close()) }()

	// Attempt to bootstrap connect
	err = testPeer.BootstrapConnect(ctx, log)
	require.NoError(t, err)
}

func TestBootstrapConnect_BootnodeIgnoresConnectionFailure(t *testing.T) {
	log := logger.New(t)
	ctx := context.Background()

	bootnode1AddrStr := randomTestAddressStr
	bootnode1Addr, err := ma.NewMultiaddr(bootnode1AddrStr)
	require.NoError(t, err)
	bootnode1KeyPair := generateKeyPair(t)
	bootnode1Conf, err := NewPeerConfiguration(bootnode1AddrStr, nil, bootnode1KeyPair, nil, nil)
	require.NoError(t, err)

	bootnode2AddrStr := "/ip4/127.0.0.2/tcp/10"
	bootnode2Addr, err := ma.NewMultiaddr(bootnode2AddrStr)
	require.NoError(t, err)
	bootnode2Conf, err := NewPeerConfiguration(bootnode2AddrStr, nil, generateKeyPair(t), nil, nil)
	require.NoError(t, err)

	bootstrapNodeAddrInfo := []peer.AddrInfo{
		{ID: bootnode1Conf.ID, Addrs: []ma.Multiaddr{bootnode1Addr}},
		{ID: bootnode2Conf.ID, Addrs: []ma.Multiaddr{bootnode2Addr}},
	}

	peerConf, err := NewPeerConfiguration(bootnode1AddrStr, nil, bootnode1KeyPair, bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)
	// Create the test peer
	testPeer, err := NewPeer(ctx, peerConf, log, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, testPeer.Close()) }()

	// Attempt to bootstrap connect
	err = testPeer.BootstrapConnect(ctx, log)
	require.NoError(t, err)
}

func TestProvidesAndDiscoverNodes(t *testing.T) {
	log := logger.New(t)
	// See TestBootstrapNodes: scoped so the DHT workers built from this context do not outlive
	// the test (#100 item 2).
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bootStrapPeerConf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
	require.NoError(t, err)
	bootstrapNode, err := NewPeer(ctx, bootStrapPeerConf, log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bootstrapNode.Close() }) // was leaked
	bootstrapNodeAddrInfo := []peer.AddrInfo{{ID: bootstrapNode.ID(), Addrs: bootstrapNode.MultiAddresses()}}

	peerConf1, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)
	peer1, err := NewPeer(ctx, peerConf1, log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer1.Close() })

	all := map[string]*Peer{"bootstrap": bootstrapNode, "peer1": peer1}
	requireRoutingTable(t, peer1, "peer1", 1, test.WaitDuration, all)

	peerConf2, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)
	peer2, err := NewPeer(ctx, peerConf2, log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer2.Close() })
	all["peer2"] = peer2

	peerConf3, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), bootstrapNodeAddrInfo, nil)
	require.NoError(t, err)
	peer3, err := NewPeer(ctx, peerConf3, log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer3.Close() })
	all["peer3"] = peer3

	// peer1 and peer2 were already up when peer3 joined, so neither learns about it
	// from its own bootstrap - it has to reach them through the bootstrap node's
	// gossip, and how long that takes is a property of the machine, not of the code
	// under test. At 2*WaitDuration this was an 8s coin flip on a loaded runner: it
	// is the "discovery timeout" recorded against F1 (#9), and it failed again in run
	// 34105234592 while the identical job on the same commit passed.
	//
	// The budget is raised rather than the wait made active: dht.RefreshRoutingTable
	// does force the lookup, but the queries it spawns outlive the test and log
	// through newDHT's routing-table callback after it completes, which panics the
	// package the same way the Subscriptions leak did. Nothing here is asserting how
	// *fast* discovery converges, only that it does, so waiting longer costs a slow
	// machine some seconds and costs a fast one nothing.
	requireRoutingTable(t, peer2, "peer2", 3, 8*test.WaitDuration, all)
	requireRoutingTable(t, peer1, "peer1", 3, 8*test.WaitDuration, all)
	testTopic := "ab/test/test_topic"
	require.NoError(t, peer2.Advertise(ctx, testTopic))
	require.NoError(t, peer1.Advertise(ctx, testTopic))

	// discover peers with the topic
	peerChan, err := peer3.Discover(ctx, testTopic)
	require.NoError(t, err)
	peers := make([]peer.AddrInfo, 0, 2)
	for p := range peerChan {
		peers = append(peers, p)
	}
	require.Contains(t, peers, peer.AddrInfo{ID: peer1.ID(), Addrs: peer1.MultiAddresses()})
	require.Contains(t, peers, peer.AddrInfo{ID: peer2.ID(), Addrs: peer2.MultiAddresses()})
	require.Len(t, peers, 2)
}

func TestAnnounceAddrs(t *testing.T) {
	ctx := context.Background()
	announceAddrs := []string{
		"/ip4/203.0.113.1/tcp/4001",
		"/ip4/203.0.113.1/tcp/4002",
	}
	conf, err := NewPeerConfiguration(randomTestAddressStr, announceAddrs, generateKeyPair(t), nil, nil)
	require.NoError(t, err)

	peer1, err := NewPeer(ctx, conf, logger.New(t), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer1.Close() }) // was leaked (#100)

	actualAddrs := peer1.host.Addrs()
	require.Len(t, actualAddrs, 2)
	require.Equal(t, announceAddrs[0], actualAddrs[0].String())
	require.Equal(t, announceAddrs[1], actualAddrs[1].String())
}

/*
createPeer returns new Peer configured with random port on localhost and registers
cleanup for it (ie in the end of the test peer.Close is called).
*/
func createPeer(t *testing.T) *Peer {
	return createBootstrappedPeer(t, nil)
}

func createBootstrappedPeer(t *testing.T, bootstrapPeers []peer.AddrInfo) *Peer {
	keyPair := generateKeyPair(t)
	peerConf, err := NewPeerConfiguration(randomTestAddressStr, nil, keyPair, bootstrapPeers, nil)
	require.NoError(t, err)

	p, err := NewPeer(context.Background(), peerConf, logger.New(t), nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	return p
}

func generateKeyPair(t *testing.T) *PeerKeyPair {
	privateKey, publicKey, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	privateKeyBytes, err := privateKey.Raw()
	require.NoError(t, err)
	publicKeyBytes, err := publicKey.Raw()
	require.NoError(t, err)

	return &PeerKeyPair{
		PublicKey:  publicKeyBytes,
		PrivateKey: privateKeyBytes,
	}
}
