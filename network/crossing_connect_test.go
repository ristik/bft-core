package network

import (
	"context"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
)

// noTCPPortReuse makes a test host dial from an ephemeral port instead of its listen port.
var noTCPPortReuse = libp2p.Transport(tcp.NewTCPTransport, tcp.DisableReuseport())

// crossingConnectFails makes two fresh hosts connect to each other at the same moment and reports whether either connect failed, and the error of an explicit
// connect made afterwards. #933: TestProvidesAndDiscoverNodes failed once in CI with "dial backoff" on such an explicit connect. With libp2p's default TCP port reuse
// both hosts dial from their listen port, so two crossing dials have the same four-tuple and become one TCP connection by simultaneous open: both ends play the TLS client
// ("tls: received unexpected handshake message of type *tls.clientHelloMsg when waiting for *tls.serverHelloMsg"), both dials fail, and the address is in dial backoff.
func crossingConnectFails(t *testing.T, extra ...libp2p.Option) (failed bool, followUp error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logger.New(t)
	var peers [2]*Peer
	for i := range peers {
		conf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
		require.NoError(t, err)
		peers[i], err = newPeer(ctx, conf, log, nil, extra...)
		require.NoError(t, err)
		defer func(p *Peer) { _ = p.Close() }(peers[i])
	}
	a, b := peers[0], peers[1]
	var wg sync.WaitGroup
	var ea, eb error
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		ea = a.host.Connect(ctx, peer.AddrInfo{ID: b.ID(), Addrs: b.MultiAddresses()})
	}()
	go func() {
		defer wg.Done()
		<-start
		eb = b.host.Connect(ctx, peer.AddrInfo{ID: a.ID(), Addrs: a.MultiAddresses()})
	}()
	close(start)
	wg.Wait()
	if ea == nil && eb == nil {
		return false, nil
	}
	return true, a.host.Connect(ctx, peer.AddrInfo{ID: b.ID(), Addrs: b.MultiAddresses()})
}

// The control: with the default transport the hazard is real (about one crossing in six fails on loopback), and the failed pair is then in dial backoff. If libp2p
// ever stops doing this, this test fails and noTCPPortReuse is no longer needed.
func TestCrossingConnectsFailWithPortReuse(t *testing.T) {
	for i := 0; i < 400; i++ {
		if failed, followUp := crossingConnectFails(t); failed {
			require.Error(t, followUp)
			require.Contains(t, followUp.Error(), "dial backoff")
			return
		}
	}
	t.Fatal("400 crossing connects with TCP port reuse all succeeded: the simultaneous-open hazard of #933 was not reproduced")
}

func TestCrossingConnectsSucceedWithoutPortReuse(t *testing.T) {
	for i := 0; i < 150; i++ {
		failed, followUp := crossingConnectFails(t, noTCPPortReuse)
		require.False(t, failed, "iteration %d: a crossing connect failed without TCP port reuse (follow-up: %v)", i, followUp)
	}
}
