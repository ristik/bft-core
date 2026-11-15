package network

import (
	"context"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
)

// #1082: a joiner behind NAT or an isolated bridge (its announced address unreachable from the host) cannot be dialled by the host's roots,
// so a vote or proposal a host root sends it is lost and its leader slots time out. The joiner's keeper dials the host members itself;
// the host then reaches it over that inbound connection, and after the host restarts (an install) within one keeper interval, past the
// swarm's dial backoff.
const keeperProtocol = "/test/keeper/1"

func keeperPeer(t *testing.T, ctx context.Context, address string, keys *PeerKeyPair, announce []string) *Peer {
	t.Helper()
	conf, err := NewPeerConfiguration(address, announce, keys, nil, nil)
	require.NoError(t, err)
	p, err := newPeer(ctx, conf, logger.New(t), nil, noTCPPortReuse)
	require.NoError(t, err)
	return p
}

// reach opens a stream from p to id and reports how long it took (or the failure).
func reach(ctx context.Context, p *Peer, id peer.ID, budget time.Duration) (time.Duration, error) {
	start := time.Now()
	c, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	s, err := p.host.NewStream(c, id, keeperProtocol)
	if err != nil {
		return time.Since(start), err
	}
	_ = s.Close()
	return time.Since(start), nil
}

func TestAMemberThatCannotBeDialledIsReachedOverItsOwnOutboundConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostKeys := generateKeyPair(t)
	host := keeperPeer(t, ctx, "/ip4/127.0.0.1/tcp/0", hostKeys, nil)
	hostAddr := host.MultiAddresses()
	// the joiner announces only an address the host cannot reach (TEST-NET-1: the dial hangs, as a private bridge address did)
	joiner := keeperPeer(t, ctx, "/ip4/127.0.0.1/tcp/0", generateKeyPair(t), []string{"/ip4/192.0.2.1/tcp/8000"})
	defer func() { _ = joiner.Close() }()
	joiner.RegisterProtocolHandler(keeperProtocol, func(s libp2pnetwork.Stream) { _ = s.Close() })
	host.host.Peerstore().AddAddrs(joiner.ID(), []ma.Multiaddr{mustAddr(t, "/ip4/192.0.2.1/tcp/8000")}, peerstore.PermanentAddrTTL)
	joiner.host.Peerstore().AddAddrs(host.ID(), hostAddr, peerstore.PermanentAddrTTL) // its bootnode: the host is reachable from it

	_, err := reach(ctx, host, joiner.ID(), time.Second)
	require.Error(t, err, "without the keeper the host cannot reach the joiner")

	keeper := joiner.NewMemberProtector("root-committee")
	keeper.Set(ctx, []peer.ID{host.ID()})
	go keeper.Maintain(ctx, 100*time.Millisecond, 2*time.Second)
	require.Eventually(t, func() bool { return len(keeper.Disconnected()) == 0 }, 5*time.Second, 20*time.Millisecond)
	took, err := reach(ctx, host, joiner.ID(), time.Second)
	require.NoError(t, err, "the host reaches the joiner over the joiner's own connection")
	t.Logf("host to joiner over the inbound connection: %s", took)

	// the host restarts (an install restart): the same identity on the same address
	require.NoError(t, host.Close())
	down := time.Now()
	time.Sleep(300 * time.Millisecond) // the keeper's dials fail meanwhile and would put the address in the swarm's dial backoff
	host = keeperPeer(t, ctx, hostAddr[0].String(), hostKeys, nil)
	defer func() { _ = host.Close() }()
	host.host.Peerstore().AddAddrs(joiner.ID(), []ma.Multiaddr{mustAddr(t, "/ip4/192.0.2.1/tcp/8000")}, peerstore.PermanentAddrTTL)
	up := time.Now()
	var reconnected time.Duration
	require.Eventually(t, func() bool {
		if _, err := reach(ctx, host, joiner.ID(), 200*time.Millisecond); err != nil {
			return false
		}
		reconnected = time.Since(up)
		return true
	}, 5*time.Second, 20*time.Millisecond, "the keeper dials the restarted host again, past the dial backoff")
	t.Logf("down %s, reachable again %s after the restarted host listened", up.Sub(down), reconnected)
	require.Less(t, reconnected, 2*time.Second, "within a few keeper intervals, not the swarm's 5 s backoff")
}

func mustAddr(t *testing.T, s string) ma.Multiaddr {
	t.Helper()
	a, err := ma.NewMultiaddr(s)
	require.NoError(t, err)
	return a
}
