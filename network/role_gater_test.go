package network

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
)

// A non-active node's gater keeps a "root" closed in both directions at the transport boundary, while a mirror connects; once the role
// changes (promotion) the same host reaches the root without a restart.
func TestRoleGaterDeniesRootsUntilPromotion(t *testing.T) {
	log := logger.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	start := func(gater *RoleGater) *Peer {
		conf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
		require.NoError(t, err)
		conf.Gater = gater
		p, err := NewPeer(ctx, conf, log, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	root, mirror := start(nil), start(nil)
	var active atomic.Bool
	follower := start(&RoleGater{Deny: func(id peer.ID) bool { return !active.Load() && id == root.ID() }})
	info := func(p *Peer) peer.AddrInfo { return peer.AddrInfo{ID: p.ID(), Addrs: p.MultiAddresses()} }

	require.NoError(t, follower.host.Connect(ctx, info(mirror)), "a mirror is reachable")
	require.Error(t, follower.host.Connect(ctx, info(root)), "a non-active node never dials a root")
	_ = root.host.Connect(ctx, info(follower)) // the dialer may see its half complete before the follower's gate closes it
	require.Eventually(t, func() bool {
		return len(follower.host.Network().ConnsToPeer(root.ID())) == 0 && len(root.host.Network().ConnsToPeer(follower.ID())) == 0
	}, 5*time.Second, 20*time.Millisecond, "nor keeps a root's inbound connection")

	active.Store(true)
	require.NoError(t, follower.host.Connect(ctx, info(root)), "an active node reaches its roots")
}
