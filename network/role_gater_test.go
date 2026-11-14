package network

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
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

// A connection to a root established while the node was active is closed when it retires (no restart), streams over it are refused in
// both directions until then, and a peer newly recognized as a root is cut off the same way.
func TestRoleGaterRevokesExistingRootConnectionsOnRetirement(t *testing.T) {
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
	root, later := start(nil), start(nil)
	var active atomic.Bool
	active.Store(true)
	var laterIsRoot atomic.Bool
	node := start(&RoleGater{Deny: func(id peer.ID) bool {
		isRoot := id == root.ID() || (laterIsRoot.Load() && id == later.ID())
		return !active.Load() && isRoot
	}})
	const proto = "/test/echo/1"
	var served atomic.Int32
	node.RegisterProtocolHandler(proto, func(s libp2pnetwork.Stream) { served.Add(1); _ = s.Close() })
	info := func(p *Peer) peer.AddrInfo { return peer.AddrInfo{ID: p.ID(), Addrs: p.MultiAddresses()} }
	require.NoError(t, node.host.Connect(ctx, info(root)), "active: the root is reachable")
	require.NoError(t, node.host.Connect(ctx, info(later)))

	active.Store(false) // retired
	_, err := node.CreateStream(ctx, root.ID(), proto)
	require.ErrorIs(t, err, ErrGated, "no stream to a root over the existing connection")
	root.host.Peerstore().AddAddrs(node.ID(), node.MultiAddresses(), peerstore.PermanentAddrTTL)
	if s, err := root.host.NewStream(ctx, node.ID(), proto); err == nil {
		_, _ = s.Read(make([]byte, 1))
		_ = s.Close()
	}
	require.Zero(t, served.Load(), "a root's stream over the old connection is not served")
	require.Equal(t, 1, node.RevokeDenied())
	require.Eventually(t, func() bool { return len(node.host.Network().ConnsToPeer(root.ID())) == 0 }, 5*time.Second, 20*time.Millisecond)
	require.NotEmpty(t, node.host.Network().ConnsToPeer(later.ID()), "a non-root stays connected")

	laterIsRoot.Store(true) // a newly learned committee member
	require.Equal(t, 1, node.RevokeDenied())
	require.Eventually(t, func() bool { return len(node.host.Network().ConnsToPeer(later.ID())) == 0 }, 5*time.Second, 20*time.Millisecond)
}

// The member protector (astra on #1054, finding 2): a set is protected and dialled at once, a peer the gater denies is neither, and an
// assignment change unprotects the peers it drops, connected or not, while a superseded warm-up cannot put one back.
func TestTheMemberProtectorFollowsAssignmentChurn(t *testing.T) {
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
	a, b, c, denied := start(nil), start(nil), start(nil), start(nil)
	node := start(&RoleGater{Deny: func(id peer.ID) bool { return id == denied.ID() }})
	for _, p := range []*Peer{a, b, c, denied} {
		node.host.Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
	}
	gone := peer.ID("16Uiu2HAmDisconnectedFormerMember") // never reachable: protection is tracked by ID, not by connection
	m := node.NewMemberProtector("shard-members")
	m.Set(ctx, []peer.ID{a.ID(), b.ID(), denied.ID(), node.ID(), gone})
	require.ElementsMatch(t, []peer.ID{a.ID(), b.ID(), gone}, m.Protected())
	cm := node.host.ConnManager()
	require.True(t, cm.IsProtected(a.ID(), "shard-members") && cm.IsProtected(gone, "shard-members"))
	require.False(t, cm.IsProtected(denied.ID(), "shard-members"))
	require.Eventually(t, func() bool { return len(node.host.Network().ConnsToPeer(a.ID())) > 0 }, 5*time.Second, 10*time.Millisecond, "dialled")
	require.Empty(t, node.host.Network().ConnsToPeer(denied.ID()))

	m.Set(ctx, []peer.ID{b.ID(), c.ID()}) // the assignment changed
	require.ElementsMatch(t, []peer.ID{b.ID(), c.ID()}, m.Protected())
	require.False(t, cm.IsProtected(a.ID(), "shard-members"), "a dropped, connected member is unprotected")
	require.False(t, cm.IsProtected(gone, "shard-members"), "a dropped, disconnected member is unprotected too")
	require.True(t, cm.IsProtected(c.ID(), "shard-members"))
	time.Sleep(100 * time.Millisecond) // any warm-up of the first set has had its chance
	require.False(t, cm.IsProtected(a.ID(), "shard-members"), "a superseded warm-up never re-protects")
	m.Set(ctx, nil)
	require.Empty(t, m.Protected())
	require.False(t, cm.IsProtected(b.ID(), "shard-members") || cm.IsProtected(c.ID(), "shard-members"))
}
