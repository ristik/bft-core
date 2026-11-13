package cmd

import (
	"context"
	"crypto/rand"
	"sync/atomic"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network"
)

// The role opens only when the activation naming this node has completed, in the installer and in the runtime. A suspended activation
// (assignment installed, EVM transition or trust activation not yet done) and a failed one leave it closed; a retirement closes it at once,
// before its activation completes; every publication changes the token.
func TestShardRoleOpensOnlyOnACompletedActivation(t *testing.T) {
	var runtime atomic.Uint64 // the runtime's completed epoch (0 until its first activation)
	role := newShardRole(1, false, runtime.Load)
	changes := 0
	role.subscribe(func() { changes++ })
	require.False(t, role.active(), "a joiner at the genesis epoch")

	role.assignmentInstalled(true) // epoch 2 names it; suspended before the EVM transition and the trust activation
	require.False(t, role.active(), "suspended mid-activation")
	// the installation fails after this point: nothing completes, the role stays closed

	role.activationCompleted(2, true) // the installer finished; the runtime has not journaled completion yet
	require.False(t, role.active(), "the runtime has not completed epoch 2")
	runtime.Store(2)
	token, active := role.Lease()
	require.True(t, active)

	role.assignmentInstalled(false) // epoch 3 retires it: closed at once, before epoch 3 completes
	require.False(t, role.active())
	role.activationCompleted(3, false)
	runtime.Store(3)
	require.False(t, role.active())
	role.activationCompleted(4, true)
	runtime.Store(4)
	token2, active := role.Lease()
	require.True(t, active)
	require.NotEqual(t, token, token2, "a new publication is a new lease")
	require.Equal(t, 4, changes)

	genesis := newShardRole(1, true, func() uint64 { return 0 })
	require.True(t, genesis.active(), "a genesis validator is active at the anchor before any runtime activation")
}

// The generated joiner's configuration (joiner.py): --bootnodes lists every root and every incumbent shard node, --follow-source the
// incumbent shard nodes. With real libp2p gating the joiner reaches its follow sources and is refused by the roots (known from the trust
// base, not from the bootnode list) until its role opens.
func TestGeneratedJoinerReachesItsFollowSourcesAndNotTheRoots(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := logger.New(t)
	start := func(gater *network.RoleGater) *network.Peer {
		conf, err := network.NewPeerConfiguration("/ip4/127.0.0.1/tcp/0", nil, followKeyPair(t), nil, nil)
		require.NoError(t, err)
		conf.Gater = gater
		p, err := network.NewPeer(ctx, conf, log, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	root, shard := start(nil), start(nil)
	tb := &types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{{NodeID: root.ID().String()}}}
	boot := []libp2ppeer.AddrInfo{{ID: root.ID(), Addrs: root.MultiAddresses()}, {ID: shard.ID(), Addrs: shard.MultiAddresses()}}
	follow := []libp2ppeer.AddrInfo{boot[1]}

	follower := newRootFreeRole(true, []*types.RootTrustBaseV1{tb})
	role := newShardRole(1, false, func() uint64 { return 0 })
	follower.setRole(role.active)
	joiner := start(&network.RoleGater{Deny: follower.deny})
	follower.setRevoke(func() { joiner.RevokeDenied() })
	role.subscribe(follower.changed)
	for _, b := range boot {
		joiner.Network().Peerstore().AddAddrs(b.ID, b.Addrs, peerstore.PermanentAddrTTL)
	}

	require.Equal(t, followSourceIDs(follow), follower.nonRoot(followSourceIDs(boot)), "the shard bootnode is a source, the root is not")
	_, err := joiner.CreateStream(ctx, shard.ID(), "/test/none/1")
	require.NotErrorIs(t, err, network.ErrGated, "the follow source is reachable")
	_, err = joiner.CreateStream(ctx, root.ID(), "/test/none/1")
	require.ErrorIs(t, err, network.ErrGated, "the root is refused")

	role.activationCompleted(1, true) // promoted (anchor epoch: complete at once)
	_, err = joiner.CreateStream(ctx, root.ID(), "/test/none/1")
	require.NotErrorIs(t, err, network.ErrGated, "active: the root opens")
	require.NotEmpty(t, joiner.Network().ConnsToPeer(root.ID()))

	role.assignmentInstalled(false) // retired without a restart: the existing root connection is closed
	require.Empty(t, joiner.Network().ConnsToPeer(root.ID()))
	require.NotEmpty(t, joiner.Network().ConnsToPeer(shard.ID()))
}

func followKeyPair(t *testing.T) *network.PeerKeyPair {
	t.Helper()
	priv, pub, err := libp2pcrypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	privRaw, err := priv.Raw()
	require.NoError(t, err)
	pubRaw, err := pub.Raw()
	require.NoError(t, err)
	return &network.PeerKeyPair{PublicKey: pubRaw, PrivateKey: privRaw}
}
