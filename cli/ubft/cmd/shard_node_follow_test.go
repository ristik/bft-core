package cmd

import (
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func followTestID(t *testing.T) libp2ppeer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	id, err := libp2ppeer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	return id
}

func TestRootFreeRoleDeniesKnownRootsWhileNonActive(t *testing.T) {
	shardBoot, genesisRoot, laterRoot, utbRoot := followTestID(t), followTestID(t), followTestID(t), followTestID(t)
	r := newRootFreeRole(true, []*types.RootTrustBaseV1{{RootNodes: []*types.NodeInfo{{NodeID: genesisRoot.String()}}}})
	revoked := 0
	r.setRevoke(func() { revoked++ })
	require.True(t, r.deny(genesisRoot), "before the role is known the node is non-active")
	require.False(t, r.deny(shardBoot), "a bootnode is not a root by being a bootnode")
	require.False(t, r.deny(laterRoot), "a root of a later epoch is unknown until its trust base is verified")
	r.addRoots(&types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{{NodeID: laterRoot.String()}}})
	require.True(t, r.deny(laterRoot))
	r.addRootNodes([]*types.NodeInfo{{NodeID: utbRoot.String()}}) // an authenticated UTB entry's committee, before its Q3 activation
	require.True(t, r.deny(utbRoot))
	require.Equal(t, 2, revoked, "each newly learned committee revokes existing connections")
	r.addRootNodes([]*types.NodeInfo{{NodeID: utbRoot.String()}})
	require.Equal(t, 2, revoked, "nothing new, nothing revoked")

	member := false
	r.setRole(func() bool { return member })
	require.True(t, r.deny(genesisRoot))
	member = true
	require.False(t, r.deny(genesisRoot) || r.deny(laterRoot), "an active validator reaches its roots")

	off := newRootFreeRole(false, []*types.RootTrustBaseV1{{RootNodes: []*types.NodeInfo{{NodeID: genesisRoot.String()}}}})
	require.False(t, off.deny(genesisRoot), "without --follow-source nothing is refused")
}

// A root identity listed as a mirror or follow source is dropped at source selection, whatever the role.
func TestRootFreeRoleDropsRootsFromMirrorLists(t *testing.T) {
	epochRoot, mirror := followTestID(t), followTestID(t)
	r := newRootFreeRole(true, []*types.RootTrustBaseV1{{RootNodes: []*types.NodeInfo{{NodeID: epochRoot.String()}}}})
	r.setMirrors(func() []libp2ppeer.ID { return []libp2ppeer.ID{mirror, epochRoot, mirror} })
	require.Equal(t, []libp2ppeer.ID{mirror}, r.mirrorPeers())
	r.setRole(func() bool { return true })
	require.Equal(t, []libp2ppeer.ID{mirror}, r.mirrorPeers(), "an active node's mirrors are still non-root sources")
	require.Equal(t, []libp2ppeer.ID{mirror}, r.nonRoot([]libp2ppeer.ID{epochRoot, mirror}))
}
