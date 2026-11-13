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
	boot, genesisRoot, laterRoot, mirror := followTestID(t), followTestID(t), followTestID(t), followTestID(t)
	r := newRootFreeRole(true, []libp2ppeer.AddrInfo{{ID: boot}}, []*types.RootTrustBaseV1{{RootNodes: []*types.NodeInfo{{NodeID: genesisRoot.String()}}}})
	require.True(t, r.deny(boot) && r.deny(genesisRoot), "before the role is known the node is non-active")
	require.False(t, r.deny(mirror))
	require.False(t, r.deny(laterRoot), "a root of a later epoch is unknown until its trust base is verified")
	r.addRoots(&types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{{NodeID: laterRoot.String()}}})
	require.True(t, r.deny(laterRoot))

	member := false
	r.setRole(func() bool { return member })
	require.True(t, r.deny(boot))
	member = true
	require.False(t, r.deny(boot) || r.deny(laterRoot), "an active validator reaches its roots")

	off := newRootFreeRole(false, []libp2ppeer.AddrInfo{{ID: boot}}, nil)
	require.False(t, off.deny(boot), "without --follow-source nothing is refused")
}
