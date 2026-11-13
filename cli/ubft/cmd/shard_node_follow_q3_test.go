package cmd

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestKnownRootsIsEveryVerifiedEpochsCommitteeAndNotTheBootnodes(t *testing.T) {
	shard, e1, e2, e3 := rootTestID(t), rootTestID(t), rootTestID(t), rootTestID(t)
	committees := map[uint64]libp2ppeer.ID{1: e1, 2: e2, 3: e3}
	active := uint64(2)
	isRoot := knownRoots(1, func() uint64 { return active }, func(_ context.Context, e uint64) (*types.RootTrustBaseV1, error) {
		return &types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{{NodeID: committees[e].String()}}}, nil
	})
	require.True(t, isRoot(e1) && isRoot(e2), "old and current committees")
	require.False(t, isRoot(shard), "an incumbent shard node listed as a bootnode is not a root")
	require.False(t, isRoot(e3), "an epoch not yet verified")
	active = 3
	require.True(t, isRoot(e3), "rebuilt when the active epoch moves")
	require.False(t, isRoot(rootTestID(t)))
}

func rootTestID(t *testing.T) libp2ppeer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	id, err := libp2ppeer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	return id
}
