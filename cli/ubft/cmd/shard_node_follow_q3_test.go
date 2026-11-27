package cmd

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/shardnode"
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

type oneEpochActivator struct{ active uint64 }

func (a *oneEpochActivator) Activate(context.Context, q3active.Bundle) error { a.active++; return nil }
func (a *oneEpochActivator) ActiveEpoch() uint64                             { return a.active }
func (a *oneEpochActivator) Activated(uint64) (q3format.Entry, bool)         { return q3format.Entry{}, false }

// The generated joiner (joiner.py): its bootnodes are every root and every incumbent shard node, its genesis shard configuration names the
// incumbents, and the root committee is authenticated by the trust base. The activation follower it builds asks an incumbent shard for
// the activation (Fetch is reached on it) and never a root.
func TestGeneratedJoinerFetchesItsActivationFromAnIncumbentShard(t *testing.T) {
	roots := []libp2ppeer.ID{rootTestID(t), rootTestID(t)}
	shards := []libp2ppeer.ID{rootTestID(t), rootTestID(t), rootTestID(t)}
	self := rootTestID(t)
	boot := append(append([]libp2ppeer.ID{}, roots...), shards...)
	var validators []*types.NodeInfo
	for _, id := range shards {
		validators = append(validators, &types.NodeInfo{NodeID: id.String(), SigKey: []byte{1}, Stake: 1})
	}
	active, err := shardnode.NewActivePeers(self, validators)
	require.NoError(t, err)
	committee := &types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{{NodeID: roots[0].String()}, {NodeID: roots[1].String()}}}
	isRoot := knownRoots(1, func() uint64 { return 0 }, func(context.Context, uint64) (*types.RootTrustBaseV1, error) { return committee, nil })
	isRootID := map[libp2ppeer.ID]bool{roots[0]: true, roots[1]: true}

	var asked []libp2ppeer.ID
	f := shardQ3Follower(&oneEpochActivator{active: 1}, 1, boot, q3MirrorPeers(active, nil), func() bool { return !active.Member() }, isRoot,
		func(_ context.Context, id libp2ppeer.ID, _ uint64) (q3active.Bundle, error) {
			require.False(t, isRootID[id], "a non-active joiner asked root %s", id)
			asked = append(asked, id)
			return q3active.Bundle{Candidate: []byte("staged")}, nil
		})
	require.NoError(t, f.CatchUp(context.Background(), 2))
	require.Len(t, asked, 1)
	require.Contains(t, shards, asked[0], "the activation came from an incumbent shard")
}
