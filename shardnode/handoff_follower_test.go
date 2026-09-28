package shardnode

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

type followerProvider struct{ bundle handoffdelivery.Bundle }

func (p followerProvider) HandoffBundle(context.Context, uint64) (*handoffdelivery.Bundle, error) {
	return &p.bundle, nil
}

type followerHistory struct {
	old      *types.RootTrustBaseV1
	accepted int
}

func (h *followerHistory) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	if epoch != 1 {
		return nil, errors.New("unexpected old epoch")
	}
	return h.old, nil
}

func (h *followerHistory) InstallHandoff(_ context.Context, bundle handoffdelivery.Bundle,
	partition types.PartitionID, shard types.ShardID, conf []byte) (handoffdelivery.Verified, error) {
	if bundle.Body.Epoch != 2 || len(bundle.Body.StateSummary) != 1 || bundle.Body.StateSummary[0] != 0xaa ||
		partition != 8 || shard.Length() != 0 || !bytes.Equal(conf, bytes.Repeat([]byte{5}, 32)) {
		return handoffdelivery.Verified{}, handoffdelivery.ErrBundle
	}
	h.accepted++
	return handoffdelivery.Verified{}, nil
}

func TestHandoffFollowerTriesAnotherRootAndRestoresSavedBundle(t *testing.T) {
	badRoot := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	goodRoot := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shardPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shardPeer.Network().Peerstore().AddAddrs(badRoot.ID(), badRoot.MultiAddresses(), peerstore.PermanentAddrTTL)
	shardPeer.Network().Peerstore().AddAddrs(goodRoot.ID(), goodRoot.MultiAddresses(), peerstore.PermanentAddrTTL)
	good := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 1}},
		Body: evmroot.TrustBaseBodyV2{Epoch: 2, StateSummary: []byte{0xaa}}}
	bad := good
	bad.Body.StateSummary = []byte{0xbb}
	badServer, err := handoffdelivery.NewServer(followerProvider{bundle: bad})
	require.NoError(t, err)
	badServer.Register(badRoot)
	goodServer, err := handoffdelivery.NewServer(followerProvider{bundle: good})
	require.NoError(t, err)
	goodServer.Register(goodRoot)
	history := &followerHistory{old: &types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{
		{NodeID: badRoot.ID().String()}, {NodeID: goodRoot.ID().String()}}}}
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	follower := &HandoffFollower{Host: shardPeer, History: history, Partition: 8,
		ConfHash: bytes.Repeat([]byte{5}, 32), AnchorEpoch: 1, Directory: dir,
		OnInstalled: func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error {
			cancel()
			return nil
		}}
	require.NoError(t, follower.Run(ctx))
	require.GreaterOrEqual(t, history.accepted, 1)
	saved, err := follower.load(2)
	require.NoError(t, err)
	require.Equal(t, good.Body.StateSummary, saved.Body.StateSummary)

	ctx2, cancel2 := context.WithCancel(context.Background())
	follower.OnInstalled = func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error {
		cancel2()
		return nil
	}
	require.NoError(t, follower.Run(ctx2))
	require.GreaterOrEqual(t, history.accepted, 2)
}
