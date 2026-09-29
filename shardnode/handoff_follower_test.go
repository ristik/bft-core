package shardnode

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestHandoffFollowerConfigurationAndSavedBundleGuards(t *testing.T) {
	ctx := context.Background()
	require.Error(t, (*HandoffFollower)(nil).Run(ctx))
	require.Error(t, (*HandoffFollower)(nil).Restore(ctx))
	peer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	base := HandoffFollower{Host: peer, History: &followerHistory{}, AnchorEpoch: 1,
		Directory: t.TempDir(), ConfHash: bytes.Repeat([]byte{5}, 32)}
	for _, tc := range []struct {
		name   string
		change func(*HandoffFollower)
	}{
		{"host", func(f *HandoffFollower) { f.Host = nil }},
		{"history", func(f *HandoffFollower) { f.History = nil }},
		{"anchor epoch", func(f *HandoffFollower) { f.AnchorEpoch = 0 }},
		{"directory", func(f *HandoffFollower) { f.Directory = "" }},
		{"config hash", func(f *HandoffFollower) { f.ConfHash = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) { f := base; tc.change(&f); require.Error(t, f.Run(ctx)) })
		if tc.name != "host" {
			t.Run(tc.name+" restore", func(t *testing.T) { f := base; tc.change(&f); require.Error(t, f.Restore(ctx)) })
		}
	}
	require.NoError(t, base.Restore(ctx)) // a fresh installation has no saved successor
	f := base
	largePath := f.path(2)
	file, err := os.Create(largePath)
	require.NoError(t, err)
	require.NoError(t, file.Truncate((64<<20)+1))
	require.NoError(t, file.Close())
	_, err = f.load(2)
	require.ErrorIs(t, err, handoffdelivery.ErrBundle)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.NoError(t, f.Run(cancelled))
	f.AnchorEpoch = ^uint64(0)
	require.ErrorContains(t, f.Run(ctx), "epoch overflow")
	require.ErrorContains(t, f.Restore(ctx), "epoch overflow")
	f.AnchorEpoch = 1
	f.Directory = filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(f.Directory, []byte{1}, 0600))
	require.Error(t, f.Run(ctx))
	f.Directory = t.TempDir()
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil}, {"malformed CBOR", []byte{0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(f.path(2), tc.raw, 0600))
			_, err := f.load(2)
			require.ErrorIs(t, err, handoffdelivery.ErrBundle)
		})
	}
	_, err = f.fetch(ctx, 3)
	require.Error(t, err) // old epoch is absent
	f.History = &followerHistory{old: &types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{
		nil, {NodeID: "not a peer id"},
	}}}
	_, err = f.fetch(ctx, 2)
	require.Error(t, err) // no usable root peer
	f.History = base.History
	wrongEpoch := handoffdelivery.Bundle{Body: evmroot.TrustBaseBodyV2{Epoch: 3}}
	require.NoError(t, f.save(2, wrongEpoch))
	_, err = f.load(2)
	require.ErrorIs(t, err, handoffdelivery.ErrBundle)
	require.ErrorIs(t, f.Restore(ctx), handoffdelivery.ErrBundle)
	oversize := handoffdelivery.Bundle{Body: evmroot.TrustBaseBodyV2{StateSummary: make([]byte, 64<<20)}}
	require.ErrorIs(t, f.save(2, oversize), handoffdelivery.ErrBundle)
	f.Directory = filepath.Join(t.TempDir(), "missing")
	require.Error(t, f.save(2, handoffdelivery.Bundle{}))
}

type followerProvider struct{ bundle handoffdelivery.Bundle }

func (p followerProvider) HandoffBundle(context.Context, uint64) (*handoffdelivery.Bundle, error) {
	return &p.bundle, nil
}

type followerHistory struct {
	old      *types.RootTrustBaseV1
	accepted int
}

type activeFollowerHistory struct {
	epoch     uint64
	ready     bool
	installed []uint64
}

func (h *activeFollowerHistory) CurrentRootEpoch() (uint64, bool) { return h.epoch, h.ready }
func (*activeFollowerHistory) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return nil, errors.New("unexpected fetch")
}
func (h *activeFollowerHistory) InstallHandoff(_ context.Context, bundle handoffdelivery.Bundle,
	_ types.PartitionID, _ types.ShardID, _ []byte) (handoffdelivery.Verified, error) {
	h.installed = append(h.installed, bundle.Body.Epoch)
	return handoffdelivery.Verified{}, nil
}

func TestHandoffFollowerStartsAfterActiveEpoch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active uint64
		ready  bool
		want   uint64
	}{
		{"installed successor", 2, true, 3},
		{"unready successor", 2, false, 2},
		{"older active report", 0, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			history := &activeFollowerHistory{epoch: tc.active, ready: tc.ready}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &HandoffFollower{Host: testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)),
				History: history, AnchorEpoch: 1, Directory: t.TempDir(),
				ConfHash: bytes.Repeat([]byte{5}, 32),
				OnInstalled: func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error {
					cancel()
					return nil
				}}
			for _, epoch := range []uint64{2, 3} {
				require.NoError(t, f.save(epoch, handoffdelivery.Bundle{Body: evmroot.TrustBaseBodyV2{Epoch: epoch}}))
			}
			require.NoError(t, f.Run(ctx))
			require.Equal(t, []uint64{tc.want}, history.installed)
		})
	}
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
	restoreCalls := 0
	follower.OnInstalled = func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error {
		restoreCalls++
		return nil
	}
	require.NoError(t, follower.Restore(context.Background()))
	require.Equal(t, 1, restoreCalls)

	ctx2, cancel2 := context.WithCancel(context.Background())
	follower.OnInstalled = func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error {
		cancel2()
		return nil
	}
	require.NoError(t, follower.Run(ctx2))
	require.GreaterOrEqual(t, history.accepted, 2)
	callbackFailure := errors.New("snapshot install failed")
	follower.OnInstalled = func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error {
		return callbackFailure
	}
	require.ErrorIs(t, follower.Restore(context.Background()), callbackFailure)
	require.ErrorIs(t, follower.Run(context.Background()), callbackFailure)
	require.NoError(t, follower.save(2, bad))
	require.ErrorIs(t, follower.Restore(context.Background()), handoffdelivery.ErrBundle)
}
