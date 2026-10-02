package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
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
	upToAnchor, err := base.CatchUp(ctx, 1)
	require.NoError(t, err)
	require.Empty(t, upToAnchor, "an already pinned anchor needs no successor bundle")
	_, err = base.CatchUp(ctx, 0)
	require.Error(t, err, "restore cannot target an epoch older than its anchor")
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
			f.replayed = true // the durable epochs were replayed by Restore, as in the node's startup order
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

func TestHandoffFollowerCrashAfterSaveReplaysInstallationCallbackOnRestart(t *testing.T) {
	root := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shardPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shardPeer.Network().Peerstore().AddAddrs(root.ID(), root.MultiAddresses(), peerstore.PermanentAddrTTL)
	bundle := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 1}},
		Body: evmroot.TrustBaseBodyV2{Epoch: 2, StateSummary: []byte{0xaa}}}
	server, err := handoffdelivery.NewServer(followerProvider{bundle: bundle})
	require.NoError(t, err)
	server.Register(root)
	history := &followerHistory{old: &types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{{NodeID: root.ID().String()}}}}
	directory := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	crash := errors.New("crash between durable handoff save and journal commit")
	liveCalls := 0
	follower := &HandoffFollower{Host: shardPeer, History: history, Partition: 8,
		ConfHash: bytes.Repeat([]byte{5}, 32), AnchorEpoch: 1, Directory: directory,
		OnInstalled: func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error {
			liveCalls++
			cancel() // End Run after returning the injected crash.
			return crash
		}}
	require.NoError(t, follower.Run(ctx))
	require.Equal(t, 1, liveCalls)
	_, err = follower.load(2)
	require.NoError(t, err, "the follower saves the verified bundle before the journal callback")

	// A restarted node restores that saved proof and invokes OnInstalled again;
	// the production callback uses this delivery to backfill the terminal UC.
	repaired := make(map[uint64]bool)
	follower.OnInstalled = func(_ context.Context, restored handoffdelivery.Bundle, _ handoffdelivery.Verified) error {
		repaired[restored.Body.Epoch] = true // idempotent journal backfill
		return nil
	}
	require.NoError(t, follower.Restore(context.Background()))
	require.True(t, repaired[2])
	require.NoError(t, follower.Restore(context.Background()))
	require.True(t, repaired[2], "reapplying a saved terminal certificate is safe after another restart")
}

func TestHandoffFollowerSourceOrderAndArchiveFallback(t *testing.T) {
	badRoot := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	goodRoot := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shardPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	shardPeer.Network().Peerstore().AddAddrs(badRoot.ID(), badRoot.MultiAddresses(), peerstore.PermanentAddrTTL)
	shardPeer.Network().Peerstore().AddAddrs(goodRoot.ID(), goodRoot.MultiAddresses(), peerstore.PermanentAddrTTL)
	good := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 1}},
		Body: evmroot.TrustBaseBodyV2{Epoch: 2, StateSummary: []byte{0xaa}}}
	bad := good
	bad.Body.StateSummary = []byte{0xbb}
	server, err := handoffdelivery.NewServer(followerProvider{bundle: bad})
	require.NoError(t, err)
	server.Register(badRoot)
	server, err = handoffdelivery.NewServer(followerProvider{bundle: good})
	require.NoError(t, err)
	server.Register(goodRoot)
	history := &followerHistory{old: &types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{{NodeID: goodRoot.ID().String()}}}}
	archiveCalls := 0
	f := &HandoffFollower{Host: shardPeer, History: history, Partition: 8, ConfHash: bytes.Repeat([]byte{5}, 32),
		AnchorEpoch: 1, Directory: t.TempDir(), CurrentRoots: []peer.ID{badRoot.ID()}, ArchiveReplicas: []peer.ID{"archive"},
		FetchArchive: func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error) {
			archiveCalls++
			return good, nil
		}}
	bundle, err := f.fetch(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, good.Body.StateSummary, bundle.Body.StateSummary)
	require.Zero(t, archiveCalls, "previous root should precede archive")
	history.old.RootNodes = nil
	bundle, err = f.fetch(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, good.Body.StateSummary, bundle.Body.StateSummary)
	require.Equal(t, 1, archiveCalls)
	f.CurrentRoots = []peer.ID{goodRoot.ID()}
	bundle, err = f.fetch(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, good.Body.StateSummary, bundle.Body.StateSummary)
	require.Equal(t, 1, archiveCalls, "current root should precede archive")
}

type sequentialHistory struct{ last uint64 }

func (h *sequentialHistory) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	if epoch != h.last {
		return nil, errors.New("history gap")
	}
	return &types.RootTrustBaseV1{}, nil
}
func (h *sequentialHistory) InstallHandoff(_ context.Context, b handoffdelivery.Bundle, _ types.PartitionID, _ types.ShardID, _ []byte) (handoffdelivery.Verified, error) {
	if b.Body.Epoch != h.last+1 && b.Body.Epoch != h.last {
		return handoffdelivery.Verified{}, errors.New("out-of-order handoff")
	}
	if b.Body.Epoch > h.last {
		h.last = b.Body.Epoch
	}
	return handoffdelivery.Verified{}, nil
}

func TestHandoffFollowerCatchUpWalksMissedEpochs(t *testing.T) {
	history := &sequentialHistory{last: 1}
	shardPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var requested, installed []uint64
	f := &HandoffFollower{Host: shardPeer, History: history, Partition: 8, ConfHash: bytes.Repeat([]byte{5}, 32),
		AnchorEpoch: 1, Directory: t.TempDir(), ArchiveReplicas: []peer.ID{"archive"},
		FetchArchive: func(_ context.Context, _ peer.ID, epoch uint64) (handoffdelivery.Bundle, error) {
			requested = append(requested, epoch)
			return handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: epoch - 1}}, Body: evmroot.TrustBaseBodyV2{Epoch: epoch}}, nil
		},
		OnInstalled: func(_ context.Context, b handoffdelivery.Bundle, _ handoffdelivery.Verified) error {
			installed = append(installed, b.Body.Epoch)
			return nil
		}}
	bundles, err := f.CatchUp(context.Background(), 3)
	require.NoError(t, err)
	require.Equal(t, []uint64{2, 3}, requested)
	require.Equal(t, []uint64{2, 3}, installed)
	require.Len(t, bundles, 2)
	for _, epoch := range []uint64{2, 3} {
		_, err := f.load(epoch)
		require.NoError(t, err)
	}
}

func TestHandoffFollowerCatchUpRejectsOlderArchiveBundleAndFallsThrough(t *testing.T) {
	history := &sequentialHistory{last: 1}
	shardPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	old := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 1}}, Body: evmroot.TrustBaseBodyV2{Epoch: 2}}
	next := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 2}}, Body: evmroot.TrustBaseBodyV2{Epoch: 3}}
	var requested []string
	f := &HandoffFollower{Host: shardPeer, History: history, Partition: 8, ConfHash: bytes.Repeat([]byte{5}, 32),
		AnchorEpoch: 1, Directory: t.TempDir(), ArchiveReplicas: []peer.ID{"stale", "fresh"},
		FetchArchive: func(_ context.Context, id peer.ID, epoch uint64) (handoffdelivery.Bundle, error) {
			requested = append(requested, string(id)+"/"+fmt.Sprint(epoch))
			if epoch == 2 || id == "stale" {
				return old, nil
			}
			return next, nil
		}}
	bundles, err := f.CatchUp(context.Background(), 3)
	require.NoError(t, err)
	require.Equal(t, []string{"stale/2", "stale/3", "fresh/3"}, requested)
	require.EqualValues(t, 3, history.last)
	require.EqualValues(t, 3, bundles[3].Body.Epoch)
	saved, err := f.load(3)
	require.NoError(t, err)
	require.EqualValues(t, 3, saved.Body.Epoch, "an older bundle must not be stored as epoch 3")
}

// An epoch that no root and no archive replica can serve at all is its own typed refusal, distinct from the replica that says it has not
// installed the step yet (ErrHandoffPeerNotReady, the only one CatchUp retries), and CatchUp keeps it behind its epoch prefix.
func TestHandoffFollowerCompleteSourceUnavailabilityIsTyped(t *testing.T) {
	const message = "handoff follower: epoch 2 unavailable from current roots, old roots and archive replicas"
	shardPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	newFollower := func(fetchArchive func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error)) *HandoffFollower {
		return &HandoffFollower{Host: shardPeer, History: &followerHistory{old: &types.RootTrustBaseV1{}}, Partition: 8,
			ConfHash: bytes.Repeat([]byte{5}, 32), AnchorEpoch: 1, Directory: t.TempDir(),
			ArchiveReplicas: []peer.ID{"archive"}, FetchArchive: fetchArchive,
			Retry: BundleRetry{Initial: time.Millisecond, Max: time.Millisecond, Total: 50 * time.Millisecond}}
	}

	t.Run("no source at all", func(t *testing.T) {
		_, err := newFollower(nil).fetch(context.Background(), 2)
		require.ErrorIs(t, err, ErrHandoffSourceUnavailable)
		require.NotErrorIs(t, err, ErrHandoffPeerNotReady)
		require.EqualError(t, err, message)
	})
	t.Run("an archive replica that fails for another reason", func(t *testing.T) {
		f := newFollower(func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error) {
			return handoffdelivery.Bundle{}, errors.New("replica down")
		})
		_, err := f.fetch(context.Background(), 2)
		require.ErrorIs(t, err, ErrHandoffSourceUnavailable)
		require.NotErrorIs(t, err, ErrHandoffPeerNotReady)
	})
	t.Run("a replica that has not installed the step stays the other class", func(t *testing.T) {
		f := newFollower(func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error) {
			return handoffdelivery.Bundle{}, ErrHandoffPeerNotReady
		})
		_, err := f.fetch(context.Background(), 2)
		require.ErrorIs(t, err, ErrHandoffPeerNotReady)
		require.NotErrorIs(t, err, ErrHandoffSourceUnavailable)
	})
	t.Run("through CatchUp", func(t *testing.T) {
		_, err := newFollower(nil).CatchUp(context.Background(), 2)
		require.ErrorIs(t, err, ErrHandoffSourceUnavailable)
		require.NotErrorIs(t, err, ErrHandoffPeerNotReady)
		require.EqualError(t, err, "epoch 2: "+message)
	})
}
