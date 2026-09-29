package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

// The saved bundle is the crash boundary between fetching a committed handoff
// and installing the successor. Reopening at that boundary and again after
// activation must preserve the two changed committees and their lineage.
func TestTwoChangedKeyHandoffsRestoreAtEachPhase(t *testing.T) {
	ctx := context.Background()
	first := handoffbundle.New(t)
	var executionID [32]byte
	executionID[0] = 2
	db := memorydb.New()
	dir := t.TempDir()
	open := func() *HistoricalTrustBaseStore {
		store, err := NewHistoricalTrustBaseStore(ctx, db, first.Old, executionID, true)
		require.NoError(t, err)
		return store
	}
	store := open()
	follower := &HandoffFollower{History: store, AnchorEpoch: 1, Directory: dir,
		Partition: first.Partition, Shard: first.Shard, ConfHash: first.ConfHash}
	follower.OnInstalled = func(_ context.Context, bundle handoffdelivery.Bundle, verified handoffdelivery.Verified) error {
		require.True(t, bytes.Equal(bundle.Proof.Control.FrozenParent, verified.Shard.IR.BlockHash))
		prior, err := store.GetByEpoch(ctx, bundle.Proof.Record.Epoch)
		if err != nil {
			return err
		}
		_, err = handoff.TransitionFromInstalledAnchor(bundle.Proof, prior, bundle.Body,
			&rctypes.EpochAnchor{GenesisID: verified.Genesis.ID(), Epoch: verified.Genesis.Epoch,
				Slot: verified.Genesis.Start - 1, StateRoot: verified.Record.StateRoot[:]}, verified.Shard.IRTR)
		if err != nil {
			return err
		}
		return store.ActivateHandoff(bundle.Body.Epoch)
	}
	firstBundle := handoffdelivery.Bundle{Proof: first.Proof, Body: first.Body, Snapshot: first.Snapshot}
	require.NoError(t, follower.save(2, firstBundle))
	// Restart after delivery, then after activation.
	for i := 0; i < 2; i++ {
		store = open()
		follower.History = store
		require.NoError(t, follower.Restore(ctx))
		epoch, ready := store.CurrentRootEpoch()
		require.True(t, ready)
		require.EqualValues(t, 2, epoch)
	}
	projected, err := store.GetByEpoch(ctx, 2)
	require.NoError(t, err)
	second := handoffbundle.Next(t, first, projected)
	require.NotEqual(t, first.Body.Members[1].NodeID, second.Body.Members[1].NodeID)
	secondBundle := handoffdelivery.Bundle{Proof: second.Proof, Body: second.Body, Snapshot: second.Snapshot}
	require.NoError(t, follower.save(3, secondBundle))
	// Restart after the second delivery, then after its activation.
	for i := 0; i < 2; i++ {
		store = open()
		follower.History = store
		require.NoError(t, follower.Restore(ctx))
		epoch, ready := store.CurrentRootEpoch()
		require.True(t, ready)
		require.EqualValues(t, 3, epoch)
	}
	require.True(t, store.IsV2Epoch(2))
	require.True(t, store.IsV2Epoch(3))
}

func TestHistoricalTrustStoreHandoffRefusalsAndReplay(t *testing.T) {
	f := handoffbundle.New(t)
	ctx := context.Background()
	var executionID [32]byte
	executionID[0] = 1
	store, err := NewHistoricalTrustBaseStore(ctx, memorydb.New(), f.Old, executionID, true)
	require.NoError(t, err)
	anchorID, err := f.Old.Hash(crypto.SHA256)
	require.NoError(t, err)
	gotAnchorID, err := store.BodyID(f.Old.Epoch)
	require.NoError(t, err)
	require.Equal(t, anchorID, gotAnchorID[:])
	_, err = store.BodyID(99)
	require.ErrorIs(t, err, trusthistorystore.ErrNotFound)
	bundle := handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	epoch, ready := store.CurrentRootEpoch()
	require.True(t, ready)
	require.EqualValues(t, 1, epoch)
	verified, err := store.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
	require.NoError(t, err)
	gotBodyID, err := store.BodyID(f.Body.Epoch)
	require.NoError(t, err)
	require.Equal(t, [32]byte(f.Body.Identity()), gotBodyID)
	epoch, _ = store.CurrentRootEpoch()
	require.EqualValues(t, 1, epoch, "proof persistence alone does not activate certification")
	_, err = handoff.TransitionFromInstalledAnchor(bundle.Proof, f.Old, bundle.Body,
		&rctypes.EpochAnchor{GenesisID: verified.Genesis.ID(), Epoch: verified.Genesis.Epoch,
			Slot: verified.Genesis.Start - 1, StateRoot: verified.Record.StateRoot[:]}, verified.Shard.IRTR)
	require.NoError(t, err)
	require.ErrorIs(t, store.ActivateHandoff(3), trusthistorystore.ErrHistory)
	require.NoError(t, store.ActivateHandoff(2))
	require.True(t, store.IsV2Epoch(2))
	_, err = store.GetByEpoch(ctx, 2)
	require.NoError(t, err)
	projected, err := store.GetByEpoch(ctx, 2)
	require.NoError(t, err)
	second := handoffbundle.Next(t, f, projected)
	secondBundle := handoffdelivery.Bundle{Proof: second.Proof, Body: second.Body, Snapshot: second.Snapshot}
	_, err = store.InstallHandoff(ctx, secondBundle, f.Partition, f.Shard, f.ConfHash)
	require.NoError(t, err)
	epoch, _ = store.CurrentRootEpoch()
	require.EqualValues(t, 2, epoch)
	require.NoError(t, store.ActivateHandoff(3))
	epoch, _ = store.CurrentRootEpoch()
	require.EqualValues(t, 3, epoch)
	require.True(t, store.IsV2Epoch(3))
	_, err = store.InstallHandoff(ctx, secondBundle, f.Partition, f.Shard, f.ConfHash)
	require.NoError(t, err)
	_, err = store.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
	require.NoError(t, err)
	t.Run("profile off", func(t *testing.T) {
		off, err := NewHistoricalTrustBaseStore(ctx, memorydb.New(), f.Old, executionID, false)
		require.NoError(t, err)
		require.False(t, off.IsV2Epoch(2))
		_, err = off.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
		require.ErrorIs(t, err, trusthistorystore.ErrUnsupportedV2)
	})
	t.Run("max old epoch", func(t *testing.T) {
		bad := bundle
		bad.Proof.Record.Epoch = ^uint64(0)
		_, err := store.InstallHandoff(ctx, bad, f.Partition, f.Shard, f.ConfHash)
		require.ErrorIs(t, err, trusthistorystore.ErrUnsupportedV2)
	})
	t.Run("unknown old epoch", func(t *testing.T) {
		bad := bundle
		bad.Proof.Record.Epoch = 88
		_, err := store.InstallHandoff(ctx, bad, f.Partition, f.Shard, f.ConfHash)
		require.Error(t, err)
	})
	t.Run("wrong predecessor", func(t *testing.T) {
		bad := bundle
		bad.Proof.Record.PredecessorBodyID = bytes.Repeat([]byte{9}, 32)
		_, err := store.InstallHandoff(ctx, bad, f.Partition, f.Shard, f.ConfHash)
		require.ErrorIs(t, err, handoffdelivery.ErrBundle)
	})
	t.Run("invalid proof", func(t *testing.T) {
		bad := bundle
		bad.Proof.CommitQC.Signatures = nil
		_, err := store.InstallHandoff(ctx, bad, f.Partition, f.Shard, f.ConfHash)
		require.ErrorIs(t, err, handoffdelivery.ErrBundle)
	})
	t.Run("wrong local shard", func(t *testing.T) {
		_, err := store.InstallHandoff(ctx, bundle, f.Partition+1, f.Shard, f.ConfHash)
		require.ErrorIs(t, err, handoffdelivery.ErrBundle)
	})
	t.Run("wrong config", func(t *testing.T) {
		_, err := store.InstallHandoff(ctx, bundle, f.Partition, f.Shard, bytes.Repeat([]byte{3}, 32))
		require.ErrorIs(t, err, handoffdelivery.ErrBundle)
	})
	_, err = store.GetByEpoch(ctx, 100)
	require.Error(t, err)
}
