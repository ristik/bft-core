package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

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
	_, err = store.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
	require.NoError(t, err)
	gotBodyID, err := store.BodyID(f.Body.Epoch)
	require.NoError(t, err)
	require.Equal(t, [32]byte(f.Body.Identity()), gotBodyID)
	require.True(t, store.IsV2Epoch(2))
	_, err = store.GetByEpoch(ctx, 2)
	require.NoError(t, err)
	projected, err := store.GetByEpoch(ctx, 2)
	require.NoError(t, err)
	second := handoffbundle.Next(t, f, projected)
	secondBundle := handoffdelivery.Bundle{Proof: second.Proof, Body: second.Body, Snapshot: second.Snapshot}
	_, err = store.InstallHandoff(ctx, secondBundle, f.Partition, f.Shard, f.ConfHash)
	require.NoError(t, err)
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
