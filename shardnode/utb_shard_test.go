package shardnode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

func newBundleStore(t *testing.T, f handoffbundle.Fixture, utb bool) *HistoricalTrustBaseStore {
	var executionID [32]byte
	executionID[0] = 3
	store, err := NewHistoricalTrustBaseStore(context.Background(), memorydb.New(), f.Old, executionID, true)
	require.NoError(t, err)
	if utb {
		store.EnableUTBProfile()
	}
	return store
}

// A shard of the signed trust-base entry profile verifies the handoffs of a UTB root: the commit certificate is in the version 3 envelope and carries the old
// committee's endorsement. A plain shard refuses that certificate, and a UTB shard refuses a handoff that was not endorsed.
func TestHistoricalStoreVerifiesBundlesByTheProfileOfItsChain(t *testing.T) {
	ctx := context.Background()
	utbFixture := handoffbundle.New(t)
	handoffbundle.WithUTB(t, utbFixture)
	plainFixture := handoffbundle.New(t)
	bundle := func(f handoffbundle.Fixture) handoffdelivery.Bundle {
		return handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	}

	t.Run("a UTB shard accepts a UTB bundle", func(t *testing.T) {
		store := newBundleStore(t, utbFixture, true)
		cfg := store.BundleSigning(utbFixture.Old)
		require.True(t, cfg.UTB)
		require.EqualValues(t, votesig.SchemeLegacy, cfg.Scheme)
		_, err := store.InstallHandoff(ctx, bundle(utbFixture), utbFixture.Partition, utbFixture.Shard, utbFixture.ConfHash)
		require.NoError(t, err)
	})
	t.Run("a plain shard refuses a UTB certificate", func(t *testing.T) {
		store := newBundleStore(t, utbFixture, false)
		_, err := store.InstallHandoff(ctx, bundle(utbFixture), utbFixture.Partition, utbFixture.Shard, utbFixture.ConfHash)
		require.Error(t, err)
		require.ErrorContains(t, err, "envelope")
	})
	t.Run("a UTB shard refuses an unendorsed handoff", func(t *testing.T) {
		store := newBundleStore(t, plainFixture, true)
		_, err := store.InstallHandoff(ctx, bundle(plainFixture), plainFixture.Partition, plainFixture.Shard, plainFixture.ConfHash)
		require.ErrorIs(t, err, handoffdelivery.ErrBundle)
	})
	t.Run("a plain shard still accepts a plain bundle", func(t *testing.T) {
		store := newBundleStore(t, plainFixture, false)
		_, err := store.InstallHandoff(ctx, bundle(plainFixture), plainFixture.Partition, plainFixture.Shard, plainFixture.ConfHash)
		require.NoError(t, err)
	})
}

// The follower's replay of its saved bundles (the restart path) verifies by the same profile as the history that holds them.
func TestFollowerReplayUsesTheProfileOfItsHistory(t *testing.T) {
	f := handoffbundle.New(t)
	handoffbundle.WithUTB(t, f)
	bundle := handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	follower := func(h HandoffHistory) *HandoffFollower {
		return &HandoffFollower{History: h, AnchorEpoch: 1, Directory: t.TempDir(), Partition: f.Partition, Shard: f.Shard, ConfHash: f.ConfHash}
	}
	_, err := follower(newBundleStore(t, f, true)).verifyReplayed(bundle, f.Old)
	require.NoError(t, err, "a UTB history verifies a UTB bundle")
	_, err = follower(newBundleStore(t, f, false)).verifyReplayed(bundle, f.Old)
	require.ErrorContains(t, err, "envelope", "a plain history refuses the version 3 certificate")
	_, err = follower(legacyOnly{newBundleStore(t, f, true)}).verifyReplayed(bundle, f.Old)
	require.ErrorContains(t, err, "envelope", "a history with no signing configuration is the legacy rule")
}

// legacyOnly hides everything but the follower's history interface.
type legacyOnly struct{ h HandoffHistory }

func (l legacyOnly) GetByEpoch(ctx context.Context, e uint64) (*types.RootTrustBaseV1, error) {
	return l.h.GetByEpoch(ctx, e)
}

func (l legacyOnly) InstallHandoff(ctx context.Context, b handoffdelivery.Bundle, p types.PartitionID, s types.ShardID, c []byte) (handoffdelivery.Verified, error) {
	return l.h.InstallHandoff(ctx, b, p, s, c)
}

// Reopening: opening the store re-verifies every stored activation proof, so a UTB shard with a stored handoff reopens only when the profile is set before the open.
func TestAUTBShardReopensItsStoredHandoffs(t *testing.T) {
	ctx := context.Background()
	f := handoffbundle.New(t)
	handoffbundle.WithUTB(t, f)
	bundle := handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	var executionID [32]byte
	executionID[0] = 4
	db := memorydb.New()
	first, err := NewHistoricalTrustBaseStore(ctx, db, f.Old, executionID, true, WithUTBProfile())
	require.NoError(t, err)
	_, err = first.InstallHandoff(ctx, bundle, f.Partition, f.Shard, f.ConfHash)
	require.NoError(t, err)

	again, err := NewHistoricalTrustBaseStore(ctx, db, f.Old, executionID, true, WithUTBProfile())
	require.NoError(t, err, "the restart of a UTB shard re-verifies the stored version 3 handoff under the profile")
	require.True(t, again.BundleSigning(f.Old).UTB)

	_, err = NewHistoricalTrustBaseStore(ctx, db, f.Old, executionID, true)
	require.Error(t, err, "a shard that forgot the profile cannot reopen a UTB history")
	require.ErrorContains(t, err, "envelope")
}
