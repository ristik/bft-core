package storage_test

import (
	"crypto"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

func boltStore(t *testing.T) (storage.BoltDB, *storage.BlockStore) {
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store, err := storage.New(crypto.SHA256, db, storage.NewMockOrchestrationForTest(func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil
	}, nil), logger.New(t), storage.ProfileHandoff)
	require.NoError(t, err)
	return db, store
}

// Production delivery to a recovering root (#1181 review F4): the root that admitted the Freeze v5 retains it as the block store does,
// serves the committed candidate its evidence, bundles and request history read (the candidate v6, never the v5 view), and a root that
// missed the Freeze retains exactly that delivery and installs the identical configurations from its own store. The v5 view, which these
// sources served before, does not install.
func TestVRDeliveryCarriesTheCandidateV6ToARecoveringRoot(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	checkpoint, commit, retained := f.committed(t)
	id := commit.NextBodyID

	// the admitting root: the Freeze block's retention, then its committed-candidate source
	g := f.genesis()
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	fz := f.must(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
	_, leader := boltStore(t)
	require.NoError(t, storage.RetainVRFreezeForTest(leader, fz.BlockData, fz))
	served, err := leader.HandoffCommittedPreimage(id)
	require.NoError(t, err)
	require.Equal(t, retained.v6[string(id)], served, "the source serves the candidate v6")
	view, err := leader.HandoffCandidate(id)
	require.NoError(t, err)
	require.Equal(t, retained.v5[string(id)], view, "the install paths' v5 view stays under the candidate key")
	body, err := leader.HandoffBody(id)
	require.NoError(t, err)

	// the recovering root retains the delivery and installs from its own store
	db, recovering := boltStore(t)
	require.NoError(t, recovering.RetainHandoffArtifacts(id, body, served))
	again, err := recovering.HandoffCommittedPreimage(id)
	require.NoError(t, err)
	require.Equal(t, served, again)
	orch := f.realOrchestration(t)
	require.NoError(t, storage.InstallCommittedForTest(db, orch, checkpoint, commit))
	want := f.realOrchestration(t)
	require.NoError(t, storage.InstallCommittedForTest(retained, want, checkpoint, commit))
	a, err := orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	b, err := want.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	for _, k := range []types.PartitionShardID{vxShard, vxAgg, vxAdded} {
		require.Equal(t, confHash(t, b[k]), confHash(t, a[k]), "the recovered root installs the identical configuration of %v", k)
	}

	// the v5 view a source served before does not install: its digest is not the one the body binds
	db2, stale := boltStore(t)
	require.NoError(t, stale.RetainHandoffArtifacts(id, body, view))
	require.Error(t, storage.InstallCommittedForTest(db2, f.realOrchestration(t), checkpoint, commit))
}
