package consensus

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The frontier proxy wraps the real store of every root in default startup. Wrapping must not hide the
// optional handoff capabilities the profile-2 code asserts for (found when the H3 lane's root could not serve
// a handoff bundle after its sampler was enabled).
func TestFrontierProxyKeepsTheHandoffStoreCapabilities(t *testing.T) {
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "root.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	var proxy PersistentStore = &frontierPersistentStore{PersistentStore: db, sampler: &frontierSampler{}, reader: db}

	id, body := bytes.Repeat([]byte{1}, 32), []byte{2, 3, 4}
	archive, ok := proxy.(interface{ StoreHandoffBody([]byte, []byte) error })
	require.True(t, ok)
	require.NoError(t, archive.StoreHandoffBody(id, body))
	reader, ok := proxy.(interface{ HandoffBody([]byte) ([]byte, error) })
	require.True(t, ok)
	got, err := reader.HandoffBody(id)
	require.NoError(t, err)
	require.Equal(t, body, got, "what the proxy stores is what the real store holds")
	direct, err := db.HandoffBody(id)
	require.NoError(t, err)
	require.Equal(t, body, direct)

	candidate := []byte{9, 9}
	require.NoError(t, proxy.(interface{ StoreHandoffCandidate([]byte, []byte) error }).StoreHandoffCandidate(id, candidate))
	gotCandidate, err := proxy.(interface{ HandoffCandidate([]byte) ([]byte, error) }).HandoffCandidate(id)
	require.NoError(t, err)
	require.Equal(t, candidate, gotCandidate)

	bundles, ok := proxy.(handoffBundleArchive)
	require.True(t, ok)
	require.NoError(t, bundles.StoreHandoffBundle(2, []byte{7, 7, 7}))
	bundle, err := bundles.HandoffBundle(2)
	require.NoError(t, err)
	require.Equal(t, []byte{7, 7, 7}, bundle)

	_, ok = proxy.(interface {
		InstallEpochAnchorRoot(*storage.ExecutedBlock, *drctypes.EpochAnchor) error
	})
	require.True(t, ok)
	_, ok = proxy.(epochAnchorSafetyStore)
	require.True(t, ok)
}

// A store without the capability behaves as the asserting callers behave when their assertion fails.
func TestFrontierProxyOverAStoreWithoutHandoffCapabilities(t *testing.T) {
	var proxy PersistentStore = &frontierPersistentStore{PersistentStore: nil}
	store, ok := proxy.(interface{ StoreHandoffBody([]byte, []byte) error })
	require.True(t, ok)
	require.NoError(t, store.StoreHandoffBody(nil, nil))
	body, ok := proxy.(interface{ HandoffBody([]byte) ([]byte, error) })
	require.True(t, ok)
	_, err := body.HandoffBody(nil)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	storeCandidate, ok := proxy.(interface{ StoreHandoffCandidate([]byte, []byte) error })
	require.True(t, ok)
	require.ErrorIs(t, storeCandidate.StoreHandoffCandidate(nil, nil), storage.ErrAssignmentHistory)
	candidates, ok := proxy.(interface{ HandoffCandidate([]byte) ([]byte, error) })
	require.True(t, ok)
	candidate, err := candidates.HandoffCandidate(nil)
	require.NoError(t, err)
	require.Nil(t, candidate)
	bundles, ok := proxy.(handoffBundleArchive)
	require.True(t, ok)
	require.NoError(t, bundles.StoreHandoffBundle(1, nil))
	bundle, err := bundles.HandoffBundle(1)
	require.NoError(t, err)
	require.Nil(t, bundle)
	anchor, ok := proxy.(interface {
		InstallEpochAnchorRoot(*storage.ExecutedBlock, *drctypes.EpochAnchor) error
	})
	require.True(t, ok)
	require.Error(t, anchor.InstallEpochAnchorRoot(nil, nil), "the atomic anchor install has no fallback")
}
