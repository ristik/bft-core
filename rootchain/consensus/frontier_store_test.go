package consensus

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
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

// The proxy forwards the record log of the real store (a root that runs the frontier sampler is every root in default startup), and a
// real store without one is a latched fault, not a silent skip.
func TestFrontierProxyForwardsTheRecordLog(t *testing.T) {
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "p.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	sampler := &frontierSampler{}
	proxy := &frontierPersistentStore{PersistentStore: db, sampler: sampler, reader: db}
	var as PersistentStore = proxy
	store, ok := as.(storage.RecordStore)
	require.True(t, ok, "the proxy keeps the record capability of the store it wraps")

	rec := rootrecords.Record{Index: 0, Kind: rootrecords.KindSessionClosed, Progress: 1, UCTime: 1, Data: make([]byte, 32)}
	rec.ID = rootrecords.RecordID(rec.Index, rec.Predecessor, rec.Kind, rec.Progress, rec.UCTime, rec.Data)
	require.NoError(t, store.AppendRecords([]rootrecords.Record{rec}))
	n, err := store.RecordCount()
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	got, err := store.Records(0, 5)
	require.NoError(t, err)
	require.Equal(t, []rootrecords.Record{rec}, got)
	require.False(t, sampler.faulted.Load())

	// an append the real store refuses latches the fault
	bad := rec
	bad.Progress++
	require.ErrorIs(t, store.AppendRecords([]rootrecords.Record{bad}), storage.ErrRecordLog)
	require.True(t, sampler.faulted.Load())

	// a real store without a log
	sampler2 := &frontierSampler{}
	noLog := &frontierPersistentStore{PersistentStore: struct{ PersistentStore }{db}, sampler: sampler2, reader: db}
	require.ErrorIs(t, noLog.AppendRecords([]rootrecords.Record{rec}), storage.ErrNoRecordStore)
	require.True(t, sampler2.faulted.Load())
	_, err = noLog.RecordCount()
	require.ErrorIs(t, err, storage.ErrNoRecordStore)
	_, err = noLog.Records(0, 1)
	require.ErrorIs(t, err, storage.ErrNoRecordStore)
}
