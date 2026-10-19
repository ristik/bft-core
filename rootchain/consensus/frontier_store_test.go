package consensus

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-go-base/types"
	"path/filepath"
	"reflect"
	"strings"
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

	// The canonical checkpoint: without it the block tree captures none and serves the current root, which stops being the committing
	// block at the next commit (P85 run 22: no terminal bundle of epoch 1 after the install restart).
	checkpoints, ok := proxy.(interface {
		StoreHandoffCheckpoint(uint64, []byte) error
		HandoffCheckpoint(uint64) ([]byte, error)
	})
	require.True(t, ok)
	require.NoError(t, checkpoints.StoreHandoffCheckpoint(2, []byte{5, 5}))
	checkpoint, err := checkpoints.HandoffCheckpoint(2)
	require.NoError(t, err)
	require.Equal(t, []byte{5, 5}, checkpoint)

	_, ok = proxy.(interface {
		InstallEpochAnchorRoot(*storage.ExecutedBlock, *drctypes.EpochAnchor) error
	})
	require.True(t, ok)
	_, ok = proxy.(epochAnchorSafetyStore)
	require.True(t, ok)
}

// Every handoff retention method of the real store is forwarded by the proxy: a method added to the store and not to the proxy is
// invisible to the asserting callers, which then behave as on a store without it.
func TestFrontierProxyForwardsEveryHandoffMethodOfTheStore(t *testing.T) {
	real, proxy := reflect.TypeOf(storage.BoltDB{}), reflect.TypeOf(&frontierPersistentStore{})
	for i := 0; i < real.NumMethod(); i++ {
		name := real.Method(i).Name
		if !strings.Contains(name, "Handoff") && !strings.Contains(name, "NetworkProfile") {
			continue
		}
		_, ok := proxy.MethodByName(name)
		require.Truef(t, ok, "frontierPersistentStore does not forward %s", name)
	}
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

func TestFrontierProxyForwardsTheControlWitnesses(t *testing.T) {
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "w.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	sampler := &frontierSampler{}
	var as PersistentStore = &frontierPersistentStore{PersistentStore: db, sampler: sampler, reader: db}
	store, ok := as.(storage.WitnessStore)
	require.True(t, ok, "the proxy keeps the witness capability of the store it wraps")

	data := []byte("canonical bundle")
	hash := sha256.Sum256(data)
	require.NoError(t, store.StoreWitness(hash, data))
	got, err := store.Witness(hash)
	require.NoError(t, err)
	require.Equal(t, data, got)
	require.False(t, sampler.faulted.Load())
	none, err := store.Witness([32]byte{1})
	require.NoError(t, err)
	require.Nil(t, none)

	require.ErrorIs(t, store.StoreWitness(hash, []byte("not the bundle")), storage.ErrWitnessStore)
	require.True(t, sampler.faulted.Load(), "a refused write latches the fault")

	sampler2 := &frontierSampler{}
	bare := &frontierPersistentStore{PersistentStore: struct{ PersistentStore }{db}, sampler: sampler2, reader: db}
	require.ErrorIs(t, bare.StoreWitness(hash, data), storage.ErrNoWitnessStore)
	require.True(t, sampler2.faulted.Load())
	_, err = bare.Witness(hash)
	require.ErrorIs(t, err, storage.ErrNoWitnessStore)
}

// The pin of the network profile is visible through the proxy of a default-startup root, and the proxy gives no fallback: a store that was
// pinned to another profile is refused through it exactly as bare, and a store that cannot pin is refused rather than skipped.
func TestFrontierProxyExposesTheProfilePinAndFailsClosed(t *testing.T) {
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "p.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.SetNetworkProfile(storage.ProfileLegacy))
	proxy := &frontierPersistentStore{PersistentStore: db, sampler: &frontierSampler{}, reader: db}
	pinned, found, err := proxy.NetworkProfile()
	require.NoError(t, err)
	require.True(t, found)
	require.EqualValues(t, storage.ProfileLegacy, pinned)
	obs := logger.New(t)
	_, err = storage.New(crypto.SHA256, proxy, emptyOrchestrationForPin(), obs, storage.ProfileHandoff)
	require.ErrorIs(t, err, storage.ErrNetworkProfile, "a profile-1 store is refused through the proxy as it is bare")
	_, err = storage.New(crypto.SHA256, db, emptyOrchestrationForPin(), obs, storage.ProfileHandoff)
	require.ErrorIs(t, err, storage.ErrNetworkProfile)

	blind := &frontierPersistentStore{PersistentStore: nil}
	_, _, err = blind.NetworkProfile()
	require.ErrorIs(t, err, storage.ErrProfilePinUnsupported)
	require.ErrorIs(t, blind.SetNetworkProfile(storage.ProfileHandoff), storage.ErrProfilePinUnsupported)
	// over a blind store the handoff profile refuses to start, the legacy one has nothing to pin
	blindOverBolt := &frontierPersistentStore{PersistentStore: struct{ PersistentStore }{db}, sampler: &frontierSampler{}, reader: db}
	_, err = storage.New(crypto.SHA256, blindOverBolt, emptyOrchestrationForPin(), obs, storage.ProfileHandoff)
	require.ErrorIs(t, err, storage.ErrNetworkProfile)
}

type pinOrchestration struct{}

func (pinOrchestration) NetworkID() types.NetworkID { return 5 }
func (pinOrchestration) ShardConfig(types.PartitionID, types.ShardID, uint64) (*types.PartitionDescriptionRecord, error) {
	return nil, nil
}
func (pinOrchestration) ShardConfigs(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
	return map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil
}
func (pinOrchestration) ShardConfigByHash(types.PartitionID, types.ShardID, []byte, crypto.Hash) (*types.PartitionDescriptionRecord, error) {
	return nil, storage.ErrConfigHistory
}

func emptyOrchestrationForPin() pinOrchestration { return pinOrchestration{} }
