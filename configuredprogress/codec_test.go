package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

func TestDescriptorAndInitialControlExactSchema(t *testing.T) {
	f := newFixture(t, 0)
	raw, digest, err := encodeDescriptor(f.origin)
	require.NoError(t, err)
	payload, err := decodeEnvelope(raw, kindDescriptor, MaxDescriptorBytes)
	require.NoError(t, err)
	r := f.origin.Record()
	pc := f.origin.ProofContext()
	manual, err := types.Cbor.Marshal([]any{uint64(2), f.origin.Identity().Bytes(), f.origin.ExecutionConfigIdentity().Bytes(), []any{r.NetworkID, r.PartitionID, r.ShardID, f.origin.FullShardConfHash().Bytes(), pc.RegistryAddress.Bytes(), pc.RegistryCodeHash.Bytes(), pc.GenesisCommitment.Bytes(), pc.ShardEpoch, pc.RootEpoch}, f.origin.BlockHash().Bytes(), f.origin.StateRoot().Bytes(), uint64(evmroot.ProfileVersionV2), uint64(1)})
	require.NoError(t, err)
	require.Equal(t, manual, payload)
	require.Equal(t, sha256.Sum256(manual), digest)
	c := controlWire{Version: 2, DescriptorDigest: digest[:], Revision: 0}
	cp, err := marshal(c)
	require.NoError(t, err)
	manualControl, err := types.Cbor.Marshal([]any{uint64(2), digest[:], uint64(0), nil, nil, nil})
	require.NoError(t, err)
	require.Equal(t, manualControl, cp, "null is distinct from empty bytes in revision-zero control")
}

func TestOpenIsolationAndMalformedState(t *testing.T) {
	t.Run("legacy bucket", func(t *testing.T) {
		path := t.TempDir() + "/db"
		db, err := bolt.Open(path, 0o600, nil)
		require.NoError(t, err)
		require.NoError(t, db.Update(func(tx *bolt.Tx) error { _, e := tx.CreateBucket(legacyBucket); return e }))
		require.NoError(t, db.Close())
		_, err = OpenConfiguredV2(path, Settings{Retain: 1})
		require.ErrorIs(t, err, ErrVersion)
	})
	t.Run("unknown bucket", func(t *testing.T) {
		path := t.TempDir() + "/db"
		db, err := bolt.Open(path, 0o600, nil)
		require.NoError(t, err)
		require.NoError(t, db.Update(func(tx *bolt.Tx) error { _, e := tx.CreateBucket([]byte("unknown")); return e }))
		require.NoError(t, db.Close())
		_, err = OpenConfiguredV2(path, Settings{Retain: 1})
		require.ErrorIs(t, err, ErrVersion)
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := dir + "/target"
		require.NoError(t, os.WriteFile(target, nil, 0o600))
		require.NoError(t, os.Symlink(target, dir+"/link"))
		_, err := OpenConfiguredV2(dir+"/link", Settings{Retain: 1})
		require.Error(t, err)
	})
	t.Run("directory sync failure", func(t *testing.T) {
		old := syncDirectory
		syncDirectory = func(string) error { return errors.New("sync cut") }
		t.Cleanup(func() { syncDirectory = old })
		_, err := OpenConfiguredV2(t.TempDir()+"/db", Settings{Retain: 1})
		require.ErrorContains(t, err, "sync cut")
	})
}

func TestLoadRefusesMissingCorruptAndOversizedControlWithoutFallback(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketName).Delete(controlKey) }))
	_, _, err = s.Load(context.Background(), f.ctx)
	require.ErrorIs(t, err, ErrUnavailable)
	// Restore by recreating a separate initialized image; initialization never clears the corrupt one.
	_, _, err = s.Initialize(context.Background(), f.ctx)
	require.Error(t, err)
	s2, _ := f.open(2)
	defer s2.Close()
	_, _, err = s2.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	require.NoError(t, s2.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put(controlKey, bytes.Repeat([]byte{1}, MaxControlBytes+1))
	}))
	_, _, err = s2.Load(context.Background(), f.ctx)
	require.True(t, errors.Is(err, ErrBounds))
}
