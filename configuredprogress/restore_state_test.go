package configuredprogress

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

// ReadArchiveRestoreState decodes the stored recovery anchor: none before a restore completed, the anchor's identity after, and a malformed
// value is an error, never a completed restore (bft-core#1309).
func TestReadArchiveRestoreStateDecodesTheAnchor(t *testing.T) {
	path := t.TempDir() + "/journal.db"
	s, c, _, item, _ := frontierTestSetup(t, path)
	state, _, err := s.Load(context.Background(), c)
	require.NoError(t, err)
	payload, err := marshal(restoreAnchorWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Height: item.Anchor.Height,
		Hash: item.Anchor.Subject.BlockHash[:], StateRoot: item.Anchor.StateRoot[:], RootRound: item.Anchor.Round})
	require.NoError(t, err)
	raw, err := encodeEnvelope(restoreAnchorKind, payload, 4096)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	_, anchor, err := ReadArchiveRestoreState(path)
	require.NoError(t, err)
	require.Nil(t, anchor, "no restore completed")
	put := func(value []byte) {
		db, err := bolt.Open(path, 0o600, nil)
		require.NoError(t, err)
		require.NoError(t, db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketName).Put(restoreAnchorKey, value) }))
		require.NoError(t, db.Close())
	}
	put(raw)
	_, anchor, err = ReadArchiveRestoreState(path)
	require.NoError(t, err)
	require.Equal(t, &RestoreAnchor{Height: item.Anchor.Height, Hash: item.Anchor.Subject.BlockHash, StateRoot: item.Anchor.StateRoot, RootRound: item.Anchor.Round}, anchor)
	put([]byte{1})
	_, anchor, err = ReadArchiveRestoreState(path)
	require.Error(t, err, "a malformed anchor is no completed restore")
	require.Nil(t, anchor)
}
