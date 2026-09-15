package certifiedstore

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// withDirectorySync replaces syncDirectory for one test. Tests using it must not run in parallel.
func withDirectorySync(t *testing.T, sync func(dir string) error) {
	previous := syncDirectory
	syncDirectory = sync
	t.Cleanup(func() { syncDirectory = previous })
}

func TestOpenSyncsTheParentDirectory(t *testing.T) {
	var synced []string
	underlying := syncDirectory
	withDirectorySync(t, func(dir string) error {
		synced = append(synced, dir)
		return underlying(dir)
	})
	path := tempDB(t)

	s, err := Open(path, Settings{Retain: 1})
	require.NoError(t, err)
	require.NoError(t, s.Close())
	require.Equal(t, []string{filepath.Dir(path)}, synced, "creating the store syncs the directory that names it")

	s, err = Open(path, Settings{Retain: 1})
	require.NoError(t, err)
	require.NoError(t, s.Close())
	require.Equal(t, []string{filepath.Dir(path), filepath.Dir(path)}, synced, "reopening syncs it again")
}

func TestOpenFailsWhenTheDirectoryCannotBeSynced(t *testing.T) {
	withDirectorySync(t, func(string) error { return errInjected })
	path := tempDB(t)

	s, err := Open(path, Settings{Retain: 1})
	require.ErrorIs(t, err, ErrDirectorySync)
	require.ErrorIs(t, err, errInjected)
	require.Nil(t, s, "no store is returned whose directory entry is not durable")

	// The failed Open closed its handle: bbolt's file lock would otherwise make this reopen time out.
	withDirectorySync(t, func(string) error { return nil })
	s, err = Open(path, Settings{Retain: 1})
	require.NoError(t, err)
	require.NoError(t, s.Close())
}
