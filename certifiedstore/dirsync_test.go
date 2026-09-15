package certifiedstore

import (
	"os"
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

/*
TestOpenRefusesSymbolicLinkStorePaths is the review of #161: bbolt follows a final-component symbolic link, so
links/db -> actual/db creates or opens actual/db while the directory synced would be links. Such paths are
refused, before anything is created through them, and nothing is synced.
*/
func TestOpenRefusesSymbolicLinkStorePaths(t *testing.T) {
	setup := func(t *testing.T) (path, target string, synced *[]string) {
		root := t.TempDir()
		links, actual := filepath.Join(root, "links"), filepath.Join(root, "actual")
		require.NoError(t, os.Mkdir(links, 0o700))
		require.NoError(t, os.Mkdir(actual, 0o700))
		var dirs []string
		withDirectorySync(t, func(dir string) error { dirs = append(dirs, dir); return nil })
		return filepath.Join(links, "db"), filepath.Join(actual, "db"), &dirs
	}

	t.Run("a dangling link", func(t *testing.T) {
		path, target, synced := setup(t)
		require.NoError(t, os.Symlink(target, path))
		s, err := Open(path, Settings{Retain: 1})
		require.ErrorIs(t, err, ErrStorePath)
		require.Nil(t, s)
		require.NoFileExists(t, target, "nothing is created through the link")
		require.Empty(t, *synced)
	})

	t.Run("a link to an existing store", func(t *testing.T) {
		path, target, synced := setup(t)
		existing, err := Open(target, Settings{Retain: 1})
		require.NoError(t, err)
		require.NoError(t, existing.Close())
		before, err := os.ReadFile(target)
		require.NoError(t, err)
		*synced = nil
		require.NoError(t, os.Symlink(target, path))

		s, err := Open(path, Settings{Retain: 1})
		require.ErrorIs(t, err, ErrStorePath)
		require.Nil(t, s)
		after, err := os.ReadFile(target)
		require.NoError(t, err)
		require.Equal(t, before, after, "the target store is not opened through the link")
		require.Empty(t, *synced)
	})

	t.Run("a path that cannot be examined", func(t *testing.T) {
		_, target, synced := setup(t)
		require.NoError(t, os.WriteFile(target, []byte("not a directory"), 0o600))
		s, err := Open(filepath.Join(target, "db"), Settings{Retain: 1})
		require.ErrorIs(t, err, ErrStorePath, "an error other than a missing entry is refused as a path error")
		require.Nil(t, s)
		require.Empty(t, *synced)
	})

	t.Run("a link substituted after the path check", func(t *testing.T) {
		path, target, synced := setup(t)
		previous := afterPathCheck
		afterPathCheck = func(p string) { require.NoError(t, os.Symlink(target, p)) }
		t.Cleanup(func() { afterPathCheck = previous })

		s, err := Open(path, Settings{Retain: 1})
		require.ErrorIs(t, err, ErrStorePath)
		require.Nil(t, s)
		require.Empty(t, *synced, "no directory is synced for an entry that is not in it")

		// The failed Open closed the backend it opened through the link: a direct open is not locked out.
		afterPathCheck = previous
		direct, err := Open(target, Settings{Retain: 1})
		require.NoError(t, err)
		require.NoError(t, direct.Close())
	})
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
