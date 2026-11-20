//go:build linux

package seed

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The path of DIR.versions is swapped for a symlink to another seed's marked directory AFTER it was opened and before the rename: the rename goes into
// the directory that was opened and checked, and the other directory is neither written to nor collected from.
func TestSwapOfTheVersionsDirectoryBetweenOpenAndRenameChangesNothing(t *testing.T) {
	f := newFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	require.NoError(t, WriteDir(dst, f.files, f.manifest, false))
	if !canExchange(parent) {
		t.Skip("no atomic exchange here")
	}
	other := filepath.Join(t.TempDir(), "other.versions")
	require.NoError(t, os.Mkdir(other, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(other, versionsMarker), nil, 0o600))
	expired := filepath.Join(other, fmt.Sprint(time.Now().Add(-time.Hour).UnixNano()))
	require.NoError(t, os.MkdirAll(expired, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(expired, "keep"), []byte("x"), 0o644))

	prev, prevGrace := retainMove, oldVersionGrace
	oldVersionGrace = 0
	defer func() { retainMove, oldVersionGrace = prev, prevGrace }()
	retainMove = func(stagefd int, stageName string, vfd int, name string) error {
		// between the open of DIR.versions and the rename: the path now names the other directory
		vd := versionsDir(dst)
		require.NoError(t, os.Rename(vd, vd+".orig"))
		require.NoError(t, os.Symlink(other, vd))
		return unix.Renameat(stagefd, stageName, vfd, name)
	}
	g := newFixture(t)
	require.NoError(t, WriteDir(dst, g.files, g.manifest, true))
	// the version went into the directory that was opened (now at .orig), not into the other one, and nothing of the other was collected
	moved, _ := os.ReadDir(versionsDir(dst) + ".orig")
	require.Len(t, moved, 2, "the marker and the retained version")
	otherEnts, _ := os.ReadDir(other)
	require.Len(t, otherEnts, 2, "the other directory is exactly as it was")
	require.FileExists(t, filepath.Join(expired, "keep"))
}

// An interrupted creation of the retention directory leaves no unmarked DIR.versions: the next replacement creates it and retains normally.
func TestInterruptedMarkerCreationIsRetriedNotRefusedForever(t *testing.T) {
	f := newFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	require.NoError(t, WriteDir(dst, f.files, f.manifest, false))
	if !canExchange(parent) {
		t.Skip("no atomic exchange here")
	}
	prev := markVersionsDir
	markVersionsDir = func(int) error { return fmt.Errorf("interrupted") }
	g := newFixture(t)
	err := WriteDir(dst, g.files, g.manifest, true)
	markVersionsDir = prev
	var re *RetentionError
	require.ErrorAs(t, err, &re)
	require.NoDirExists(t, versionsDir(dst), "no half-made retention directory is left in place")
	// the retry: the creation completes, and the old version of THIS replacement is retained
	h := newFixture(t)
	require.NoError(t, WriteDir(dst, h.files, h.manifest, true))
	require.FileExists(t, filepath.Join(versionsDir(dst), versionsMarker))
	ents, _ := os.ReadDir(versionsDir(dst))
	require.Len(t, ents, 2, "the marker and the one retained version")
}

func TestCollectionExpiresRetainedFilesAndSymlinksWithoutFollowing(t *testing.T) {
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	vd := versionsDir(dst)
	require.NoError(t, os.Mkdir(vd, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(vd, versionsMarker), nil, 0o600))
	victim := filepath.Join(parent, "victim")
	require.NoError(t, os.Mkdir(victim, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(victim, "keep"), []byte("x"), 0o644))
	old := time.Now().Add(-time.Hour).UnixNano()
	file := filepath.Join(vd, fmt.Sprint(old))
	link := filepath.Join(vd, fmt.Sprint(old+1))
	fresh := filepath.Join(vd, fmt.Sprint(time.Now().UnixNano()))
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
	require.NoError(t, os.Symlink(victim, link))
	require.NoError(t, os.Symlink(victim, fresh))
	gcOldVersions(vd, "")
	require.NoFileExists(t, file)
	_, err := os.Lstat(link)
	require.True(t, os.IsNotExist(err), "the expired symlink is removed")
	require.FileExists(t, filepath.Join(victim, "keep"), "the symlink's target is never followed")
	_, err = os.Lstat(fresh)
	require.NoError(t, err, "a version inside the grace period stays")
}

// Entries are classified by fstatat relative to the real directory descriptor, never by a listing's type: files, directories and symlinks (also to
// directories) are told apart, and a nested expired version is removed completely.
func TestEntriesAreClassifiedByFstatatNotByTheListing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "d"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(dir, "d"), filepath.Join(dir, "l")))
	fd, err := unix.Open(dir, openDirFlags, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	for name, want := range map[string]bool{"f": false, "d": true, "l": false} {
		got, err := isDirAt(fd, name)
		require.NoError(t, err)
		require.Equal(t, want, got, name)
	}
	_, err = isDirAt(fd, "missing")
	require.Error(t, err)
	require.ElementsMatch(t, []string{"f", "d", "l"}, namesAt(fd))

	// a nested expired version (directories inside directories, files and a symlink to a directory) is removed completely, nothing outside it touched
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o644))
	vd := filepath.Join(t.TempDir(), "v.versions")
	require.NoError(t, os.Mkdir(vd, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(vd, versionsMarker), nil, 0o600))
	old := filepath.Join(vd, fmt.Sprint(time.Now().Add(-time.Hour).UnixNano()))
	require.NoError(t, os.MkdirAll(filepath.Join(old, "a", "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(old, "a", "b", "f"), []byte("x"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(old, "a", "link")))
	gcOldVersions(vd, "")
	_, err = os.Lstat(old)
	require.True(t, os.IsNotExist(err), "the expired nested version is removed")
	require.FileExists(t, filepath.Join(outside, "keep"), "a symlink inside it is removed itself, never followed")
}
