//go:build linux

package seed

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// retainMove moves the replaced version (stageName inside the directory stagefd) into retention (name inside vfd): a descriptor-relative renameat. It is
// a variable so a test can make it fail or interleave a swap.
var retainMove = func(stagefd int, stageName string, vfd int, name string) error {
	return unix.Renameat(stagefd, stageName, vfd, name)
}

const openDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// markVersionsDir writes the marker into a directory (a variable so a test can interrupt the creation).
var markVersionsDir = func(dirfd int) error {
	mfd, err := unix.Openat(dirfd, versionsMarker, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	return unix.Close(mfd)
}

// checkMarked requires the regular marker inside vfd, relative to the descriptor (fstatat AT_SYMLINK_NOFOLLOW).
func checkMarked(vfd int) bool {
	var st unix.Stat_t
	return unix.Fstatat(vfd, versionsMarker, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
}

// openVersionsDir returns a descriptor of <dir>.versions, opened once with no symlink followed (a symlink or a non-directory fails the open), after
// checking its marker on the descriptor. When the directory does not exist it is created COMPLETE: made under a private temporary name, marked there, and
// renamed into place only if the name is still free (RENAME_NOREPLACE), so an interrupted creation never leaves an unmarked DIR.versions behind to be
// refused forever (a leftover is only the temporary name, which nothing reads). A directory that already exists is used only if it carries the marker.
func openVersionsDir(dir string) (int, error) {
	vd := versionsDir(dir)
	open := func() (int, error) {
		vfd, err := unix.Open(vd, openDirFlags, 0)
		if err != nil {
			return -1, err
		}
		if !checkMarked(vfd) {
			_ = unix.Close(vfd)
			return -1, refuse("%s already exists and is not this tool's version directory", vd)
		}
		return vfd, nil
	}
	if vfd, err := open(); err == nil {
		return vfd, nil
	} else if !errors.Is(err, unix.ENOENT) {
		if errors.Is(err, ErrSeed) {
			return -1, err
		}
		return -1, refuse("%s is not a real directory of this tool's (%v)", vd, err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(vd), filepath.Base(vd)+".new-")
	if err != nil {
		return -1, err
	}
	tfd, err := unix.Open(tmp, openDirFlags, 0)
	if err != nil {
		_ = os.Remove(tmp)
		return -1, err
	}
	merr := markVersionsDir(tfd)
	_ = unix.Close(tfd)
	if merr != nil {
		_ = os.RemoveAll(tmp) // our own temporary directory
		return -1, &os.PathError{Op: "mark", Path: vd, Err: merr}
	}
	switch err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, vd, unix.RENAME_NOREPLACE); {
	case err == nil:
	case errors.Is(err, unix.EEXIST):
		_ = os.RemoveAll(tmp) // somebody created it first: use theirs only if it is marked
	default:
		_ = os.RemoveAll(tmp)
		return -1, &os.PathError{Op: "rename", Path: vd, Err: err}
	}
	vfd, err := open()
	if err != nil {
		return -1, err
	}
	return vfd, nil
}

// retainOldVersion moves a replaced version (stage, a sibling of dir) into <dir>.versions/<unix nano> and collects what is past the grace period from
// there, all relative to descriptors: the versions directory is opened once without following a symlink, its marker is checked on it, the version is
// renamed into it (renameat) and expired entries are removed from it (unlinkat). A swap of the path after the open changes nothing.
func retainOldVersion(stage, dir string) error {
	vfd, err := openVersionsDir(dir)
	if err != nil {
		return err
	}
	defer unix.Close(vfd)
	parent, err := unix.Open(parentOf(stage), openDirFlags, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	name := strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := retainMove(parent, baseOf(stage), vfd, name); err != nil {
		return err
	}
	collectExpired(vfd, name)
	return nil
}

// gcOldVersions collects expired versions of the retention directory vd (a path), opening it once without following a symlink and requiring its marker.
func gcOldVersions(vd, keep string) {
	vfd, err := unix.Open(vd, openDirFlags, 0)
	if err != nil {
		return
	}
	defer unix.Close(vfd)
	var st unix.Stat_t
	if unix.Fstatat(vfd, versionsMarker, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return
	}
	collectExpired(vfd, baseOf(keep))
}

// isDirAt classifies name inside dirfd with fstatat(AT_SYMLINK_NOFOLLOW), relative to the real directory descriptor. It never relies on the d_type a
// directory listing may omit (and a listing's fallback lstat would resolve against a synthetic name); a symlink, even to a directory, is not a directory.
func isDirAt(dirfd int, name string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, err
	}
	return st.Mode&unix.S_IFMT == unix.S_IFDIR, nil
}

// namesAt lists the entry names of the directory vfd without types (so every classification goes through isDirAt).
func namesAt(vfd int) []string {
	f := os.NewFile(uintptr(mustDup(vfd)), "dir")
	if f == nil {
		return nil
	}
	defer f.Close()
	names, _ := f.Readdirnames(-1)
	return names
}

// collectExpired removes the timestamp-named entries older than the grace period (never keep) relative to vfd. Directories are removed recursively
// relative to their own descriptors, files and symlinks with unlinkat (a symlink is removed itself, never followed). Entries are classified by fstatat on
// vfd, not by the listing.
func collectExpired(vfd int, keep string) {
	for _, name := range namesAt(vfd) {
		ns, err := strconv.ParseInt(name, 10, 64)
		if err != nil || name == keep || time.Since(time.Unix(0, ns)) < oldVersionGrace {
			continue
		}
		isDir, err := isDirAt(vfd, name)
		if err != nil {
			continue
		}
		if isDir {
			removeAllAt(vfd, name)
		} else {
			_ = unix.Unlinkat(vfd, name, 0)
		}
	}
}

func mustDup(fd int) int {
	n, err := unix.Dup(fd)
	if err != nil {
		return -1
	}
	return n
}

// removeAllAt removes the directory name inside dirfd and everything under it, relative to descriptors and without following a symlink.
func removeAllAt(dirfd int, name string) {
	fd, err := unix.Openat(dirfd, name, openDirFlags, 0)
	if err != nil {
		return
	}
	for _, e := range namesAt(fd) {
		if isDir, err := isDirAt(fd, e); err == nil && isDir {
			removeAllAt(fd, e)
		} else {
			_ = unix.Unlinkat(fd, e, 0)
		}
	}
	_ = unix.Close(fd)
	_ = unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
}
