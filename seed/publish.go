package seed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// publishDir puts the staged directory at dir, exclusively. A lock file created with O_EXCL beside dir (dir + ".lock") serialises publications of the
// same destination: of two concurrent fresh publications exactly one succeeds, the other is refused. Without replace the destination must not exist.
// With replace an existing destination is exchanged for the staged one in a single atomic step (Linux renameat2 with RENAME_EXCHANGE: the
// destination is never absent). Where that is not available the replacement is refused before anything moves. stage must be a directory next to dir.
func publishDir(stage, dir string, replace bool) error {
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	return publishLocked(stage, dir, replace)
}

// lockDir takes the destination lock (dir + ".lock", created exclusively); the caller releases it.
func lockDir(dir string) (func(), error) {
	lock := dir + ".lock"
	lf, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, refuse("another publication or import of %s is in progress (or %s is left by one that crashed: remove it once no seed command runs)", dir, lock)
		}
		return nil, err
	}
	_ = lf.Close()
	return func() { _ = os.Remove(lock) }, nil
}

// publishLocked is publishDir under a lock the caller already holds.
func publishLocked(stage, dir string, replace bool) error {

	_, statErr := os.Lstat(dir)
	exists := statErr == nil
	switch {
	case exists && !replace:
		return refuse("%s already exists (pass --replace to replace it)", dir)
	case !exists:
		return os.Rename(stage, dir)
	}
	if ok, err := exchangeDirs(stage, dir); ok || err != nil {
		if ok {
			// stage now holds the OLD version. A reader that opened the old directory still has its descriptor on it, so the old entries must survive:
			// the version moves into <dir>.versions/, a directory this tool owns (marked), and is removed only after oldVersionGrace, by a later
			// publication, and only from there. If the move fails the old version STAYS at the stage path and the error says so: it is never deleted.
			if rerr := retainOldVersion(stage, dir); rerr != nil {
				return &RetentionError{Stage: stage, Err: rerr}
			}
		}
		return err
	}
	// No atomic exchange here (macOS, a filesystem without RENAME_EXCHANGE). Nothing has been moved: the existing directory stays exactly as it is, so
	// its import.json is never absent. Remove it by hand and publish again.
	return refuse("replacing %s atomically is not supported on this system; nothing was changed: remove it first and publish again", dir)
}

// versionsMarker marks a directory as this tool's retention directory: only a marked directory is ever collected from.
const versionsMarker = ".unicity-seed-versions"

// retainMove moves the replaced version into retention (a variable so a test can make it fail).
var retainMove = os.Rename

// RetentionError reports that a replacement took effect but the replaced version could not be moved into retention. The old version is intact at
// Stage; callers must not remove Stage.
type RetentionError struct {
	Stage string
	Err   error
}

func (e *RetentionError) Error() string {
	return fmt.Sprintf("the replacement is in place, but the previous version could not be retained (%v): it is kept at %s", e.Err, e.Stage)
}
func (e *RetentionError) Unwrap() error { return e.Err }

// cleanStage removes a staging directory unless it holds a version that could not be retained.
func cleanStage(stage string, err error) {
	var re *RetentionError
	if errors.As(err, &re) {
		return
	}
	_ = os.RemoveAll(stage)
}

func versionsDir(dir string) string { return dir + ".versions" }

// retainOldVersion moves a replaced version to <dir>.versions/<unix nano> and collects what is past the grace period from there.
func retainOldVersion(stage, dir string) error {
	vd := versionsDir(dir)
	if err := os.Mkdir(vd, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	marker := filepath.Join(vd, versionsMarker)
	if _, err := os.Lstat(marker); err != nil {
		// an existing directory of that name that this tool did not mark is not ours: nothing is moved into it and nothing is collected from it
		if ents, rerr := os.ReadDir(vd); rerr != nil || len(ents) > 0 {
			return refuse("%s exists and is not this tool's version directory", vd)
		}
		if err := os.WriteFile(marker, nil, 0o600); err != nil {
			return err
		}
	}
	kept := filepath.Join(vd, strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := retainMove(stage, kept); err != nil {
		return err
	}
	gcOldVersions(vd, kept)
	return nil
}

// oldVersionGrace is how long a replaced version stays on disk for readers that opened it before the replacement (a verification or an HTTP response
// in flight holds a descriptor on one version and reads its files relative to it).
var oldVersionGrace = 10 * time.Minute

// gcOldVersions removes versions older than the grace period (never keep, the one just retained) from the marked retention directory vd, and only
// entries named by a timestamp that this tool wrote. Nothing outside vd is ever touched.
func gcOldVersions(vd, keep string) {
	if _, err := os.Lstat(filepath.Join(vd, versionsMarker)); err != nil {
		return
	}
	ents, err := os.ReadDir(vd)
	if err != nil {
		return
	}
	for _, e := range ents {
		ns, err := strconv.ParseInt(e.Name(), 10, 64)
		if err != nil || !e.IsDir() || filepath.Join(vd, e.Name()) == keep || time.Since(time.Unix(0, ns)) < oldVersionGrace {
			continue
		}
		_ = os.RemoveAll(filepath.Join(vd, e.Name()))
	}
}
