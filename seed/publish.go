package seed

import (
	"errors"
	"os"
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
		return err // stage now holds the old directory; the caller removes the stage
	}
	// No atomic exchange here (macOS, a filesystem without RENAME_EXCHANGE). Nothing has been moved: the existing directory stays exactly as it is, so
	// its import.json is never absent. Remove it by hand and publish again.
	return refuse("replacing %s atomically is not supported on this system; nothing was changed: remove it first and publish again", dir)
}
