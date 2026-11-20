package seed

import (
	"errors"
	"os"
)

// publishDir puts the staged directory at dir, exclusively. A lock file created with O_EXCL beside dir (dir + ".lock") serialises publications of the
// same destination: of two concurrent fresh publications exactly one succeeds, the other is refused. Without replace the destination must not exist.
// With replace an existing destination is exchanged for the staged one in a single atomic step where the platform has it (Linux renameat2 with
// RENAME_EXCHANGE: the destination is never absent), and otherwise moved aside and replaced (briefly absent), the old directory kept if the final
// rename and the restore both fail. stage must be a directory next to dir (the same filesystem).
func publishDir(stage, dir string, replace bool) error {
	lock := dir + ".lock"
	lf, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return refuse("another publication of %s is in progress (or %s is left by one that crashed: remove it once no seed command runs)", dir, lock)
		}
		return err
	}
	_ = lf.Close()
	defer os.Remove(lock)

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
	// no atomic exchange here: move the old one aside, put the new one in, restore on failure, and never delete the old one if the restore fails
	aside := stage + ".old"
	if err := os.Rename(dir, aside); err != nil {
		return err
	}
	if err := os.Rename(stage, dir); err != nil {
		if rerr := os.Rename(aside, dir); rerr != nil {
			return refuse("replacing %s failed (%v) and the old directory could not be restored (%v): it is kept at %s", dir, err, rerr, aside)
		}
		return err
	}
	return os.RemoveAll(aside)
}
