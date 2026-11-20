package seed

import (
	"os"
	"path/filepath"
)

// WriteDir publishes a seed directory: the files are written with exclusive creation into a fresh private staging directory next to dir, and the
// staging directory is published by publishDir (exclusive; an exchange on replace), so a reader never sees a mixed directory and an existing symlink
// at a file name is never followed.
func WriteDir(dir string, payload map[string][]byte, manifest []byte, replace bool) error {
	dir = filepath.Clean(dir)
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	// the parent is resolved ONCE, up front (it may be a stable symlink such as "current"): staging, the exchange, the lock and retention all use the
	// resolved path, so no symlinked component is opened after publication
	rp, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	parent = rp
	dir = filepath.Join(parent, filepath.Base(dir))
	stage, err := os.MkdirTemp(parent, ".seed-stage-")
	if err != nil {
		return err
	}
	for _, n := range PayloadFiles {
		if err := writeNew(filepath.Join(stage, n), payload[n]); err != nil {
			_ = os.RemoveAll(stage)
			return err
		}
	}
	if err := writeNew(filepath.Join(stage, ManifestName), manifest); err != nil {
		_ = os.RemoveAll(stage)
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		_ = os.RemoveAll(stage)
		return err
	}
	err = publishDir(stage, dir, replace)
	cleanStage(stage, err) // after a rename it is gone; after a failed publication it is ours to remove; a version that could not be retained is kept
	return err
}

// writeNew creates a file that must not exist.
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
