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
	stage, err := os.MkdirTemp(parent, ".seed-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage) // after an exchange it holds the old directory; after a rename it is gone
	for _, n := range PayloadFiles {
		if err := writeNew(filepath.Join(stage, n), payload[n]); err != nil {
			return err
		}
	}
	if err := writeNew(filepath.Join(stage, ManifestName), manifest); err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	return publishDir(stage, dir, replace)
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
