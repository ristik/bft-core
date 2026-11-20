package seed

import (
	"os"
	"path/filepath"
)

// WriteDir publishes a seed directory: the files are written with exclusive creation into a fresh private staging directory next to dir, and the
// staging directory is renamed to dir, so a reader never sees a mixed directory and an existing symlink at a file name is never followed. dir must
// not exist (replace=false), or is moved aside and removed once the new one is in place (replace=true).
func WriteDir(dir string, payload map[string][]byte, manifest []byte, replace bool) error {
	dir = filepath.Clean(dir)
	if _, err := os.Lstat(dir); err == nil && !replace {
		return refuse("%s already exists (pass --replace to replace it)", dir)
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".seed-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage) // gone after a successful rename
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
	return swapDir(stage, dir)
}

// swapDir puts stage at dir. An existing dir is moved aside first and removed after, restored if the rename fails.
func swapDir(stage, dir string) error {
	var aside string
	if _, err := os.Lstat(dir); err == nil {
		tmp, err := os.MkdirTemp(filepath.Dir(dir), ".seed-old-")
		if err != nil {
			return err
		}
		aside = filepath.Join(tmp, "old")
		if err := os.Rename(dir, aside); err != nil {
			os.RemoveAll(tmp)
			return err
		}
		defer os.RemoveAll(tmp)
	}
	if err := os.Rename(stage, dir); err != nil {
		if aside != "" {
			_ = os.Rename(aside, dir)
		}
		return err
	}
	return nil
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
