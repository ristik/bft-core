// Package archivetest writes archives as earlier binaries left them, for the tests of their readers.
package archivetest

import (
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-core/archive"
)

// WriteDirectoryLayout stores a record in an archive directory in the directory layout (before bft-core#1049), as an earlier store published
// it: written to a temporary directory and renamed into place complete. It returns the record directory's name.
func WriteDirectoryLayout(dir string, q archive.Request, rec *archive.Record, variant bool) (string, error) {
	name, files, err := archive.DirectoryLayoutFiles(q, rec, variant)
	if err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(dir, ".writing-")
	if err != nil {
		return "", err
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(tmp, n), b, 0600); err != nil {
			_ = os.RemoveAll(tmp)
			return "", err
		}
	}
	return name, os.Rename(tmp, filepath.Join(dir, name))
}
