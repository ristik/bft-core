package seed

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// seedDir is a seed directory opened ONCE. Every file of one verification or one HTTP request is opened relative to this descriptor, so the files all
// come from the same directory version (a concurrent swap of the path cannot mix two versions), and each component is opened with O_NOFOLLOW: a symlink
// is refused explicitly, whether it is the directory itself or one of the files in it.
type seedDir struct{ fd int }

func openSeedDir(dir string) (*seedDir, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return &seedDir{fd: fd}, nil
}

func (d *seedDir) Close() { _ = unix.Close(d.fd) }

// openRegular opens name (a single path element) relative to the directory: no symlink followed, no blocking on a FIFO or device (O_NONBLOCK), and the
// OPENED descriptor must be a regular file of at most max bytes.
func (d *seedDir) openRegular(name string, max int64) (*os.File, os.FileInfo, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, nil, refuse("%q is not a file name inside the seed directory", name)
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, nil, refuse("%s is a symlink", name)
		}
		return nil, nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, refuse("%s is not a regular file", name)
	}
	if st.Size() > max {
		f.Close()
		return nil, nil, refuse("%s is %d bytes (limit %d)", name, st.Size(), max)
	}
	return f, st, nil
}

// read reads a whole bounded file through openRegular.
func (d *seedDir) read(name string, max int64) ([]byte, error) {
	f, st, err := d.openRegular(name, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != st.Size() {
		return nil, refuse("%s changed while it was read", name)
	}
	return b, nil
}

// readManifest reads and decodes the manifest from this directory version.
func (d *seedDir) readManifest() ([]byte, *Manifest, error) {
	raw, err := d.read(ManifestName, MaxManifestBytes)
	if err != nil {
		return nil, nil, err
	}
	m, err := DecodeManifest(raw)
	return raw, m, err
}
