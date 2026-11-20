//go:build linux

package seed

import (
	"os"

	"golang.org/x/sys/unix"
)

// exchangeDirs atomically swaps two directories (renameat2 RENAME_EXCHANGE): after it, a is the old b and b the old a, and b is never absent.
// ok is false when the kernel or filesystem does not support it (the caller falls back).
func exchangeDirs(a, b string) (ok bool, err error) {
	switch err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE); err {
	case nil:
		return true, nil
	case unix.ENOSYS, unix.EINVAL, unix.ENOTSUP:
		return false, nil
	default:
		return false, err
	}
}

// canExchange probes, inside home, whether the filesystem supports the atomic exchange a replacement needs.
func canExchange(home string) bool {
	a, err := os.MkdirTemp(home, ".seed-probe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(a)
	b, err := os.MkdirTemp(home, ".seed-probe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(b)
	ok, err := exchangeDirs(a, b)
	return ok && err == nil
}
