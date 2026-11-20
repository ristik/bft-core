//go:build linux

package seed

import "golang.org/x/sys/unix"

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
