//go:build unix

package monitoring

import "syscall"

// statfs returns the free (to an unprivileged user) and total bytes of the filesystem holding path.
func statfs(path string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err = syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)                                        // #nosec G115 -- a block size is positive
	return uint64(st.Bavail) * bsize, uint64(st.Blocks) * bsize, nil // #nosec G115 -- counts are unsigned or small
}
