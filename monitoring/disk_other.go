//go:build !unix

package monitoring

import "errors"

func statfs(string) (uint64, uint64, error) {
	return 0, 0, errors.New("disk statistics are not available on this platform")
}
