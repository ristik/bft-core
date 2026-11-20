//go:build !linux

package seed

// exchangeDirs has no atomic exchange off Linux: the caller moves the old directory aside instead.
func exchangeDirs(a, b string) (bool, error) { return false, nil }
