package bridgeprofile

import (
	"bytes"
	"encoding/hex"
)

// replaceOnce replaces the first occurrence of old in b, panicking when the
// pattern is absent so a vector or test construction cannot silently no-op.
func replaceOnce(b, old, repl []byte) []byte {
	i := bytes.Index(b, old)
	if i < 0 {
		panic("construction: pattern not found")
	}
	return append(append(append([]byte{}, b[:i]...), repl...), b[i+len(old):]...)
}

func hexMust(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func cloneNodes(n [][]byte) [][]byte {
	out := make([][]byte, len(n))
	for i := range n {
		out[i] = bytes.Clone(n[i])
	}
	return out
}
