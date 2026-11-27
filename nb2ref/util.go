package nb2ref

import "encoding/hex"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// addr20 is the first 20 bytes of a hash.
func addr20(h [32]byte) (a [20]byte) { copy(a[:], h[:20]); return }

func hexOf(b []byte) string { return hex.EncodeToString(b) }
