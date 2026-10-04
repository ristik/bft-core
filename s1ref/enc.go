package s1ref

// Minimal deterministic CBOR writer for the one structure S1 derives itself,
// the conflict identity preimage. Shortest heads, definite lengths.

func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= 0xff:
		return append(b, m|24, byte(n))
	case n <= 0xffff:
		return append(b, m|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		return append(b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendUint(b []byte, n uint64) []byte   { return appendHead(b, 0, n) }
func appendBytes(b, s []byte) []byte         { return append(appendHead(b, 2, uint64(len(s))), s...) }
func appendText(b []byte, s string) []byte   { return append(appendHead(b, 3, uint64(len(s))), s...) }
func appendArrayHead(b []byte, n int) []byte { return appendHead(b, 4, uint64(n)) }
