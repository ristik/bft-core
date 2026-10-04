package s1gen

import "encoding/binary"

// The generator's CBOR writer: shortest-form heads and definite lengths (RFC
// 8949 core deterministic for the types S1 uses; no maps are ever produced).

func head(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n < 1<<8:
		return []byte{m | 24, byte(n)}
	case n < 1<<16:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n < 1<<32:
		b := []byte{m | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
	b := []byte{m | 27, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(b[1:], n)
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func cUint(n uint64) []byte  { return head(0, n) }
func cBytes(b []byte) []byte { return cat(head(2, uint64(len(b))), b) }
func cText(s string) []byte  { return cat(head(3, uint64(len(s))), []byte(s)) }
func cTag(n uint64, content []byte) []byte {
	return cat(head(6, n), content)
}
func cArr(items ...[]byte) []byte {
	return cat(head(4, uint64(len(items))), cat(items...))
}

var cNull = []byte{0xf6}

// cNullOr is null for a nil slice and a byte string (possibly empty) otherwise.
func cNullOr(b []byte) []byte {
	if b == nil {
		return cNull
	}
	return cBytes(b)
}
