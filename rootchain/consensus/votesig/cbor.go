package votesig

import (
	"fmt"
	"unicode/utf8"
)

// encoder is the minimal deterministic CBOR writer: major types 0 (unsigned), 2 (bytes), 3 (text), 4 (array) with the
// shortest head, and simple value null.
type encoder struct{ b []byte }

func (e *encoder) head(major byte, n uint64) *encoder {
	m := major << 5
	switch {
	case n < 24:
		e.b = append(e.b, m|byte(n))
	case n <= 0xff:
		e.b = append(e.b, m|24, byte(n))
	case n <= 0xffff:
		e.b = append(e.b, m|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		e.b = append(e.b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		e.b = append(e.b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return e
}

func (e *encoder) uint(n uint64) *encoder { return e.head(0, n) }
func (e *encoder) array(n int) *encoder   { return e.head(4, uint64(n)) }
func (e *encoder) bytes(b []byte) *encoder {
	e.head(2, uint64(len(b)))
	e.b = append(e.b, b...)
	return e
}
func (e *encoder) text(s string) *encoder {
	e.head(3, uint64(len(s)))
	e.b = append(e.b, s...)
	return e
}
func (e *encoder) null() *encoder { e.b = append(e.b, 0xf6); return e }

// Decode is the strict decoder of the value types the signing objects use: uint64, string, []byte, nil and []any. It
// refuses anything else (tags, floats, maps, indefinite lengths, negative integers), a head that is not the shortest
// encoding, invalid UTF-8 in text, and trailing bytes: a supplied signing object is never normalised into a second
// statement.
func Decode(b []byte) (any, error) {
	v, rest, err := decode(b, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrNotCanonical, len(rest))
	}
	return v, nil
}

func decode(b []byte, depth int) (any, []byte, error) {
	if depth > 8 {
		return nil, nil, fmt.Errorf("%w: nesting too deep", ErrNotCanonical)
	}
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("%w: truncated", ErrNotCanonical)
	}
	if b[0] == 0xf6 {
		return nil, b[1:], nil
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	var n uint64
	switch {
	case info < 24:
		n = uint64(info)
	case info >= 24 && info <= 27:
		size := 1 << (info - 24)
		if len(b) < size {
			return nil, nil, fmt.Errorf("%w: truncated head", ErrNotCanonical)
		}
		for _, c := range b[:size] {
			n = n<<8 | uint64(c)
		}
		b = b[size:]
		if (info == 24 && n < 24) || (info == 25 && n <= 0xff) || (info == 26 && n <= 0xffff) || (info == 27 && n <= 0xffffffff) {
			return nil, nil, fmt.Errorf("%w: head is not the shortest encoding", ErrNotCanonical)
		}
	default:
		return nil, nil, fmt.Errorf("%w: indefinite length or reserved additional information", ErrNotCanonical)
	}
	switch major {
	case 0:
		return n, b, nil
	case 2, 3:
		if uint64(len(b)) < n {
			return nil, nil, fmt.Errorf("%w: truncated string", ErrNotCanonical)
		}
		s := b[:n]
		if major == 2 {
			return append([]byte{}, s...), b[n:], nil
		}
		if !validUTF8(s) {
			return nil, nil, fmt.Errorf("%w: invalid UTF-8", ErrNotCanonical)
		}
		return string(s), b[n:], nil
	case 4:
		if n > 64 {
			return nil, nil, fmt.Errorf("%w: array too long", ErrNotCanonical)
		}
		out := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			var v any
			var err error
			v, b, err = decode(b, depth+1)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, v)
		}
		return out, b, nil
	}
	return nil, nil, fmt.Errorf("%w: unsupported major type %d", ErrNotCanonical, major)
}

func validUTF8(s []byte) bool { return utf8.Valid(s) }

// PeekWrapper reports whether data is the scheme wrapper [2, payload]: a two-item array whose first item is an unsigned
// integer. Every legacy form of a vote, timeout and certificate starts with a different item (a tagged or nested array),
// so the two never overlap. An integer first item other than the canonical 2 is a wrapper of an unknown version
// (ErrScheme) or a non-shortest one (ErrNotCanonical); the scheme is never inferred from a signature length or by trying
// the other verifier.
func PeekWrapper(data []byte) (bool, error) {
	if len(data) < 2 || data[0] != 0x82 || data[1]>>5 != 0 {
		return false, nil
	}
	switch info := data[1] & 0x1f; {
	case info < 24:
		if info == byte(SchemeDomainBound) {
			return true, nil
		}
		return false, fmt.Errorf("%w: unknown wire version %d", ErrScheme, info)
	default:
		return false, fmt.Errorf("%w: wire version is not a one-byte integer", ErrNotCanonical)
	}
}
