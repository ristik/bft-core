package bridgeprofile

import (
	"encoding/binary"
	"math/big"
)

// Encoder: shortest-form heads, definite lengths. The profile uses no maps,
// text strings, floats or booleans.

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

// CUint is a CBOR unsigned integer.
func CUint(n uint64) []byte { return head(0, n) }

// CBytes is a CBOR byte string.
func CBytes(b []byte) []byte { return cat(head(2, uint64(len(b))), b) }

// CTag is a CBOR tag applied to already-encoded content.
func CTag(n uint64, content []byte) []byte { return cat(head(6, n), content) }

// CArr is a CBOR array of already-encoded items.
func CArr(items ...[]byte) []byte { return cat(head(4, uint64(len(items))), cat(items...)) }

// CNull is the CBOR null item.
var CNull = []byte{0xf6}

// CNullOr is null for a nil slice and a byte string otherwise. A non-nil empty
// slice is the empty byte string, so null and empty stay distinct.
func CNullOr(b []byte) []byte {
	if b == nil {
		return CNull
	}
	return CBytes(b)
}

// CAmount encodes an amount as a minimal big-endian byte string; zero is the
// empty string.
func CAmount(a *big.Int) []byte { return CBytes(AmountBytes(a)) }

// AmountBytes is the minimal unsigned big-endian form of a, empty for zero.
func AmountBytes(a *big.Int) []byte { return a.Bytes() }

// Decoder: a strict scanner for the profile's CBOR subset.
const (
	majUint  = 0
	majBytes = 2
	majArray = 4
	majTag   = 6
	majSimp  = 7
)

type item struct {
	major      byte
	arg        uint64
	start, end int
	data       []byte
	kids       []item
	null       bool
}

type scanner struct {
	b      []byte
	pos    int
	tokens int
}

// scanOne scans exactly one item spanning all of b.
func scanOne(b []byte) (*item, error) {
	return scanOneShared(b, new(int))
}

func scanOneShared(b []byte, tokens *int) (*item, error) {
	s := scanner{b: b, tokens: *tokens}
	it, err := s.item(0)
	*tokens = s.tokens
	if err != nil {
		return nil, err
	}
	if s.pos != len(b) {
		return nil, ErrTrailing
	}
	return &it, nil
}

func (s *scanner) head() (major byte, arg uint64, err error) {
	if s.pos >= len(s.b) {
		return 0, 0, ErrTruncated
	}
	ib := s.b[s.pos]
	s.pos++
	major, ai := ib>>5, ib&0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai > 27:
		if ai == 31 {
			return 0, 0, ErrForbiddenCBOR
		}
		return 0, 0, ErrNonCanonical
	}
	n := 1 << (ai - 24)
	if len(s.b)-s.pos < n {
		return 0, 0, ErrTruncated
	}
	for i := 0; i < n; i++ {
		arg = arg<<8 | uint64(s.b[s.pos+i])
	}
	s.pos += n
	if (ai == 24 && arg < 24) || (ai == 25 && arg <= 0xff) || (ai == 26 && arg <= 0xffff) || (ai == 27 && arg <= 0xffffffff) {
		return 0, 0, ErrNonCanonical
	}
	return major, arg, nil
}

func (s *scanner) item(depth int) (item, error) {
	start := s.pos
	if s.tokens++; s.tokens > MaxCBORItems {
		return item{}, ErrTooManyItems
	}
	if s.pos < len(s.b) {
		if mj := s.b[s.pos] >> 5; mj == 3 || mj == 5 || (mj == majSimp && s.b[s.pos] != 0xf6) {
			return item{}, ErrForbiddenCBOR
		}
	}
	major, arg, err := s.head()
	if err != nil {
		return item{}, err
	}
	it := item{major: major, arg: arg, start: start}
	rest := uint64(len(s.b) - s.pos)
	switch major {
	case majUint:
	case majBytes:
		if arg > rest {
			return item{}, ErrTruncated
		}
		it.data = s.b[s.pos : s.pos+int(arg)]
		s.pos += int(arg)
	case majArray, majTag:
		if depth+1 > MaxCBORDepth {
			return item{}, ErrTooDeep
		}
		n := arg
		if major == majTag {
			n = 1
		} else if arg > rest {
			return item{}, ErrTruncated
		}
		it.kids = make([]item, 0, n)
		for i := uint64(0); i < n; i++ {
			kid, err := s.item(depth + 1)
			if err != nil {
				return item{}, err
			}
			it.kids = append(it.kids, kid)
		}
	case majSimp:
		it.null = true
	}
	it.end = s.pos
	return it, nil
}

func (it *item) raw(b []byte) []byte { return b[it.start:it.end] }

func (it *item) isUint() bool  { return it.major == majUint }
func (it *item) isBytes() bool { return it.major == majBytes }
func (it *item) isArray(n int) bool {
	return it.major == majArray && len(it.kids) == n
}

// bytesN returns the payload of a byte string of exactly n bytes.
func (it *item) bytesN(n int) ([]byte, error) {
	if !it.isBytes() {
		return nil, ErrShape
	}
	if len(it.data) != n {
		return nil, ErrLength
	}
	return it.data, nil
}

// tagContent returns the content of a tag with the given number.
func (it *item) tagContent(tag uint64) (*item, error) {
	if it.major != majTag {
		return nil, ErrShape
	}
	if it.arg != tag {
		return nil, ErrTag
	}
	return &it.kids[0], nil
}

// uintMax returns the unsigned value, bounded by max.
func (it *item) uintMax(max uint64) (uint64, error) {
	if !it.isUint() {
		return 0, ErrShape
	}
	if it.arg > max {
		return 0, ErrIntRange
	}
	return it.arg, nil
}

// version checks the literal wire version field.
func (it *item) version() error {
	if !it.isUint() {
		return ErrShape
	}
	if it.arg != WireVersion {
		return ErrVersion
	}
	return nil
}

// amount returns a positive minimal big-endian amount of at most 32 bytes.
func (it *item) amount() (*big.Int, error) {
	if !it.isBytes() {
		return nil, ErrShape
	}
	d := it.data
	if len(d) == 0 || len(d) > MaxAmountBytes || d[0] == 0 {
		return nil, ErrIntRange
	}
	return new(big.Int).SetBytes(d), nil
}
