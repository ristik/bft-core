package nb2ref

import (
	"encoding/binary"
	"math/big"
)

// Canonical CBOR (section 3), copied from bridgeprofile/cbor.go with the v2 rule names. The encoder writes shortest heads and
// definite lengths. The decoder is a strict scanner: shortest heads, definite lengths, exact arity checked by the callers,
// complete consumption, and no maps, floats, text strings or simple values other than null in any v2 structure. The opaque
// native certificates inside an inclusion proof or a deposit proof are the one exception (native mode admits text strings and
// maps there); their canonical form is the certificate decoder's concern.

const (
	// MaxCBORDepth is the profile's cborDepth bound.
	MaxCBORDepth = 16
	// maxCBORItems bounds the items of one scan. It is not a profile bound, only a guard against allocation; every vector is far
	// below it.
	maxCBORItems = 1 << 20
)

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

// CNullOr is null for a nil slice and a byte string otherwise.
func CNullOr(b []byte) []byte {
	if b == nil {
		return CNull
	}
	return CBytes(b)
}

// AmountBytes is the minimal unsigned big-endian form of a positive amount.
func AmountBytes(a *big.Int) []byte { return a.Bytes() }

// CAmount encodes an Amount: a minimal positive big-endian byte string.
func CAmount(a *big.Int) []byte { return CBytes(AmountBytes(a)) }

const (
	majUint  = 0
	majBytes = 2
	majText  = 3
	majArray = 4
	majMap   = 5
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
	native bool
}

// scanOne scans exactly one strict item spanning all of b.
func scanOne(b []byte) (*item, error) { return scanWith(b, false) }

// scanNative scans one item that may embed a native certificate (text strings and maps admitted).
func scanNative(b []byte) (*item, error) { return scanWith(b, true) }

func scanWith(b []byte, native bool) (*item, error) {
	s := scanner{b: b, native: native}
	it, err := s.item(0)
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
		return 0, 0, ErrNonCanonical // indefinite length (31) or reserved additional information
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
	if s.tokens++; s.tokens > maxCBORItems {
		return item{}, ErrInputTooLarge
	}
	if s.pos < len(s.b) {
		mj := s.b[s.pos] >> 5
		// Forbidden items: negative integers, text strings and maps outside native certificates, floats and every simple value
		// other than null.
		if mj == 1 || (!s.native && (mj == majText || mj == majMap)) || (mj == majSimp && s.b[s.pos] != 0xf6) {
			return item{}, ErrNonCanonical
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
	case majBytes, majText:
		if arg > rest {
			return item{}, ErrTruncated
		}
		it.data = s.b[s.pos : s.pos+int(arg)]
		s.pos += int(arg)
	case majArray, majTag, majMap:
		if depth+1 > MaxCBORDepth {
			return item{}, ErrInputTooLarge
		}
		n := arg
		if major == majTag {
			n = 1
		} else if arg > rest {
			return item{}, ErrTruncated
		} else if major == majMap {
			n = 2 * arg
			if n > rest {
				return item{}, ErrTruncated
			}
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
	default:
		return item{}, ErrNonCanonical
	}
	it.end = s.pos
	return it, nil
}

func (it *item) raw(b []byte) []byte { return b[it.start:it.end] }

func (it *item) isUint() bool  { return it.major == majUint }
func (it *item) isBytes() bool { return it.major == majBytes }

// array requires an array of exactly n items.
func (it *item) array(n int) error {
	if it.major != majArray || len(it.kids) != n {
		return ErrShape
	}
	return nil
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

func (it *item) fixed(dst []byte) error {
	d, err := it.bytesN(len(dst))
	if err != nil {
		return err
	}
	copy(dst, d)
	return nil
}

// bstr returns any byte string.
func (it *item) bstr() ([]byte, error) {
	if !it.isBytes() {
		return nil, ErrShape
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

// uintIn returns an unsigned value in [lo, hi].
func (it *item) uintIn(lo, hi uint64) (uint64, error) {
	if !it.isUint() {
		return 0, ErrShape
	}
	if it.arg < lo || it.arg > hi {
		return 0, ErrIntRange
	}
	return it.arg, nil
}

// version checks a literal version field.
func (it *item) version(want uint64) error {
	if !it.isUint() {
		return ErrShape
	}
	if it.arg != want {
		return ErrVersion
	}
	return nil
}

// literal checks an ASCII domain literal.
func (it *item) literal(s string) error {
	if !it.isBytes() || string(it.data) != s {
		return ErrShape
	}
	return nil
}

// amount reads an Amount: a minimal positive big-endian byte string of 1 to 32 bytes.
func (it *item) amount() (*big.Int, error) {
	if !it.isBytes() {
		return nil, ErrShape
	}
	d := it.data
	if len(d) == 0 {
		return nil, ErrIntRange
	}
	if len(d) > 32 {
		return nil, ErrLength
	}
	if d[0] == 0 {
		return nil, ErrNonCanonical
	}
	return new(big.Int).SetBytes(d), nil
}

// Deadline is the SDK transaction deadline: unset (null) or a u64 in [1, 2^64-1].
type Deadline struct {
	Set bool
	At  uint64
}

// CDeadline is the deadline's CBOR item.
func CDeadline(d Deadline) []byte {
	if !d.Set {
		return CNull
	}
	return CUint(d.At)
}

func (it *item) deadline() (Deadline, error) {
	if it.null {
		return Deadline{}, nil
	}
	v, err := it.uintIn(1, ^uint64(0))
	if err != nil {
		return Deadline{}, err
	}
	return Deadline{Set: true, At: v}, nil
}

func nullableBytes(it *item) ([]byte, error) {
	if it.null {
		return nil, nil
	}
	return it.bstr()
}
