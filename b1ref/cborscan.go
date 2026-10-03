package b1ref

import (
	"bytes"
	"unicode/utf8"
)

// CBOR major types.
const (
	majUint  = 0
	majBytes = 2
	majText  = 3
	majArray = 4
	majMap   = 5
	majTag   = 6
	majSimp  = 7
)

const cborNull = 0xf6

// item is one scanned CBOR data item. kids holds array elements, alternating
// map keys and values, or the single tagged content.
type item struct {
	major      byte
	arg        uint64 // value, length, element count or tag number
	start, end int    // byte range in the scanned buffer
	data       []byte // string payload
	kids       []item
	null       bool
}

// scanner is a strict RFC 8949 core-deterministic scanner. It never allocates
// from a length it has not checked against the remaining input, enforces the
// nesting and token bounds, rejects everything outside the B1 profile
// (floats, simple values other than null, indefinite lengths, non-shortest
// heads, unsorted or duplicate map keys, invalid UTF-8) and reports the first
// violation. tokens is shared across every object of one call.
type scanner struct {
	b      []byte
	pos    int
	tokens *int
}

// scanOne scans exactly one data item spanning all of b.
func scanOne(b []byte, tokens *int) (*item, error) {
	s := scanner{b: b, tokens: tokens}
	it, err := s.item(0)
	if err != nil {
		return nil, err
	}
	if s.pos != len(b) {
		return nil, ErrTrailingBytes
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
			return 0, 0, ErrForbiddenCBOR // indefinite length or break
		}
		return 0, 0, ErrNonCanonical // reserved additional information
	}
	n := 1 << (ai - 24)
	if len(s.b)-s.pos < n {
		return 0, 0, ErrTruncated
	}
	for i := 0; i < n; i++ {
		arg = arg<<8 | uint64(s.b[s.pos+i])
	}
	s.pos += n
	// shortest form: the argument must not fit the next smaller head
	if (ai == 24 && arg < 24) || (ai == 25 && arg <= 0xff) || (ai == 26 && arg <= 0xffff) || (ai == 27 && arg <= 0xffffffff) {
		return 0, 0, ErrNonCanonical
	}
	return major, arg, nil
}

func (s *scanner) item(depth int) (item, error) {
	start := s.pos
	if *s.tokens++; *s.tokens > MaxCBORTokens {
		return item{}, ErrTokens
	}
	if s.pos < len(s.b) && s.b[s.pos]>>5 == majSimp && s.b[s.pos] != cborNull {
		return item{}, ErrForbiddenCBOR // floats, booleans, undefined, break
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
		if major == majText && !utf8.Valid(it.data) {
			return item{}, ErrInvalidUTF8
		}
	case majArray, majMap, majTag:
		if depth+1 > MaxCBORDepth {
			return item{}, ErrDepth
		}
		n := arg
		switch major {
		case majMap:
			if arg > rest/2 {
				return item{}, ErrTruncated
			}
			n = 2 * arg
		case majArray:
			if arg > rest {
				return item{}, ErrTruncated
			}
		case majTag:
			n = 1
		}
		it.kids = make([]item, 0, n)
		for i := uint64(0); i < n; i++ {
			kid, err := s.item(depth + 1)
			if err != nil {
				return item{}, err
			}
			if major == majMap && i%2 == 0 && i > 0 {
				if err := s.checkKeyOrder(it.kids, kid); err != nil {
					return item{}, err
				}
			}
			it.kids = append(it.kids, kid)
		}
	case majSimp:
		it.null = true // only 0xf6 passed the check above
	}
	it.end = s.pos
	return it, nil
}

// checkKeyOrder enforces the core deterministic map order: encoded keys
// strictly increasing bytewise. A key that does not sort after its predecessor
// is a duplicate when it equals any earlier key (adjacent or not) and
// otherwise just out of order.
func (s *scanner) checkKeyOrder(kids []item, key item) error {
	prev := kids[len(kids)-2]
	cmp := bytes.Compare(s.b[prev.start:prev.end], s.b[key.start:key.end])
	if cmp < 0 {
		return nil
	}
	for i := 0; i+1 < len(kids); i += 2 {
		if bytes.Equal(s.b[kids[i].start:kids[i].end], s.b[key.start:key.end]) {
			return ErrDuplicateMapKey
		}
	}
	return ErrNonCanonical
}

func (it *item) isUint() bool { return it.major == majUint }

func (it *item) isArray(n int) bool {
	return it.major == majArray && len(it.kids) == n
}

// isBytes reports a byte string of exactly n bytes.
func (it *item) isBytes(n int) bool { return it.major == majBytes && len(it.data) == n }

// isHash reports a bstr32.
func (it *item) isHash() bool { return it.isBytes(32) }

// isNullOrHash reports a native nullable hash: null or bstr32.
func (it *item) isNullOrHash() bool { return it.null || it.isHash() }

// tagContent returns the content of a tag with the given number.
func (it *item) tagContent(tag uint64) (*item, bool) {
	if it.major != majTag || it.arg != tag {
		return nil, false
	}
	return &it.kids[0], true
}
