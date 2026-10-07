package b1ref

import (
	"bytes"
	"github.com/unicitynetwork/bft-go-base/types"
	"math"
	"math/bits"
	"unicode/utf8"
)

// skip validates deterministic CBOR without building a tree. Map cardinality
// is bounded by the only map in the caller schema, the seal signature map.
func (s *scanner) skip(depth int) error {
	*s.tokens++
	if *s.tokens > MaxCBORTokens {
		return ErrTokens
	}
	if s.pos < len(s.b) && s.b[s.pos]>>5 == majSimp && s.b[s.pos] != cborNull {
		return ErrForbiddenCBOR
	}
	major, arg, err := s.head()
	if err != nil {
		return err
	}
	rest := uint64(len(s.b) - s.pos)
	switch major {
	case majUint, 1:
	case majBytes, majText:
		if arg > rest {
			return ErrTruncated
		}
		data := s.b[s.pos : s.pos+int(arg)]
		s.pos += int(arg)
		if major == majText && !utf8.Valid(data) {
			return ErrInvalidUTF8
		}
	case majArray, majMap, majTag:
		if depth+1 > MaxCBORDepth {
			return ErrDepth
		}
		n := arg
		if major == majTag {
			n = 1
		} else if major == majMap {
			if arg > rest/2 {
				return ErrTruncated
			}
			if arg > MaxSigsPerSeal {
				return ErrTooManySigs
			}
			n = 2 * arg
		} else if arg > rest {
			return ErrTruncated
		}
		var keys [MaxSigsPerSeal][2]int
		for i := uint64(0); i < n; i++ {
			start := s.pos
			if err := s.skip(depth + 1); err != nil {
				return err
			}
			if major == majMap && i%2 == 0 {
				idx := i / 2
				for j := uint64(0); j < idx; j++ {
					if bytes.Equal(s.b[keys[j][0]:keys[j][1]], s.b[start:s.pos]) {
						return ErrDuplicateMapKey
					}
				}
				if idx > 0 && bytes.Compare(s.b[keys[idx-1][0]:keys[idx-1][1]], s.b[start:s.pos]) >= 0 {
					return ErrNonCanonical
				}
				keys[idx] = [2]int{start, s.pos}
			}
		}
	case majSimp:
	default:
		return ErrForbiddenCBOR
	}
	return nil
}

// shapeReader makes a second allocation-free pass over canonical bytes,
// enforcing the native schema and obtaining the metering counters. The generic
// pass runs first so malformed nested depth/tokens always precede semantics.
type shapeReader struct {
	scanner
	err error
}

func (r *shapeReader) h() (byte, uint64) {
	if r.err != nil {
		return 0, 0
	}
	m, n, e := r.head()
	if e != nil {
		r.err = e
	}
	return m, n
}
func (r *shapeReader) array(n uint64) {
	m, v := r.h()
	if r.err == nil && (m != majArray || v != n) {
		r.err = ErrShape
	}
}
func (r *shapeReader) tag(n uint64) {
	m, v := r.h()
	if r.err == nil && (m != majTag || v != n) {
		r.err = ErrShape
	}
}
func (r *shapeReader) uint(max uint64) uint64 {
	m, v := r.h()
	if r.err == nil && (m != majUint || v > max) {
		r.err = ErrShape
	}
	return v
}
func (r *shapeReader) version() {
	if r.uint(math.MaxUint64) != 1 && r.err == nil {
		r.err = ErrVersion
	}
}
func (r *shapeReader) null() bool {
	if r.err == nil && r.pos < len(r.b) && r.b[r.pos] == cborNull {
		r.pos++
		return true
	}
	return false
}
func (r *shapeReader) blob(major byte, min, max uint64, bound error) []byte {
	m, n := r.h()
	if r.err != nil {
		return nil
	}
	if m != major || n < min {
		r.err = ErrShape
		return nil
	}
	if n > max {
		r.err = bound
		return nil
	}
	if n > uint64(len(r.b)-r.pos) {
		r.err = ErrTruncated
		return nil
	}
	v := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return v
}
func (r *shapeReader) hash(nullable bool) {
	if nullable && r.null() {
		return
	}
	r.blob(majBytes, 32, 32, ErrShape)
}
func (r *shapeReader) collection(major byte, max uint64, bound error) uint64 {
	if r.err != nil {
		return 0
	}
	if r.null() {
		return 0
	}
	m, n := r.h()
	if m != major {
		r.err = ErrShape
		return 0
	}
	if n > max {
		r.err = bound
		return 0
	}
	return n
}
func (r *shapeReader) uc() (sigs, steps uint64) {
	r.tag(types.UnicityCertificateTag)
	r.array(7)
	r.version()
	r.tag(types.InputRecordTag)
	r.array(10)
	r.version()
	r.uint(math.MaxUint64)
	r.uint(math.MaxUint64)
	r.hash(true)
	r.hash(false)
	if !r.null() {
		r.blob(majBytes, 0, MaxSummaryBytes, ErrSummaryTooLong)
	}
	r.uint(math.MaxUint64)
	r.hash(true)
	r.uint(math.MaxUint64)
	r.hash(true)
	r.hash(false)
	r.hash(false)
	r.tag(types.ShardTreeCertificateTag)
	r.array(3)
	r.version()
	shard := r.blob(majBytes, 0, MaxShardBytes, ErrShardTooDeep)
	if r.err == nil {
		if err := validateShard(shard); err != nil {
			r.err = err
		}
	}
	n := r.collection(majArray, MaxShardSiblings, ErrTooManySiblings)
	steps += n
	for i := uint64(0); i < n && r.err == nil; i++ {
		r.hash(false)
	}
	r.tag(types.UnicityTreeCertificateTag)
	r.array(3)
	r.version()
	r.uint(math.MaxUint32)
	n = r.collection(majArray, MaxUnicitySteps, ErrTooManySteps)
	steps += n
	for i := uint64(0); i < n && r.err == nil; i++ {
		r.array(2)
		r.uint(math.MaxUint32)
		r.hash(false)
	}
	r.tag(types.UnicitySealTag)
	r.array(8)
	r.version()
	r.uint(math.MaxUint16)
	r.uint(math.MaxUint64)
	r.uint(math.MaxUint64)
	r.uint(math.MaxUint64)
	r.hash(false)
	r.hash(false)
	sigs = r.collection(majMap, MaxSigsPerSeal, ErrTooManySigs)
	for i := uint64(0); i < sigs && r.err == nil; i++ {
		r.blob(majText, 0, MaxNodeIDBytes, ErrNodeIDTooLong)
		sig := r.blob(majBytes, 0, math.MaxUint64, ErrShape)
		if r.err == nil && ((len(sig) != 64 && len(sig) != 65) || (len(sig) == 65 && sig[64] > 1)) {
			r.err = ErrSigFormat
		}
	}
	return
}
func scanCertCall(in []byte, shared bool) (uint64, error) {
	if len(in) > MaxCallBytes {
		return 0, ErrInputTooLarge
	}
	n, err := header(in)
	if err != nil {
		return 0, err
	}
	if n < 1 || n > MaxClaims || (!shared && n != 1) {
		return 0, ErrCount
	}
	r := reader{b: in, pos: 4}
	tokens := 0
	var maxS, steps uint64
	for i := uint16(0); i < n; i++ {
		if _, err := r.u32(); err != nil {
			return 0, err
		}
		sl, err := r.u16()
		if err != nil {
			return 0, err
		}
		if sl > MaxShardBytes {
			return 0, ErrShardTooDeep
		}
		shard, err := r.take(sl)
		if err != nil {
			return 0, err
		}
		if err := validateShard(shard); err != nil {
			return 0, err
		}
		if _, err := r.take(96); err != nil {
			return 0, err
		}
		ul, err := r.u32()
		if err != nil {
			return 0, err
		}
		if ul > MaxUCBytes {
			return 0, ErrUCTooLarge
		}
		raw, err := r.take(ul)
		if err != nil {
			return 0, err
		}
		s := scanner{b: raw, tokens: &tokens}
		if err := s.skip(0); err != nil {
			return 0, err
		}
		if s.pos != len(raw) {
			return 0, ErrTrailingBytes
		}
		sr := shapeReader{scanner: scanner{b: raw}}
		sig, p := sr.uc()
		if sr.err != nil {
			return 0, sr.err
		}
		if sr.pos != len(raw) {
			return 0, ErrShape
		}
		if sig > maxS {
			maxS = sig
		}
		steps += p
	}
	if r.left() != 0 {
		return 0, ErrTrailingBytes
	}
	return UCGas(uint64(len(in)), maxS, uint64(n), steps), nil
}

func validateShard(b []byte) error {
	if len(b) == 0 || b[len(b)-1] == 0 {
		return ErrShardEncoding
	}
	if len(b) > MaxShardBytes || len(b)*8-bits.TrailingZeros8(b[len(b)-1])-1 > MaxShardDepth {
		return ErrShardTooDeep
	}
	return nil
}
