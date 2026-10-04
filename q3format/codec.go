// Package q3format is the inactive Q3 format and history layer (briefs/q3-design-v2.md section 6, slice B): the V3 protocol
// tuple and trust-base body with their predecessor and version codecs, candidate-bound readiness receipts, the explicit
// per-epoch history resolver, activation minted only from a verified committed record, and the bounded proof envelope.
// Nothing in production imports it yet; Rust vectors follow with C2.
//
// Every value is deterministic CBOR (RFC 8949 section 4.2.1) built from unsigned integers, byte strings, text strings,
// definite arrays and null only. Decoding refuses everything else, and anything that does not re-encode to the same bytes.
package q3format

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrFormat is returned for malformed, truncated, noncanonical or trailing-garbage input, and for a field of the wrong kind.
	ErrFormat = errors.New("q3format: malformed or noncanonical encoding")
	// ErrTooLarge is returned when an encoding or a counted field exceeds its bound; it is checked before any allocation.
	ErrTooLarge = errors.New("q3format: size or count limit exceeded")
	// ErrVersion is returned for an unknown or unsupported version or domain.
	ErrVersion = errors.New("q3format: unknown or unsupported version")
)

var decMode = func() cbor.DecMode {
	// Indefinite lengths need no option: they re-encode as definite lengths and so fail the canonical comparison in parse.
	m, err := cbor.DecOptions{MaxNestedLevels: 8, MaxArrayElements: 1024, MaxMapPairs: 16,
		TagsMd: cbor.TagsForbidden, DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// enc is the canonical encoding of an array of the supported kinds (uint64, []byte, string, nil, nested []any).
func enc(items ...any) []byte {
	b, err := types.Cbor.Marshal(items)
	if err != nil {
		panic(fmt.Sprintf("q3format: encoding unsupported value: %v", err)) // a programming error, never input-dependent
	}
	return b
}

// parse decodes one canonical array of at most limit bytes into a reader.
func parse(raw []byte, limit int) (*reader, error) {
	if len(raw) > limit {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(raw), limit)
	}
	var v any
	if err := decMode.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if again, err := types.Cbor.Marshal(v); err != nil || !bytes.Equal(again, raw) {
		return nil, fmt.Errorf("%w: not the canonical encoding", ErrFormat)
	}
	return newReader(v, -1)
}

// reader walks one decoded array; the first failure is sticky and every later read returns the zero value.
type reader struct {
	items []any
	next  int
	err   error
}

// newReader requires v to be an array, of exactly n items unless n is negative.
func newReader(v any, n int) (*reader, error) {
	a, ok := v.([]any)
	if !ok || (n >= 0 && len(a) != n) {
		return nil, fmt.Errorf("%w: expected an array of %d items", ErrFormat, n)
	}
	return &reader{items: a}, nil
}

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *reader) take() any {
	if r.err != nil {
		return nil
	}
	if r.next >= len(r.items) {
		r.fail(fmt.Errorf("%w: truncated", ErrFormat))
		return nil
	}
	r.next++
	return r.items[r.next-1]
}

func (r *reader) uint() uint64 {
	v, ok := r.take().(uint64)
	if !ok {
		r.fail(fmt.Errorf("%w: expected an unsigned integer", ErrFormat))
	}
	return v
}

// bytes reads a byte string of exactly size bytes, or of at most max bytes when size is negative.
func (r *reader) bytes(size, max int) []byte {
	v, ok := r.take().([]byte)
	switch {
	case r.err != nil:
	case !ok:
		r.fail(fmt.Errorf("%w: expected a byte string", ErrFormat))
	case size >= 0 && len(v) != size:
		r.fail(fmt.Errorf("%w: byte string of %d, want %d", ErrFormat, len(v), size))
	case size < 0 && len(v) > max:
		r.fail(fmt.Errorf("%w: byte string of %d, limit %d", ErrTooLarge, len(v), max))
	}
	return v
}

func (r *reader) text(max int) string {
	v, ok := r.take().(string)
	switch {
	case r.err != nil:
	case !ok:
		r.fail(fmt.Errorf("%w: expected a text string", ErrFormat))
	case len(v) > max:
		r.fail(fmt.Errorf("%w: text of %d, limit %d", ErrTooLarge, len(v), max))
	}
	return v
}

// optBytes reads a byte string or null (nil).
func (r *reader) optBytes(max int) []byte {
	if r.err == nil && r.next < len(r.items) && r.items[r.next] == nil {
		r.next++
		return nil
	}
	return r.bytes(-1, max)
}

// array reads a nested array of at most max items.
func (r *reader) array(max int) *reader {
	a, ok := r.take().([]any)
	switch {
	case r.err != nil:
	case !ok:
		r.fail(fmt.Errorf("%w: expected an array", ErrFormat))
	case len(a) > max:
		r.fail(fmt.Errorf("%w: %d items, limit %d", ErrTooLarge, len(a), max))
	}
	return &reader{items: a, err: r.err}
}

// sub reads a nested array of exactly n items.
func (r *reader) sub(n int) *reader {
	s := r.array(1024) // the decoder's own bound; the arity is checked next
	if r.err == nil && len(s.items) != n {
		r.fail(fmt.Errorf("%w: %d items, want %d", ErrFormat, len(s.items), n))
	}
	return s
}

func (r *reader) len() int { return len(r.items) }

// expect checks the domain text of the first item.
func (r *reader) expect(domain string) {
	if got := r.text(len(domain)); r.err == nil && got != domain {
		r.fail(fmt.Errorf("%w: domain %q, want %q", ErrVersion, got, domain))
	}
}

// done reports the sticky failure, or trailing items.
func (r *reader) done() error {
	if r.err == nil && r.next != len(r.items) {
		r.fail(fmt.Errorf("%w: %d trailing items", ErrFormat, len(r.items)-r.next))
	}
	return r.err
}
