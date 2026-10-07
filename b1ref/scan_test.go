package b1ref

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
)

func scan(b []byte) (*item, error) {
	tokens := 0
	return scanOne(b, &tokens)
}

func nest(n int, leaf byte) []byte { return append(bytes.Repeat([]byte{0x81}, n), leaf) }

func TestScanHeads(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
		want error
	}{
		{"uint 23", []byte{0x17}, nil},
		{"uint 24 shortest", []byte{0x18, 0x18}, nil},
		{"uint 255 shortest", []byte{0x18, 0xff}, nil},
		{"uint 256 shortest", []byte{0x19, 0x01, 0x00}, nil},
		{"uint 65536 shortest", []byte{0x1a, 0x00, 0x01, 0x00, 0x00}, nil},
		{"uint 2^32 shortest", []byte{0x1b, 0, 0, 0, 1, 0, 0, 0, 0}, nil},
		{"uint 5 in 1 byte", []byte{0x18, 0x05}, ErrNonCanonical},
		{"uint 23 in 1 byte", []byte{0x18, 0x17}, ErrNonCanonical},
		{"uint 255 in 2 bytes", []byte{0x19, 0x00, 0xff}, ErrNonCanonical},
		{"uint 65535 in 4 bytes", []byte{0x1a, 0x00, 0x00, 0xff, 0xff}, ErrNonCanonical},
		{"uint 2^32-1 in 8 bytes", []byte{0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, ErrNonCanonical},
		{"reserved info 28", []byte{0x1c}, ErrNonCanonical},
		{"indefinite array", []byte{0x9f, 0xff}, ErrForbiddenCBOR},
		{"indefinite bytes", []byte{0x5f, 0xff}, ErrForbiddenCBOR},
		{"break", []byte{0xff}, ErrForbiddenCBOR},
		{"false", []byte{0xf4}, ErrForbiddenCBOR},
		{"true", []byte{0xf5}, ErrForbiddenCBOR},
		{"undefined", []byte{0xf7}, ErrForbiddenCBOR},
		{"half float", []byte{0xf9, 0, 0}, ErrForbiddenCBOR},
		{"single float", []byte{0xfa, 0, 0, 0, 0}, ErrForbiddenCBOR},
		{"negative integer", []byte{0x20}, nil}, // scanned; the shape rules reject it
		{"null", []byte{0xf6}, nil},
		{"empty", nil, ErrTruncated},
		{"cut head", []byte{0x19, 0x01}, ErrTruncated},
		{"trailing", []byte{0x01, 0x01}, ErrTrailingBytes},
		{"bytes past end", []byte{0x42, 0x01}, ErrTruncated},
		{"text not utf8", []byte{0x62, 0xc3, 0x28}, ErrInvalidUTF8},
		{"map duplicate key", []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02}, ErrDuplicateMapKey},
		{"map key order", []byte{0xa2, 0x61, 'b', 0x01, 0x61, 'a', 0x02}, ErrNonCanonical},
		{"map key order, distant duplicate", []byte{0xa3, 0x61, 'a', 0x01, 0x61, 'b', 0x02, 0x61, 'a', 0x03}, ErrDuplicateMapKey},
		{"map length-first order", []byte{0xa2, 0x61, 'z', 0x01, 0x62, 'a', 'a', 0x02}, nil},
		{"map shorter key after longer", []byte{0xa2, 0x62, 'a', 'a', 0x01, 0x61, 'z', 0x02}, ErrNonCanonical},
	} {
		if _, err := scan(c.in); !errors.Is(err, c.want) && !(c.want == nil && err == nil) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

func TestScanDepth(t *testing.T) {
	if _, err := scan(nest(MaxCBORDepth, 0xf6)); err != nil {
		t.Fatalf("depth %d must pass: %v", MaxCBORDepth, err)
	}
	if _, err := scan(nest(MaxCBORDepth+1, 0xf6)); !errors.Is(err, ErrDepth) {
		t.Fatalf("depth %d: %v", MaxCBORDepth+1, err)
	}
	// tags and maps count as containers too.
	tags := append(bytes.Repeat([]byte{0xd9, 0x98, 0x59}, MaxCBORDepth+1), 0xf6)
	if _, err := scan(tags); !errors.Is(err, ErrDepth) {
		t.Fatalf("tag nesting: %v", err)
	}
	maps := append(bytes.Repeat([]byte{0xa1, 0x61, 'a'}, MaxCBORDepth+1), 0xf6)
	if _, err := scan(maps); !errors.Is(err, ErrDepth) {
		t.Fatalf("map nesting: %v", err)
	}
}

func TestScanTokenBound(t *testing.T) {
	in := append([]byte{0x99, 0x9c, 0x40}, bytes.Repeat([]byte{0xf6}, 40000)...) // array of 40000 nulls
	if _, err := scan(in); !errors.Is(err, ErrTokens) {
		t.Fatalf("40000 tokens: %v", err)
	}
	ok := append([]byte{0x99, 0x7f, 0xfe}, bytes.Repeat([]byte{0xf6}, 32766)...) // 1 + 32766 tokens
	if _, err := scan(ok); err != nil {
		t.Fatalf("32767 tokens: %v", err)
	}
	// the budget is shared across the objects of a call.
	tokens := MaxCBORTokens - 1
	if _, err := scanOne([]byte{0x82, 0xf6, 0xf6}, &tokens); !errors.Is(err, ErrTokens) {
		t.Fatalf("shared budget: %v", err)
	}
}

// TestScanClaimedLengthsDoNotAllocate: a head claiming an enormous count must
// fail on the remaining-input check without allocating from it.
func TestScanClaimedLengthsDoNotAllocate(t *testing.T) {
	max8 := bytes.Repeat([]byte{0xff}, 8)
	for _, head := range []byte{0x5b, 0x7b, 0x9b, 0xbb} { // bytes, text, array, map
		in := append([]byte{head}, max8...)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := scan(in)
		runtime.ReadMemStats(&after)
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("head %#x: %v", head, err)
		}
		if grown := after.TotalAlloc - before.TotalAlloc; grown > 4096 {
			t.Fatalf("head %#x allocated %d bytes", head, grown)
		}
	}
}

func TestUCGasMaximum(t *testing.T) {
	if g := UCGas(MaxCallBytes, MaxSigsPerSeal, MaxClaims, MaxClaims*(MaxShardSiblings+MaxUnicitySteps)); g != 6_412_004 {
		t.Fatalf("%d", g)
	}
	if MaxRSMTInputBytes != 12392 {
		t.Fatalf("%d", MaxRSMTInputBytes)
	}
}

// FuzzScan: whatever the bytes, the scanner either rejects with a malformed
// reason or returns a tree within the depth and token bounds that spans the
// whole input.
func FuzzScan(f *testing.F) {
	for _, s := range [][]byte{{0xf6}, {0x82, 0x01, 0x02}, {0xa1, 0x61, 'a', 0x41, 0x00}, nest(16, 0xf6), nest(17, 0xf6), {0xd9, 0x98, 0x59, 0x80}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		tokens := 0
		it, err := scanOne(in, &tokens)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("non-malformed scan error %v", err)
			}
			return
		}
		if tokens > MaxCBORTokens || it.start != 0 || it.end != len(in) {
			t.Fatalf("tokens=%d span=[%d,%d) len=%d", tokens, it.start, it.end, len(in))
		}
		var walk func(*item, int) int
		walk = func(x *item, depth int) int {
			n := 1
			if len(x.kids) > 0 {
				depth++
			}
			if depth > MaxCBORDepth {
				t.Fatalf("depth %d admitted", depth)
			}
			for i := range x.kids {
				n += walk(&x.kids[i], depth)
			}
			return n
		}
		if n := walk(it, 0); n != tokens {
			t.Fatalf("walked %d items, counted %d tokens", n, tokens)
		}
	})
}
