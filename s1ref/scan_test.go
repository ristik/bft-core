package s1ref

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func scan(b []byte) error {
	tokens := 0
	_, err := scanOne(b, &tokens)
	return err
}

func TestScannerShortestForms(t *testing.T) {
	for name, b := range map[string][]byte{
		"0x18 below 24":      {0x18, 0x17},
		"0x19 fits one byte": {0x19, 0x00, 0xff},
		"0x1a fits two":      {0x1a, 0x00, 0x00, 0xff, 0xff},
		"0x1b fits four":     {0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff},
		"reserved ai 28":     {0x1c},
		"reserved ai 30":     {0x1e},
		"array length form":  {0x98, 0x01, 0x00},
		"bstr length form":   {0x58, 0x01, 0x00},
		"tag number form":    {0xd8, 0x05, 0x00},
	} {
		if err := scan(b); !errors.Is(err, ErrNonCanonical) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, b := range [][]byte{{0x17}, {0x18, 0x18}, {0x19, 0x01, 0x00}, {0x1a, 0x00, 0x01, 0x00, 0x00}, {0x1b, 0, 0, 0, 1, 0, 0, 0, 0}} {
		if err := scan(b); err != nil {
			t.Errorf("% x: %v", b, err)
		}
	}
}

func TestScannerForbiddenItems(t *testing.T) {
	for name, b := range map[string][]byte{
		"indefinite array": {0x9f, 0xff}, "indefinite bstr": {0x5f, 0xff}, "break": {0xff},
		"false": {0xf4}, "true": {0xf5}, "undefined": {0xf7}, "float16": {0xf9, 0, 0},
		"float32": {0xfa, 0, 0, 0, 0}, "float64": {0xfb, 0, 0, 0, 0, 0, 0, 0, 0}, "simple 16": {0xf8, 0x10},
	} {
		if err := scan(b); !errors.Is(err, ErrForbiddenCBOR) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := scan([]byte{0xf6}); err != nil {
		t.Errorf("null: %v", err)
	}
}

func TestScannerMaps(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"adjacent duplicate":     {[]byte{0xa2, 0x01, 0x00, 0x01, 0x00}, ErrDuplicateMapKey},
		"non-adjacent duplicate": {[]byte{0xa3, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00}, ErrDuplicateMapKey},
		"unsorted":               {[]byte{0xa2, 0x02, 0x00, 0x01, 0x00}, ErrNonCanonical},
		"sorted":                 {[]byte{0xa2, 0x01, 0x00, 0x02, 0x00}, nil},
		"text keys sorted":       {[]byte{0xa2, 0x61, 'a', 0x00, 0x61, 'b', 0x00}, nil},
		"length-first order":     {[]byte{0xa2, 0x61, 'z', 0x00, 0x62, 'a', 'a', 0x00}, nil},
	} {
		if err := scan(tc.in); !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestScannerBounds(t *testing.T) {
	nest := func(n int) []byte {
		b := bytes.Repeat([]byte{0x81}, n)
		return append(b, 0xf6)
	}
	if err := scan(nest(MaxCBORDepth)); err != nil {
		t.Errorf("depth %d: %v", MaxCBORDepth, err)
	}
	if err := scan(nest(MaxCBORDepth + 1)); !errors.Is(err, ErrDepth) {
		t.Errorf("depth %d: %v", MaxCBORDepth+1, err)
	}
	tags := append(bytes.Repeat([]byte{0xc1}, MaxCBORDepth+1), 0x00)
	if err := scan(tags); !errors.Is(err, ErrDepth) {
		t.Errorf("tag depth: %v", err)
	}
	flat := func(n int) []byte {
		b := []byte{0x99, byte(n >> 8), byte(n)}
		return append(b, make([]byte, n)...)
	}
	if err := scan(flat(MaxCBORTokens - 1)); err != nil {
		t.Errorf("%d tokens: %v", MaxCBORTokens, err)
	}
	if err := scan(flat(MaxCBORTokens)); !errors.Is(err, ErrTokens) {
		t.Errorf("%d tokens: %v", MaxCBORTokens+1, err)
	}
	// The token budget is shared across every object of one call.
	tokens := 0
	for i := 0; i < 3; i++ {
		if _, err := scanOne(flat(16000), &tokens); i < 2 && err != nil {
			t.Fatal(err)
		} else if i == 2 && !errors.Is(err, ErrTokens) {
			t.Fatalf("shared budget not enforced: %v", err)
		}
	}
	// Claimed lengths are checked against the remaining input before any allocation.
	for name, b := range map[string][]byte{
		"bstr 2^63":  {0x5b, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"bstr 2^64":  {0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"text 2^32":  {0x7b, 0, 0, 0, 1, 0, 0, 0, 0},
		"array 2^63": {0x9b, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"map 2^63":   {0xbb, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"array 2^32": {0x9a, 0xff, 0xff, 0xff, 0xff},
	} {
		if err := scan(b); !errors.Is(err, ErrTruncated) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestScannerTextAndTrailing(t *testing.T) {
	if err := scan([]byte{0x62, 0xc3, 0x28}); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("invalid UTF-8: %v", err)
	}
	if err := scan([]byte{0x62, 0xc3, 0xa9}); err != nil {
		t.Errorf("valid UTF-8: %v", err)
	}
	if err := scan([]byte{0xf6, 0xf6}); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("trailing: %v", err)
	}
	if err := scan(nil); !errors.Is(err, ErrTruncated) {
		t.Errorf("empty: %v", err)
	}
}

func TestSignatureShape(t *testing.T) {
	// each negative is the named shape refusal, not merely some error; the valid controls are nil
	check := func(what string, err error, ok bool) {
		t.Helper()
		switch {
		case ok && err != nil:
			t.Errorf("%s: valid shape refused: %v", what, err)
		case !ok && !errors.Is(err, ErrSigShape):
			t.Errorf("%s: want ErrSigShape, got %v", what, err)
		}
	}
	for n, ok := range map[int]bool{0: false, 1: false, 63: false, 64: true, 65: true, 66: false, 128: false} {
		check(fmt.Sprintf("length %d", n), sigShape(make([]byte, n)), ok)
	}
	for v, ok := range map[byte]bool{0: true, 1: true, 2: false, 27: false, 255: false} {
		sig := make([]byte, 65)
		sig[64] = v
		check(fmt.Sprintf("v=%d", v), sigShape(sig), ok)
	}
	if err := sigShape(nil); !errors.Is(err, ErrSigShape) {
		t.Errorf("nil: %v", err)
	}
}

func FuzzScan(f *testing.F) {
	for _, s := range [][]byte{{0xf6}, {0x86, 0x01}, {0xa2, 0x01, 0x00, 0x01, 0x00}, {0xd9, 0x98, 0x5d, 0x88}, {0x62, 0xc3, 0x28}, {0x9f, 0xff}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		tokens := 0
		_, err := scanOne(in, &tokens)
		if err != nil && !errors.Is(err, ErrMalformed) {
			t.Fatalf("scan error outside the malformed family: %v", err)
		}
		if tokens > MaxCBORTokens+1 {
			t.Fatalf("token count %d beyond the bound", tokens)
		}
		// Evidence and view admission never panic and never leave the families.
		tokens = 0
		if _, err := scanEvidence(in, &tokens); err != nil && !errors.Is(err, ErrMalformed) {
			t.Fatalf("evidence error outside the malformed family: %v", err)
		}
		tokens = 0
		if _, err := scanView(in, &tokens); err != nil && !errors.Is(err, ErrMalformed) {
			t.Fatalf("view error outside the malformed family: %v", err)
		}
	})
}
