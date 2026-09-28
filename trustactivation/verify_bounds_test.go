package trustactivation

import "testing"

func TestProofSizeBoundary(t *testing.T) {
	for _, test := range []struct {
		size int
		want bool
	}{{0, false}, {1, true}, {maxProofBytes, true}, {maxProofBytes + 1, false}} {
		if got := proofSizeAllowed(test.size); got != test.want {
			t.Fatalf("size %d: got %v, want %v", test.size, got, test.want)
		}
	}
}
