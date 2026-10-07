package b1gen_test

import (
	"bytes"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"os"
	"testing"
)

// Pin the independent generator itself so mutation checks in this package
// cannot silently change published request bytes, verdicts or gas counters.
func TestPublishedManifest(t *testing.T) {
	expected, err := os.ReadFile("../testdata/b1-vectors-aprime.json")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := b1gen.Build("b1-oracle-v1").JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, actual) {
		t.Fatal("published independent vector manifest changed")
	}
}
