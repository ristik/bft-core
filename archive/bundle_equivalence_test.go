package archive

import (
	"bytes"
	"errors"
	"testing"
)

// Two honest copies of one handoff may differ in bytes. The store keeps the first when the caller's comparison says they are the same
// handoff, and refuses a semantically different one with ErrBundleConflict; it never absorbs a difference silently.
func TestPutBundleKeepsTheFirstEquivalentCopyAndRefusesAConflict(t *testing.T) {
	request, _ := fixture()
	q := BundleRequest{Context: request.Context, Epoch: 3}
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, second := []byte("copy one"), []byte("copy two: same handoff, other signatures")
	if stored, err := store.PutBundle(q, first, nil); err != nil || !stored {
		t.Fatal(stored, err)
	}
	equivalent := func(existing, incoming []byte) (bool, error) {
		if !bytes.Equal(existing, first) || !bytes.Equal(incoming, second) {
			t.Fatalf("compared the wrong bytes: %q %q", existing, incoming)
		}
		return true, nil
	}
	stored, err := store.PutBundle(q, second, equivalent)
	if err != nil || stored {
		t.Fatalf("an equivalent copy is a no-op: stored=%v err=%v", stored, err)
	}
	if got, _ := store.GetBundle(q); !bytes.Equal(got, first) {
		t.Fatalf("the first copy is kept: %q", got)
	}

	different := func(_, _ []byte) (bool, error) { return false, nil }
	if _, err := store.PutBundle(q, []byte("a different handoff"), different); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("a semantically different bundle: %v", err)
	}
	if _, err := store.PutBundle(q, []byte("a different handoff"), nil); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("with no comparison any difference is a conflict: %v", err)
	}
	boom := errors.New("comparison failed")
	if _, err := store.PutBundle(q, second, func(_, _ []byte) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Fatalf("a failed comparison is its own error, not a conflict: %v", err)
	}
	if got, _ := store.GetBundle(q); !bytes.Equal(got, first) {
		t.Fatalf("nothing replaced the first copy: %q", got)
	}
}
