package archive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleCustodyAcrossRestartAndContext(t *testing.T) {
	request, _ := fixture()
	q := BundleRequest{Context: request.Context, Epoch: 6}
	encoded, err := EncodeBundleRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBundleRequest(encoded)
	if err != nil || decoded.Epoch != q.Epoch {
		t.Fatalf("round trip: %+v %v", decoded, err)
	}
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("authenticated bundle bytes")
	if err := store.PutBundle(q, raw); err != nil {
		t.Fatal(err)
	}
	if err := store.PutBundle(q, raw); err != nil {
		t.Fatal(err)
	}
	if err := store.PutBundle(q, []byte("different")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mutable bundle: %v", err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetBundle(q)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("reopen: %x %v", got, err)
	}
	epochs, err := reopened.BundleEpochs(q.Context)
	if err != nil || len(epochs) != 1 || epochs[0] != 6 {
		t.Fatalf("epochs: %v %v", epochs, err)
	}
	foreign := q
	foreign.Context.ExecutionIdentity = []byte("foreign identity")
	if _, err := reopened.GetBundle(foreign); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign context: %v", err)
	}
	name, _ := bundleName(q)
	file := filepath.Join(dir, name)
	bytesOnDisk, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	bytesOnDisk[len(bytesOnDisk)-1] ^= 1
	if err := os.WriteFile(file, bytesOnDisk, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetBundle(q); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt bundle: %v", err)
	}
}
