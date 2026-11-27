package archive

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
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
	if stored, err := store.PutBundle(q, raw, nil); err != nil || !stored {
		t.Fatal(stored, err)
	}
	if stored, err := store.PutBundle(q, raw, nil); err != nil || stored {
		t.Fatal(stored, err)
	}
	if _, err := store.PutBundle(q, []byte("different"), nil); !errors.Is(err, ErrBundleConflict) {
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
	file := filepath.Join(dir, bundleDir, name)
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatalf("a new bundle is written to the bundle directory, not the store directory: %v", err)
	}
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

// A store written before the bundle directory keeps its bundles in the store directory (bft-core#1018). They are still read, listed and
// counted as existing, alongside the ones written since.
func TestBundleLegacyLocationIsReadListedAndImmutable(t *testing.T) {
	request, _ := fixture()
	dir := t.TempDir()
	old, now := BundleRequest{Context: request.Context, Epoch: 3}, BundleRequest{Context: request.Context, Epoch: 5}
	legacyRaw := []byte("bundle written by the earlier layout")
	name, err := bundleName(old)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(legacyRaw)
	if err := os.WriteFile(filepath.Join(dir, name), append(digest[:], legacyRaw...), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetBundle(old); err != nil || !bytes.Equal(got, legacyRaw) {
		t.Fatalf("legacy bundle: %q %v", got, err)
	}
	if stored, err := store.PutBundle(old, legacyRaw, nil); err != nil || stored {
		t.Fatalf("the legacy copy is the existing copy: %v %v", stored, err)
	}
	if _, err := store.PutBundle(old, []byte("different"), nil); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("a different bundle under a legacy key: %v", err)
	}
	if epochs, err := store.BundleEpochs(old.Context); err != nil || !slices.Equal(epochs, []uint64{3}) {
		t.Fatalf("epochs before the new bundle: %v %v", epochs, err)
	}
	if stored, err := store.PutBundle(now, []byte("bundle written by this layout"), nil); err != nil || !stored {
		t.Fatal(stored, err)
	}
	if epochs, err := store.BundleEpochs(old.Context); err != nil || !slices.Equal(epochs, []uint64{3, 5}) {
		t.Fatalf("epochs after the new bundle: %v %v", epochs, err)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("the legacy bundle is left where it is: %v", err)
	}
}

// The bundle directory's entry is made durable before a bundle is published in it, and a failed sync of the store directory is retried by
// the next put even though the directory exists by then; once one sync succeeded, no later put syncs the store directory again.
func TestBundleDirectoryEntrySyncIsRetriedUntilItSucceeds(t *testing.T) {
	request, _ := fixture()
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	storeSyncs, failNext := 0, true
	injected := errors.New("injected sync failure")
	store.disk = &diskOps{syncFile: (*os.File).Sync, rename: os.Rename, syncDir: func(dir string) error {
		if dir == store.dir {
			storeSyncs++
			if failNext {
				failNext = false
				return injected
			}
		}
		return syncDir(dir)
	}}
	put := func(epoch uint64) error {
		_, err := store.PutBundle(BundleRequest{Context: request.Context, Epoch: epoch}, []byte("bundle"), nil)
		return err
	}
	if err := put(1); !errors.Is(err, injected) {
		t.Fatalf("the failed sync is returned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.dir, bundleDir)); err != nil {
		t.Fatalf("the directory was made: %v", err)
	}
	if err := put(1); err != nil || storeSyncs != 2 {
		t.Fatalf("the next put syncs the store directory again (%d syncs): %v", storeSyncs, err)
	}
	if err := put(2); err != nil || storeSyncs != 2 {
		t.Fatalf("after one successful sync none follows (%d syncs): %v", storeSyncs, err)
	}
	if epochs, err := store.BundleEpochs(request.Context); err != nil || !slices.Equal(epochs, []uint64{1, 2}) {
		t.Fatalf("epochs: %v %v", epochs, err)
	}
}
