package archive

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func openFiles(t *testing.T, n int) []*os.File {
	t.Helper()
	dir := t.TempDir()
	files := make([]*os.File, n)
	for i := range files {
		f, err := os.Create(filepath.Join(dir, "f"+string(rune('a'+i%26))+string(rune('a'+i/26))))
		if err != nil {
			t.Fatal(err)
		}
		files[i] = f
	}
	return files
}

// bft-core#913: a full batch has hundreds of files; at most MaxConcurrentFileSyncs syncs may be in flight, every file is synced and
// closed once, and the syncs still overlap (a serial loop would pass the bound but lose the shared device flush).
func TestSyncAndCloseAllBoundsConcurrentSyncs(t *testing.T) {
	const n = 416
	files := openFiles(t, n)
	var inFlight, peak, calls atomic.Int64
	s := &Store{disk: &diskOps{
		syncFile: func(f *os.File) error {
			cur := inFlight.Add(1)
			for {
				p := peak.Load()
				if cur <= p || peak.CompareAndSwap(p, cur) {
					break
				}
			}
			calls.Add(1)
			if calls.Load() <= 4*MaxConcurrentFileSyncs {
				time.Sleep(20 * time.Millisecond) // keep the first syncs in flight, so an unbounded start shows in the peak
			}
			inFlight.Add(-1)
			return f.Sync()
		},
		syncDir: syncDir, rename: os.Rename,
	}}
	if err := s.syncAndCloseAll(files); err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got != MaxConcurrentFileSyncs {
		t.Fatalf("peak concurrent syncs %d, want exactly %d", got, MaxConcurrentFileSyncs)
	}
	if calls.Load() != n {
		t.Fatalf("%d syncs, want %d", calls.Load(), n)
	}
	for i, f := range files {
		if err := f.Close(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("file %d not closed by syncAndCloseAll: %v", i, err)
		}
	}
}

// Every failure is still reported, and a failed sync does not stop the others from being synced and closed.
func TestSyncAndCloseAllReportsEveryFailureUnderTheBound(t *testing.T) {
	const n = 50
	files := openFiles(t, n)
	boom := errors.New("sync failed")
	var calls atomic.Int64
	s := &Store{disk: &diskOps{
		syncFile: func(f *os.File) error {
			if calls.Add(1)%10 == 0 {
				return boom
			}
			return f.Sync()
		},
		syncDir: syncDir, rename: os.Rename,
	}}
	err := s.syncAndCloseAll(files)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the sync failure", err)
	}
	if calls.Load() != n {
		t.Fatalf("%d syncs after failures, want %d", calls.Load(), n)
	}
	for i, f := range files {
		if cerr := f.Close(); !errors.Is(cerr, os.ErrClosed) {
			t.Fatalf("file %d left open after a failure: %v", i, cerr)
		}
	}
}

func TestSyncAndCloseAllEmpty(t *testing.T) {
	if err := (&Store{}).syncAndCloseAll(nil); err != nil {
		t.Fatal(err)
	}
}
