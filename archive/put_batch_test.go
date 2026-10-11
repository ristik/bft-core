package archive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// batchFixture is n distinct valid records of the fixture's context.
func batchFixture(t *testing.T, n int) ([]Request, []*Record) {
	t.Helper()
	qs, recs := make([]Request, n), make([]*Record, n)
	for i := range qs {
		q, r := fixture()
		r.Header = append(bytes.Clone(r.Header), byte(i))
		q.BlockHash = [32]byte(crypto.Keccak256(r.Header))
		// a certificate the round index can read: it names this block at round i+1
		uc, err := types.Cbor.Marshal(&types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1, RoundNumber: uint64(i + 1), BlockHash: q.BlockHash[:]}})
		if err != nil {
			t.Fatal(err)
		}
		r.ResultingUC = uc
		qs[i], recs[i] = q, r
	}
	return qs, recs
}

// leftovers lists the store directory's temporary directories.
func leftovers(t *testing.T, s *Store) (out []string) {
	t.Helper()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".writing-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestPutBatchStoresEveryRecordAsPutDoes(t *testing.T) {
	qs, recs := batchFixture(t, 5)
	batched, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	single, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := batched.PutBatch(qs, recs); err != nil {
		t.Fatal(err)
	}
	for i := range qs {
		if err := single.Put(qs[i], recs[i]); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := Open(batched.dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range qs {
		got, err := reopened.Get(qs[i])
		if err != nil {
			t.Fatalf("record %d after reopen: %v", i, err)
		}
		want, err := single.Get(qs[i])
		if err != nil {
			t.Fatal(err)
		}
		a, _ := EncodeResponse(Response{qs[i], OK, got})
		b, _ := EncodeResponse(Response{qs[i], OK, want})
		if !bytes.Equal(a, b) {
			t.Fatalf("record %d differs between PutBatch and Put", i)
		}
		// the on-disk form is the same too: same directory name, same manifest bytes
		loc, _ := location(qs[i], recordV2(recs[i]))
		ma, err := os.ReadFile(batched.dir + "/" + loc + "/manifest")
		if err != nil {
			t.Fatal(err)
		}
		mb, err := os.ReadFile(single.dir + "/" + loc + "/manifest")
		if err != nil || !bytes.Equal(ma, mb) {
			t.Fatalf("record %d: manifests differ (%v)", i, err)
		}
	}
	if left := leftovers(t, batched); len(left) != 0 {
		t.Fatalf("temporary directories left: %v", left)
	}
}

func TestPutBatchBounds(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	qs, recs := batchFixture(t, MaxPutBatch+1)
	for name, call := range map[string]func() error{
		"empty":           func() error { return s.PutBatch(nil, nil) },
		"length mismatch": func() error { return s.PutBatch(qs[:2], recs[:1]) },
		"over the bound":  func() error { return s.PutBatch(qs, recs) },
	} {
		if err := call(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := s.PutBatch(qs[:MaxPutBatch], recs[:MaxPutBatch]); err != nil {
		t.Fatalf("a full batch: %v", err)
	}
}

// A fault before any publication publishes nothing of the batch; a fault between two publications leaves the published ones whole
// and the rest absent; in both cases the batch can be put again and no temporary directory survives the call.
func TestPutBatchFaultsPublishOnlyWholeRecords(t *testing.T) {
	fault := errors.New("injected")
	for _, tc := range []struct {
		name      string
		point     string
		failOn    int // the n-th hit of the point fails (1-based)
		published int
	}{
		{"while the chunks of the second record are written", "after-chunk", 12, 0},
		{"before the first publication", "before-publish", 1, 0},
		{"before the third publication", "before-publish", 3, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			qs, recs := batchFixture(t, 4)
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			hits := 0
			s.Fault = func(point string) error {
				if point == tc.point {
					if hits++; hits == tc.failOn {
						return fault
					}
				}
				return nil
			}
			if err := s.PutBatch(qs, recs); !errors.Is(err, fault) {
				t.Fatalf("fault ignored: %v", err)
			}
			s.Fault = nil
			if left := leftovers(t, s); len(left) != 0 {
				t.Fatalf("temporary directories left after the failed batch: %v", left)
			}
			published := 0
			for i := range qs {
				got, err := s.Get(qs[i])
				switch {
				case err == nil:
					published++
					if !bytes.Equal(got.Header, recs[i].Header) {
						t.Fatalf("record %d published changed", i)
					}
				case !errors.Is(err, ErrUnavailable):
					t.Fatalf("record %d is neither whole nor absent: %v", i, err)
				}
			}
			if published != tc.published {
				t.Fatalf("%d records published, want %d", published, tc.published)
			}
			if err := s.PutBatch(qs, recs); err != nil {
				t.Fatalf("putting the batch again: %v", err)
			}
			for i := range qs {
				if _, err := s.Get(qs[i]); err != nil {
					t.Fatalf("record %d after the second put: %v", i, err)
				}
			}
		})
	}
}

func TestPutBatchExistingAndRepeatedRecords(t *testing.T) {
	qs, recs := batchFixture(t, 3)
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(qs[0], recs[0]); err != nil {
		t.Fatal(err)
	}
	// the stored record again, and one record twice in the batch: both are the same bytes, so the batch is accepted
	if err := s.PutBatch([]Request{qs[0], qs[1], qs[1], qs[2]}, []*Record{recs[0], recs[1], recs[1], recs[2]}); err != nil {
		t.Fatal(err)
	}
	// a stored record with other content is refused, and so is a record that differs from its earlier copy in the same batch
	changed := *recs[0]
	changed.Body = []byte("changed")
	if err := s.PutBatch([]Request{qs[0]}, []*Record{&changed}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a changed stored record: %v", err)
	}
	fresh, freshRecs := batchFixture(t, 5)
	other := *freshRecs[4]
	other.Body = []byte("changed")
	if err := s.PutBatch([]Request{fresh[4], fresh[4]}, []*Record{freshRecs[4], &other}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a record that differs from its copy in the batch: %v", err)
	}
	if _, err := s.Get(fresh[4]); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a refused batch published a record: %v", err)
	}
	if left := leftovers(t, s); len(left) != 0 {
		t.Fatalf("temporary directories left: %v", left)
	}
}

// indexedCount is how many records the store's round index holds.
func indexedCount(s *Store) (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, byRound := range s.rounds {
		for _, reqs := range byRound {
			n += len(reqs)
		}
	}
	return n
}

// opLog records the disk operations of a put in the order they RETURN, through the store's own seam, and can fail the n-th of a kind.
type opLog struct {
	mu     sync.Mutex
	events []string
	failOn map[string]int // kind -> which occurrence fails (1-based)
	seen   map[string]int
}

var errInjected = errors.New("injected disk failure")

func (l *opLog) do(kind, storeDir, path string, real func() error) error {
	l.mu.Lock()
	if l.seen == nil {
		l.seen = map[string]int{}
	}
	if kind == "sync-dir" && path == storeDir {
		kind = "sync-store"
	}
	l.seen[kind]++
	fail := l.failOn[kind] == l.seen[kind]
	l.mu.Unlock()
	var err error
	if fail {
		err = errInjected
	} else {
		err = real()
	}
	l.mu.Lock()
	if err == nil {
		l.events = append(l.events, kind)
	} else {
		l.events = append(l.events, kind+" FAILED")
	}
	l.mu.Unlock()
	return err
}

func (l *opLog) install(s *Store) {
	s.disk = &diskOps{
		syncFile: func(f *os.File) error { return l.do("sync-file", s.dir, f.Name(), f.Sync) },
		syncDir:  func(dir string) error { return l.do("sync-dir", s.dir, dir, func() error { return syncDir(dir) }) },
		rename: func(from, to string) error {
			return l.do("rename", s.dir, to, func() error { return os.Rename(from, to) })
		},
	}
}

func (l *opLog) count(kind string) (n int) {
	for _, e := range l.events {
		if e == kind {
			n++
		}
	}
	return n
}

func (l *opLog) first(kind string) int { return slices.Index(l.events, kind) }
func (l *opLog) last(kind string) int {
	for i := len(l.events) - 1; i >= 0; i-- {
		if l.events[i] == kind {
			return i
		}
	}
	return -1
}

// The durability rule of a put, observed: every file of every record is synced before any temporary directory is, every temporary
// directory before any record is published by its rename, and the store directory after the last rename and before the put returns.
// Each file, each directory and the store are synced exactly once; nothing is skipped.
func TestPutBatchSyncsFilesThenDirectoriesThenPublishesThenSyncsTheStore(t *testing.T) {
	const n = 4
	qs, recs := batchFixture(t, n)
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := &opLog{}
	log.install(s)
	if err := s.PutBatch(qs, recs); err != nil {
		t.Fatal(err)
	}
	fields, _ := allFields(recs[0])
	filesPerRecord := len(fields) + 1 // the chunks and the manifest
	if got := log.count("sync-file"); got != n*filesPerRecord {
		t.Fatalf("%d file syncs, want %d (every chunk and manifest of every record): %v", got, n*filesPerRecord, log.events)
	}
	if got := log.count("sync-dir"); got != n {
		t.Fatalf("%d temporary-directory syncs, want %d", got, n)
	}
	if got := log.count("rename"); got != n {
		t.Fatalf("%d renames, want %d", got, n)
	}
	if got := log.count("sync-store"); got != 1 {
		t.Fatalf("%d store-directory syncs, want 1", got)
	}
	if log.last("sync-file") > log.first("sync-dir") {
		t.Fatalf("a temporary directory was synced before every file was: %v", log.events)
	}
	if log.last("sync-dir") > log.first("rename") {
		t.Fatalf("a record was published before every temporary directory was synced: %v", log.events)
	}
	if log.last("rename") > log.first("sync-store") {
		t.Fatalf("the store directory was synced before the last publication: %v", log.events)
	}
	if log.events[len(log.events)-1] != "sync-store" || len(log.events) != n*filesPerRecord+2*n+1 {
		t.Fatalf("the put did not end with the store directory's sync, or did something else: %v", log.events)
	}

	// a single Put is the same sequence for one record
	one := &opLog{}
	q, r := fixture()
	single, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	one.install(single)
	if err := single.Put(q, r); err != nil {
		t.Fatal(err)
	}
	want := append(slices.Repeat([]string{"sync-file"}, filesPerRecord), "sync-dir", "rename", "sync-store")
	if !slices.Equal(one.events, want) {
		t.Fatalf("Put: %v, want %v", one.events, want)
	}
}

// A failed sync is never ignored. A file or temporary-directory sync that fails publishes nothing and the put returns the failure;
// a failed store-directory sync is returned too (the records are renamed by then, and the caller is told they are not durable).
func TestPutBatchReturnsAFailedSyncAndPublishesNothingBeforeIt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kind       string
		occurrence int
		published  int
	}{
		{"the first file sync", "sync-file", 1, 0},
		{"a file sync of the last record", "sync-file", 4*11 - 1, 0},
		{"the first temporary-directory sync", "sync-dir", 1, 0},
		{"the last temporary-directory sync", "sync-dir", 4, 0},
		{"the store-directory sync", "sync-store", 1, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			qs, recs := batchFixture(t, 4)
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			s.rounds = map[string]map[uint64][]Request{} // the round index is on
			log := &opLog{failOn: map[string]int{tc.kind: tc.occurrence}}
			log.install(s)
			if err := s.PutBatch(qs, recs); !errors.Is(err, errInjected) {
				t.Fatalf("the failed %s was not returned: %v", tc.kind, err)
			}
			if got := log.count("rename"); got != tc.published {
				t.Fatalf("%d records published, want %d: %v", got, tc.published, log.events)
			}
			if tc.published == 0 && log.count("sync-store") != 0 {
				t.Fatalf("the store directory was synced although nothing was to be published: %v", log.events)
			}
			if left := leftovers(t, s); len(left) != 0 {
				t.Fatalf("temporary directories left: %v", left)
			}
			if indexed := indexedCount(s); indexed != 0 {
				t.Fatalf("%d records indexed by a put that did not return nil", indexed)
			}
			// with the disk working again the same batch goes through
			s.disk = nil
			if err := s.PutBatch(qs, recs); err != nil {
				t.Fatalf("putting the batch again: %v", err)
			}
		})
	}
}

// A rename that fails part way through a batch: the records published before it are made durable (the store directory is synced)
// and indexed before the error is returned, and the rest are absent and can be put again.
func TestPutBatchMakesAPartlyPublishedBatchDurableBeforeReturningTheError(t *testing.T) {
	qs, recs := batchFixture(t, 4)
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.rounds = map[string]map[uint64][]Request{} // the round index is on
	log := &opLog{failOn: map[string]int{"rename": 3}}
	log.install(s)
	if err := s.PutBatch(qs, recs); !errors.Is(err, errInjected) {
		t.Fatalf("the failed rename was not returned: %v", err)
	}
	if log.count("rename") != 2 || log.count("sync-store") != 1 || log.last("rename") > log.first("sync-store") {
		t.Fatalf("two records published, then the store directory synced, is what must have happened: %v", log.events)
	}
	if indexed := indexedCount(s); indexed != 2 {
		t.Fatalf("%d records indexed, want the 2 that were published", indexed)
	}
	for i := range qs {
		_, err := s.Get(qs[i])
		if (i < 2) != (err == nil) || (i >= 2 && !errors.Is(err, ErrUnavailable)) {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if left := leftovers(t, s); len(left) != 0 {
		t.Fatalf("temporary directories left: %v", left)
	}
	s.disk = nil
	if err := s.PutBatch(qs, recs); err != nil {
		t.Fatalf("putting the batch again: %v", err)
	}
	if indexed := indexedCount(s); indexed != 4 {
		t.Fatalf("%d records indexed after the second put, want 4", indexed)
	}
}

// A put writes and syncs its files without the store's lock: a read of another record does not wait for them.
func TestGetDoesNotWaitForAPutsFileSyncs(t *testing.T) {
	qs, recs := batchFixture(t, 2)
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(qs[0], recs[0]); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.disk = &diskOps{
		syncFile: func(f *os.File) error { once.Do(func() { close(entered) }); <-release; return f.Sync() },
		syncDir:  syncDir, rename: os.Rename,
	}
	putDone := make(chan error, 1)
	go func() { putDone <- s.Put(qs[1], recs[1]) }()
	<-entered // the put is inside its file syncs and stays there

	got := make(chan error, 1)
	go func() { _, err := s.Get(qs[0]); got <- err }()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("reading a stored record during another record's put: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Get waited for a put that is syncing its files")
	}
	if _, err := s.Get(qs[1]); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the record being put is not readable yet: %v", err)
	}
	close(release)
	if err := <-putDone; err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(qs[1]); err != nil {
		t.Fatal(err)
	}
}

// The publication still happens under the lock: between a record's rename and the store directory's sync no reader sees it, so
// nothing is read back that a crash could still lose.
func TestARecordIsNotReadableBeforeTheStoreDirectoryIsSynced(t *testing.T) {
	q, r := fixture()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	renamed, release := make(chan struct{}), make(chan struct{})
	s.disk = &diskOps{
		syncFile: (*os.File).Sync,
		syncDir: func(dir string) error {
			if dir == s.dir {
				close(renamed) // the store directory is synced after the rename: the record is in place, not yet durable
				<-release
			}
			return syncDir(dir)
		},
		rename: os.Rename,
	}
	putDone := make(chan error, 1)
	go func() { putDone <- s.Put(q, r) }()
	<-renamed
	read := make(chan error, 1)
	go func() { _, err := s.Get(q); read <- err }()
	select {
	case err := <-read:
		t.Fatalf("Get returned (%v) while the publication was not durable", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-putDone; err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatalf("after the sync the record is readable: %v", err)
	}
}

// Two puts of one record staged at the same time: the first to publish stores it, the second finds it stored and identical and
// publishes nothing. If the second's content differs it is refused, as a later put of a stored record always was.
func TestConcurrentPutsOfOneRecord(t *testing.T) {
	for _, differ := range []bool{false, true} {
		q, r := fixture()
		other := *r
		if differ {
			other.Body = []byte("changed")
		}
		s, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		log := &opLog{}
		log.install(s)
		// both puts are held in their file syncs until both are there: each has staged the record before either publishes
		inner := *s.disk
		var mu sync.Mutex
		stagedDirs := map[string]bool{}
		both := make(chan struct{})
		s.disk.syncFile = func(f *os.File) error {
			mu.Lock()
			if dir := filepath.Dir(f.Name()); !stagedDirs[dir] {
				stagedDirs[dir] = true
				if len(stagedDirs) == 2 {
					close(both)
				}
			}
			mu.Unlock()
			select {
			case <-both:
			case <-time.After(10 * time.Second):
				t.Error("the two puts did not stage at the same time")
			}
			return inner.syncFile(f)
		}
		errs := make(chan error, 2)
		for _, rec := range []*Record{r, &other} {
			go func() { errs <- s.Put(q, rec) }()
		}
		e1, e2 := <-errs, <-errs
		stored, err := s.Get(q)
		if err != nil {
			t.Fatalf("differ=%v: the record is stored once: %v", differ, err)
		}
		if left := leftovers(t, s); len(left) != 0 {
			t.Fatalf("differ=%v: temporary directories left: %v", differ, left)
		}
		if got := log.count("rename"); got > 1 {
			t.Fatalf("differ=%v: %d publications of one record", differ, got)
		}
		if !differ {
			if e1 != nil || e2 != nil {
				t.Fatalf("identical concurrent puts: %v, %v", e1, e2)
			}
			continue
		}
		// one of the two is stored; the other is refused, whichever order they published in
		refused := 0
		for _, e := range []error{e1, e2} {
			if errors.Is(e, ErrInvalid) {
				refused++
			} else if e != nil {
				t.Fatalf("unexpected error: %v", e)
			}
		}
		if refused != 1 {
			t.Fatalf("exactly one of two differing puts is refused, got %d (%v, %v)", refused, e1, e2)
		}
		if !bytes.Equal(stored.Body, r.Body) && !bytes.Equal(stored.Body, other.Body) {
			t.Fatal("the stored record is neither of the two")
		}
	}
}
