package archive

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// batchFixture is n distinct valid records of the fixture's context.
func batchFixture(t *testing.T, n int) ([]Request, []*Record) {
	t.Helper()
	qs, recs := make([]Request, n), make([]*Record, n)
	for i := range qs {
		q, r := fixture()
		r.Header = append(bytes.Clone(r.Header), byte(i))
		q.BlockHash = [32]byte(crypto.Keccak256(r.Header))
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
