package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/archive"
)

type receiptGetter interface {
	GetReceiptComplete(archive.Request) (*archive.Record, error)
}

// archiveLocator finds a block's receipt-complete record in a validator's archive at a cost independent of the archive's size. A record's
// directory is named by its Request (Context and block hash), so with the archive's few distinct Contexts known, a lookup is one record read
// per Context. The Contexts are learnt from the manifests of directories not seen before: once at start, then, when a lookup misses (a new
// epoch brings a new Context), at most once per rescanEvery and single-flight. Like archive's round index it is only a locator: archive.Store
// rereads and checks the record on every lookup.
type archiveLocator struct {
	dir          string
	store        receiptGetter
	rescanEvery  time.Duration
	listDir      func(string) ([]string, error) // the archive's entry names; a test counts the listings
	readManifest func(string) ([]byte, error)   // os.ReadFile; a test counts the reads
	now          func() time.Time

	mu       sync.Mutex
	contexts map[string]archive.Context // keyed by a Request's encoding without its trailing block hash
	seen     map[uint64]struct{}        // directories already read, by the first 8 bytes of their name's hash
	lastScan time.Time
	scanning chan struct{} // closed when the running scan ends; nil when none runs
}

func newArchiveLocator(ctx context.Context, dir string, store receiptGetter, rescanEvery time.Duration) (*archiveLocator, error) {
	l := &archiveLocator{dir: dir, store: store, rescanEvery: rescanEvery, listDir: listNames, readManifest: os.ReadFile, now: time.Now,
		contexts: map[string]archive.Context{}, seen: map[uint64]struct{}{}}
	return l, l.rescan(ctx)
}

// locate returns the record of blockHash, or errNotFound when no known Context holds it, after at most one (shared, throttled) rescan.
func (l *archiveLocator) locate(ctx context.Context, blockHash [32]byte) (archive.Request, *archive.Record, error) {
	q, rec, err := l.lookup(blockHash)
	if err == nil || !errors.Is(err, errNotFound) {
		return q, rec, err
	}
	if err := l.rescan(ctx); err != nil {
		return archive.Request{}, nil, err
	}
	return l.lookup(blockHash)
}

func (l *archiveLocator) lookup(blockHash [32]byte) (archive.Request, *archive.Record, error) {
	l.mu.Lock()
	contexts := make([]archive.Context, 0, len(l.contexts))
	for _, c := range l.contexts {
		contexts = append(contexts, c)
	}
	l.mu.Unlock()
	for _, c := range contexts {
		q := archive.Request{Context: c, BlockHash: blockHash}
		rec, err := l.store.GetReceiptComplete(q)
		switch {
		case err == nil:
			return q, rec, nil
		case !errors.Is(err, archive.ErrUnavailable):
			return archive.Request{}, nil, err
		}
	}
	return archive.Request{}, nil, errNotFound
}

// rescan reads the manifests of directories not read before, unless a scan ended less than rescanEvery ago; a scan already running is waited
// for instead of started again. A cancelled ctx ends the wait or the scan; what the scan read so far is kept.
func (l *archiveLocator) rescan(ctx context.Context) error {
	l.mu.Lock()
	if running := l.scanning; running != nil {
		l.mu.Unlock()
		select {
		case <-running:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !l.lastScan.IsZero() && l.now().Sub(l.lastScan) < l.rescanEvery {
		l.mu.Unlock()
		return nil
	}
	done := make(chan struct{})
	l.scanning = done
	l.mu.Unlock()
	err := l.scan(ctx)
	l.mu.Lock()
	l.scanning, l.lastScan = nil, l.now()
	l.mu.Unlock()
	close(done)
	return err
}

func (l *archiveLocator) scan(ctx context.Context) error {
	names, err := l.listDir(l.dir)
	if err != nil {
		return err
	}
	for i, name := range names {
		if i%256 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		key, ok := nameKey(name)
		if !ok {
			continue
		}
		l.mu.Lock()
		_, done := l.seen[key]
		l.mu.Unlock()
		if done {
			continue
		}
		m, err := l.readManifest(filepath.Join(l.dir, name, "manifest"))
		if err != nil {
			continue // not published yet (a record is renamed into place complete), or unreadable: the next scan tries again
		}
		q, ok := manifestRequest(m)
		l.mu.Lock()
		l.seen[key] = struct{}{}
		if ok {
			if k, err := archive.EncodeRequest(q); err == nil {
				l.contexts[string(k[:len(k)-32])] = q.Context // the encoding ends with the block hash: the rest identifies the Context
			}
		}
		l.mu.Unlock()
	}
	return nil
}

func listNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1) // unsorted: a listing of a large archive need not sort
}

// nameKey is the first 8 bytes of a v2 record directory's name ("v2-" + hex sha256 of its Request); other entries are not records.
func nameKey(name string) (uint64, bool) {
	h, ok := strings.CutPrefix(name, "v2-")
	if !ok || len(h) != 64 {
		return 0, false
	}
	b, err := hex.DecodeString(h[:16])
	if err != nil {
		return 0, false
	}
	return binary.BigEndian.Uint64(b), true
}

// manifestRequest decodes the Request a v2 manifest starts with ("ARCHIVE2", a 4-byte length, the encoded Request).
func manifestRequest(m []byte) (archive.Request, bool) {
	if len(m) < 12 || !bytes.Equal(m[:8], []byte("ARCHIVE2")) {
		return archive.Request{}, false
	}
	n := binary.BigEndian.Uint32(m[8:12])
	if n == 0 || uint64(n)+12 > uint64(len(m)) {
		return archive.Request{}, false
	}
	q, err := archive.DecodeRequest(m[12 : 12+n])
	return q, err == nil
}
