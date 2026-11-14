package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
)

var ErrUnavailable = errors.New("archive record unavailable")
var ErrCorrupt = errors.New("archive record invalid")

// Store holds immutable local availability copies. One process may write a
// store at a time; archivewiring owns peer publication and verification.
type Store struct {
	dir             string
	mu              sync.Mutex
	Fault           func(string) error
	disk            *diskOps // nil: the real operations (see diskOps)
	rounds          map[string]map[uint64][]Request
	receiptRounds   map[string]map[uint64][]Request
	legacyBundles   []string // bundle file names in the store directory itself (the layout before bundleDir), listed once; nil until then
	bundleDirSynced bool     // the store directory has been synced since bundleDir was found or made (PutBundle); under mu
	prepMu          sync.Mutex
	prepared        bool            // the packed layout's directories exist and are durable (prepareRecordDirs)
	migrateSkip     map[string]bool // directory-layout records MigrateLegacy leaves as they are; under mu
	unsynced        map[string]bool // fan-out directories whose sync after a publication failed: synced again by the next put; under mu
	durable         map[string]bool // packed records published or synced by this process (ensureDurableLocked); under mu
}

func Open(dir string) (*Store, error) {
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, ErrInvalid
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func reserved(k string) bool {
	for _, name := range required {
		if k == name {
			return true
		}
	}
	return false
}
func sortedExtensions(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func allFields(r *Record) (map[string][]byte, error) {
	if !validRecord(r) {
		return nil, ErrInvalid
	}
	f := fields(r)
	for k, v := range r.Extensions {
		if reserved(k) {
			return nil, ErrInvalid
		}
		f[k] = v
	}
	return f, nil
}

// ManifestDigest is the digest of the exact versioned manifest payload that
// Put publishes for this request and record, before its trailing checksum.
func ManifestDigest(q Request, rec *Record) ([32]byte, error) {
	var zero [32]byte
	f, err := allFields(rec)
	if err != nil {
		return zero, err
	}
	qb, err := EncodeRequest(q)
	if err != nil || !bytes.Equal(crypto.Keccak256(rec.Header), q.BlockHash[:]) {
		return zero, ErrInvalid
	}
	keys := sortedExtensions(f)
	var manifest bytes.Buffer
	manifest.WriteString(archiveMagic(recordV2(rec)))
	putBytes(&manifest, qb)
	manifest.WriteByte(byte(len(keys)))
	for _, k := range keys {
		if len(k) == 0 || len(k) > 64 {
			return zero, ErrInvalid
		}
		putBytes(&manifest, []byte(k))
		put32(&manifest, uint32(len(f[k])))
		d := sha256.Sum256(f[k])
		manifest.Write(d[:])
	}
	return sha256.Sum256(manifest.Bytes()), nil
}
func fileName(k string) string { return hex.EncodeToString([]byte(k)) + ".chunk" }
func location(q Request, versions ...bool) (string, error) {
	v2 := len(versions) != 0 && versions[0]
	b, err := EncodeRequest(q)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	name := hex.EncodeToString(h[:])
	if v2 {
		name = "v2-" + name
	}
	return name, nil
}
func recordV2(r *Record) bool { return HasReceiptList(r) }
func archiveMagic(v2 bool) string {
	if v2 {
		return "ARCHIVE2"
	}
	return "ARCHIVE1"
}

// fault calls the Fault hook, if one is set, at a named point of a put: "after-chunk" (each chunk written) and "before-publish"
// (before each record's publication). An error from the hook fails the put there.
func (s *Store) fault(point string) error {
	if s.Fault == nil {
		return nil
	}
	return s.Fault(point)
}

// diskOps are the operations a put's durability rests on. The store's are the real ones; a test replaces them to observe the order
// in which a put issues them and to fail one. syncFile and syncDir are called concurrently.
type diskOps struct {
	syncFile func(*os.File) error
	syncDir  func(dir string) error
	rename   func(from, to string) error
}

var realDiskOps = diskOps{syncFile: (*os.File).Sync, syncDir: syncDir, rename: func(from, to string) error { return publishNoReplace(from, to, os.Remove) }}

// publishNoReplace gives the synced temporary file its final name by a hard link, which unlike a rename never replaces a file already at to
// (os.ErrExist then): a record is immutable, and another writer of the directory (a joiner's archive seed) may have placed one there. Once the
// link exists the record is published, whatever happens to the temporary name: a failure to remove it is ignored (the leftover is the same
// inode, and the caller removes it again), so the publication is synced and indexed like any other.
func publishNoReplace(from, to string, remove func(string) error) error {
	if err := os.Link(from, to); err != nil {
		return err
	}
	_ = remove(from)
	return nil
}

// ensureDurableLocked makes a packed record that this store did not publish itself durable before it counts as stored: another writer (a
// joiner's seed, or an earlier process whose directory sync failed) may have placed it without syncing it, and a put that finds it reports
// the record durable to its caller (a replica's acknowledgement). The file and its fan-out directory are synced once per name per process.
// Called under the store's lock.
func (s *Store) ensureDurableLocked(name string) error {
	if s.durable[name] {
		return nil
	}
	path := s.packedPath(name)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = s.ops().syncFile(f)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = s.ops().syncDir(filepath.Dir(path))
	}
	if err != nil {
		return err
	}
	s.markDurableLocked(name)
	return nil
}

func (s *Store) markDurableLocked(name string) {
	if s.durable == nil {
		s.durable = map[string]bool{}
	}
	s.durable[name] = true
}

func (s *Store) ops() diskOps {
	if s.disk != nil {
		return *s.disk
	}
	return realDiskOps
}

// syncDirs syncs the directories concurrently and reports every failure.
func (s *Store) syncDirs(dirs []string) error {
	errs := make([]error, len(dirs))
	var wg sync.WaitGroup
	for i, dir := range dirs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.ops().syncDir(dir)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, ErrCorrupt
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrCorrupt
	}
	return b, nil
}

// MaxConcurrentFileSyncs bounds the file syncs a put has in flight. A blocked fsync can hold an OS thread, and a full batch has up
// to 832 files (bft-core#913); the sync of a batch still overlaps on the device, but never occupies more than this many threads.
const MaxConcurrentFileSyncs = 16

// syncAndCloseAll syncs the files, at most MaxConcurrentFileSyncs at a time, and closes each. It returns only after every sync has
// returned, and reports every failure of a sync or a close: the caller publishes nothing unless all of them succeeded.
func (s *Store) syncAndCloseAll(files []*os.File) error {
	errs := make([]error, len(files))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(MaxConcurrentFileSyncs, len(files)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				h := files[i]
				err := s.ops().syncFile(h)
				if closeErr := h.Close(); err == nil {
					err = closeErr
				}
				errs[i] = err
			}
		}()
	}
	for i := range files {
		next <- i
	}
	close(next)
	wg.Wait()
	return errors.Join(errs...)
}

// Put publishes a record only after its packed file has been synced, by a link into its fan-out directory, and returns only after that
// directory has been synced. A failed write leaves at most an ignored temporary file. Existing records are immutable.
func (s *Store) Put(q Request, rec *Record) error {
	return s.PutBatch([]Request{q}, []*Record{rec})
}

// MaxPutBatch bounds one PutBatch: its records are held in memory and their files are open together until they are synced.
const MaxPutBatch = 32

// staged is one record of a batch written to its temporary file, not yet synced or published.
type staged struct {
	q       Request
	rec     *Record
	v2      bool
	name    string // the record's name: its location, and for a variant "-" and its manifest digest
	tmp     string
	final   string
	encoded []byte
	index   bool
}

// PutBatch is Put for several records with the device flushes shared: every record's packed file is written, then all are synced
// together, then each record is published by its link, and every fan-out directory a record was published in is synced once. The
// rule of Put holds for each record: nothing of it is published before its file has been synced, and PutBatch returns nil only when
// every record is durable. On an error some records of the batch may already be published (each of them whole and immutable); the
// rest leave at most ignored temporary files, and the caller may put them again. A record that is already stored, in either layout,
// must be identical, as with Put.
func (s *Store) PutBatch(qs []Request, recs []*Record) error {
	return s.putBatch(qs, recs, false)
}

// PutVariant stores a record that is ANOTHER valid representation of a block already stored under its request (bft-core#876: the same certified block under a different
// resulting certificate has a different manifest). The base object of the request is never touched: the variant is a separate immutable object addressed by (request, manifest
// digest), published with the same stage / sync / link discipline, and a variant that is already stored must be identical. Variants are read with GetExact only.
func (s *Store) PutVariant(q Request, rec *Record) error {
	return s.putBatch([]Request{q}, []*Record{rec}, true)
}

func (s *Store) putBatch(qs []Request, recs []*Record, variant bool) error {
	if len(qs) != len(recs) || len(qs) == 0 || len(qs) > MaxPutBatch {
		return ErrInvalid
	}
	inBatch := make(map[string][]byte, len(qs))
	var items []staged
	var packed [][]byte
	for i, q := range qs {
		rec := recs[i]
		f, err := allFields(rec)
		if err != nil {
			return err
		}
		if !bytes.Equal(crypto.Keccak256(rec.Header), q.BlockHash[:]) {
			return ErrInvalid
		}
		v2 := recordV2(rec)
		name, err := location(q, v2)
		if err != nil {
			return err
		}
		if variant {
			digest, derr := ManifestDigest(q, rec)
			if derr != nil {
				return derr
			}
			name += "-" + hex.EncodeToString(digest[:])
		}
		encoded, _ := EncodeResponse(Response{q, OK, rec})
		if earlier, dup := inBatch[name]; dup {
			if !bytes.Equal(earlier, encoded) {
				return ErrInvalid
			}
			continue
		}
		inBatch[name] = encoded
		if exists, err := s.storedSame(q, v2, name, encoded); err != nil {
			return err
		} else if exists {
			continue
		}
		manifest, keys, err := encodeManifest(q, rec, f, func() error { return s.fault("after-chunk") })
		if err != nil {
			return err
		}
		items = append(items, staged{q: q, rec: rec, v2: v2, name: name, final: s.packedPath(name), encoded: encoded, index: !variant})
		packed = append(packed, packRecord(manifest, keys, f))
	}
	if _, err := s.publishPacked(items, packed, s.storedSameLocked); err != nil {
		return err
	}
	return s.syncUnsynced()
}

// syncUnsynced syncs the fan-out directories an earlier publication failed to sync: a put of a record found already stored reports success
// only once the record is durable.
func (s *Store) syncUnsynced() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.unsynced) == 0 {
		return nil
	}
	dirs := make([]string, 0, len(s.unsynced))
	for d := range s.unsynced {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	if err := s.syncDirs(dirs); err != nil {
		return err
	}
	s.unsynced = nil
	return nil
}

// publishPacked writes each item's packed bytes to a temporary file in its fan-out directory, syncs them all, then, under the store's lock,
// publishes each by its link (publishNoReplace) unless exists (called under the lock) reports it stored meanwhile, and syncs every fan-out directory it
// published in. It returns the items it published and made durable.
//
// The writing and syncing run without the store's lock: they are most of a put's time, and a reader, or another writer staging its own
// records, has no reason to wait for them. The lock is held for the publication, so that a record is never visible to a reader before its
// directory is synced. If a link fails part way, the records published before it are made durable and indexed like the rest before the
// error is returned, so a failure leaves no record that is readable but neither synced nor indexed.
func (s *Store) publishPacked(items []staged, packed [][]byte, exists func(Request, bool, string, []byte) (bool, error)) ([]staged, error) {
	if len(items) == 0 {
		return nil, nil
	}
	if err := s.prepareRecordDirs(); err != nil {
		return nil, err
	}
	var open []*os.File // written, not yet synced; closed here if this returns before syncAndCloseAll takes them
	defer func() {
		for _, h := range open {
			_ = h.Close()
		}
		for _, it := range items {
			if it.tmp != "" {
				_ = os.Remove(it.tmp) // already gone when the record was published (or a leftover link to it, which is harmless)
			}
		}
	}()
	for i := range items {
		h, err := os.CreateTemp(filepath.Dir(items[i].final), ".writing-*")
		if err != nil {
			return nil, err
		}
		open = append(open, h)
		items[i].tmp = h.Name()
		if _, err := h.Write(packed[i]); err != nil {
			return nil, err
		}
	}
	synced := open
	open = nil
	if err := s.syncAndCloseAll(synced); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var publishErr error
	var published []staged
	dirs := map[string]bool{}
	for _, it := range items {
		if publishErr = s.fault("before-publish"); publishErr != nil {
			break
		}
		// another put may have published the same record while this one was being staged: it must be identical, and then there
		// is nothing to publish (the staged copy is removed on return)
		var stored bool
		if stored, publishErr = exists(it.q, it.v2, it.name, it.encoded); publishErr != nil {
			break
		} else if stored {
			continue
		}
		if publishErr = s.ops().rename(it.tmp, it.final); errors.Is(publishErr, os.ErrExist) {
			// placed by another writer since the check: it must be this record
			if stored, publishErr = exists(it.q, it.v2, it.name, it.encoded); publishErr == nil && !stored {
				publishErr = ErrInvalid
			}
			if publishErr != nil {
				break
			}
			continue
		}
		if publishErr != nil {
			break
		}
		published = append(published, it)
		dirs[filepath.Dir(it.final)] = true
	}
	if len(published) == 0 {
		return nil, publishErr
	}
	// the publications are durable once their directories are
	syncs := make([]string, 0, len(dirs))
	for d := range dirs {
		syncs = append(syncs, d)
	}
	sort.Strings(syncs)
	if dirErr := s.syncDirs(syncs); dirErr != nil {
		if s.unsynced == nil {
			s.unsynced = map[string]bool{}
		}
		for _, d := range syncs {
			s.unsynced[d] = true
		}
		return nil, errors.Join(publishErr, dirErr)
	}
	for _, it := range published {
		s.markDurableLocked(it.name)
		if s.rounds != nil && it.index {
			s.indexRecord(it.q, it.rec)
		}
	}
	return published, publishErr
}

// prepareRecordDirs makes the packed layout's directories once per process: records/ and its 256 fan-out directories, each parent synced
// after, so that a link into a fan-out directory is never lost with the directory's own entry. It is done on the first write, not at
// Open, so a reader (a tool) never writes to an archive.
func (s *Store) prepareRecordDirs() error {
	s.prepMu.Lock()
	defer s.prepMu.Unlock()
	if s.prepared {
		return nil
	}
	root := filepath.Join(s.dir, recordDir)
	if err := os.Mkdir(root, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	for i := 0; i < 256; i++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("%02x", i)), 0700); err != nil && !os.IsExist(err) {
			return err
		}
	}
	// synced even when they existed: an earlier process may have made them and stopped before its sync
	if err := s.ops().syncDir(root); err != nil {
		return err
	}
	if err := s.ops().syncDir(s.dir); err != nil {
		return err
	}
	s.prepared = true
	return nil
}

// storedSame reports whether the record is already stored, in either layout, which it may only be with identical content (ErrInvalid otherwise).
func (s *Store) storedSame(q Request, v2 bool, name string, encoded []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.storedSameLocked(q, v2, name, encoded)
}

// storedSameLocked is storedSame under the store's lock. Only a record that is absent in both layouts counts as absent (a directory-layout record
// that lost a chunk is ErrUnavailable, and a put then stores a sound packed copy, which reads prefer); a damaged or foreign copy in either layout
// is refused as the read refuses it, never shadowed by a new copy. A packed copy found identical is made durable before it counts as stored.
func (s *Store) storedSameLocked(q Request, v2 bool, name string, encoded []byte) (bool, error) {
	old, err := readNamed(s.dir, q, v2, name)
	if errors.Is(err, ErrUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	a, _ := EncodeResponse(Response{q, OK, old})
	if !bytes.Equal(a, encoded) {
		return false, ErrInvalid
	}
	if _, statErr := os.Stat(s.packedPath(name)); statErr == nil {
		if err := s.ensureDurableLocked(name); err != nil {
			return false, err
		}
	}
	return true, nil
}

// Get refuses missing or damaged chunks as a whole. It never returns partial
// evidence. A consumer must verify every returned field under its own trust.
func (s *Store) Get(q Request) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, err := s.getVersion(q, true); err == nil || !errors.Is(err, ErrUnavailable) {
		return r, err
	}
	return s.getVersion(q, false)
}

// GetExact reads the stored representation of the request whose manifest digest is the given one: the base object of the request if it is that manifest, else the variant
// object stored for it (PutVariant). The digest is a locator, not a verdict: what is returned is re-read, validated and its manifest digest recomputed and compared. A damaged
// base object does not hide a sound variant; with neither, the result is ErrCorrupt if something was damaged and ErrUnavailable if nothing was stored.
func (s *Store) GetExact(q Request, digest [32]byte) (*Record, error) {
	return s.getExact(q, digest, false)
}

// GetExactReceiptComplete is GetExact restricted to the receipt-complete namespace.
func (s *Store) GetExactReceiptComplete(q Request, digest [32]byte) (*Record, error) {
	r, err := s.getExact(q, digest, true)
	if err != nil {
		return nil, err
	}
	if !validReceiptList(r) {
		return nil, ErrUnavailable
	}
	return r, nil
}

func (s *Store) getExact(q Request, digest [32]byte, receiptCompleteOnly bool) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := []bool{true, false}
	if receiptCompleteOnly {
		versions = []bool{true}
	}
	damaged := false
	for _, v2 := range versions {
		base, err := location(q, v2)
		if err != nil {
			return nil, err
		}
		for _, name := range []string{base, base + "-" + hex.EncodeToString(digest[:])} {
			// the manifest names its own digest (self-hashed): an object of another digest is passed over without reading its chunks, so
			// a caller's wrong digest costs a manifest read, not a record read (bft-core#1066, astra's review of #1070), in either layout
			held, err := namedManifestDigest(s.dir, name)
			if errors.Is(err, ErrUnavailable) {
				continue
			}
			if err != nil {
				damaged = true
				continue
			}
			if held != digest {
				continue
			}
			r, err := readNamed(s.dir, q, v2, name)
			if errors.Is(err, ErrUnavailable) {
				continue
			}
			if err != nil {
				damaged = true
				continue
			}
			if got, derr := ManifestDigest(q, r); derr == nil && got == digest {
				return r, nil
			}
		}
	}
	if damaged {
		return nil, ErrCorrupt
	}
	return nil, ErrUnavailable
}

// GetReceiptComplete reads only the receipt-complete immutable namespace.
func (s *Store) GetReceiptComplete(q Request) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.getVersion(q, true)
	if err != nil {
		return nil, err
	}
	if !validReceiptList(r) {
		return nil, ErrUnavailable
	}
	return r, nil
}
func (s *Store) get(q Request) (*Record, error) {
	return s.getVersion(q, false)
}
func (s *Store) getVersion(q Request, v2 bool) (*Record, error) {
	loc, err := location(q, v2)
	if err != nil {
		return nil, err
	}
	return readNamed(s.dir, q, v2, loc)
}

func binaryRead32(r io.Reader, v *uint32) error {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	*v = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return nil
}

// Serve maps local storage outcomes into the typed response envelope. A future
// transport must validate DecodeRequest before calling Serve: malformed
// requests have no canonical echo and cannot be encoded as a response.
func (s *Store) Serve(q Request) Response {
	rec, err := s.Get(q)
	if err == nil {
		return Response{q, OK, rec}
	}
	if errors.Is(err, ErrInvalid) {
		return Response{q, Invalid, nil}
	}
	if errors.Is(err, ErrCorrupt) {
		return Response{q, Unavailable, nil}
	}
	return Response{q, Unavailable, nil}
}
