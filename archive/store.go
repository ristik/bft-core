package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	dir           string
	mu            sync.Mutex
	Fault         func(string) error
	disk          *diskOps // nil: the real operations (see diskOps)
	rounds        map[string]map[uint64][]Request
	receiptRounds map[string]map[uint64][]Request
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
// (before each record's rename). An error from the hook fails the put there.
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

var realDiskOps = diskOps{syncFile: (*os.File).Sync, syncDir: syncDir, rename: os.Rename}

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

// writeUnsynced creates path exclusively, writes b and leaves the file open in *open for syncAndCloseAll.
func writeUnsynced(open *[]*os.File, path string, b []byte) error {
	h, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	*open = append(*open, h)
	_, err = h.Write(b)
	return err
}

// syncAndCloseAll syncs the files concurrently and closes each. It returns only after every sync has returned, and reports every
// failure of a sync or a close: the caller publishes nothing unless all of them succeeded.
func (s *Store) syncAndCloseAll(files []*os.File) error {
	errs := make([]error, len(files))
	var wg sync.WaitGroup
	for i, h := range files {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.ops().syncFile(h)
			if closeErr := h.Close(); err == nil {
				err = closeErr
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Put publishes chunks only after every chunk and the checksummed manifest
// have been synced. A failed pre-publication write leaves at most an ignored
// temporary directory. Existing records are immutable.
func (s *Store) Put(q Request, rec *Record) error {
	return s.PutBatch([]Request{q}, []*Record{rec})
}

// MaxPutBatch bounds one PutBatch: its records are held in memory and their files are open together until they are synced. A record
// has nine fields, its extensions (at most sixteen) and a manifest, so a full batch can hold up to 832 files open at once; the
// restore uses batches of 16.
const MaxPutBatch = 32

// staged is one record of a batch written to its temporary directory, not yet synced or published.
type staged struct {
	q     Request
	rec   *Record
	tmp   string
	final string
}

// PutBatch is Put for several records with the device flushes shared: every file of every record is written, then all files are
// synced together, then all temporary directories, then each record is published by its rename and the store directory is synced
// once. The rule of Put holds for each record: nothing of it is published before every one of its chunks, its manifest and its
// directory have been synced, and PutBatch returns nil only when every record is durable. On an error some records of the batch may
// already be published (each of them whole and immutable); the rest leave at most ignored temporary directories, and the caller may
// put them again. A record that is already stored must be identical, as with Put.
func (s *Store) PutBatch(qs []Request, recs []*Record) error {
	if len(qs) != len(recs) || len(qs) == 0 || len(qs) > MaxPutBatch {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var open []*os.File // written, not yet synced; closed here if PutBatch returns before syncAndCloseAll takes them
	var batch []staged
	defer func() {
		for _, h := range open {
			_ = h.Close()
		}
		for _, st := range batch {
			_ = os.RemoveAll(st.tmp) // already renamed away when the record was published
		}
	}()
	inBatch := make(map[string][]byte, len(qs))
	for i, q := range qs {
		rec := recs[i]
		f, err := allFields(rec)
		if err != nil {
			return err
		}
		if !bytes.Equal(crypto.Keccak256(rec.Header), q.BlockHash[:]) {
			return ErrInvalid
		}
		loc, err := location(q, recordV2(rec))
		if err != nil {
			return err
		}
		final := filepath.Join(s.dir, loc)
		encoded, _ := EncodeResponse(Response{q, OK, rec})
		if earlier, dup := inBatch[final]; dup {
			if !bytes.Equal(earlier, encoded) {
				return ErrInvalid
			}
			continue
		}
		inBatch[final] = encoded
		if _, err = os.Stat(final); err == nil {
			old, e := s.getVersion(q, recordV2(rec))
			if e != nil {
				return e
			}
			a, _ := EncodeResponse(Response{q, OK, old})
			if !bytes.Equal(a, encoded) {
				return ErrInvalid
			}
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		tmp, err := os.MkdirTemp(s.dir, ".writing-")
		if err != nil {
			return err
		}
		batch = append(batch, staged{q: q, rec: rec, tmp: tmp, final: final})
		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var manifest bytes.Buffer
		manifest.Write([]byte(archiveMagic(recordV2(rec))))
		qb, _ := EncodeRequest(q)
		putBytes(&manifest, qb)
		manifest.WriteByte(byte(len(keys)))
		for _, k := range keys {
			if len(k) > 64 || len(k) == 0 {
				return ErrInvalid
			}
			if er := writeUnsynced(&open, filepath.Join(tmp, fileName(k)), f[k]); er != nil {
				return er
			}
			putBytes(&manifest, []byte(k))
			put32(&manifest, uint32(len(f[k])))
			d := sha256.Sum256(f[k])
			manifest.Write(d[:])
			if er := s.fault("after-chunk"); er != nil {
				return er
			}
		}
		d := sha256.Sum256(manifest.Bytes())
		expected, err := ManifestDigest(q, rec)
		if err != nil || d != expected {
			return ErrInvalid
		}
		manifest.Write(d[:])
		if err = writeUnsynced(&open, filepath.Join(tmp, "manifest"), manifest.Bytes()); err != nil {
			return err
		}
	}
	// Every chunk and manifest is synced before its directory is, and every directory before any publication below. The syncs of one
	// stage are issued together, so one device flush can serve them, instead of one after another.
	synced := open
	open = nil
	if err := s.syncAndCloseAll(synced); err != nil {
		return err
	}
	dirs := make([]string, len(batch))
	for i, st := range batch {
		dirs[i] = st.tmp
	}
	if err := s.syncDirs(dirs); err != nil {
		return err
	}
	// Publication. If a rename fails part way, the records renamed before it are already visible to Get: they are made durable and
	// indexed like the rest before the error is returned, so a failed batch leaves no record that is readable but neither synced
	// nor indexed.
	var publishErr error
	published := 0
	for _, st := range batch {
		if publishErr = s.fault("before-publish"); publishErr != nil {
			break
		}
		if publishErr = s.ops().rename(st.tmp, st.final); publishErr != nil {
			break
		}
		published++
	}
	// the publications (and, for records that were already stored, their earlier ones) are durable once the store directory is
	storeErr := s.ops().syncDir(s.dir)
	if storeErr == nil && s.rounds != nil {
		for _, st := range batch[:published] {
			s.indexRecord(st.q, st.rec)
		}
	}
	return errors.Join(publishErr, storeErr)
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
	dir := filepath.Join(s.dir, loc)
	m, err := readBounded(filepath.Join(dir, "manifest"), 16<<10)
	if os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, ErrCorrupt
	}
	magic := archiveMagic(v2)
	if len(m) < 8+4+1+32 || !bytes.Equal(m[:8], []byte(magic)) {
		return nil, ErrCorrupt
	}
	d := sha256.Sum256(m[:len(m)-32])
	if !bytes.Equal(d[:], m[len(m)-32:]) {
		return nil, ErrCorrupt
	}
	r := bytes.NewReader(m[8 : len(m)-32])
	qb, err := readBytes(r, MaxRequestBytes)
	if err != nil {
		return nil, ErrCorrupt
	}
	if _, err := DecodeRequest(qb); err != nil {
		return nil, ErrCorrupt
	}
	want, _ := EncodeRequest(q)
	if !bytes.Equal(want, qb) {
		return nil, ErrCorrupt
	}
	n, err := r.ReadByte()
	if err != nil || n < byte(len(required)) || n > byte(len(required)+16) {
		return nil, ErrCorrupt
	}
	f := make(map[string][]byte, int(n))
	last := ""
	total := 0
	for i := 0; i < int(n); i++ {
		kb, e := readBytes(r, 64)
		if e != nil || len(kb) == 0 || string(kb) <= last {
			return nil, ErrCorrupt
		}
		k := string(kb)
		last = k
		var size uint32
		if e = binaryRead32(r, &size); e != nil || size > MaxChunkBytes || (size == 0 && k != "parent-accounting") || (size != 0 && k == "parent-accounting") {
			return nil, ErrCorrupt
		}
		var hash [32]byte
		if _, e = io.ReadFull(r, hash[:]); e != nil {
			return nil, ErrCorrupt
		}
		v, e := readBounded(filepath.Join(dir, fileName(k)), MaxChunkBytes)
		if os.IsNotExist(e) {
			return nil, ErrUnavailable
		}
		if e != nil {
			return nil, ErrCorrupt
		}
		if len(v) != int(size) {
			return nil, ErrCorrupt
		}
		check := sha256.Sum256(v)
		if check != hash {
			return nil, ErrCorrupt
		}
		f[k] = v
		total += len(v)
		if total > MaxRecordBytes {
			return nil, ErrCorrupt
		}
	}
	if r.Len() != 0 {
		return nil, ErrCorrupt
	}
	rec := &Record{Header: f["header"], Body: f["body"], CanonicalRootInput: f["root-input"], OriginalUC: f["original-uc"], OriginalTR: f["original-tr"], ResultingUC: f["resulting-uc"], ResultingTR: f["resulting-tr"], Companion: f["companion"], ParentAccounting: f["parent-accounting"], Extensions: map[string][]byte{}}
	for k, v := range f {
		if !reserved(k) {
			rec.Extensions[k] = v
		}
	}
	if !validRecord(rec) || recordV2(rec) != v2 || !bytes.Equal(crypto.Keccak256(rec.Header), q.BlockHash[:]) {
		return nil, ErrCorrupt
	}
	return rec, nil
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
