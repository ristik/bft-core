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
	dir   string
	mu    sync.Mutex
	Fault func(string) error
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

// ManifestDigest is the digest of the exact ARCHIVE1 manifest payload that
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
	manifest.WriteString("ARCHIVE1")
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
func location(q Request) (string, error) {
	b, err := EncodeRequest(q)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
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

// Put publishes chunks only after every chunk and the checksummed manifest
// have been synced. A failed pre-publication write leaves at most an ignored
// temporary directory. Existing records are immutable.
func (s *Store) Put(q Request, rec *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := allFields(rec)
	if err != nil {
		return err
	}
	if !bytes.Equal(crypto.Keccak256(rec.Header), q.BlockHash[:]) {
		return ErrInvalid
	}
	loc, err := location(q)
	if err != nil {
		return err
	}
	final := filepath.Join(s.dir, loc)
	if _, err = os.Stat(final); err == nil {
		old, e := s.get(q)
		if e != nil {
			return e
		}
		a, _ := EncodeResponse(Response{q, OK, old})
		b, _ := EncodeResponse(Response{q, OK, rec})
		if !bytes.Equal(a, b) {
			return ErrInvalid
		}
		return syncDir(s.dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.MkdirTemp(s.dir, ".writing-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var manifest bytes.Buffer
	manifest.Write([]byte("ARCHIVE1"))
	qb, _ := EncodeRequest(q)
	putBytes(&manifest, qb)
	manifest.WriteByte(byte(len(keys)))
	for _, k := range keys {
		if len(k) > 64 || len(k) == 0 {
			return ErrInvalid
		}
		p := filepath.Join(tmp, fileName(k))
		h, er := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if er != nil {
			return er
		}
		_, er = h.Write(f[k])
		if er == nil {
			er = h.Sync()
		}
		closeErr := h.Close()
		if er != nil {
			return er
		}
		if closeErr != nil {
			return closeErr
		}
		putBytes(&manifest, []byte(k))
		put32(&manifest, uint32(len(f[k])))
		d := sha256.Sum256(f[k])
		manifest.Write(d[:])
		if s.Fault != nil {
			if er = s.Fault("after-chunk"); er != nil {
				return er
			}
		}
	}
	d := sha256.Sum256(manifest.Bytes())
	expected, err := ManifestDigest(q, rec)
	if err != nil || d != expected {
		return ErrInvalid
	}
	manifest.Write(d[:])
	h, err := os.OpenFile(filepath.Join(tmp, "manifest"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = h.Write(manifest.Bytes())
	if err == nil {
		err = h.Sync()
	}
	closeErr := h.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = syncDir(tmp); err != nil {
		return err
	}
	if s.Fault != nil {
		if err = s.Fault("before-publish"); err != nil {
			return err
		}
	}
	if err = os.Rename(tmp, final); err != nil {
		return err
	}
	return syncDir(s.dir)
}

// Get refuses missing or damaged chunks as a whole. It never returns partial
// evidence. A consumer must verify every returned field under its own trust.
func (s *Store) Get(q Request) (*Record, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.get(q) }
func (s *Store) get(q Request) (*Record, error) {
	loc, err := location(q)
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
	if len(m) < 8+4+1+32 || !bytes.Equal(m[:8], []byte("ARCHIVE1")) {
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
	if !validRecord(rec) || !bytes.Equal(crypto.Keccak256(rec.Header), q.BlockHash[:]) {
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
