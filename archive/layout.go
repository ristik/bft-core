package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// The on-disk layouts of a record (bft-core#1049).
//
// Packed (written since #1049): one file per record, records/<hh>/<name>, where <name> is the record's location (and, for a variant, "-" and its
// manifest digest) and <hh> is the first byte of the location's hash in hex, so no directory holds more than about 1/256 of the archive. The file is
// packedMagic, the manifest's length (4 bytes, big-endian), the manifest (exactly the bytes the directory layout keeps as its manifest file,
// checksum included), then the chunks back to back in the manifest's key order. It is written to a temporary file in its fan-out directory,
// synced, linked into place (never replacing a file already there) and the directory synced: a record is either whole or absent, never partial.
//
// Directory (before #1049): a directory <name> in the store directory itself, holding the manifest and one <hex(key)>.chunk file per field. Such
// records are still read, and MigrateLegacy moves them to the packed layout. A record takes 13 inodes this way and one packed: the kernel's inode
// and dentry cache for them is charged to the memory cgroup of the process, which a growing archive filled (bft-core#1018).
const (
	recordDir        = "records"
	packedMagic      = "ARCHPAK1"
	maxManifestBytes = 16 << 10
	maxPackedBytes   = len(packedMagic) + 4 + maxManifestBytes + MaxRecordBytes
)

// shardOf is the fan-out directory of a record name: the first byte of its hash, in hex.
func shardOf(name string) string { return strings.TrimPrefix(name, "v2-")[:2] }

func (s *Store) packedPath(name string) string { return packedPath(s.dir, name) }
func packedPath(dir, name string) string       { return filepath.Join(dir, recordDir, shardOf(name), name) }

// recordName reports whether name is a record name: a location ("<64 hex>" or "v2-<64 hex>"), with variant ("-<64 hex>") when variants is set.
func recordName(name string, variants bool) bool {
	h := strings.TrimPrefix(name, "v2-")
	if len(h) == 64+1+64 && variants && h[64] == '-' {
		return isHex(h[:64]) && isHex(h[65:])
	}
	return len(h) == 64 && isHex(h)
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type manifestEntry struct {
	key  string
	size uint32
	hash [32]byte
}

// encodeManifest is the manifest of a record (with its trailing checksum) and the field keys in its order. fault is called after each key.
func encodeManifest(q Request, rec *Record, f map[string][]byte, fault func() error) ([]byte, []string, error) {
	keys := sortedExtensions(f)
	var manifest bytes.Buffer
	manifest.WriteString(archiveMagic(recordV2(rec)))
	qb, err := EncodeRequest(q)
	if err != nil {
		return nil, nil, err
	}
	putBytes(&manifest, qb)
	manifest.WriteByte(byte(len(keys)))
	for _, k := range keys {
		if len(k) > 64 || len(k) == 0 {
			return nil, nil, ErrInvalid
		}
		putBytes(&manifest, []byte(k))
		put32(&manifest, uint32(len(f[k])))
		d := sha256.Sum256(f[k])
		manifest.Write(d[:])
		if err := fault(); err != nil {
			return nil, nil, err
		}
	}
	d := sha256.Sum256(manifest.Bytes())
	expected, err := ManifestDigest(q, rec)
	if err != nil || d != expected {
		return nil, nil, ErrInvalid
	}
	manifest.Write(d[:])
	return manifest.Bytes(), keys, nil
}

// packRecord is the packed file of a record whose manifest and key order encodeManifest gave.
func packRecord(manifest []byte, keys []string, f map[string][]byte) []byte {
	size := len(packedMagic) + 4 + len(manifest)
	for _, k := range keys {
		size += len(f[k])
	}
	out := make([]byte, 0, size)
	out = append(out, packedMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(manifest)))
	out = append(out, manifest...)
	for _, k := range keys {
		out = append(out, f[k]...)
	}
	return out
}

// checkManifest verifies a manifest's checksum and magic and returns the request it names, its entries and whether it is a v2 record.
func checkManifest(m []byte) (Request, []manifestEntry, bool, error) {
	if len(m) < 8+4+1+32 {
		return Request{}, nil, false, ErrCorrupt
	}
	var v2 bool
	switch string(m[:8]) {
	case archiveMagic(true):
		v2 = true
	case archiveMagic(false):
	default:
		return Request{}, nil, false, ErrCorrupt
	}
	d := sha256.Sum256(m[:len(m)-32])
	if !bytes.Equal(d[:], m[len(m)-32:]) {
		return Request{}, nil, false, ErrCorrupt
	}
	r := bytes.NewReader(m[8 : len(m)-32])
	qb, err := readBytes(r, MaxRequestBytes)
	if err != nil {
		return Request{}, nil, false, ErrCorrupt
	}
	q, err := DecodeRequest(qb)
	if err != nil {
		return Request{}, nil, false, ErrCorrupt
	}
	n, err := r.ReadByte()
	if err != nil || n < byte(len(required)) || n > byte(len(required)+16) {
		return Request{}, nil, false, ErrCorrupt
	}
	entries := make([]manifestEntry, 0, int(n))
	last := ""
	for i := 0; i < int(n); i++ {
		kb, e := readBytes(r, 64)
		if e != nil || len(kb) == 0 || string(kb) <= last {
			return Request{}, nil, false, ErrCorrupt
		}
		k := string(kb)
		last = k
		var en manifestEntry
		en.key = k
		if e = binaryRead32(r, &en.size); e != nil || en.size > MaxChunkBytes || (en.size == 0 && k != "parent-accounting") || (en.size != 0 && k == "parent-accounting") {
			return Request{}, nil, false, ErrCorrupt
		}
		if _, e = io.ReadFull(r, en.hash[:]); e != nil {
			return Request{}, nil, false, ErrCorrupt
		}
		entries = append(entries, en)
	}
	if r.Len() != 0 {
		return Request{}, nil, false, ErrCorrupt
	}
	return q, entries, v2, nil
}

// parseManifest is checkManifest for a record read as q in the v2 or v1 namespace.
func parseManifest(m []byte, q Request, v2 bool) ([]manifestEntry, error) {
	got, entries, isV2, err := checkManifest(m)
	if err != nil {
		return nil, err
	}
	want, _ := EncodeRequest(q)
	have, _ := EncodeRequest(got)
	if isV2 != v2 || !bytes.Equal(want, have) {
		return nil, ErrCorrupt
	}
	return entries, nil
}

// assemble checks a record's fields as read and builds the record.
func assemble(q Request, v2 bool, f map[string][]byte) (*Record, error) {
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

// readPacked reads and validates the packed record file at path for the request.
func readPacked(q Request, v2 bool, path string) (*Record, error) {
	b, err := readBounded(path, int64(maxPackedBytes))
	if os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, ErrCorrupt
	}
	if len(b) < len(packedMagic)+4 || string(b[:len(packedMagic)]) != packedMagic {
		return nil, ErrCorrupt
	}
	off := len(packedMagic) + 4
	m := int(binary.BigEndian.Uint32(b[len(packedMagic):off]))
	if m > maxManifestBytes || off+m > len(b) {
		return nil, ErrCorrupt
	}
	entries, err := parseManifest(b[off:off+m], q, v2)
	if err != nil {
		return nil, err
	}
	off += m
	f := make(map[string][]byte, len(entries))
	total := 0
	for _, e := range entries {
		if int(e.size) > len(b)-off {
			return nil, ErrCorrupt
		}
		v := b[off : off+int(e.size) : off+int(e.size)]
		if sha256.Sum256(v) != e.hash {
			return nil, ErrCorrupt
		}
		f[e.key] = v
		off += int(e.size)
		if total += int(e.size); total > MaxRecordBytes {
			return nil, ErrCorrupt
		}
	}
	if off != len(b) {
		return nil, ErrCorrupt
	}
	return assemble(q, v2, f)
}

// readLegacy reads and validates the record kept in the directory layout in dir for the request. A missing chunk is ErrUnavailable: the
// directory is renamed into place complete, so only damage leaves one out.
func readLegacy(q Request, v2 bool, dir string) (*Record, error) {
	m, err := readBounded(filepath.Join(dir, "manifest"), maxManifestBytes)
	if os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, ErrCorrupt
	}
	entries, err := parseManifest(m, q, v2)
	if err != nil {
		return nil, err
	}
	f := make(map[string][]byte, len(entries))
	total := 0
	for _, e := range entries {
		v, err := readBounded(filepath.Join(dir, fileName(e.key)), MaxChunkBytes)
		if os.IsNotExist(err) {
			return nil, ErrUnavailable
		}
		if err != nil || len(v) != int(e.size) || sha256.Sum256(v) != e.hash {
			return nil, ErrCorrupt
		}
		f[e.key] = v
		if total += len(v); total > MaxRecordBytes {
			return nil, ErrCorrupt
		}
	}
	return assemble(q, v2, f)
}

// readNamed reads the record stored under name for the request: the packed file, else the directory. A damaged copy in one layout does not hide
// a sound copy in the other; with neither, the error is the packed copy's unless it is absent.
func readNamed(dir string, q Request, v2 bool, name string) (*Record, error) {
	rec, packedErr := readPacked(q, v2, packedPath(dir, name))
	if packedErr == nil {
		return rec, nil
	}
	rec, legacyErr := readLegacy(q, v2, filepath.Join(dir, name))
	if legacyErr == nil {
		return rec, nil
	}
	if errors.Is(packedErr, ErrUnavailable) {
		return nil, legacyErr
	}
	return nil, packedErr
}

// StoredNames hands each chunk of the names of the base records held in an archive directory, in either layout, to each, unsorted: a
// directory-layout record by its directory name ("<hex>" or "v2-<hex>"), a packed record by its path relative to dir
// ("records/<hh>/<name>"). Variant objects, temporaries and bundles are not listed. chunk bounds how many names one call holds.
func StoredNames(dir string, chunk int, each func([]string) error) error {
	if chunk <= 0 {
		chunk = 1024
	}
	if err := listNames(dir, chunk, func(names []string) error {
		var out []string
		for _, n := range names {
			// a record held in both layouts (a migration between its two steps, or a tool on a live archive) is listed once, packed, as a
			// read prefers it
			if recordName(n, false) && !fileExists(packedPath(dir, n)) {
				out = append(out, n)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return each(out)
	}); err != nil {
		return err
	}
	shards, err := os.ReadDir(filepath.Join(dir, recordDir))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, sh := range shards {
		if !sh.IsDir() || len(sh.Name()) != 2 || !isHex(sh.Name()) {
			continue
		}
		prefix := recordDir + "/" + sh.Name() + "/"
		err := listNames(filepath.Join(dir, recordDir, sh.Name()), chunk, func(names []string) error {
			var out []string
			for _, n := range names {
				if recordName(n, false) && shardOf(n) == sh.Name() {
					out = append(out, prefix+n)
				}
			}
			if len(out) == 0 {
				return nil
			}
			return each(out)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func listNames(dir string, chunk int, each func([]string) error) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		names, err := f.Readdirnames(chunk)
		if len(names) > 0 {
			if err := each(names); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// storedLocation is the record name and layout of a name StoredNames gave.
func storedLocation(name string) (string, bool, error) {
	if rest, ok := strings.CutPrefix(name, recordDir+"/"); ok {
		shard, base, found := strings.Cut(rest, "/")
		if !found || !recordName(base, false) || shardOf(base) != shard {
			return "", false, ErrInvalid
		}
		return base, true, nil
	}
	if !recordName(name, false) {
		return "", false, ErrInvalid
	}
	return name, false, nil
}

// StoredManifest is the checksum-verified manifest of the record a name from StoredNames names. Only the manifest is read.
func StoredManifest(dir, name string) ([]byte, error) {
	base, packed, err := storedLocation(name)
	if err != nil {
		return nil, err
	}
	if !packed {
		m, err := readBounded(filepath.Join(dir, base, "manifest"), maxManifestBytes)
		if os.IsNotExist(err) {
			return nil, ErrUnavailable
		}
		if err != nil {
			return nil, ErrCorrupt
		}
		if _, _, _, err := checkManifest(m); err != nil {
			return nil, err
		}
		return m, nil
	}
	m, err := readPackedManifest(packedPath(dir, base))
	if err != nil {
		return nil, err
	}
	if _, _, _, err := checkManifest(m); err != nil {
		return nil, err
	}
	return m, nil
}

// readPackedManifest reads only the manifest of the packed record file at path, unchecked.
func readPackedManifest(path string) ([]byte, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, ErrCorrupt
	}
	defer f.Close()
	head := make([]byte, len(packedMagic)+4)
	if _, err := io.ReadFull(f, head); err != nil || string(head[:len(packedMagic)]) != packedMagic {
		return nil, ErrCorrupt
	}
	n := binary.BigEndian.Uint32(head[len(packedMagic):])
	if n > maxManifestBytes {
		return nil, ErrCorrupt
	}
	m := make([]byte, n)
	if _, err := io.ReadFull(f, m); err != nil {
		return nil, ErrCorrupt
	}
	return m, nil
}

// StoredRequest is the request the record a name from StoredNames names is stored under, and whether it is a v2 (receipt-complete
// namespace) record. The manifest must name the request the record is located by.
func StoredRequest(dir, name string) (Request, bool, error) {
	m, err := StoredManifest(dir, name)
	if err != nil {
		return Request{}, false, err
	}
	q, _, v2, err := checkManifest(m)
	if err != nil {
		return Request{}, false, err
	}
	base, _, _ := storedLocation(name)
	if loc, err := location(q, v2); err != nil || loc != base {
		return Request{}, false, fmt.Errorf("%w: %s holds the manifest of another request", ErrCorrupt, name)
	}
	return q, v2, nil
}

// ReadStored reads and validates the whole record a name from StoredNames names, in the layout the name gives.
func ReadStored(dir, name string) (Request, *Record, error) {
	q, v2, err := StoredRequest(dir, name)
	if err != nil {
		return Request{}, nil, err
	}
	base, packed, _ := storedLocation(name)
	var rec *Record
	if packed {
		rec, err = readPacked(q, v2, packedPath(dir, base))
	} else {
		rec, err = readLegacy(q, v2, filepath.Join(dir, base))
	}
	return q, rec, err
}

// RecordPaths are the paths a record of the request may occupy in an archive directory, in both layouts and both namespaces, with the
// variant object of the manifest digest when one is given. A test that simulates a lost disk removes them.
func RecordPaths(dir string, q Request, variant *[32]byte) ([]string, error) {
	var out []string
	for _, v2 := range []bool{true, false} {
		loc, err := location(q, v2)
		if err != nil {
			return nil, err
		}
		if variant != nil {
			loc += "-" + fmt.Sprintf("%x", variant[:])
		}
		out = append(out, packedPath(dir, loc), filepath.Join(dir, loc))
	}
	return out, nil
}

// DirectoryLayoutFiles is a record as the directory layout (before bft-core#1049) holds it: the directory's name (its location, with "-" and
// the manifest digest for a variant) and its files by name. It exists for tests and tools that must reproduce an archive an earlier binary
// wrote; the store itself never writes this layout.
func DirectoryLayoutFiles(q Request, rec *Record, variant bool) (string, map[string][]byte, error) {
	f, err := allFields(rec)
	if err != nil {
		return "", nil, err
	}
	if !bytes.Equal(crypto.Keccak256(rec.Header), q.BlockHash[:]) {
		return "", nil, ErrInvalid
	}
	name, err := location(q, recordV2(rec))
	if err != nil {
		return "", nil, err
	}
	if variant {
		digest, err := ManifestDigest(q, rec)
		if err != nil {
			return "", nil, err
		}
		name += "-" + fmt.Sprintf("%x", digest[:])
	}
	manifest, _, err := encodeManifest(q, rec, f, func() error { return nil })
	if err != nil {
		return "", nil, err
	}
	files := map[string][]byte{"manifest": manifest}
	for k, v := range f {
		files[fileName(k)] = v
	}
	return name, files, nil
}

// exactLayout is one storage layout as an exact read uses it: its manifest digest alone, then the record.
type exactLayout struct {
	digest func(dir, name string) ([32]byte, error)
	read   func(dir string, q Request, v2 bool, name string) (*Record, error)
}

// exactLayouts are the layouts an exact read tries, packed first (as readNamed prefers it), each judged by itself.
var exactLayouts = []exactLayout{
	{digest: packedManifestDigest, read: func(dir string, q Request, v2 bool, name string) (*Record, error) {
		return readPacked(q, v2, packedPath(dir, name))
	}},
	{digest: legacyManifestDigest, read: func(dir string, q Request, v2 bool, name string) (*Record, error) {
		return readLegacy(q, v2, filepath.Join(dir, name))
	}},
}

// manifestDigestOf is the digest a self-hashed manifest carries (the record's ManifestDigest), checked against its own content.
func manifestDigestOf(m []byte) ([32]byte, error) {
	var d [32]byte
	if _, _, _, err := checkManifest(m); err != nil {
		return d, err
	}
	return [32]byte(m[len(m)-32:]), nil
}

// packedManifestDigest is the manifest digest of the packed record file of name; no chunk is read.
func packedManifestDigest(dir, name string) ([32]byte, error) {
	m, err := readPackedManifest(packedPath(dir, name))
	if err != nil {
		return [32]byte{}, err
	}
	return manifestDigestOf(m)
}

// legacyManifestDigest is the manifest digest of the directory-layout record of name; no chunk is read.
func legacyManifestDigest(dir, name string) ([32]byte, error) {
	m, err := readBounded(filepath.Join(dir, name, "manifest"), maxManifestBytes)
	if os.IsNotExist(err) {
		return [32]byte{}, ErrUnavailable
	}
	if err != nil {
		return [32]byte{}, ErrCorrupt
	}
	return manifestDigestOf(m)
}
