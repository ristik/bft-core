package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const MaxBundleBytes = 64 << 20
const bundleDomain = "archive/handoff-bundle/1"

// BundleRequest names a complete handoff bundle under the same immutable
// deployment context used for execution records. Epoch is the successor.
type BundleRequest struct {
	Context Context
	Epoch   uint64
}

func EncodeBundleRequest(q BundleRequest) ([]byte, error) {
	if q.Epoch == 0 {
		return nil, ErrInvalid
	}
	probe := Request{Context: q.Context}
	probe.BlockHash[0] = 1
	raw, err := EncodeRequest(probe)
	if err != nil {
		return nil, err
	}
	out := append([]byte(bundleDomain), raw[len(requestDomain):len(raw)-32]...)
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], q.Epoch)
	return append(out, epoch[:]...), nil
}

func DecodeBundleRequest(raw []byte) (BundleRequest, error) {
	if len(raw) < len(bundleDomain)+8 || len(raw) > MaxRequestBytes+32 || !bytes.HasPrefix(raw, []byte(bundleDomain)) {
		return BundleRequest{}, ErrInvalid
	}
	probe := append([]byte(requestDomain), raw[len(bundleDomain):len(raw)-8]...)
	probe = append(probe, make([]byte, 32)...)
	probe[len(probe)-32] = 1
	request, err := DecodeRequest(probe)
	if err != nil {
		return BundleRequest{}, err
	}
	q := BundleRequest{Context: request.Context, Epoch: binary.BigEndian.Uint64(raw[len(raw)-8:])}
	canonical, err := EncodeBundleRequest(q)
	if err != nil || !bytes.Equal(raw, canonical) {
		return BundleRequest{}, ErrInvalid
	}
	return q, nil
}

func bundleName(q BundleRequest) (string, error) {
	raw, err := EncodeBundleRequest(q)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw[:len(raw)-8])
	return fmt.Sprintf("bundle-%016x-%s", q.Epoch, hex.EncodeToString(digest[:])), nil
}

// ErrBundleConflict is a handoff bundle that is semantically different from the one already retained under the same key. Two honest
// copies of one handoff may differ in bytes (the signatures the commit certificate carries, the order of the snapshot's shard entries), but
// they never differ in what they commit to: a difference there is evidence of equivocation or of a bug, and is never absorbed.
var ErrBundleConflict = errors.New("archive: a semantically different handoff bundle is already retained under this key")

// BundleEquivalence decides whether two byte-different bundles under one key are the same handoff. The store cannot: it holds
// untrusted availability bytes and knows no handoff format. The caller verifies BOTH bundles before it compares them.
type BundleEquivalence func(existing, incoming []byte) (bool, error)

// PutBundle atomically retains untrusted availability bytes. Verification of the proof, full snapshot and lineage belongs to the caller.
//
// Under an existing key, identical bytes are a no-op. Different bytes are compared with same: an equivalent bundle is a no-op and the
// first copy is kept (stored is false), a different one is refused with ErrBundleConflict, and so is any difference when same is nil.
func (s *Store) PutBundle(q BundleRequest, raw []byte, same BundleEquivalence) (stored bool, err error) {
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return false, ErrInvalid
	}
	name, err := bundleName(q)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, name)
	if old, err := readBundle(path); err == nil {
		if bytes.Equal(old, raw) {
			return false, nil
		}
		if same == nil {
			return false, ErrBundleConflict
		}
		equal, err := same(old, raw)
		if err != nil {
			return false, err
		}
		if !equal {
			return false, ErrBundleConflict
		}
		return false, nil
	} else if err != ErrUnavailable {
		return false, err
	}
	file, err := os.CreateTemp(s.dir, ".bundle-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(file.Name())
	digest := sha256.Sum256(raw)
	if _, err = file.Write(digest[:]); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return false, err
	}
	if closeErr != nil {
		return false, closeErr
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return false, err
	}
	return true, syncDir(s.dir)
}

func readBundle(path string) ([]byte, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 33 || st.Size() > MaxBundleBytes+32 {
		return nil, ErrCorrupt
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxBundleBytes+33))
	if err != nil || len(raw) != int(st.Size()) {
		return nil, ErrCorrupt
	}
	digest := sha256.Sum256(raw[32:])
	if !bytes.Equal(raw[:32], digest[:]) {
		return nil, ErrCorrupt
	}
	return raw[32:], nil
}

func (s *Store) GetBundle(q BundleRequest) ([]byte, error) {
	name, err := bundleName(q)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return readBundle(filepath.Join(s.dir, name))
}

func (s *Store) BundleEpochs(ctx Context) ([]uint64, error) {
	name, err := bundleName(BundleRequest{Context: ctx, Epoch: 1})
	if err != nil {
		return nil, err
	}
	suffix := name[len("bundle-")+16:]
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var epochs []uint64
	for _, entry := range entries {
		n := entry.Name()
		if !strings.HasPrefix(n, "bundle-") || !strings.HasSuffix(n, suffix) || len(n) != len(name) {
			continue
		}
		epoch, err := strconv.ParseUint(n[len("bundle-"):len("bundle-")+16], 16, 64)
		if err == nil && epoch >= 1 {
			epochs = append(epochs, epoch)
		}
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	return epochs, nil
}
