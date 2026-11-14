package archive

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// MigrationResult is what one MigrateLegacy call did.
type MigrationResult struct {
	Migrated int  // directory-layout records now held packed only (their directories removed)
	Skipped  int  // directory-layout records left as they are: damaged, or packed differently under the same name (counted once per Store)
	Done     bool // no directory-layout record that can be migrated is left
}

var errStopListing = errors.New("stop listing")

// MigrateLegacy moves up to max records of the directory layout (before bft-core#1049) to the packed layout, so an archive written by an
// earlier binary sheds its 13 inodes per record without a flag day: every record stays readable throughout, in one layout or the other.
//
// For each record it reads and validates the directory, writes the identical record packed (temporary file, file sync, rename, fan-out
// directory sync: publishPacked), and only once that is durable removes the directory and syncs the store directory, under the store's lock
// so no reader is between the two. A crash between the two steps leaves the record in both layouts, identical; reads prefer the packed copy
// and the next call removes the directory. A directory whose record is already packed identically is removed; one packed differently under the
// same name, or one that is damaged with no sound packed copy, is left untouched and counted as skipped (once per Store). A damaged directory
// whose packed copy is sound is removed: the packed copy is the record. max is bounded by MaxPutBatch.
func (s *Store) MigrateLegacy(max int) (MigrationResult, error) {
	if max <= 0 || max > MaxPutBatch {
		max = MaxPutBatch
	}
	var res MigrationResult
	var names []string
	more := false
	err := listNames(s.dir, 1024, func(chunk []string) error {
		for _, n := range chunk {
			if !recordName(n, true) {
				continue
			}
			s.mu.Lock()
			skip := s.migrateSkip[n]
			s.mu.Unlock()
			if skip {
				continue
			}
			if len(names) == max {
				more = true
				return errStopListing
			}
			names = append(names, n)
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopListing) {
		return res, err
	}
	if len(names) == 0 {
		res.Done = true
		return res, nil
	}
	var items []staged
	var packed [][]byte
	var remove []string
	skip := func(n string) {
		s.mu.Lock()
		if s.migrateSkip == nil {
			s.migrateSkip = map[string]bool{}
		}
		s.migrateSkip[n] = true
		s.mu.Unlock()
		res.Skipped++
	}
	for _, n := range names {
		item, raw, err := s.legacyItem(n)
		if err != nil {
			s.mu.Lock()
			sound := s.soundPacked(n)
			s.mu.Unlock()
			if sound {
				remove = append(remove, n)
			} else {
				skip(n)
			}
			continue
		}
		s.mu.Lock()
		existing, perr := readPacked(item.q, item.v2, s.packedPath(n))
		s.mu.Unlock()
		switch {
		case perr == nil:
			if a, _ := EncodeResponse(Response{item.q, OK, existing}); bytes.Equal(a, item.encoded) {
				remove = append(remove, n) // packed already (an interrupted migration, or a put while the directory was kept)
			} else {
				skip(n)
			}
		case errors.Is(perr, ErrUnavailable):
			items = append(items, item)
			packed = append(packed, raw)
		default:
			skip(n) // a damaged packed copy is left for an operator to see; the directory stays readable
		}
	}
	published, publishErr := s.publishPacked(items, packed, func(q Request, v2 bool, name string, encoded []byte) (bool, error) {
		old, err := readPacked(q, v2, s.packedPath(name))
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
		return true, s.ensureDurableLocked(name)
	})
	for _, it := range published {
		remove = append(remove, it.name)
	}
	if len(remove) != 0 {
		if err := s.removeLegacy(remove); err != nil {
			return res, errors.Join(publishErr, err)
		}
	}
	res.Migrated = len(remove)
	res.Done = !more && publishErr == nil && len(items) == len(published)
	return res, publishErr
}

// legacyItem reads the directory-layout record n and stages its packed form.
func (s *Store) legacyItem(n string) (staged, []byte, error) {
	dir := filepath.Join(s.dir, n)
	m, err := readBounded(filepath.Join(dir, "manifest"), maxManifestBytes)
	if err != nil {
		return staged{}, nil, ErrCorrupt
	}
	q, _, v2, err := checkManifest(m)
	if err != nil {
		return staged{}, nil, err
	}
	rec, err := readLegacy(q, v2, dir)
	if err != nil {
		return staged{}, nil, err
	}
	if !nameMatches(n, q, v2, rec) {
		return staged{}, nil, ErrCorrupt
	}
	f, err := allFields(rec)
	if err != nil {
		return staged{}, nil, err
	}
	manifest, keys, err := encodeManifest(q, rec, f, func() error { return nil })
	if err != nil || !bytes.Equal(manifest, m) {
		return staged{}, nil, ErrCorrupt
	}
	encoded, err := EncodeResponse(Response{q, OK, rec})
	if err != nil {
		return staged{}, nil, err
	}
	return staged{q: q, rec: rec, v2: v2, name: n, final: s.packedPath(n), encoded: encoded}, packRecord(manifest, keys, f), nil
}

// nameMatches reports whether n is the name the record is stored under: its location, and for a variant "-" and its manifest digest.
func nameMatches(n string, q Request, v2 bool, rec *Record) bool {
	loc, err := location(q, v2)
	if err != nil || !strings.HasPrefix(n, loc) {
		return false
	}
	if n == loc {
		return true
	}
	digest, err := ManifestDigest(q, rec)
	return err == nil && n == loc+"-"+hex.EncodeToString(digest[:])
}

// soundPacked reports whether a whole, valid packed record is stored under name n. Called under the store's lock.
func (s *Store) soundPacked(n string) bool {
	path := s.packedPath(n)
	m, err := readPackedManifest(path)
	if err != nil {
		return false
	}
	q, _, v2, err := checkManifest(m)
	if err != nil {
		return false
	}
	rec, err := readPacked(q, v2, path)
	return err == nil && nameMatches(n, q, v2, rec)
}

// removeLegacy removes the directories of records held packed and syncs the store directory, under the store's lock.
func (s *Store) removeLegacy(names []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fault("migrate-before-remove"); err != nil {
		return err
	}
	// a packed copy this call found rather than wrote may not be durable (placed by a seed, or by an earlier process whose directory sync
	// failed): it is synced before the directory, the other copy, goes
	for _, n := range names {
		if err := s.ensureDurableLocked(n); err != nil {
			return err
		}
	}
	for _, n := range names {
		if err := os.RemoveAll(filepath.Join(s.dir, n)); err != nil {
			return err
		}
	}
	return s.ops().syncDir(s.dir)
}
