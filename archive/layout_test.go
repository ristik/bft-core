package archive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// putLegacy stores a record in the directory layout, as a store before bft-core#1049 wrote it: one file per field and a manifest in a
// directory named by the record's location (and, for a variant, its manifest digest), renamed into the store directory complete.
func putLegacy(t testing.TB, dir string, q Request, rec *Record, variant bool) string {
	t.Helper()
	name, files, err := DirectoryLayoutFiles(q, rec, variant)
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := os.MkdirTemp(dir, ".writing-")
	if err != nil {
		t.Fatal(err)
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(tmp, n), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	return name
}

// legacyDirs lists the directory-layout records in a store directory.
func legacyDirs(t *testing.T, dir string) (out []string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() && recordName(e.Name(), true) {
			out = append(out, e.Name())
		}
	}
	return out
}

func encoded(t *testing.T, q Request, rec *Record) []byte {
	t.Helper()
	b, err := EncodeResponse(Response{q, OK, rec})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// variantOf is another valid representation of the same block: the same request, another resulting certificate (bft-core#876).
func variantOf(rec *Record) *Record {
	v := *rec
	v.ResultingTR = append(bytes.Clone(rec.ResultingTR), 0x01)
	return &v
}

// A store written before #1049 holds its records as directories. Every read finds them, a put of the same record is a no-op (nothing is
// written packed), a put of different content under the same request is refused, and the round index covers both layouts.
func TestDirectoryLayoutRecordsAreReadImmutableAndIndexed(t *testing.T) {
	qs, recs := batchFixture(t, 3)
	dir := t.TempDir()
	putLegacy(t, dir, qs[0], recs[0], false)
	putLegacy(t, dir, qs[0], variantOf(recs[0]), true)
	putLegacy(t, dir, qs[1], recs[1], false)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(qs[2], recs[2]); err != nil { // a new record goes packed
		t.Fatal(err)
	}
	for i := range qs {
		got, err := s.Get(qs[i])
		if err != nil || !bytes.Equal(encoded(t, qs[i], got), encoded(t, qs[i], recs[i])) {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	digest, _ := ManifestDigest(qs[0], variantOf(recs[0]))
	if got, err := s.GetExact(qs[0], digest); err != nil || !bytes.Equal(got.ResultingTR, variantOf(recs[0]).ResultingTR) {
		t.Fatalf("the directory-layout variant: %v", err)
	}
	if err := s.Put(qs[0], recs[0]); err != nil {
		t.Fatalf("the same record again: %v", err)
	}
	loc, _ := location(qs[0], false)
	if _, err := os.Stat(s.packedPath(loc)); !os.IsNotExist(err) {
		t.Fatalf("a put of a record held in the directory layout wrote it packed: %v", err)
	}
	changed := *recs[0]
	changed.Body = []byte("changed")
	if err := s.Put(qs[0], &changed); !errors.Is(err, ErrInvalid) {
		t.Fatalf("different content under a directory-layout record: %v", err)
	}
	for i := range qs {
		got, _, err := s.GetLatest(RoundRequest{Context: qs[i].Context, Round: uint64(i + 1)})
		if err != nil || got.BlockHash != qs[i].BlockHash {
			t.Fatalf("round index, record %d: %v", i, err)
		}
	}
	var listed []string
	if err := StoredNames(dir, 2, func(names []string) error { listed = append(listed, names...); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 3 {
		t.Fatalf("StoredNames lists each base record once, in its layout: %v", listed)
	}
	for _, n := range listed {
		q, rec, err := ReadStored(dir, n)
		if err != nil || !slices.ContainsFunc(qs, func(x Request) bool { return x.BlockHash == q.BlockHash }) || rec == nil {
			t.Fatalf("ReadStored %s: %v", n, err)
		}
	}
}

// A packed record that is damaged does not hide a sound directory-layout copy of the same record, and a truncated or altered packed file is
// refused as corrupt, never read in part.
func TestPackedRecordDamageIsRefusedWhole(t *testing.T) {
	q, rec := fixture()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(q, rec); err != nil {
		t.Fatal(err)
	}
	loc, _ := location(q, false)
	path := s.packedPath(loc)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, damaged := range map[string][]byte{
		"truncated":            good[:len(good)-1],
		"a chunk byte flipped": append(bytes.Clone(good[:len(good)-1]), good[len(good)-1]^1),
		"trailing bytes":       append(bytes.Clone(good), 0),
		"another magic":        append([]byte("ARCHPAK2"), good[8:]...),
	} {
		if err := os.WriteFile(path, damaged, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(q); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	putLegacy(t, s.dir, q, rec, false)
	if got, err := s.Get(q); err != nil || !bytes.Equal(got.Body, rec.Body) {
		t.Fatalf("the sound directory copy is read past the damaged packed one: %v", err)
	}
	if err := os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(q); err != nil {
		t.Fatal(err)
	}
}

// MigrateLegacy moves every directory-layout record, base and variant, to the packed layout in bounded steps; every record reads the same
// throughout and after, the directories are gone, and nothing is left to migrate.
func TestMigrateLegacyMovesEveryRecordInBoundedSteps(t *testing.T) {
	const n = 2*MaxPutBatch + 5
	qs, recs := batchFixture(t, n)
	dir := t.TempDir()
	for i := range qs {
		putLegacy(t, dir, qs[i], recs[i], false)
	}
	putLegacy(t, dir, qs[0], variantOf(recs[0]), true)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	calls, migrated := 0, 0
	for {
		res, err := s.MigrateLegacy(MaxPutBatch)
		if err != nil {
			t.Fatal(err)
		}
		calls++
		migrated += res.Migrated
		if res.Skipped != 0 {
			t.Fatalf("nothing is damaged: %+v", res)
		}
		if res.Done {
			break
		}
		if calls > 10 {
			t.Fatal("migration does not end")
		}
	}
	if migrated != n+1 || calls < 3 {
		t.Fatalf("%d records migrated in %d calls, want %d in at least 3", migrated, calls, n+1)
	}
	if left := legacyDirs(t, dir); len(left) != 0 {
		t.Fatalf("directories left: %v", left)
	}
	for i := range qs {
		got, err := s.Get(qs[i])
		if err != nil || !bytes.Equal(encoded(t, qs[i], got), encoded(t, qs[i], recs[i])) {
			t.Fatalf("record %d after the migration: %v", i, err)
		}
	}
	digest, _ := ManifestDigest(qs[0], variantOf(recs[0]))
	if _, err := s.GetExact(qs[0], digest); err != nil {
		t.Fatalf("the variant after the migration: %v", err)
	}
	if res, err := s.MigrateLegacy(MaxPutBatch); err != nil || !res.Done || res.Migrated != 0 {
		t.Fatalf("a migrated store: %+v %v", res, err)
	}
	if left := leftovers(t, s); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

// A crash after a record is durably packed and before its directory is removed leaves the record in both layouts: it reads, and the next
// migration removes the directory without writing again.
func TestMigrateLegacyInterruptedBeforeTheRemovalIsCompletedNextTime(t *testing.T) {
	qs, recs := batchFixture(t, 3)
	dir := t.TempDir()
	for i := range qs {
		putLegacy(t, dir, qs[i], recs[i], false)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	crash := errors.New("crash")
	s.Fault = func(point string) error {
		if point == "migrate-before-remove" {
			return crash
		}
		return nil
	}
	if _, err := s.MigrateLegacy(MaxPutBatch); !errors.Is(err, crash) {
		t.Fatalf("the fault: %v", err)
	}
	s.Fault = nil
	if len(legacyDirs(t, dir)) != 3 {
		t.Fatal("the directories are kept until the packed copies are durable and the removal runs")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range qs {
		if _, err := reopened.Get(qs[i]); err != nil {
			t.Fatalf("record %d in both layouts: %v", i, err)
		}
	}
	log := &opLog{}
	log.install(reopened)
	res, err := reopened.MigrateLegacy(MaxPutBatch)
	if err != nil || !res.Done || res.Migrated != 3 {
		t.Fatalf("the completion: %+v %v", res, err)
	}
	if log.count("rename") != 0 {
		t.Fatalf("records already packed are not written again: %v", log.events)
	}
	if len(legacyDirs(t, dir)) != 0 {
		t.Fatal("directories left")
	}
}

// A damaged directory with no packed copy, and a directory packed differently under the same name, are left untouched (and counted once);
// a damaged directory whose packed copy is sound is removed.
func TestMigrateLegacyLeavesWhatItCannotProveAndRemovesWhatIsHeldPacked(t *testing.T) {
	qs, recs := batchFixture(t, 4)
	dir := t.TempDir()
	damaged := putLegacy(t, dir, qs[0], recs[0], false)
	if err := os.Remove(filepath.Join(dir, damaged, fileName("body"))); err != nil {
		t.Fatal(err)
	}
	conflicting := putLegacy(t, dir, qs[1], recs[1], false)
	putLegacy(t, dir, qs[2], recs[2], false)
	repaired := putLegacy(t, dir, qs[3], recs[3], false)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// another record packed under the conflicting name (only an outside writer can do that), and a sound packed copy of record 3
	other := *recs[1]
	other.Body = []byte("other")
	writePacked(t, s, conflicting, qs[1], &other)
	writePacked(t, s, repaired, qs[3], recs[3])
	if err := os.Remove(filepath.Join(dir, repaired, fileName("header"))); err != nil {
		t.Fatal(err)
	}
	res, err := s.MigrateLegacy(MaxPutBatch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Migrated != 2 || res.Skipped != 2 {
		t.Fatalf("record 2 migrated and record 3's damaged directory removed; records 0 and 1 left: %+v", res)
	}
	if got := legacyDirs(t, dir); !slices.Equal(sorted(got), sorted([]string{damaged, conflicting})) {
		t.Fatalf("directories left: %v", got)
	}
	if res, err := s.MigrateLegacy(MaxPutBatch); err != nil || !res.Done || res.Skipped != 0 {
		t.Fatalf("what was left is not counted again: %+v %v", res, err)
	}
	if _, err := s.Get(qs[0]); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the damaged record reads as before: %v", err)
	}
}

// Reads never miss a record while it is being migrated.
func TestMigrateLegacyConcurrentWithReads(t *testing.T) {
	qs, recs := batchFixture(t, 2*MaxPutBatch)
	dir := t.TempDir()
	for i := range qs {
		putLegacy(t, dir, qs[i], recs[i], false)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	var readErr error
	var once sync.Once
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				if _, err := s.Get(qs[i%len(qs)]); err != nil {
					once.Do(func() { readErr = err })
				}
			}
		}()
	}
	for {
		res, err := s.MigrateLegacy(8)
		if err != nil {
			t.Fatal(err)
		}
		if res.Done {
			break
		}
	}
	close(done)
	wg.Wait()
	if readErr != nil {
		t.Fatalf("a read during the migration: %v", readErr)
	}
}

func writePacked(t *testing.T, s *Store, name string, q Request, rec *Record) {
	t.Helper()
	f, err := allFields(rec)
	if err != nil {
		t.Fatal(err)
	}
	manifest, keys, err := encodeManifest(q, rec, f, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareRecordDirs(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.packedPath(name), packRecord(manifest, keys, f), 0600); err != nil {
		t.Fatal(err)
	}
}

func sorted(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }
