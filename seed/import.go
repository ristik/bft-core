package seed

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// ImportDir is the verified seed's directory in a validator home.
	ImportDir = "seed"
	// ImportRecordName is the record of an import, beside the seed files in ImportDir.
	ImportRecordName   = "import.json"
	importRecordFormat = "unicity.seed.import.v1"
)

// ImportRecord is what `ubft validator status` reads about the seed a node started from.
type ImportRecord struct {
	Format         string   `json:"format"`
	ManifestDigest string   `json:"manifestDigest"`
	Sources        []string `json:"sources,omitempty"`
	ImportedAt     string   `json:"importedAt"`
	UTBGenesisID   string   `json:"utbGenesisId"`
	UTBTipEpoch    uint64   `json:"utbTipEpoch"`
	RootEpoch      uint64   `json:"checkpointRootEpoch"`
	RootRound      uint64   `json:"checkpointRootRound"`
	ShardRound     uint64   `json:"checkpointShardRound"`
	BlockHash      string   `json:"checkpointBlockHash"`
	// UnverifiedUrethHead is the exporter's claimed execution head: an observation nothing verified, for status only.
	UnverifiedUrethHead uint64 `json:"unverifiedExporterUrethHead,omitempty"`
}

// ReadImportRecord reads a home's import record; (nil, nil) when the node did not start from a seed.
func ReadImportRecord(home string) (*ImportRecord, error) {
	raw, err := readBounded(filepath.Join(home, ImportDir, ImportRecordName), MaxManifestBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r ImportRecord
	if err := json.Unmarshal(raw, &r); err != nil || r.Format != importRecordFormat {
		return nil, fmt.Errorf("%w: the import record in %s is not valid", ErrSeed, home)
	}
	return &r, nil
}

// ImportTxn is one import of a seed into a home, holding the destination lock from the first check until Close: two imports of the same home cannot
// interleave, so the decision made at Begin is the one Commit publishes under, and no store is advanced by an import that another one is deciding.
type ImportTxn struct {
	v         *Verified
	home      string
	unlock    func()
	existing  *ImportRecord // an import of the same seed is already complete
	replacing bool
}

// BeginImport takes the home's import lock and decides, before anything is written anywhere, whether v may be imported: no import yet (a fresh start),
// the same seed again (a resume: the stores may be completed, the published import stays as it is), or another seed with replace. A refused
// import returns before any store is touched. The caller installs into its entry stores, then Commit publishes, then Close releases the lock.
func BeginImport(home string, v *Verified, replace bool) (*ImportTxn, error) {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	final := filepath.Join(home, ImportDir)
	unlock, err := lockDir(final)
	if err != nil {
		return nil, err
	}
	t := &ImportTxn{v: v, home: home, unlock: unlock}
	old, err := ReadImportRecord(home)
	switch {
	case err != nil && !replace:
		unlock()
		return nil, err
	case old != nil && old.ManifestDigest == v.ManifestDigest:
		t.existing = old
		return t, nil
	case old != nil && !replace:
		unlock()
		return nil, refuse("%s already holds an import of seed %s; pass --replace to replace it with %s", home, old.ManifestDigest, v.ManifestDigest)
	case old != nil:
		t.replacing = true
	default:
		if _, err := os.Lstat(final); err == nil {
			if !replace {
				unlock()
				return nil, refuse("%s exists and is not a seed import; pass --replace to replace it", final)
			}
			t.replacing = true
		}
	}
	// a replacement must be atomic (the published import.json is never absent): refuse it BEFORE any store is touched where it cannot be
	if t.replacing && !canExchange(home) {
		unlock()
		return nil, refuse("replacing an import atomically is not supported on this system: remove %s by hand and import again", final)
	}
	return t, nil
}

// Close releases the lock.
func (t *ImportTxn) Close() { t.unlock() }

// Commit publishes the import: the staged directory with the record last. Importing the same seed again (a complete import exists) publishes nothing.
func (t *ImportTxn) Commit(sources []string, now time.Time) (*ImportRecord, error) {
	if t.existing != nil {
		return t.existing, nil
	}
	v, home := t.v, t.home
	tmp, err := os.MkdirTemp(home, ".seed-import-")
	if err != nil {
		return nil, err
	}
	var cerr error
	defer func() { cleanStage(tmp, cerr) }()
	for _, n := range PayloadFiles {
		if err := writeNew(filepath.Join(tmp, n), v.Files[n]); err != nil {
			return nil, err
		}
	}
	if err := writeNew(filepath.Join(tmp, ManifestName), v.ManifestRaw); err != nil {
		return nil, err
	}
	cp := v.Manifest.Checkpoint
	rec := &ImportRecord{Format: importRecordFormat, ManifestDigest: v.ManifestDigest, Sources: sources, ImportedAt: now.UTC().Format(time.RFC3339),
		UTBGenesisID: v.Manifest.Network.UTBGenesisID, UTBTipEpoch: v.Manifest.Network.UTBTipEpoch, RootEpoch: cp.RootEpoch, RootRound: cp.RootRound,
		ShardRound: cp.ShardRound, BlockHash: cp.BlockHash}
	if v.Manifest.Ureth != nil {
		// the exporter's claimed execution head: an observation nothing verified, for status only
		rec.UnverifiedUrethHead = v.Manifest.Ureth.HeadNumber
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(tmp, ImportRecordName), append(raw, '\n')); err != nil {
		return nil, err
	}
	if cerr = publishLocked(tmp, filepath.Join(home, ImportDir), t.replacing); cerr != nil {
		return nil, cerr
	}
	return rec, nil
}

// Import is BeginImport, Commit and Close for a caller that has no stores to install into.
func Import(v *Verified, home string, sources []string, replace bool, now time.Time) (*ImportRecord, error) {
	t, err := BeginImport(home, v, replace)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	return t.Commit(sources, now)
}
