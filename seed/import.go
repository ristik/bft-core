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

// CheckImportDestination decides, BEFORE anything is written anywhere, whether importing v into home is allowed: no import yet (a fresh start), the
// same seed again (a resume), or another seed with replace. Call it before touching any entry store, so a refused replacement changes nothing. It
// reports whether the destination exists (the publication then replaces it).
func CheckImportDestination(home string, v *Verified, replace bool) (replacing bool, err error) {
	final := filepath.Join(home, ImportDir)
	old, err := ReadImportRecord(home)
	switch {
	case err != nil && !replace:
		return false, err
	case old != nil && old.ManifestDigest != v.ManifestDigest && !replace:
		return false, refuse("%s already holds an import of seed %s; pass --replace to replace it with %s", home, old.ManifestDigest, v.ManifestDigest)
	case old != nil:
		return true, nil
	}
	if _, err := os.Lstat(final); err == nil {
		if !replace {
			return false, refuse("%s exists and is not a seed import; pass --replace to replace it", final)
		}
		return true, nil
	}
	return false, nil
}

// Import places a verified seed in a validator home: <home>/seed/{manifest.json, the payload files, import.json}. The files are what Verify
// returned (never re-read from a source). Call it LAST, after every requested store install has succeeded: the record is the statement that the
// import is complete. Importing the same seed again is a resume (it republishes the identical files); another seed over an existing import needs
// replace, so a start from one seed is never silently changed to another. The directory is staged privately (exclusive creation) and swapped in by
// rename; the previous import stays in place until the new one is.
func Import(v *Verified, home string, sources []string, replace bool, now time.Time) (*ImportRecord, error) {
	final := filepath.Join(home, ImportDir)
	replacing, err := CheckImportDestination(home, v, replace)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(home, ".seed-import-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
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
		rec.UnverifiedUrethHead = v.Manifest.Ureth.HeadNumber
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(tmp, ImportRecordName), append(raw, '\n')); err != nil {
		return nil, err
	}
	if err := publishDir(tmp, final, replacing); err != nil {
		return nil, err
	}
	return rec, nil
}
