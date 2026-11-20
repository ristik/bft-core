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
	UrethHead      uint64   `json:"seedUrethHead,omitempty"`
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

// Import places a verified seed in a validator home: <home>/seed/{manifest.json, the payload files, import.json}. The files are what Verify
// returned (never re-read from a source). An existing import is refused unless replace is set, so a start from one seed is never silently
// changed to another. The home is created if missing; nothing else in it is touched.
func Import(v *Verified, home string, sources []string, replace bool, now time.Time) (*ImportRecord, error) {
	final := filepath.Join(home, ImportDir)
	if old, err := ReadImportRecord(home); err != nil {
		return nil, err
	} else if old != nil && !replace {
		return nil, refuse("%s already holds an import of seed %s; pass --replace to replace it", home, old.ManifestDigest)
	} else if old == nil {
		if _, err := os.Lstat(final); err == nil && !replace {
			return nil, refuse("%s exists and is not a seed import; pass --replace to replace it", final)
		}
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
		if err := os.WriteFile(filepath.Join(tmp, n), v.Files[n], 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, ManifestName), v.ManifestRaw, 0o644); err != nil {
		return nil, err
	}
	cp := v.Manifest.Checkpoint
	rec := &ImportRecord{Format: importRecordFormat, ManifestDigest: v.ManifestDigest, Sources: sources, ImportedAt: now.UTC().Format(time.RFC3339),
		UTBGenesisID: v.Manifest.Network.UTBGenesisID, UTBTipEpoch: v.Manifest.Network.UTBTipEpoch, RootEpoch: cp.RootEpoch, RootRound: cp.RootRound,
		ShardRound: cp.ShardRound, BlockHash: cp.BlockHash}
	if v.Manifest.Ureth != nil {
		rec.UrethHead = v.Manifest.Ureth.HeadNumber
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, ImportRecordName), append(raw, '\n'), 0o644); err != nil {
		return nil, err
	}
	if replace {
		if err := os.RemoveAll(final); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, err
	}
	return rec, nil
}
