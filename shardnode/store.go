package shardnode

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-go-base/types"
)

// FileStore persists the last accepted Unicity Certificate to a single JSON
// file, so a restarted node can seed BFTClient.SeedLUC instead of starting
// from a cold, empty non-equivocation state — see
// docs/engine-api-adapter-plan.md task C1.4.
//
// This is deliberately simple: one file, overwritten atomically on every
// call, no history. Sufficient for the exec-mode PoC's single-epoch,
// single-executor-instance scope; a production shard node would want this
// backed by the same keyvaluedb abstraction the root chain uses.
type FileStore struct {
	path string
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// SaveLUC atomically overwrites the stored certificate: write to a temp
// file in the same directory, then rename over the target, so a crash
// mid-write never leaves a corrupt store for the next restart to trip over.
func (s *FileStore) SaveLUC(uc *types.UnicityCertificate) error {
	data, err := json.Marshal(uc)
	if err != nil {
		return fmt.Errorf("marshaling certificate: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating store directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".luc-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("renaming into place: %w", err)
	}
	return nil
}

// LoadLUC returns the stored certificate, or (nil, nil) if this node has
// never certified anything before (fresh start — not an error).
func (s *FileStore) LoadLUC() (*types.UnicityCertificate, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading store: %w", err)
	}
	var uc types.UnicityCertificate
	if err := json.Unmarshal(data, &uc); err != nil {
		return nil, fmt.Errorf("unmarshaling stored certificate: %w", err)
	}
	return &uc, nil
}
