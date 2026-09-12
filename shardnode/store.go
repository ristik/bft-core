package shardnode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-go-base/types"
)

// FileStore persists the last accepted Unicity Certificate to a single file, so a
// restarted node can seed BFTClient.SeedLUC instead of starting from a cold, empty
// non-equivocation state — see docs/engine-api-adapter-plan.md task C1.4.
//
// The encoding is canonical CBOR, produced by the same types.Cbor codec that computes
// the bytes the certificate's signatures cover. That is not a style preference. This
// store previously used encoding/json, and JSON is *lossy* for these types: hex.Bytes
// marshals nil and empty alike to an empty string and unmarshals that back to nil,
// while canonical CBOR distinguishes empty bytes (0x40) from null (0xf6). A round trip
// therefore silently rewrote a non-nil empty SummaryValue — which BuildInputRecord
// deliberately emits — into nil, changing InputRecord.Bytes() and with it the
// authenticated representation.
//
// The consequences were not cosmetic. A restarted node's restored certificate failed
// its own UC.Verify ("summary value is nil"), and because the restored certificate is
// the authority the non-equivocation check compares against, the node then rejected the
// genuine, correctly signed certificate for that round as "different input records for
// same partition round N" and refused everything after it. See issue #86 and
// docs/design/f1-baseline.md §6.3.1.
//
// Still deliberately simple: one file, overwritten atomically on every call, no history.
// Durable write ordering and fault injection remain F6 (#14) — a rename is not an fsync.
type FileStore struct {
	path string
}

// checkpointVersion is the on-disk format version. Bump it only for a change that an
// older binary must not misread; the reader rejects anything it does not know rather
// than guessing.
const checkpointVersion uint32 = 1

// lucCheckpoint is the versioned envelope actually written. The version travels with the
// data instead of being inferred from the bytes, so a future format change is a clear
// rejection rather than a misparse.
type lucCheckpoint struct {
	_       struct{} `cbor:",toarray"`
	Version uint32
	UC      *types.UnicityCertificate
}

// ErrLegacyJSONCheckpoint is returned by LoadLUC when the file on disk is the old
// encoding/json format. It is deliberately fatal rather than self-healing: the stored
// certificate is this node's non-equivocation authority, the legacy encoding cannot be
// converted losslessly (the nil/empty distinction it destroyed is not recoverable from
// the file itself), and silently continuing would mean either voting from genesis or
// treating a certificate that no longer matches what was signed as authoritative.
// The old file is left untouched for recovery and evidence.
var ErrLegacyJSONCheckpoint = errors.New("shardnode: certificate store is in the legacy JSON format")

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// SaveLUC atomically overwrites the stored certificate: write to a temp
// file in the same directory, then rename over the target, so a crash
// mid-write never leaves a corrupt store for the next restart to trip over.
func (s *FileStore) SaveLUC(uc *types.UnicityCertificate) error {
	data, err := types.Cbor.Marshal(lucCheckpoint{Version: checkpointVersion, UC: uc})
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
	if looksLikeJSON(data) {
		// Distinguish a genuine legacy checkpoint from a damaged file that merely starts with
		// "{" — scripts/chaos-evm.sh's tampering scenario writes exactly that. Both are fatal;
		// only the operator guidance differs, and pointing someone at a migration procedure for
		// a corrupt file wastes their time.
		var legacy types.UnicityCertificate
		if json.Unmarshal(data, &legacy) == nil && legacy.InputRecord != nil && legacy.UnicitySeal != nil {
			return nil, fmt.Errorf("%w (%s): it cannot be converted losslessly, and this node must not "+
				"vote from a certificate that differs from the one that was signed. Recover by copying a "+
				"current certificate store from a healthy validator, or — only for a devnet whose state can "+
				"be discarded — stop the node, move the file aside and re-register the shard. The existing "+
				"file has been left in place", ErrLegacyJSONCheckpoint, s.path)
		}
		return nil, fmt.Errorf("certificate store %s is damaged: it is neither a valid checkpoint nor a "+
			"readable legacy JSON certificate. It has been left in place; recover it from a healthy "+
			"validator rather than deleting it, since starting without it means voting from genesis", s.path)
	}
	var cp lucCheckpoint
	if err := types.Cbor.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("unmarshaling stored certificate: %w", err)
	}
	if cp.Version != checkpointVersion {
		return nil, fmt.Errorf("stored certificate is format version %d, this build understands %d",
			cp.Version, checkpointVersion)
	}
	if cp.UC == nil {
		return nil, errors.New("stored certificate is empty")
	}
	return cp.UC, nil
}

// looksLikeJSON reports whether data begins like a JSON object. A canonical CBOR checkpoint
// is an array-or-tag header, never "{", so this cleanly separates "not our format" from a
// truncated checkpoint. It only selects which error to report — never a fresh-store fallback.
func looksLikeJSON(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("{"))
}
