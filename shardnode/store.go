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
// Still deliberately simple: one file, overwritten durably on every call, no history.
// SaveLUC syncs both the temporary file and the directory that names it, in that order, so a
// power loss cannot lose a completed save; see the write sequence comment on SaveLUC.
type FileStore struct {
	path string

	// checkpoint, when set by tests, is called at named points of SaveLUC. A returned error
	// fails the save at that point; a checkpoint may also end the process to model a crash.
	// Mirrors certifiedstore.Store.checkpoint so the fault-injection shape is the same on both
	// stores.
	checkpoint func(name string) error
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

func (s *FileStore) at(name string) error {
	if s.checkpoint == nil {
		return nil
	}
	return s.checkpoint(name)
}

/*
syncFile makes a temporary checkpoint's data durable before the rename that names it. That order
matters: a durable directory entry pointing at data the device has not written is the one
arrangement that can produce a file which exists and does not parse. On macOS os.File.Sync issues
F_FULLFSYNC, so no platform-specific code is needed.

It is a package variable rather than a direct call so the durability tests can inject a failure and
confirm SaveLUC reports it instead of continuing. certifiedstore keeps its directory sync in the
same shape for the same reason.
*/
var syncFile = func(f *os.File) error { return f.Sync() }

/*
syncDirectory makes a directory entry durable. A rename changes the directory that names the file,
and syncing the file does not sync that directory, so a power loss shortly after a successful
SaveLUC can lose the entry entirely. LoadLUC then treats the absent file as a clean fresh start,
which restarts a long-running validator from genesis.

This deliberately mirrors certifiedstore.syncDirectory instead of sharing it: shardnode must not
import certifiedstore, and the reach guards enforce that. Keeping the same shape means a later
extraction into a shared internal package is mechanical, and doing it here would change a merged
durability path and its fault-injection hook for no functional gain.
*/
var syncDirectory = func(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the directory of the operator-configured store path
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

/*
SaveLUC durably overwrites the stored certificate. The sequence is:

 1. create a temporary file in the target's directory;
 2. write the encoded checkpoint;
 3. sync the temporary file, so its data is durable before anything names it;
 4. close it;
 5. rename it over the target, so no reader sees a half-written checkpoint;
 6. sync the parent directory, so the entry the rename created is durable.

Steps 3 and 6 are what make the write durable, and they are separate because a rename changes a
directory entry while syncing the file does not sync the directory. The order of 3 before 5 is the
part that matters for integrity: a durable entry pointing at data that is not yet durable is the
only arrangement that can produce a file which exists and does not parse. Without step 6 a power
loss can drop the entry and LoadLUC would read an absent file as a clean fresh start.

Any step failing returns an error. Steps 1 to 4 leave the existing file untouched; step 5 has
already replaced it, so a failure at step 6 reports that the new certificate's durability is not
established even though a reader now sees it. The deferred remove still clears the temporary file
on every in-process failure path.
*/
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

	if err := s.at("before-write"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("before writing the temporary certificate: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := s.at("after-write"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("after writing the temporary certificate: %w", err)
	}
	// Before the rename, so the entry can never name data that is not durable.
	if err := syncFile(tmp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := s.at("after-file-sync"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("after syncing the temporary certificate: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := s.at("after-close"); err != nil {
		return fmt.Errorf("after closing the temporary certificate: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("renaming into place: %w", err)
	}
	if err := s.at("after-rename"); err != nil {
		return fmt.Errorf("after renaming the certificate into place: %w", err)
	}
	// After the rename: the entry now names the new file, but only syncing the directory makes
	// that entry durable across a power loss.
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("syncing store directory: %w", err)
	}
	if err := s.at("after-dir-sync"); err != nil {
		return fmt.Errorf("after syncing the store directory: %w", err)
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
