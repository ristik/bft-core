// Package seed is the public sync seed (VT-11, bft-core#1151): a bundle of untrusted data that a synced validator exports and any web server
// can serve, and that a new validator verifies before it starts as a follower.
//
// Trust model. Nothing in a seed is trusted. The only anchors are what the importer holds independently: the pinned UTB genesis EntryID (and,
// when given, its own shard configuration). Everything else is verified from them: the trust-base history chains from the pinned genesis by
// quorum signatures; the checkpoint's UnicityCertificate verifies against the trust base of its own root epoch taken from that history; the
// manifest's claims (tip, block hash, state root, rounds) must equal what the verified bytes say; every file matches its manifest hash. A seed
// that verifies is still only a point in the past: the node catches up from its peers, which authenticate every later step themselves.
package seed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// Format is the manifest's format tag.
	Format = "unicity.seed.v1"

	ManifestName = "manifest.json"
	UTBFile      = "utb-bundle.cbor"
	TipUCFile    = "tip-uc.cbor"
	TipTRFile    = "tip-tr.cbor"

	// MaxManifestBytes bounds a manifest read from disk or a source.
	MaxManifestBytes = 1 << 20
	// MaxPinFileBytes bounds the checkpoint UC and TR files (the restore pin's own limit).
	MaxPinFileBytes = 1 << 20
	// MaxUTBBytes bounds the trust-base history file: an allocation guard, not a history cap.
	MaxUTBBytes = 256 << 20
)

// ErrSeed is wrapped by every refusal of a seed.
var ErrSeed = errors.New("seed")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrSeed}, a...)...)
}

// fileLimits are the files of a seed and the byte bound of each. A seed has exactly these three payload files.
var fileLimits = map[string]int64{UTBFile: MaxUTBBytes, TipUCFile: MaxPinFileBytes, TipTRFile: MaxPinFileBytes}

// PayloadFiles are the seed's payload files in manifest order.
var PayloadFiles = []string{UTBFile, TipUCFile, TipTRFile}

// File is one payload file of the manifest.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// BlockPin is a certified EVM block as the exporting node's shard node reports it (informational: the checkpoint's verified fields are the
// block hash and state root of Checkpoint).
type BlockPin struct {
	Height    uint64 `json:"height"`
	Hash      string `json:"hash"`
	StateRoot string `json:"stateRoot,omitempty"`
	RootEpoch uint64 `json:"rootEpoch,omitempty"`
	RootRound uint64 `json:"rootRound,omitempty"`
}

// Manifest describes a seed. Its exact bytes are the seed's identity (ManifestDigest): two sources that serve different bytes disagree.
type Manifest struct {
	Format  string `json:"format"`
	Created string `json:"created"` // informational

	Network struct {
		NetworkID    uint32 `json:"networkId"`
		UTBGenesisID string `json:"utbGenesisId"` // the pin, 0x-prefixed SHA-256 EntryID
		UTBTipEpoch  uint64 `json:"utbTipEpoch"`
		UTBTipID     string `json:"utbTipId"`
	} `json:"network"`

	Files []File `json:"files"`

	// Checkpoint is the certified shard tip the seed was taken at. UC and TR are the canonical files (the restore pin's format).
	Checkpoint struct {
		PartitionID uint32 `json:"partitionId"`
		ShardID     string `json:"shardId"` // hex of the shard id bytes ("" for the unsplit shard)
		RootEpoch   uint64 `json:"rootEpoch"`
		RootRound   uint64 `json:"rootRound"`
		ShardRound  uint64 `json:"shardRound"`
		BlockHash   string `json:"blockHash"`
		StateRoot   string `json:"stateRoot"`
		ShardConf   string `json:"shardConfHash"`
		UC          string `json:"uc"`
		TR          string `json:"tr"`
	} `json:"checkpoint"`

	// Archive is the EVM archive's frontier as the exporter's shard node reports it, plus the root epochs whose activation bundles it holds.
	// The archive records themselves are not in the seed: the follower fetches them from archive replicas, authenticating each against the
	// verified checkpoint (restore) as today.
	Archive struct {
		CertifiedTip  *BlockPin `json:"certifiedTip,omitempty"`
		PruneFrontier *BlockPin `json:"pruneFrontier,omitempty"`
		RestoreBase   *BlockPin `json:"restoreBase,omitempty"`
		BundleEpochs  []uint64  `json:"bundleEpochs,omitempty"`
	} `json:"archive"`

	// Ureth is the exporter's execution client at export time. v1 ships no reth snapshot: the client is driven to the head by its shard node
	// (engine API), and this head is the floor the importer's client must reach.
	Ureth *UrethRef `json:"ureth,omitempty"`
}

// UrethRef is the exporter's execution head.
type UrethRef struct {
	HeadNumber uint64 `json:"headNumber"`
	HeadHash   string `json:"headHash"`
	Mode       string `json:"mode"` // "engine-resync": no snapshot, the shard node drives the client
}

// Encode is the manifest's canonical file bytes (indented JSON, trailing newline).
func (m *Manifest) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeManifest strictly decodes a manifest: bounded, no unknown fields, nothing after the object, the format tag.
func DecodeManifest(raw []byte) (*Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return nil, refuse("the manifest is %d bytes (limit %d)", len(raw), MaxManifestBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, refuse("decoding the manifest: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, refuse("the manifest has trailing data")
	}
	if m.Format != Format {
		return nil, refuse("manifest format %q, want %q", m.Format, Format)
	}
	if len(m.Files) != len(PayloadFiles) {
		return nil, refuse("the manifest lists %d files, want %d", len(m.Files), len(PayloadFiles))
	}
	for i, f := range m.Files {
		if f.Name != PayloadFiles[i] {
			return nil, refuse("manifest file %d is %q, want %q", i, f.Name, PayloadFiles[i])
		}
		if f.Size <= 0 || f.Size > fileLimits[f.Name] {
			return nil, refuse("file %s: size %d outside 1..%d", f.Name, f.Size, fileLimits[f.Name])
		}
		if b, err := hex.DecodeString(f.SHA256); err != nil || len(b) != sha256.Size {
			return nil, refuse("file %s: sha256 is not 64 hex digits", f.Name)
		}
	}
	return &m, nil
}

// ManifestDigest is the identity of a seed: the SHA-256 of the exact manifest bytes (which commit to every file's hash).
func ManifestDigest(raw []byte) string {
	s := sha256.Sum256(raw)
	return "0x" + hex.EncodeToString(s[:])
}

func (m *Manifest) file(name string) File {
	for _, f := range m.Files {
		if f.Name == name {
			return f
		}
	}
	return File{}
}

// readBounded reads a regular file of at most max bytes.
func readBounded(path string, max int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, refuse("%s is not a regular file", filepath.Base(path))
	}
	if st.Size() > max {
		return nil, refuse("%s is %d bytes (limit %d)", filepath.Base(path), st.Size(), max)
	}
	return os.ReadFile(path)
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// DecodeManifestFile reads and decodes a seed directory's manifest (shape only: no hashes, no signatures).
func DecodeManifestFile(dir string) (*Manifest, error) {
	raw, err := readBounded(filepath.Join(dir, ManifestName), MaxManifestBytes)
	if err != nil {
		return nil, refuse("reading the manifest: %v", err)
	}
	return DecodeManifest(raw)
}
