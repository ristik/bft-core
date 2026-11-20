package seed

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utb"
)

// Pins are what the importer holds independently of the seed.
type Pins struct {
	// GenesisID is the pinned EntryID of the UTB genesis entry. Required: a seed without it authenticates nothing.
	GenesisID [types.TrustBaseV2IDLen]byte
	// MinTipEpoch, when set, refuses a seed whose trust-base history ends before it (a floor against a stale seed).
	MinTipEpoch uint64
	// Partition and Shard, when set, are the importer's own shard (from its shard configuration): the checkpoint must be of that shard.
	Partition *types.PartitionID
	Shard     *types.ShardID
}

// Verified is a seed that passed every check, with the decoded evidence.
type Verified struct {
	Manifest       *Manifest
	ManifestRaw    []byte
	ManifestDigest string
	Bundle         *types.TrustBaseBundle
	UC             *types.UnicityCertificate
	TR             *certification.TechnicalRecord
	// Files are the verified payload bytes by name.
	Files map[string][]byte
}

// ParseGenesisID reads a 0x-prefixed (or bare) 32-byte hex EntryID.
func ParseGenesisID(s string) ([types.TrustBaseV2IDLen]byte, error) {
	var pin [types.TrustBaseV2IDLen]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil || len(b) != len(pin) {
		return pin, refuse("the genesis pin must be a %d-byte hex EntryID", len(pin))
	}
	copy(pin[:], b)
	return pin, nil
}

// VerifyDir reads a seed directory (the manifest and exactly its three payload files; any other file is ignored, never read) and verifies it. The
// manifest is parsed first and its validated sizes bound the payload reads; every file is opened without following a symlink and checked on the
// opened descriptor.
func VerifyDir(dir string, p Pins) (*Verified, error) {
	mraw, err := ReadFileBounded(filepath.Join(dir, ManifestName), MaxManifestBytes)
	if err != nil {
		return nil, refuse("reading the manifest: %v", err)
	}
	m, err := DecodeManifest(mraw)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, f := range m.Files {
		b, err := ReadFileBounded(filepath.Join(dir, f.Name), f.Size)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, refuse("the seed has no %s", f.Name)
			}
			return nil, refuse("reading %s: %v", f.Name, err)
		}
		files[f.Name] = b
	}
	return Verify(mraw, files, p)
}

// Verify checks a seed given as bytes. Order: manifest shape, file hashes, the trust-base history against the pinned genesis, the manifest's
// network claims against that history, the checkpoint certificate against the trust base of its own root epoch, the manifest's checkpoint
// claims against the certificate.
func Verify(manifestRaw []byte, files map[string][]byte, p Pins) (v *Verified, err error) {
	// the decoders and verifiers are fed untrusted bytes: whatever they might still trip over becomes a refusal of the seed
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, refuse("the seed could not be verified (malformed certificate: %v)", r)
		}
	}()
	m, err := DecodeManifest(manifestRaw)
	if err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		b, ok := files[f.Name]
		switch {
		case !ok:
			return nil, refuse("the seed has no %s", f.Name)
		case int64(len(b)) != f.Size:
			return nil, refuse("%s is %d bytes, the manifest says %d", f.Name, len(b), f.Size)
		case sum(b) != strings.ToLower(f.SHA256):
			return nil, refuse("%s does not match its manifest hash", f.Name)
		}
	}
	if m.Checkpoint.UC != TipUCFile || m.Checkpoint.TR != TipTRFile {
		return nil, refuse("the checkpoint must name %s and %s", TipUCFile, TipTRFile)
	}

	// 1. the trust-base history, chained from the pinned genesis
	utbRaw := files[UTBFile]
	bundle, err := types.DecodeTrustBaseBundle(utbRaw, types.TrustBaseLimits{MaxBytes: len(utbRaw), MaxEntries: len(utbRaw)/16 + 1})
	if err != nil {
		return nil, refuse("the trust-base history: %v", err)
	}
	if err := types.VerifyTrustBaseBundle(bundle, p.GenesisID); err != nil {
		return nil, refuse("the trust-base history does not verify against the pinned genesis: %v", err)
	}
	tip := bundle.Tip()
	tipID, err := tip.EntryID()
	if err != nil {
		return nil, err
	}
	genID, _ := bundle.Entries[0].EntryID()
	switch {
	case !strings.EqualFold(m.Network.UTBGenesisID, "0x"+hex.EncodeToString(genID[:])):
		return nil, refuse("the manifest's genesis id is not the history's")
	case m.Network.UTBTipEpoch != tip.Epoch || !strings.EqualFold(m.Network.UTBTipID, "0x"+hex.EncodeToString(tipID[:])):
		return nil, refuse("the manifest's trust-base tip (epoch %d) is not the history's tip (epoch %d)", m.Network.UTBTipEpoch, tip.Epoch)
	case uint64(m.Network.NetworkID) != uint64(bundle.Network):
		return nil, refuse("the manifest's network id %d is not the history's %d", m.Network.NetworkID, bundle.Network)
	case tip.Epoch < p.MinTipEpoch:
		return nil, refuse("the seed's trust-base history ends at epoch %d, below the required %d (a stale seed)", tip.Epoch, p.MinTipEpoch)
	}

	// 2. the checkpoint certificate
	var uc types.UnicityCertificate
	var tr certification.TechnicalRecord
	ucRaw, trRaw := files[TipUCFile], files[TipTRFile]
	if err := types.Cbor.Unmarshal(ucRaw, &uc); err != nil {
		return nil, refuse("decoding the checkpoint UC: %v", err)
	}
	if err := types.Cbor.Unmarshal(trRaw, &tr); err != nil {
		return nil, refuse("decoding the checkpoint TR: %v", err)
	}
	if again, err := types.Cbor.Marshal(&uc); err != nil || !bytes.Equal(again, ucRaw) {
		return nil, refuse("the checkpoint UC is not canonical CBOR")
	}
	if again, err := types.Cbor.Marshal(&tr); err != nil || !bytes.Equal(again, trRaw) {
		return nil, refuse("the checkpoint TR is not canonical CBOR")
	}
	// every field the accessors and the verifier dereference must be present: a certificate with a missing part is a refusal, not a panic
	switch {
	case uc.InputRecord == nil || uc.UnicitySeal == nil:
		return nil, refuse("the checkpoint UC has no input record or seal")
	case uc.UnicityTreeCertificate == nil:
		return nil, refuse("the checkpoint UC has no unicity tree certificate")
	case len(uc.TRHash) != 32 || len(uc.ShardConfHash) != 32:
		return nil, refuse("the checkpoint UC's TR hash or shard configuration hash is not 32 bytes")
	}
	if err := tr.IsValid(); err != nil {
		return nil, refuse("the checkpoint TR: %v", err)
	}
	if err := tr.HashMatches(uc.TRHash); err != nil {
		return nil, refuse("the checkpoint TR does not match the UC: %v", err)
	}
	rootEpoch := uc.GetRootEpoch()
	var entry *types.RootTrustBaseV2
	for _, e := range bundle.Entries {
		if e.Epoch == rootEpoch {
			entry = e
		}
	}
	if entry == nil {
		if rootEpoch > tip.Epoch {
			return nil, refuse("the checkpoint is of root epoch %d but the seed's trust-base history ends at epoch %d (a stale or truncated history)", rootEpoch, tip.Epoch)
		}
		return nil, refuse("the trust-base history has no entry for the checkpoint's root epoch %d", rootEpoch)
	}
	tb, err := utb.Projection(entry)
	if err != nil {
		return nil, refuse("the trust base of epoch %d: %v", rootEpoch, err)
	}
	if uint64(uc.UnicitySeal.NetworkID) != uint64(bundle.Network) {
		return nil, refuse("the checkpoint UC is of network %d, the history's is %d", uc.UnicitySeal.NetworkID, bundle.Network)
	}
	partition, shard := uc.GetPartitionID(), uc.GetShardID()
	if err := uc.Verify(quorumweight.Checked(tb), crypto.SHA256, partition, shard, uc.ShardConfHash); err != nil {
		return nil, refuse("the checkpoint UC does not verify against the trust base of root epoch %d: %v", rootEpoch, err)
	}
	if p.Partition != nil && *p.Partition != partition {
		return nil, refuse("the checkpoint is of partition %d, this node's is %d", partition, *p.Partition)
	}
	if p.Shard != nil && !bytes.Equal(p.Shard.Bytes(), shard.Bytes()) {
		return nil, refuse("the checkpoint is of another shard than this node's")
	}

	// 3. the manifest's claims are what the verified bytes say
	cp := m.Checkpoint
	ir := uc.InputRecord
	switch {
	case cp.PartitionID != uint32(partition) || cp.ShardID != hex.EncodeToString(shard.Bytes()):
		return nil, refuse("the manifest's partition or shard is not the certificate's")
	case cp.RootEpoch != rootEpoch || cp.RootRound != uc.GetRootRoundNumber() || cp.ShardRound != ir.RoundNumber:
		return nil, refuse("the manifest's checkpoint rounds are not the certificate's")
	case !hexEq(cp.BlockHash, ir.BlockHash) || !hexEq(cp.StateRoot, ir.Hash) || !hexEq(cp.ShardConf, uc.ShardConfHash):
		return nil, refuse("the manifest's block hash, state root or shard configuration hash is not the certificate's")
	}
	return &Verified{Manifest: m, ManifestRaw: manifestRaw, ManifestDigest: ManifestDigest(manifestRaw), Bundle: bundle, UC: &uc, TR: &tr, Files: files}, nil
}

func hexEq(s string, b []byte) bool {
	return strings.EqualFold(strings.TrimPrefix(s, "0x"), hex.EncodeToString(b))
}

// Summary is one line for an operator.
func (v *Verified) Summary() string {
	cp := v.Manifest.Checkpoint
	return fmt.Sprintf("seed %s: trust-base epochs %d..%d, checkpoint root epoch %d round %d, shard round %d, block %s",
		v.ManifestDigest, v.Bundle.Entries[0].Epoch, v.Bundle.Tip().Epoch, cp.RootEpoch, cp.RootRound, cp.ShardRound, cp.BlockHash)
}
