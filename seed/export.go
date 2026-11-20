package seed

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/archive"
)

// ExportInput is what a synced validator supplies.
type ExportInput struct {
	// UTBBundle is the node's complete signed trust-base history (the GetTrustBase bundle encoding).
	UTBBundle []byte
	// GenesisID is the pinned genesis EntryID the exporter checks its own export against.
	GenesisID [types.TrustBaseV2IDLen]byte
	// ArchiveDir is the shard node's archive directory (immutable record files, readable while the node runs).
	ArchiveDir string
	// StatusJSON, when set, is the shard node's /api/v1/operator/status answer: its frontier pins go into the manifest.
	StatusJSON []byte
	// Ureth, when set, is asked about the archive tip's block (its number and hash): it returns the execution client's reference, or refuses when
	// the client does not hold that block (an exporter whose execution client disagrees with its archive exports nothing).
	Ureth func(height uint64, blockHash string) (*UrethRef, error)
	Now   time.Time
}

// ArchiveTip is the newest certified record of an archive: the checkpoint the seed is taken at.
type ArchiveTip struct {
	Request          archive.Request
	UC, TR           []byte
	Header           []byte
	RootEpoch, Round uint64
}

// ScanArchiveTip finds the archive's newest certified record by root epoch and root round (shard rounds restart at a handoff, so the shard round
// alone cannot order records), preferring version 2 records, which keep the complete proof material. The result is availability data: Verify
// authenticates it against the trust-base history before a seed leaves.
func ScanArchiveTip(dir string) (*ArchiveTip, error) {
	var best *ArchiveTip
	var bestV2 bool
	err := archive.StoredNames(dir, 1024, func(names []string) error {
		for _, name := range names {
			q, rec, err := archive.ReadStored(dir, name)
			if err != nil || rec == nil {
				continue
			}
			var uc types.UnicityCertificate
			if types.Cbor.Unmarshal(rec.ResultingUC, &uc) != nil || uc.InputRecord == nil || len(uc.InputRecord.BlockHash) != 32 || len(rec.ResultingTR) == 0 {
				continue
			}
			v2 := archive.HasReceiptList(rec)
			e, r := uc.GetRootEpoch(), uc.GetRootRoundNumber()
			better := best == nil || v2 != bestV2 && v2 || v2 == bestV2 && (e > best.RootEpoch || e == best.RootEpoch && r > best.Round)
			if better {
				best, bestV2 = &ArchiveTip{Request: q, UC: rec.ResultingUC, TR: rec.ResultingTR, Header: rec.Header, RootEpoch: e, Round: r}, v2
			}
		}
		return nil
	})
	if err != nil {
		return nil, refuse("reading the archive: %v", err)
	}
	if best == nil {
		return nil, refuse("the archive holds no certified record")
	}
	return best, nil
}

// Height is the EVM block number of the archive tip.
func (t *ArchiveTip) Height() (uint64, error) {
	var h gethtypes.Header
	if err := rlp.DecodeBytes(t.Header, &h); err != nil || h.Number == nil {
		return 0, refuse("the archive tip header does not decode")
	}
	return h.Number.Uint64(), nil
}

// bundleEpochs lists the root epochs whose activation bundles the archive holds (files "bundle-<16 hex epoch>-...", in bundles/ or the directory
// itself).
func bundleEpochs(dir string) []uint64 {
	seen := map[uint64]bool{}
	for _, d := range []string{filepath.Join(dir, "bundles"), dir} {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			rest, ok := strings.CutPrefix(e.Name(), "bundle-")
			if !ok || e.IsDir() || len(rest) < 17 || rest[16] != '-' {
				continue
			}
			if n, err := strconv.ParseUint(rest[:16], 16, 64); err == nil {
				seen[n] = true
			}
		}
	}
	out := make([]uint64, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Export writes a seed directory and verifies it before returning: an exporter never publishes a seed its own checks refuse.
func Export(in ExportInput, outDir string) (*Verified, error) {
	tip, err := ScanArchiveTip(in.ArchiveDir)
	if err != nil {
		return nil, err
	}
	bundle, err := types.DecodeTrustBaseBundle(in.UTBBundle, types.TrustBaseLimits{MaxBytes: len(in.UTBBundle), MaxEntries: len(in.UTBBundle)/16 + 1})
	if err != nil {
		return nil, refuse("the node's trust-base history: %v", err)
	}
	tipID, err := bundle.Tip().EntryID()
	if err != nil {
		return nil, err
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(tip.UC, &uc); err != nil {
		return nil, refuse("the archive tip UC: %v", err)
	}

	m, payload := assemble(bundle, tipID, in.UTBBundle, tip.UC, tip.TR, &uc, in.GenesisID, in.Now)
	cp := &m.Checkpoint
	m.Archive.BundleEpochs = bundleEpochs(in.ArchiveDir)
	if len(in.StatusJSON) > 0 {
		var st struct {
			CertifiedTip  *BlockPin `json:"certifiedTip"`
			PruneFrontier *BlockPin `json:"pruneFrontier"`
			RestoreBase   *BlockPin `json:"restoreBase"`
		}
		if err := json.Unmarshal(in.StatusJSON, &st); err != nil {
			return nil, refuse("the shard node status: %v", err)
		}
		m.Archive.CertifiedTip, m.Archive.PruneFrontier, m.Archive.RestoreBase = st.CertifiedTip, st.PruneFrontier, st.RestoreBase
	}
	if err := checkHeaderMatches(tip, &uc); err != nil {
		return nil, err
	}
	if in.Ureth != nil {
		h, err := tip.Height()
		if err != nil {
			return nil, err
		}
		if m.Ureth, err = in.Ureth(h, cp.BlockHash); err != nil {
			return nil, refuse("the execution client: %v", err)
		}
	}

	manifest, err := m.Encode()
	if err != nil {
		return nil, err
	}
	// Verify before anything is written, from the same bytes that will be written.
	v, err := Verify(manifest, payload, Pins{GenesisID: in.GenesisID})
	if err != nil {
		return nil, fmt.Errorf("the node's own seed does not verify, nothing exported: %w", err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	for _, n := range PayloadFiles {
		if err := writeAtomic(filepath.Join(outDir, n), payload[n]); err != nil {
			return nil, err
		}
	}
	if err := writeAtomic(filepath.Join(outDir, ManifestName), manifest); err != nil { // last: a directory with a manifest is complete
		return nil, err
	}
	return v, nil
}

// checkHeaderMatches refuses an archive record whose header is not the block the certificate commits to.
func checkHeaderMatches(tip *ArchiveTip, uc *types.UnicityCertificate) error {
	var h gethtypes.Header
	if err := rlp.DecodeBytes(tip.Header, &h); err != nil {
		return refuse("the archive tip header: %v", err)
	}
	if h.Hash().Hex() != "0x"+hex.EncodeToString(uc.InputRecord.BlockHash) {
		return refuse("the archive tip header is not the block its certificate commits to")
	}
	return nil
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// assemble builds the manifest and the payload map of a seed from its parts.
func assemble(bundle *types.TrustBaseBundle, tipID [types.TrustBaseV2IDLen]byte, utbRaw, ucRaw, trRaw []byte, uc *types.UnicityCertificate,
	genesis [types.TrustBaseV2IDLen]byte, now time.Time) (*Manifest, map[string][]byte) {
	m := &Manifest{Format: Format, Created: now.UTC().Format(time.RFC3339)}
	m.Network.NetworkID = uint32(bundle.Network)
	m.Network.UTBGenesisID = "0x" + hex.EncodeToString(genesis[:])
	m.Network.UTBTipEpoch = bundle.Tip().Epoch
	m.Network.UTBTipID = "0x" + hex.EncodeToString(tipID[:])
	payload := map[string][]byte{UTBFile: utbRaw, TipUCFile: ucRaw, TipTRFile: trRaw}
	for _, n := range PayloadFiles {
		m.Files = append(m.Files, File{Name: n, Size: int64(len(payload[n])), SHA256: sum(payload[n])})
	}
	cp := &m.Checkpoint
	cp.PartitionID, cp.ShardID = uint32(uc.GetPartitionID()), hex.EncodeToString(uc.GetShardID().Bytes())
	cp.RootEpoch, cp.RootRound, cp.ShardRound = uc.GetRootEpoch(), uc.GetRootRoundNumber(), uc.InputRecord.RoundNumber
	cp.BlockHash, cp.StateRoot = "0x"+hex.EncodeToString(uc.InputRecord.BlockHash), "0x"+hex.EncodeToString(uc.InputRecord.Hash)
	cp.ShardConf, cp.UC, cp.TR = "0x"+hex.EncodeToString(uc.ShardConfHash), TipUCFile, TipTRFile

	return m, payload
}
