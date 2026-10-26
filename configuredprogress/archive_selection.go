package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// An ARCHIVE SELECTION is this journal's durable choice of which resulting certificate the archive representation of one certified block carries (bft-core#876).
//
// The journal's own association of a certified candidate, the first resulting certificate it verified, is consensus-adjacent state and is never touched. The archive requires
// the manifests of a block's copies to be byte-identical across replicas, and two validators can hold different, individually valid first associations for the same block (a
// repeat of the same input record at a later root round). A node whose association differs from the one its replicas already covered and pruned can then never obtain two
// matching copies. When two configured replicas hold the same other valid representation, the node adopts it for ARCHIVE purposes only: one selection record, written once,
// while the block is hot and not yet covered. Everything that rebuilds the archive record of the block (publication, hot verification, frontier coverage) reads the selected
// pair; observations, signing records and the association itself stay as they were.
const journalArchiveSelectionKind uint64 = 11

var journalArchiveSelectionPrefix = []byte("journal/archive-select/")

func archiveSelectionKey(hash []byte) []byte {
	return append(bytes.Clone(journalArchiveSelectionPrefix), hash...)
}

type journalArchiveSelectionWire struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Descriptor []byte
	Hash       []byte
	OldDigest  []byte
	NewDigest  []byte
	UC, TR     []byte
}

// ArchiveSelection is a selected resulting pair for the archive representation of one block.
type ArchiveSelection struct {
	BlockHash [32]byte
	OldDigest [32]byte // the manifest of the representation built from the journal's own association
	NewDigest [32]byte // the manifest of the selected one
	UC        *types.UnicityCertificate
	TR        *certification.TechnicalRecord
	rawUC     []byte
	rawTR     []byte
}

// Raw returns the selected pair as stored.
func (a ArchiveSelection) Raw() (uc, tr []byte) { return bytes.Clone(a.rawUC), bytes.Clone(a.rawTR) }

// ArchiveSelectionRequest is a request to select a pair. Prior identifies the association the selection was planned against (a hash of its pair); a journal whose association
// is another one refuses. The pair is authenticated here, under the journal's historical trust, whatever the caller checked.
type ArchiveSelectionRequest struct {
	BlockHash [32]byte
	Prior     [32]byte
	OldDigest [32]byte
	NewDigest [32]byte
	UC, TR    []byte
}

// PairID is the identity a selection request names its Prior by: a hash of the journal's resulting pair bytes.
func PairID(uc, tr []byte) [32]byte {
	h := sha256.New()
	h.Write(uc)
	h.Write([]byte{0})
	h.Write(tr)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func encodeArchiveSelection(w journalArchiveSelectionWire) ([]byte, error) {
	p, err := marshal(w)
	if err != nil {
		return nil, err
	}
	return encodeEnvelope(journalArchiveSelectionKind, p, 4096+MaxPairBytes*2)
}

func decodeArchiveSelection(raw []byte) (journalArchiveSelectionWire, error) {
	p, err := decodeEnvelope(raw, journalArchiveSelectionKind, 4096+MaxPairBytes*2)
	if err != nil {
		return journalArchiveSelectionWire{}, err
	}
	var w journalArchiveSelectionWire
	err = decodePayload(p, &w)
	return w, err
}

// readArchiveSelection returns the verified selection for the block, or nil. The selected pair is authenticated and must still bind the candidate it was selected for.
func readArchiveSelection(ctx context.Context, b *bolt.Bucket, c Context, descriptor [32]byte, w journalCandidateWire) (*ArchiveSelection, error) {
	raw := b.Get(archiveSelectionKey(w.Hash))
	if raw == nil {
		return nil, nil
	}
	sw, err := decodeArchiveSelection(raw)
	if err != nil {
		return nil, err
	}
	if sw.Version != journalVersion || !bytes.Equal(sw.Descriptor, descriptor[:]) || !bytes.Equal(sw.Hash, w.Hash) || len(sw.OldDigest) != sha256.Size || len(sw.NewDigest) != sha256.Size {
		return nil, fmt.Errorf("%w: archive selection", ErrUntrusted)
	}
	if w.Status != 1 {
		return nil, fmt.Errorf("%w: archive selection of an uncertified candidate", ErrUntrusted)
	}
	if err := bindsArchiveSelection(ctx, c, w, sw.UC, sw.TR); err != nil {
		return nil, err
	}
	uc, tr, err := verifiedPairBytes(ctx, c, sw.UC, sw.TR)
	if err != nil {
		return nil, fmt.Errorf("%w: archive selection: %v", ErrUntrusted, err)
	}
	out := &ArchiveSelection{UC: uc, TR: tr, rawUC: bytes.Clone(sw.UC), rawTR: bytes.Clone(sw.TR)}
	copy(out.BlockHash[:], sw.Hash)
	copy(out.OldDigest[:], sw.OldDigest)
	copy(out.NewDigest[:], sw.NewDigest)
	return out, nil
}

// bindsArchiveSelection checks a selected pair against the candidate it is a representation of: it certifies the SAME input record as the journal's own association (a repeat
// of it), for the same block, and follows the candidate's authorization exactly as an association must.
func bindsArchiveSelection(ctx context.Context, c Context, w journalCandidateWire, uc, tr []byte) error {
	selUC, _, err := verifiedPairBytes(ctx, c, uc, tr)
	if err != nil {
		return fmt.Errorf("%w: selected certificate pair: %v", ErrUntrusted, err)
	}
	ownUC, _, err := verifiedPairBytes(ctx, c, w.ResultingUC, w.ResultingTR)
	if err != nil {
		return fmt.Errorf("%w: existing association: %v", ErrUntrusted, err)
	}
	authUC, _, err := verifiedPairBytes(ctx, c, w.AuthorizingUC, w.AuthorizingTR)
	if err != nil {
		return fmt.Errorf("%w: authorization: %v", ErrUntrusted, err)
	}
	selIR, e1 := types.Cbor.Marshal(selUC.InputRecord)
	ownIR, e2 := types.Cbor.Marshal(ownUC.InputRecord)
	if e1 != nil || e2 != nil || !bytes.Equal(selIR, ownIR) {
		return fmt.Errorf("%w: the selected certificate does not certify the association's complete input record", ErrConflict)
	}
	if selUC.InputRecord == nil || selUC.GetRoundNumber() != w.Round || selUC.InputRecord.RoundNumber != w.Round || !bytes.Equal(selUC.InputRecord.BlockHash, w.Hash) || !bytes.Equal(selUC.InputRecord.Hash, w.StateRoot) ||
		rootinput.CheckEpochCertificates(authUC, selUC) != nil || authUC.GetRootEpoch() == selUC.GetRootEpoch() && authUC.GetRootRoundNumber() >= selUC.GetRootRoundNumber() {
		return fmt.Errorf("%w: the selected certificate does not bind after the candidate's authorization", ErrConflict)
	}
	return nil
}

// SelectArchiveRepresentation records the selection. It is a compare-and-set in ONE Bolt transaction: the block is still a certified candidate whose association is the
// one the selection was planned against, it is above the frontier and the coverage base, no coverage promise exists at its height, and no selection exists (an identical one is
// idempotent, another is a conflict). A committed coverage of the block therefore refuses the selection, and a coverage planned against the earlier representation fails its
// own transaction (checkCoveredCandidate) and is replanned.
func (s *Store) SelectArchiveRepresentation(ctx context.Context, c Context, limits JournalLimits, req ArchiveSelectionRequest) error {
	if !s.journal {
		return fmt.Errorf("%w: journal not enabled", ErrSettings)
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	if err := s.at("before-archive-selection"); err != nil {
		return err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		raw := b.Get(journalCandidateKey(req.BlockHash[:]))
		if raw == nil {
			return fmt.Errorf("%w: the block is no longer a journal candidate (pruned)", ErrConflict)
		}
		w, err := decodeCandidate(raw)
		if err != nil {
			return err
		}
		if w.Status != 1 {
			return fmt.Errorf("%w: the candidate is not certified", ErrConflict)
		}
		if PairID(w.ResultingUC, w.ResultingTR) != req.Prior {
			return fmt.Errorf("%w: the association changed since the selection was planned", ErrStale)
		}
		if existing := b.Get(archiveSelectionKey(req.BlockHash[:])); existing != nil {
			sw, err := decodeArchiveSelection(existing)
			if err != nil {
				return err
			}
			if bytes.Equal(sw.NewDigest, req.NewDigest[:]) && bytes.Equal(sw.UC, req.UC) && bytes.Equal(sw.TR, req.TR) {
				return nil // idempotent
			}
			return fmt.Errorf("%w: another representation is already selected for the block", ErrConflict)
		}
		if b.Get(coverageKey(w.Number)) != nil {
			return fmt.Errorf("%w: the block is already covered at height %d", ErrConflict, w.Number)
		}
		if s.frontier != nil {
			f, err := readFrontier(b, state.i.descriptorDigest, *s.frontier)
			if err != nil {
				return err
			}
			if f.Anchor != nil && w.Number <= f.Anchor.Height {
				return fmt.Errorf("%w: the block is at or below the frontier anchor %d", ErrConflict, f.Anchor.Height)
			}
		}
		if base, _, err := readCoverageBase(b, state.i.descriptorDigest, [32]byte(c.Origin.BlockHash())); err != nil {
			return err
		} else if base != nil && w.Number <= base.Height {
			return fmt.Errorf("%w: the block is at or below the coverage base %d", ErrConflict, base.Height)
		}
		if err := bindsArchiveSelection(ctx, c, w, req.UC, req.TR); err != nil {
			return err
		}
		enc, err := encodeArchiveSelection(journalArchiveSelectionWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Hash: req.BlockHash[:],
			OldDigest: req.OldDigest[:], NewDigest: req.NewDigest[:], UC: bytes.Clone(req.UC), TR: bytes.Clone(req.TR)})
		if err != nil {
			return err
		}
		if err := s.at("before-archive-selection-commit"); err != nil {
			return err
		}
		return b.Put(archiveSelectionKey(req.BlockHash[:]), enc)
	})
	if err != nil {
		return err
	}
	return s.at("after-archive-selection")
}

// ArchiveSelectionOf returns the selection of a block, if there is one. Selections outlive the pruning of the candidate: a pruned block's archive manifest is
// then the one its coverage promise names.
func (s *Store) ArchiveSelectionOf(ctx context.Context, c Context, limits JournalLimits, hash [32]byte) (*ArchiveSelection, error) {
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return nil, err
	}
	var out *ArchiveSelection
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		raw := b.Get(journalCandidateKey(hash[:]))
		if raw == nil {
			return nil
		}
		w, err := decodeCandidate(raw)
		if err != nil {
			return err
		}
		out, err = readArchiveSelection(ctx, b, c, state.i.descriptorDigest, w)
		return err
	})
	return out, err
}

// ArchiveDigestOf returns the manifest digest of the representation selected for a block, if a selection exists, WITHOUT authenticating the pair (it is a routing hint for the default
// read; whoever reads the object recomputes its digest, and the pair itself is authenticated whenever the journal is loaded). The row outlives the candidate's pruning.
func (s *Store) ArchiveDigestOf(ctx context.Context, c Context, limits JournalLimits, hash [32]byte) ([32]byte, bool) {
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return [32]byte{}, false
	}
	var out [32]byte
	found := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if readJournalMeta(b, state.i.descriptorDigest, limits) != nil {
			return nil
		}
		raw := b.Get(archiveSelectionKey(hash[:]))
		if raw == nil {
			return nil
		}
		sw, err := decodeArchiveSelection(raw)
		if err != nil || len(sw.NewDigest) != sha256.Size || !bytes.Equal(sw.Descriptor, state.i.descriptorDigest[:]) {
			return nil
		}
		copy(out[:], sw.NewDigest)
		found = true
		return nil
	})
	return out, found
}
