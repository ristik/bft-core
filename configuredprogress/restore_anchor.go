package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

const restoreAnchorKind uint64 = 9

var restoreAnchorKey = []byte("journal/restore-anchor")

// RestoreAnchor is the certified execution base installed only after a full
// archive replay from genesis. It is not a two-replica pruning acknowledgment.
// A later journal suffix is checked against this exact block identity.
type RestoreAnchor struct {
	Height    uint64
	Hash      [32]byte
	StateRoot [32]byte
	RootRound uint64
}

type restoreAnchorWire struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Descriptor []byte
	Height     uint64
	Hash       []byte
	StateRoot  []byte
	RootRound  uint64
}

func readRestoreAnchor(b *bolt.Bucket, descriptor [32]byte, image JournalSnapshot) (*RestoreAnchor, error) {
	raw := b.Get(restoreAnchorKey)
	if raw == nil {
		return nil, nil
	}
	payload, err := decodeEnvelope(raw, restoreAnchorKind, 4096)
	if err != nil {
		return nil, err
	}
	var w restoreAnchorWire
	if err := decodePayload(payload, &w); err != nil {
		return nil, err
	}
	if w.Version != journalVersion || !bytes.Equal(w.Descriptor, descriptor[:]) || w.Height == 0 || w.RootRound == 0 || len(w.Hash) != sha256.Size || len(w.StateRoot) != sha256.Size {
		return nil, ErrContext
	}
	var out RestoreAnchor
	out.Height, out.RootRound = w.Height, w.RootRound
	copy(out.Hash[:], w.Hash)
	copy(out.StateRoot[:], w.StateRoot)
	if image.Frontier != nil && image.Frontier.Anchor != nil && image.Frontier.Anchor.Height > out.Height {
		return &out, nil // the checked marker remains reportable after the frontier supersedes its body
	}
	if len(image.Observations) == 0 || image.Observations[len(image.Observations)-1].UC.InputRecord == nil {
		return nil, ErrUntrusted
	}
	bound := false
	for _, entry := range image.Candidates {
		if entry.Certified && entry.Candidate.Number == out.Height && bytes.Equal(entry.Candidate.Hash, out.Hash[:]) &&
			bytes.Equal(entry.Candidate.StateRoot, out.StateRoot[:]) && entry.ResultingUC.GetRootRoundNumber() == out.RootRound {
			bound = true
			break
		}
	}
	if !bound {
		return nil, fmt.Errorf("%w: restored anchor lacks its certified journal body", ErrUntrusted)
	}
	return &out, nil
}

func encodeCoverageBase(descriptor [32]byte, base CoverageBase) ([]byte, error) {
	w := journalCoverageBaseWire{Version: journalVersion, Descriptor: descriptor[:], Height: base.Height, Hash: base.Hash[:]}
	payload, err := marshal(w)
	if err != nil {
		return nil, err
	}
	return encodeEnvelope(journalCoverageBaseKind, payload, 4096)
}

// readCoverageBase binds a non-genesis coverage base to the durable verified
// restore pin. A missing base is valid only for a journal with no restore pin.
func readCoverageBase(b *bolt.Bucket, descriptor [32]byte, genesis [32]byte) (*CoverageBase, bool, error) {
	raw := b.Get(journalCoverageBaseKey)
	if raw == nil {
		anchorRaw := b.Get(restoreAnchorKey)
		if anchorRaw == nil {
			return &CoverageBase{Hash: genesis}, false, nil
		}
		payload, err := decodeEnvelope(anchorRaw, restoreAnchorKind, 4096)
		if err != nil {
			return nil, false, err
		}
		var anchor restoreAnchorWire
		if err := decodePayload(payload, &anchor); err != nil {
			return nil, false, err
		}
		if anchor.Version != journalVersion || !bytes.Equal(anchor.Descriptor, descriptor[:]) || anchor.Height == 0 ||
			len(anchor.Hash) != sha256.Size || len(anchor.StateRoot) != sha256.Size || anchor.RootRound == 0 {
			return nil, false, ErrUntrusted
		}
		var base CoverageBase
		base.Height = anchor.Height
		copy(base.Hash[:], anchor.Hash)
		if base.Hash == ([32]byte{}) {
			return nil, false, ErrUntrusted
		}
		return &base, true, nil
	}
	payload, err := decodeEnvelope(raw, journalCoverageBaseKind, 4096)
	if err != nil {
		return nil, false, err
	}
	var w journalCoverageBaseWire
	if err := decodePayload(payload, &w); err != nil {
		return nil, false, err
	}
	if w.Version != journalVersion || !bytes.Equal(w.Descriptor, descriptor[:]) || w.Height == 0 || len(w.Hash) != sha256.Size {
		return nil, false, ErrContext
	}
	var hash [32]byte
	copy(hash[:], w.Hash)
	if hash == ([32]byte{}) {
		return nil, false, ErrUntrusted
	}
	// The restore marker is written in the same transaction as this base. Its
	// envelope and descriptor bind the base to the pin that restore verified.
	anchorRaw := b.Get(restoreAnchorKey)
	if anchorRaw == nil {
		return nil, false, fmt.Errorf("%w: coverage base has no verified restore pin", ErrUntrusted)
	}
	anchorPayload, err := decodeEnvelope(anchorRaw, restoreAnchorKind, 4096)
	if err != nil {
		return nil, false, err
	}
	var anchor restoreAnchorWire
	if err := decodePayload(anchorPayload, &anchor); err != nil {
		return nil, false, err
	}
	if anchor.Version != journalVersion || !bytes.Equal(anchor.Descriptor, descriptor[:]) || anchor.Height != w.Height || !bytes.Equal(anchor.Hash, w.Hash) {
		return nil, false, fmt.Errorf("%w: coverage base differs from verified restore pin", ErrUntrusted)
	}
	var out CoverageBase
	out.Height = w.Height
	copy(out.Hash[:], w.Hash)
	return &out, false, nil
}

// persistCoverageBase upgrades a journal created before the explicit base
// marker existed. The only migration source is its already verified durable
// restore pin, and the write is immutable and monotonic.
func (s *Store) persistCoverageBase(ctx context.Context, c Context, base *CoverageBase) error {
	if base == nil || base.Height == 0 || base.Hash == ([32]byte{}) {
		return ErrUntrusted
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	raw, err := encodeCoverageBase(state.i.descriptorDigest, *base)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		current, missing, err := readCoverageBase(b, state.i.descriptorDigest, [32]byte(c.Origin.BlockHash()))
		if err != nil {
			return err
		}
		if current.Height != base.Height || current.Hash != base.Hash {
			return fmt.Errorf("%w: coverage base cannot move backwards or change identity", ErrConflict)
		}
		if !missing {
			return nil
		}
		return b.Put(journalCoverageBaseKey, raw)
	})
}

// InstallRestoreAnchor durably marks the certified replay target as the base
// for subsequent journal recovery. The caller has already imported all of its
// ancestors through the paired Engine path and checked the EL head and root.
func (s *Store) InstallRestoreAnchor(ctx context.Context, c Context, limits JournalLimits, a RestoreAnchor) error {
	if !s.journal || a.Height == 0 || a.RootRound == 0 || a.Hash == ([32]byte{}) || a.StateRoot == ([32]byte{}) {
		return ErrSettings
	}
	image, err := s.LoadJournal(ctx, c, limits)
	if err != nil {
		return err
	}
	if image.Restored != nil || image.Frontier != nil || len(image.Candidates) != 1 || len(image.Observations) == 0 ||
		!bytes.Equal(image.Observations[len(image.Observations)-1].UC.InputRecord.Hash, a.StateRoot[:]) {
		return ErrConflict
	}
	matched := false
	for _, entry := range image.Candidates {
		matched = entry.Certified && entry.Candidate.Number == a.Height && bytes.Equal(entry.Candidate.Hash, a.Hash[:]) &&
			bytes.Equal(entry.Candidate.StateRoot, a.StateRoot[:]) && entry.ResultingUC.GetRootRoundNumber() == a.RootRound
	}
	if !matched {
		return ErrUntrusted
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	w := restoreAnchorWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Height: a.Height,
		Hash: a.Hash[:], StateRoot: a.StateRoot[:], RootRound: a.RootRound}
	payload, err := marshal(w)
	if err != nil {
		return err
	}
	raw, err := encodeEnvelope(restoreAnchorKind, payload, 4096)
	if err != nil {
		return err
	}
	coverageRaw, err := encodeCoverageBase(state.i.descriptorDigest, CoverageBase{Height: a.Height, Hash: a.Hash})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) || b.Get(restoreAnchorKey) != nil || b.Get(journalCoverageBaseKey) != nil {
			return ErrStale
		}
		if err := b.Put(restoreAnchorKey, raw); err != nil {
			return err
		}
		return b.Put(journalCoverageBaseKey, coverageRaw)
	})
}
