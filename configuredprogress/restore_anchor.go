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
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) || b.Get(restoreAnchorKey) != nil {
			return ErrStale
		}
		return b.Put(restoreAnchorKey, raw)
	})
}
