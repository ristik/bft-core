package trustbase

import (
	"bytes"
	"crypto"
	"errors"

	"github.com/unicitynetwork/bft-go-base/types"
)

// InstallV2Projection persists the runtime signature-verification view of a
// proof-verified v2 body. The caller checks the body and G before projecting.
// No synthetic V1 endorsement signatures are created.
func (s *TrustBaseStore) InstallV2Projection(projected *types.RootTrustBaseV1) (*types.RootTrustBaseV1, error) {
	if projected == nil || projected.Epoch < 2 {
		return nil, errors.New("invalid successor projection")
	}
	old, err := s.GetByEpoch(projected.Epoch - 1)
	if err != nil || old.Epoch+1 != projected.Epoch || old.NetworkID != projected.NetworkID {
		return nil, errors.New("old runtime trust base unavailable")
	}
	previousHash, err := old.Hash(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(projected.PreviousEntryHash, previousHash) {
		return nil, errors.New("successor projection predecessor mismatch")
	}
	existing, err := s.GetByEpoch(projected.Epoch)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if existing != nil {
		if existing.EpochStart != projected.EpochStart || existing.QuorumThreshold != projected.QuorumThreshold || len(existing.RootNodes) != len(projected.RootNodes) ||
			!bytes.Equal(existing.PreviousEntryHash, projected.PreviousEntryHash) ||
			!bytes.Equal(existing.StateHash, projected.StateHash) ||
			!bytes.Equal(existing.ChangeRecordHash, projected.ChangeRecordHash) {
			return nil, ErrAlreadyExists
		}
		for i := range existing.RootNodes {
			if existing.RootNodes[i].NodeID != projected.RootNodes[i].NodeID || existing.RootNodes[i].Stake != projected.RootNodes[i].Stake ||
				!bytes.Equal(existing.RootNodes[i].SigKey, projected.RootNodes[i].SigKey) {
				return nil, ErrAlreadyExists
			}
		}
		return existing, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.db.Write(toDBKey(1, projected.Epoch), projected); err != nil {
		return nil, err
	}
	s.cache[projected.Epoch] = projected
	return projected, nil
}
