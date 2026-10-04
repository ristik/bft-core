package trustbase

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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

// InstallVerified persists the verifier projection of an epoch whose protocol configuration the bound verified history holds. cfg
// must be exactly the history's configuration for that epoch: the projection cannot select its own scheme. It is idempotent and
// otherwise InstallV2Projection (a different projection for an installed epoch is ErrAlreadyExists).
func (s *TrustBaseStore) InstallVerified(projected *types.RootTrustBaseV1, cfg votesig.Config) (*types.RootTrustBaseV1, error) {
	if projected == nil {
		return nil, errors.New("invalid successor projection")
	}
	s.mu.RLock()
	authority := s.signing.authority
	s.mu.RUnlock()
	if authority == nil {
		return nil, fmt.Errorf("%w: no verified history is bound", ErrSigningHistory)
	}
	want, err := authority.Signing(projected.Epoch)
	if err != nil {
		return nil, fmt.Errorf("%w: epoch %d: %w", ErrSigningHistory, projected.Epoch, err)
	}
	if want != cfg || cfg.Network != uint64(projected.NetworkID) {
		return nil, fmt.Errorf("%w: epoch %d: configuration differs from the verified history's", ErrSigningHistory, projected.Epoch)
	}
	return s.InstallV2Projection(projected)
}
