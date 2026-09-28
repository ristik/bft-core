package shardnode

import (
	"context"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/m2contract"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-go-base/types"
)

// HistoricalTrustBaseStore exposes a v2 epoch only after its activation proof
// has been checked on append and again when the durable store is opened.
type HistoricalTrustBaseStore struct {
	history  *trusthistorystore.Store
	profile2 bool
}

func NewHistoricalTrustBaseStore(ctx context.Context, db keyvaluedb.KeyValueDB, anchor *types.RootTrustBaseV1, executionID [32]byte, profile2 bool) (*HistoricalTrustBaseStore, error) {
	var verifier trusthistorystore.ActivationVerifier
	if profile2 {
		verifier = trustactivation.Verifier{}
	}
	s, err := trusthistorystore.Open(ctx, db, anchor, executionID, verifier)
	if err != nil {
		return nil, err
	}
	return &HistoricalTrustBaseStore{history: s, profile2: profile2}, nil
}

func (s *HistoricalTrustBaseStore) AppendVerified(ctx context.Context, in m2contract.TrustInterval, proof []byte) error {
	if !s.profile2 {
		return trusthistorystore.ErrUnsupportedV2
	}
	return s.history.AppendVerified(ctx, in, proof)
}

func (s *HistoricalTrustBaseStore) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	r, err := s.history.ByEpoch(epoch)
	if err != nil {
		return nil, err
	}
	if r.V1 != nil {
		return r.V1, nil
	}
	if !s.profile2 || r.V2 == nil {
		return nil, trusthistorystore.ErrUnsupportedV2
	}
	return trustactivation.Project(r)
}

func (s *HistoricalTrustBaseStore) Evict() { s.history.Evict() }

// IsV2Epoch lets certificate admission keep the proof-aware handoff gate
// closed even after a successor body has been authenticated and persisted.
func (s *HistoricalTrustBaseStore) IsV2Epoch(epoch uint64) bool {
	if !s.profile2 {
		return false
	}
	r, err := s.history.ByEpoch(epoch)
	return err == nil && r.V2 != nil
}
