package shardnode

import (
	"context"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-go-base/types"
)

// HistoricalTrustBaseStore gives shard verification its v1 anchor while
// retaining checked epoch/round history for catch-up. The v2 branch remains
// unavailable to UC verification until WP3 activates it.
type HistoricalTrustBaseStore struct{ history *trusthistorystore.Store }

func NewHistoricalTrustBaseStore(ctx context.Context, db keyvaluedb.KeyValueDB, anchor *types.RootTrustBaseV1, executionID [32]byte, verifier trusthistorystore.ActivationVerifier) (*HistoricalTrustBaseStore, error) {
	s, err := trusthistorystore.Open(ctx, db, anchor, executionID, verifier)
	if err != nil {
		return nil, err
	}
	return &HistoricalTrustBaseStore{history: s}, nil
}
func (s *HistoricalTrustBaseStore) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	r, err := s.history.ByEpoch(epoch)
	if err != nil {
		return nil, err
	}
	if r.V1 == nil {
		return nil, trusthistorystore.ErrUnsupportedV2
	}
	return r.V1, nil
}
func (s *HistoricalTrustBaseStore) GetByRound(round uint64) (trusthistorystore.Record, error) {
	return s.history.ByRound(round)
}
func (s *HistoricalTrustBaseStore) Evict() { s.history.Evict() }
