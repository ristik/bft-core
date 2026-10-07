package shardnode

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrQ3Epoch is returned when a V3 epoch is activated out of order or without the verified history holding it.
var ErrQ3Epoch = errors.New("shardnode: V3 epoch is not the next activation of the verified history")

// Q3TrustStore is the shard node's root trust over a verified Q3 history: the genesis epoch (and any legacy epoch) from the historical store,
// and every V3 epoch from the verified history's own exact-weight projection, served only once the install journal has completed and
// recovered that activation. It is the TrustBaseStore the certificate client and the adapter verify against, and the epoch authority
// ("which root epoch is current") the observation contexts consult.
//
// The shard node trusts its own Go verification from the pinned root genesis: a V3 epoch exists here only because this node's runtime
// authenticated the old committee's commit of it. Nothing a peer, a certificate or the execution client supplies selects a committee or a
// scheme.
type Q3TrustStore struct {
	*HistoricalTrustBaseStore
	rt      *q3active.Runtime
	guarded *q3active.Guarded
	active  atomic.Uint64 // the latest V3 epoch the follower finished installing (0: none)
}

// NewQ3TrustStore wraps the historical store with the runtime's guarded lookup.
func NewQ3TrustStore(base *HistoricalTrustBaseStore, rt *q3active.Runtime) *Q3TrustStore {
	return &Q3TrustStore{HistoricalTrustBaseStore: base, rt: rt, guarded: rt.Trust(base)}
}

// Guarded is the runtime's trust lookup over this store: the shard participant of the install journal.
func (s *Q3TrustStore) Guarded() *q3active.Guarded { return s.guarded }

// GetByEpoch is the trust base of a root epoch: a V3 epoch's projection once installed, a legacy epoch's after the history agrees with it,
// and an epoch the history does not hold is refused.
func (s *Q3TrustStore) GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	return s.guarded.GetByEpoch(ctx, epoch)
}

// CurrentRootEpoch is the latest epoch whose handoff this node has installed: the V3 follower's, or the historical store's.
func (s *Q3TrustStore) CurrentRootEpoch() (uint64, bool) {
	base, ok := s.HistoricalTrustBaseStore.CurrentRootEpoch()
	if !ok {
		return 0, false
	}
	return max(base, s.active.Load()), true
}

// ActivateQ3 advances the current root epoch to the next V3 epoch once the follower has installed everything the activation needs (the
// shard configuration, the execution transition, the terminal certificate). The epoch must be the one after the current one and be an
// activation of the verified history, completed by the journal.
func (s *Q3TrustStore) ActivateQ3(epoch uint64) error {
	current, _ := s.CurrentRootEpoch()
	if epoch == current {
		return nil
	}
	if epoch != current+1 {
		return fmt.Errorf("%w: %d after %d", ErrQ3Epoch, epoch, current)
	}
	if _, ok := s.rt.Activated(epoch); !ok {
		return fmt.Errorf("%w: %d is not an activation", ErrQ3Epoch, epoch)
	}
	s.active.Store(epoch)
	return nil
}

// IsV2Epoch keeps certificate admission's proof-aware handoff gate closed for a V3 epoch exactly as for a V2 one.
func (s *Q3TrustStore) IsV2Epoch(epoch uint64) bool {
	if _, ok := s.rt.Activated(epoch); ok {
		return true
	}
	return s.HistoricalTrustBaseStore.IsV2Epoch(epoch)
}

// BodyID is the body identity of an epoch: the verified entry's for a V3 epoch.
func (s *Q3TrustStore) BodyID(epoch uint64) ([32]byte, error) {
	if e, ok := s.rt.Activated(epoch); ok {
		return e.BodyID(), nil
	}
	id, err := s.HistoricalTrustBaseStore.BodyID(epoch)
	if err != nil {
		return id, errors.Join(trusthistorystore.ErrHistory, err)
	}
	return id, nil
}
