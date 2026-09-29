package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
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
	active   atomic.Uint64
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
	out := &HistoricalTrustBaseStore{history: s, profile2: profile2}
	out.active.Store(anchor.Epoch)
	return out, nil
}

// CurrentRootEpoch advances only after the native bundle, local snapshot and
// execution transition have all been installed by the follower.
func (s *HistoricalTrustBaseStore) CurrentRootEpoch() (uint64, bool) {
	if !s.profile2 {
		return 0, false
	}
	return s.active.Load(), true
}

func (s *HistoricalTrustBaseStore) ActivateHandoff(epoch uint64) error {
	if !s.profile2 || epoch == 0 {
		return trusthistorystore.ErrUnsupportedV2
	}
	for {
		current := s.active.Load()
		if epoch == current {
			return nil
		}
		if current == ^uint64(0) || epoch != current+1 {
			return trusthistorystore.ErrHistory
		}
		r, err := s.history.ByEpoch(epoch)
		if err != nil || r.V2 == nil {
			return trusthistorystore.ErrHistory
		}
		if s.active.CompareAndSwap(current, epoch) {
			return nil
		}
	}
}

func (s *HistoricalTrustBaseStore) AppendVerified(ctx context.Context, in m2contract.TrustInterval, proof []byte) error {
	if !s.profile2 {
		return trusthistorystore.ErrUnsupportedV2
	}
	return s.history.AppendVerified(ctx, in, proof)
}

// InstallHandoff checks a fetched native proof, full shard snapshot and exact
// local shard configuration before extending durable trust lineage.
func (s *HistoricalTrustBaseStore) InstallHandoff(ctx context.Context, bundle handoffdelivery.Bundle,
	partition types.PartitionID, shard types.ShardID, confHash []byte) (handoffdelivery.Verified, error) {
	if !s.profile2 || bundle.Proof.Record.Epoch == ^uint64(0) {
		return handoffdelivery.Verified{}, trusthistorystore.ErrUnsupportedV2
	}
	prior, err := s.history.ByEpoch(bundle.Proof.Record.Epoch)
	if err != nil {
		return handoffdelivery.Verified{}, err
	}
	var predecessor []byte
	if prior.V1 != nil {
		predecessor, err = prior.V1.Hash(crypto.SHA256)
	} else if prior.V2 != nil {
		predecessor = prior.BodyID[:]
	} else {
		return handoffdelivery.Verified{}, trusthistorystore.ErrHistory
	}
	if err != nil || !bytes.Equal(predecessor, bundle.Proof.Record.PredecessorBodyID) {
		return handoffdelivery.Verified{}, handoffdelivery.ErrBundle
	}
	old, err := s.GetByEpoch(ctx, prior.Epoch)
	if err != nil {
		return handoffdelivery.Verified{}, err
	}
	verified, err := handoffdelivery.Verify(bundle, old, partition, shard, confHash)
	if err != nil {
		return handoffdelivery.Verified{}, err
	}
	id := bundle.Body.Identity()
	interval := m2contract.TrustInterval{Body: bundle.Body, Activation: evmroot.ActivatedTrustBase{
		BodyIdentity: id[:], EpochStart: verified.Genesis.Start, ActivationCommitID: verified.Record.RecordID[:]}}
	proof, err := types.Cbor.Marshal(bundle.Proof)
	if err != nil {
		return handoffdelivery.Verified{}, err
	}
	if err := s.history.AppendVerified(ctx, interval, proof); err != nil {
		if !errors.Is(err, trusthistorystore.ErrAlreadyExists) {
			return handoffdelivery.Verified{}, err
		}
		stored, lookupErr := s.history.ByEpoch(bundle.Body.Epoch)
		if lookupErr != nil || stored.V2 == nil || stored.BodyID != id || stored.Start != verified.Genesis.Start {
			return handoffdelivery.Verified{}, fmt.Errorf("%w: fetched handoff conflicts with durable history", handoffdelivery.ErrBundle)
		}
	}
	return verified, nil
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

func (s *HistoricalTrustBaseStore) BodyID(epoch uint64) ([32]byte, error) {
	record, err := s.history.ByEpoch(epoch)
	if err != nil {
		return [32]byte{}, err
	}
	if record.V2 != nil {
		return record.BodyID, nil
	}
	if record.V1 == nil {
		return [32]byte{}, trusthistorystore.ErrHistory
	}
	raw, err := record.V1.Hash(crypto.SHA256)
	var out [32]byte
	copy(out[:], raw)
	return out, err
}

// IsV2Epoch lets certificate admission keep the proof-aware handoff gate
// closed even after a successor body has been authenticated and persisted.
func (s *HistoricalTrustBaseStore) IsV2Epoch(epoch uint64) bool {
	if !s.profile2 {
		return false
	}
	r, err := s.history.ByEpoch(epoch)
	return err == nil && r.V2 != nil
}
