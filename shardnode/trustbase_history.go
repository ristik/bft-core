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
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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
	utb      atomic.Bool
}

// EnableUTBProfile is WithUTBProfile for a store that is already open; a node of the profile uses the option, because the opening itself verifies the stored handoffs.
//
// EnableUTBProfile says the handoffs this store verifies were committed by roots of the signed trust-base entry profile: their commit certificates are in the
// version 3 envelope and carry the old committee's endorsement, which the verification of an old commit proof then demands. It is set once at start-up from the
// deployment's pinned genesis (--utb-genesis), the shard equivalent of the root's trust-base store flag.
func (s *HistoricalTrustBaseStore) EnableUTBProfile() { s.utb.Store(true) }

// BundleSigning is the signing configuration the old epoch's commit certificate of a bundle is verified under: the legacy scheme, with the UTB envelope when the
// profile is on. (A Q3 shard takes the configuration from its verified history instead.)
func (s *HistoricalTrustBaseStore) BundleSigning(old *types.RootTrustBaseV1) votesig.Config {
	return votesig.Config{Scheme: votesig.SchemeLegacy, Network: uint64(old.NetworkID), UTB: s.utb.Load()}
}

// HistoryOption configures a HistoricalTrustBaseStore before its durable history is opened.
type HistoryOption func(*HistoricalTrustBaseStore)

// WithUTBProfile makes the store verify by the signed trust-base entry profile from the start. It must be an option and not a later call: opening the store re-verifies every
// stored activation proof, and those handoffs were committed in the version 3 envelope.
func WithUTBProfile() HistoryOption { return func(s *HistoricalTrustBaseStore) { s.utb.Store(true) } }

func NewHistoricalTrustBaseStore(ctx context.Context, db keyvaluedb.KeyValueDB, anchor *types.RootTrustBaseV1, executionID [32]byte, profile2 bool, opts ...HistoryOption) (*HistoricalTrustBaseStore, error) {
	out := &HistoricalTrustBaseStore{profile2: profile2}
	for _, o := range opts {
		o(out)
	}
	var verifier trusthistorystore.ActivationVerifier
	if profile2 {
		// the activation proof of every stored handoff is verified (on append and again when the store opens) by the rule of its old epoch: the legacy scheme, in
		// the UTB envelope once the profile is on
		verifier = trustactivation.Verifier{Signing: func(uint64) (votesig.Config, error) {
			return votesig.Config{Scheme: votesig.SchemeLegacy, Network: uint64(anchor.NetworkID), UTB: out.utb.Load()}, nil
		}}
	}
	s, err := trusthistorystore.Open(ctx, db, anchor, executionID, verifier)
	if err != nil {
		return nil, err
	}
	out.history = s
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
	verified, err := handoffdelivery.VerifySigning(bundle, old, s.BundleSigning(old), partition, shard, confHash)
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
