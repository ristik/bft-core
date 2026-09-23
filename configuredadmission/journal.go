package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// JournalFactory activates the synchronous v2 admission path. Every authenticated UC/TR is
// committed to configured progress and its journal association before BFTClient receives it.
// It deliberately does not coalesce intermediate certificates: recovery needs full history.
type JournalFactory struct {
	Store   *configuredprogress.Store
	Origin  registrygenesis.GenesisOrigin
	Limits  configuredprogress.JournalLimits
	CatchUp func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error
	OnStop  func(error)
}

type journalAdmission struct {
	mu        sync.Mutex
	closed    bool
	store     *configuredprogress.Store
	context   configuredprogress.Context
	limits    configuredprogress.JournalLimits
	gate      shardnode.FinalityBoundary
	callbacks shardnode.AdmissionCallbacks
	epoch     uint64
	catchUp   func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error
	onStop    func(error)
}

func journalContext(origin registrygenesis.GenesisOrigin, id shardnode.AdmissionIdentity) (configuredprogress.Context, error) {
	if !origin.Valid() || id.TrustBases == nil {
		return configuredprogress.Context{}, fmt.Errorf("configuredadmission: journal needs checked origin and trust bases")
	}
	r := origin.Record()
	if uint64(id.PartitionID) != r.PartitionID || !bytes.Equal(id.ShardID.Bytes(), r.ShardID) || !bytes.Equal(id.FullShardConfHash, origin.FullShardConfHash().Bytes()) {
		return configuredprogress.Context{}, fmt.Errorf("configuredadmission: journal identity differs from origin")
	}
	obs := rootinput.ObservationContextV2{NetworkID: types.NetworkID(r.NetworkID), PartitionID: id.PartitionID, ShardID: id.ShardID, ShardConfHash: bytes.Clone(id.FullShardConfHash), RootEpoch: r.RootEpoch, TrustBases: id.TrustBases}
	record := certifiedstore.Context{NetworkID: types.NetworkID(r.NetworkID), PartitionID: id.PartitionID, ShardID: id.ShardID, FullShardConfHash: bytes.Clone(id.FullShardConfHash), Registry: origin.ProofContext(), TrustBases: id.TrustBases}
	return configuredprogress.Context{Origin: origin, Observation: obs, Record: record}, nil
}

func (f JournalFactory) Start(ctx context.Context, id shardnode.AdmissionIdentity, gate shardnode.FinalityBoundary, callbacks shardnode.AdmissionCallbacks) (shardnode.CertificateAdmission, error) {
	if f.Store == nil || gate == nil || callbacks.DeliverDurable == nil || callbacks.AuthenticatedFeed == nil {
		return nil, fmt.Errorf("configuredadmission: incomplete journal admission")
	}
	c, err := journalContext(f.Origin, id)
	if err != nil {
		return nil, err
	}
	if _, err = f.Store.LoadJournal(ctx, c, f.Limits); err != nil {
		return nil, fmt.Errorf("loading execution journal: %w", err)
	}
	a := &journalAdmission{store: f.Store, context: c, limits: f.Limits, gate: gate, callbacks: callbacks, epoch: c.Observation.RootEpoch, catchUp: f.CatchUp, onStop: f.OnStop}
	return a, nil
}

func (a *journalAdmission) Submit(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (outErr error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() {
		if outErr != nil && a.onStop != nil && (errors.Is(outErr, configuredprogress.ErrBounds) || errors.Is(outErr, configuredprogress.ErrConflict) || errors.Is(outErr, configuredprogress.ErrUntrusted) || errors.Is(outErr, configuredprogress.ErrUnavailable) || errors.Is(outErr, ErrRecoveryBudget) || errors.Is(outErr, ErrRecoveryConflict) || errors.Is(outErr, ErrRecoveryUnavailable)) {
			a.onStop(outErr)
		}
	}()
	if a.closed {
		return configuredprogress.ErrAdmissionClosed
	}
	o, err := rootinput.AuthenticateObservationV2(ctx, a.context.Observation, uc, tr)
	if err != nil {
		return err
	}
	p, _, err := a.store.PrepareObservation(ctx, a.context, o)
	if err != nil {
		if a.catchUp == nil || !errors.Is(err, configuredprogress.ErrConflict) && !errors.Is(err, configuredprogress.ErrUnavailable) {
			return err
		}
		if catchErr := a.catchUp(ctx, uc, tr); catchErr != nil {
			return fmt.Errorf("journal peer catch-up after non-contiguous certificate: %w (initial admission: %v)", catchErr, err)
		}
		p, _, err = a.store.PrepareObservation(ctx, a.context, o)
		if err != nil {
			return err
		}
	}
	release, err := a.gate.Hold(ctx, "execution-journal-admission")
	if err != nil {
		return err
	}
	current, _, err := a.store.CommitObservation(p)
	release()
	if err != nil {
		return fmt.Errorf("durable journal admission: %w", err)
	}
	a.callbacks.AuthenticatedFeed(current.Certificate(), current.TechnicalRecord())
	image, err := a.store.LoadJournal(ctx, a.context, a.limits)
	if err != nil {
		return fmt.Errorf("verifying admitted execution journal: %w", err)
	}
	if a.catchUp != nil {
		for _, observed := range image.Observations {
			if observed.Unresolved {
				if catchErr := a.catchUp(ctx, current.Certificate(), current.TechnicalRecord()); catchErr != nil {
					return fmt.Errorf("journal peer catch-up for certified target %x: %w", observed.TargetHash, catchErr)
				}
				image, err = a.store.LoadJournal(ctx, a.context, a.limits)
				if err != nil {
					return fmt.Errorf("verifying fetched execution journal: %w", err)
				}
				break
			}
		}
	}
	for _, observed := range image.Observations {
		if observed.Unresolved {
			return fmt.Errorf("%w: certified target %x has no retained proposal body; certification is durable but the shard remains unready", configuredprogress.ErrUnavailable, observed.TargetHash)
		}
	}
	return a.callbacks.DeliverDurable(ctx, current.Certificate(), current.TechnicalRecord())
}
func (a *journalAdmission) RootEpoch() uint64 { return a.epoch }
func (a *journalAdmission) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	return nil
}

// ProposalJournal adapts the round's opaque Block/Params to the configured-origin store.
type ProposalJournal struct {
	Store   *configuredprogress.Store
	Context configuredprogress.Context
	Limits  configuredprogress.JournalLimits
}

func (j ProposalJournal) RetainCandidate(ctx context.Context, b shardnode.Block, p shardnode.RoundParams, locallyBuilt bool) error {
	if j.Store == nil {
		return configuredprogress.ErrSettings
	}
	if !bytes.Equal(b.ParentHash, p.Parent.Hash) {
		return fmt.Errorf("configuredadmission: candidate parent differs from held executor head")
	}
	return j.Store.PutJournalCandidate(ctx, j.Context, j.Limits, configuredprogress.JournalCandidate{
		Round: p.Round, Number: b.Number, ParentNumber: p.Parent.Number, Hash: b.Hash, StateRoot: b.StateRoot, ParentHash: b.ParentHash, ParentState: p.Parent.StateRoot, Raw: b.Raw, BlockSize: b.BlockSize, StateSize: b.StateSize, LocallyBuilt: locallyBuilt, AuthorizingUC: p.AuthorizingCertificate, AuthorizingTR: p.AuthorizingTechnicalRecord,
	})
}
