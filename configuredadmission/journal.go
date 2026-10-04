package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/evmroot"
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
	Store             *configuredprogress.Store
	Origin            registrygenesis.GenesisOrigin
	ExecutionConfigV2 [32]byte
	Limits            configuredprogress.JournalLimits
	CatchUp           func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error
	OnStop            func(error)
	Logger            *slog.Logger
	EpochAuthority    rootinput.RootEpochAuthority
	// Freshness, when set, is started with the admission: it runs the automatic root-quorum
	// bootstrap acquisition and learns of ordinary progress the admission authenticates (#350).
	Freshness *Freshness
}

type journalAdmission struct {
	mu              sync.Mutex
	closed          bool
	store           *configuredprogress.Store
	context         configuredprogress.Context
	limits          configuredprogress.JournalLimits
	gate            shardnode.FinalityBoundary
	callbacks       shardnode.AdmissionCallbacks
	epoch           uint64
	catchUp         func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error
	freshness       *Freshness
	onStop          func(error)
	logger          *slog.Logger
	ctx             context.Context
	closeCh         chan struct{}
	retrying        bool
	pendingUC       *types.UnicityCertificate
	pendingTR       *certification.TechnicalRecord
	pendingID       uint64
	pendingSince    time.Time
	pendingAttempts uint64
	pendingError    string
}

func journalContext(origin registrygenesis.GenesisOrigin, id shardnode.AdmissionIdentity) (configuredprogress.Context, error) {
	if !origin.Valid() || id.TrustBases == nil {
		return configuredprogress.Context{}, fmt.Errorf("configuredadmission: journal needs checked origin and trust bases")
	}
	r := origin.Record()
	if uint64(id.PartitionID) != r.PartitionID || !bytes.Equal(id.ShardID.Bytes(), r.ShardID) || !bytes.Equal(id.FullShardConfHash, origin.FullShardConfHash().Bytes()) {
		return configuredprogress.Context{}, fmt.Errorf("configuredadmission: journal identity differs from origin")
	}
	obs := rootinput.ObservationContextV2{NetworkID: types.NetworkID(r.NetworkID), PartitionID: id.PartitionID, ShardID: id.ShardID, ShardConfHash: bytes.Clone(id.FullShardConfHash), ConfForEpoch: id.ConfForEpoch, RootEpoch: r.RootEpoch, TrustBases: id.TrustBases}
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
	c.ExecutionConfigV2 = f.ExecutionConfigV2
	c.Observation.EpochAuthority = f.EpochAuthority
	c.Record.EpochAuthority = f.EpochAuthority
	if _, err = f.Store.LoadJournal(ctx, c, f.Limits); err != nil {
		return nil, fmt.Errorf("loading execution journal: %w", err)
	}
	a := &journalAdmission{store: f.Store, context: c, limits: f.Limits, gate: gate, callbacks: callbacks, epoch: c.Observation.RootEpoch, catchUp: f.CatchUp, onStop: f.OnStop, logger: f.Logger, ctx: ctx, closeCh: make(chan struct{})}
	if f.Freshness != nil {
		a.freshness = f.Freshness
		f.Freshness.start(ctx, c, f.Store, a.Submit)
	}
	return a, nil
}

func (a *journalAdmission) Submit(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (outErr error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var authenticatedUC *types.UnicityCertificate
	var authenticatedTR *certification.TechnicalRecord
	defer func() {
		if outErr != nil && terminalAdmissionError(outErr) {
			if a.onStop != nil {
				a.onStop(outErr)
			}
			a.pendingUC, a.pendingTR = nil, nil
			a.pendingSince, a.pendingAttempts, a.pendingError = time.Time{}, 0, ""
		} else if outErr == nil {
			if a.pendingUC == nil || laterRootUC(uc, a.pendingUC) {
				a.pendingUC, a.pendingTR = nil, nil
				a.pendingSince, a.pendingAttempts, a.pendingError = time.Time{}, 0, ""
			}
		} else if authenticatedUC != nil && !terminalAdmissionError(outErr) && a.ctx.Err() == nil {
			if a.pendingUC == nil || laterRootUC(authenticatedUC, a.pendingUC) {
				if a.pendingSince.IsZero() {
					a.pendingSince = time.Now()
				}
				a.pendingAttempts++
				a.pendingError = outErr.Error()
				a.pendingUC, a.pendingTR = authenticatedUC, authenticatedTR
				a.pendingID++
				if !a.retrying {
					a.retrying = true
					go a.retryPending()
				}
			}
		}
	}()
	if a.closed {
		return configuredprogress.ErrAdmissionClosed
	}
	if uc != nil && a.context.Observation.EpochAuthority != nil {
		if current, ready := a.context.Observation.EpochAuthority.CurrentRootEpoch(); ready && uc.GetRootEpoch() < current {
			// The handoff has retired this live response. Historical journal
			// replay authenticates old epochs through its separate path.
			if a.pendingUC != nil && a.pendingUC.GetRootEpoch() < current {
				a.pendingUC, a.pendingTR = nil, nil
				a.pendingSince, a.pendingAttempts, a.pendingError = time.Time{}, 0, ""
			}
			return nil
		}
	}
	o, err := rootinput.AuthenticateObservationV2(ctx, a.context.Observation, uc, tr)
	if err != nil {
		return err
	}
	authenticatedUC, authenticatedTR = o.Certificate(), o.TechnicalRecord()
	if o.Class() != evmroot.OriginBootstrapV2 {
		// Ordinary progress ends bootstrap eligibility the moment it authenticates, before any
		// write that could fail (F6f section 4).
		a.freshness.noteOrdinary()
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
	current, outcome, err := a.store.CommitObservation(p)
	release()
	if err != nil {
		return fmt.Errorf("durable journal admission: %w", err)
	}
	a.callbacks.AuthenticatedFeed(current.Certificate(), current.TechnicalRecord())
	image, err := a.store.LoadJournal(ctx, a.context, a.limits)
	if err != nil {
		return fmt.Errorf("verifying admitted execution journal: %w", err)
	}
	if a.logger != nil && outcome != configuredprogress.ObservationDuplicate && outcome != configuredprogress.ObservationStale {
		uc := current.Certificate()
		var height uint64 // Zero means the durable certificate has no retained body yet.
		for _, entry := range image.Candidates {
			if matchesCertifiedCandidate(entry, uc) {
				height = entry.Candidate.Number
				break
			}
		}
		a.logger.InfoContext(ctx, "certificate admitted", slog.String("block", fmt.Sprintf("%x", uc.InputRecord.BlockHash)), slog.Uint64("height", height), slog.Uint64("round", uc.GetRoundNumber()), slog.Uint64("rootRound", uc.GetRootRoundNumber()), slog.Uint64("rootEpoch", uc.GetRootEpoch()))
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

func laterRootUC(a, b *types.UnicityCertificate) bool {
	return a.GetRootEpoch() > b.GetRootEpoch() || a.GetRootEpoch() == b.GetRootEpoch() && a.GetRootRoundNumber() >= b.GetRootRoundNumber()
}

func matchesCertifiedCandidate(entry configuredprogress.JournalEntry, uc *types.UnicityCertificate) bool {
	return entry.Certified && entry.ResultingUC != nil && entry.ResultingUC.GetRootEpoch() == uc.GetRootEpoch() && entry.ResultingUC.GetRootRoundNumber() == uc.GetRootRoundNumber() && entry.ResultingUC.GetRoundNumber() == uc.GetRoundNumber() && bytes.Equal(entry.Candidate.Hash, uc.InputRecord.BlockHash)
}

func (a *journalAdmission) RootEpoch() uint64 {
	if authority := a.context.Observation.EpochAuthority; authority != nil {
		if current, ready := authority.CurrentRootEpoch(); ready && current >= a.epoch {
			return current
		}
	}
	return a.epoch
}

func (a *journalAdmission) Profile2Ready(epoch uint64) bool {
	if a.context.Observation.EpochAuthority == nil {
		return false
	}
	current, ready := a.context.Observation.EpochAuthority.CurrentRootEpoch()
	return ready && current == epoch
}
func (a *journalAdmission) Pending() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pendingUC != nil
}

func (a *journalAdmission) PendingAdmission() (shardnode.PendingAdmission, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pendingUC == nil {
		return shardnode.PendingAdmission{}, false
	}
	return shardnode.PendingAdmission{RootRound: a.pendingUC.GetRootRoundNumber(), Round: a.pendingUC.GetRoundNumber(), BlockHash: bytes.Clone(a.pendingUC.InputRecord.BlockHash), Since: a.pendingSince, Attempts: a.pendingAttempts, LastError: a.pendingError}, true
}

func terminalAdmissionError(err error) bool {
	return errors.Is(err, configuredprogress.ErrBounds) || errors.Is(err, configuredprogress.ErrConflict) || errors.Is(err, configuredprogress.ErrUntrusted) || errors.Is(err, ErrRecoveryBudget) || errors.Is(err, ErrRecoveryConflict)
}

// A bounded attempt is followed by increasing delay. It keeps the authenticated
// target alive when every configured peer is temporarily unavailable.
func (a *journalAdmission) retryPending() {
	delay := time.Second
	for {
		timer := time.NewTimer(delay)
		select {
		case <-a.ctx.Done():
			timer.Stop()
			return
		case <-a.closeCh:
			timer.Stop()
			return
		case <-timer.C:
		}
		a.mu.Lock()
		uc, tr, id := a.pendingUC, a.pendingTR, a.pendingID
		if uc == nil || a.closed {
			a.retrying = false
			a.mu.Unlock()
			return
		}
		a.mu.Unlock()
		err := a.Submit(a.ctx, uc, tr)
		a.mu.Lock()
		if (err == nil || terminalAdmissionError(err)) && a.pendingID == id {
			a.pendingUC, a.pendingTR = nil, nil
		}
		if a.pendingUC == nil || a.closed {
			a.retrying = false
			a.mu.Unlock()
			return
		}
		a.mu.Unlock()
		if delay < 8*time.Second {
			delay *= 2
		}
	}
}
func (a *journalAdmission) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.closed = true
		close(a.closeCh)
	}
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
	if authority := j.Context.Observation.EpochAuthority; authority != nil && p.AuthorizingCertificate != nil {
		if current, ready := authority.CurrentRootEpoch(); ready && p.AuthorizingCertificate.GetRootEpoch() < current {
			// Activation may land between sealing and the journal fsync. This
			// proposal has lost its authority, but no durable state is damaged.
			if locallyBuilt {
				return fmt.Errorf("%w: root epoch advanced before publication", shardnode.ErrLeaderProposalConflict)
			}
			return fmt.Errorf("%w: root epoch advanced before verification", shardnode.ErrProposalRejected)
		}
	}
	if !bytes.Equal(b.ParentHash, p.Parent.Hash) {
		return fmt.Errorf("configuredadmission: candidate parent differs from held executor head")
	}
	err := j.Store.PutJournalCandidate(ctx, j.Context, j.Limits, configuredprogress.JournalCandidate{
		Round: p.Round, Number: b.Number, ParentNumber: p.Parent.Number, Hash: b.Hash, StateRoot: b.StateRoot, ParentHash: b.ParentHash, ParentState: p.Parent.StateRoot, Raw: b.Raw, BlockSize: b.BlockSize, StateSize: b.StateSize, LocallyBuilt: locallyBuilt, AuthorizingUC: p.AuthorizingCertificate, AuthorizingTR: p.AuthorizingTechnicalRecord,
	})
	if err != nil && p.AuthorizingCertificate != nil {
		if authority := j.Context.Observation.EpochAuthority; authority != nil {
			if current, ready := authority.CurrentRootEpoch(); ready && p.AuthorizingCertificate.GetRootEpoch() < current {
				// Activation can race the journal's authentication after the
				// first epoch check. The superseded round is a refusal, not a
				// reason to stop certified execution.
				if locallyBuilt {
					return fmt.Errorf("%w: root epoch advanced during retention", shardnode.ErrLeaderProposalConflict)
				}
				return fmt.Errorf("%w: root epoch advanced during retention", shardnode.ErrProposalRejected)
			}
		}
	}
	if locallyBuilt && errors.Is(err, configuredprogress.ErrLocalProposalConflict) {
		return fmt.Errorf("%w: %v", shardnode.ErrLeaderProposalConflict, err)
	}
	if !locallyBuilt && errors.Is(err, configuredprogress.ErrConflict) {
		return fmt.Errorf("%w: %v", shardnode.ErrProposalRejected, err)
	}
	return err
}
