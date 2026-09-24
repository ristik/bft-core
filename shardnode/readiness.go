package shardnode

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// ReadinessTicket is an opaque prepared result. Only its producer can make one, which is why the
// interface exposes no accessor beyond a validity check: a round that could construct a ticket
// could claim readiness it never established.
type ReadinessTicket interface{ Valid() bool }

// ChildReadiness decides whether this node may act on the certified-block record's child (#14 W3b).
// It is the round-facing half of recordwiring.Readiness, deliberately expressed without importing
// recordwiring: that package imports shardnode, so the dependency runs the other way.
//
// Prepare does all expensive store, witness, trust and continuity verification. It is called with
// the round lock held and the finality gate free, so it may read the executor (a head read takes no
// gate) but must make no call that changes what the executor treats as canonical or final.
//
// Revalidate does only the decisive mutable-state checks (held bytes, observed history, durable
// head, executor identity). It is called inside the finality gate, immediately before a
// finality-changing executor call or a signature, so it must be cheap and must not repeat trust or
// proof work.
type ChildReadiness interface {
	Prepare(ctx context.Context, held *types.UnicityCertificate) (ReadinessTicket, error)
	Revalidate(ctx context.Context, ticket ReadinessTicket, held *types.UnicityCertificate) error
}

// JournalRecovery is the sole owner of execution catch-up for a journal-backed node.
// Recover is called after durable certificate admission and before the round may
// build or sign. The same owner supplies the readiness ticket below.
type JournalRecovery interface {
	Recover(context.Context, *types.UnicityCertificate) (BlockRef, error)
	Terminal(error) bool
}

// CertificateObserver is fed every authenticated certificate and its technical record at the one
// site where the two arrive together. Observing authorizes nothing; it is what lets a readiness
// predicate later name the continuity between the durable record and the certificate in hand.
type CertificateObserver interface {
	ObserveCertificate(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error
}

var (
	// errReadinessRevoked marks a ticket that no longer holds at the finality boundary. It is not a
	// processing error: the round abstains and returns nil, exactly as a P-id refusal does.
	errReadinessRevoked = errors.New("shardnode: certified-record readiness was revoked at the finality boundary")
	// errReadinessTicketInvalid is a defensive refusal for a ChildReadiness implementation that
	// reports success without producing a usable ticket. The recordwiring adapter cannot do this;
	// the round must not treat a nil ticket as readiness.
	errReadinessTicketInvalid = errors.New("shardnode: child readiness returned no valid ticket")
)

// The two IR-divergence reasons the record gate adds. They are separate from P-id's reasons so an
// operator can tell "this node cannot prove where it stands" from "this node cannot prove the
// record's child is ready".
const (
	metricRecordReadinessDeclinedLeadership = "record_readiness_declined_leadership"
	metricRecordReadinessAbstained          = "record_readiness_abstained"
)

// readinessOutcome* are the health values of certifiedRecordReadiness. They are set on every round
// the gate evaluates and are empty on a node without the gate.
const (
	readinessOutcomeReady    = "ready"
	readinessOutcomeNotReady = "not-ready"
	readinessOutcomeRevoked  = "revoked"
)

// nonVotingRecordReadiness is the prefix every record-readiness non-voting reason carries. It names
// the gate so it is distinguishable from P-id and from a signing refusal in health without reading
// logs.
const nonVotingRecordReadiness = "certified-record readiness is not established for the held certificate's child"

// prepareChildReadiness runs the gate's expensive preparation once for this round. A node without
// the gate has no work to do and returns a nil ticket, which every caller treats as "no verdict".
// The error is the refusal; the ticket is the authority to revalidate later. A refusal updates
// health here because it is the gate's verdict for the round, whether the round goes on to lead,
// follow or abstain.
func (r *Round) prepareChildReadiness(ctx context.Context, held *types.UnicityCertificate) (ReadinessTicket, error) {
	if r.childReadiness == nil {
		return nil, nil
	}
	ticket, err := r.childReadiness.Prepare(ctx, held)
	if err != nil {
		r.health.updateCertifiedRecordReadiness(readinessOutcomeNotReady, err.Error())
		return nil, err
	}
	if ticket == nil || !ticket.Valid() {
		r.health.updateCertifiedRecordReadiness(readinessOutcomeNotReady, errReadinessTicketInvalid.Error())
		return nil, errReadinessTicketInvalid
	}
	r.health.updateCertifiedRecordReadiness(readinessOutcomeReady, "")
	return ticket, nil
}

// recordReadinessAbstained reports a non-leader round that withholds its signature because the gate
// refused. The block has still been built or verified and r.pending recorded, so the node stays a
// warm follower and its own captures can make it ready again without recovery.
func (r *Round) recordReadinessAbstained(ctx context.Context, err error) {
	r.metrics.recordIRDivergence(ctx, metricRecordReadinessAbstained)
	r.health.updateCertifiedRecordReadiness(readinessOutcomeNotReady, err.Error())
	r.health.updateVoting(false, nonVotingRecordReadiness+": "+err.Error())
	if r.log != nil {
		r.log.WarnContext(ctx, "abstaining from the vote: the certified-block record cannot prove readiness for the held certificate's child",
			slog.String("reason", err.Error()))
	}
}

// recordReadinessRevoked reports a round that had a valid ticket and lost it inside the finality
// gate, either before Build or before the signature. The round abstains and returns nil; failing
// HandleCertificate would make a transient record lag look like a certificate-processing error to
// the delivery layer.
func (r *Round) recordReadinessRevoked(ctx context.Context, err error) {
	r.metrics.recordIRDivergence(ctx, metricRecordReadinessAbstained)
	r.health.updateCertifiedRecordReadiness(readinessOutcomeRevoked, err.Error())
	r.health.updateVoting(false, nonVotingRecordReadiness+": "+err.Error())
	if r.log != nil {
		r.log.WarnContext(ctx, "abstaining: certified-record readiness was revoked inside the finality gate",
			slog.String("reason", err.Error()))
	}
}

// revalidateChildReadiness runs the ticket's mutable-state checks inside the finality gate. A nil
// ticket means no gate is installed; the caller must not call this on a node without one because
// there is nothing to revalidate.
func (r *Round) revalidateChildReadiness(ctx context.Context, ticket ReadinessTicket, held *types.UnicityCertificate) error {
	if r.childReadiness == nil || ticket == nil {
		return nil
	}
	if err := r.childReadiness.Revalidate(ctx, ticket, held); err != nil {
		return fmt.Errorf("%w: %w", errReadinessRevoked, err)
	}
	return nil
}

// revalidateUnderFinality takes the finality gate for the vote's revalidation alone and releases it
// before returning. buildFinal already holds the gate when it revalidates, so it calls
// revalidateChildReadiness directly rather than re-entering this method. A round wired with a
// readiness gate but no finality gate is a wiring the tests use; there the revalidation still runs,
// just without a gate to hold.
//
// A round without the gate acquires nothing. Taking the gate for a revalidation that does no work
// would not be free: the recovery applier takes the gate with tryAcquire and reports being turned
// away rather than waiting, so a no-op acquisition on every round could cost a recovery attempt the
// round it was made in. The ungated path must reach no gate at all, not merely hold it briefly.
func (r *Round) revalidateUnderFinality(ctx context.Context, ticket ReadinessTicket, held *types.UnicityCertificate) error {
	if r.childReadiness == nil || ticket == nil {
		return nil
	}
	if r.finality == nil {
		return r.revalidateChildReadiness(ctx, ticket, held)
	}
	release, err := r.finality.acquire(ctx, "readiness-revalidate")
	if err != nil {
		return err
	}
	defer release()
	return r.revalidateChildReadiness(ctx, ticket, held)
}
