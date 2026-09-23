package shardnode

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics is optional throughout this package: every method on it is
// nil-safe, and every call site in round.go/bftclient.go guards with
// `if m != nil`. A shard node run without --metrics still works identically;
// it just doesn't record anything.
type Metrics struct {
	roundsCertified   metric.Int64Counter
	repeatUCs         metric.Int64Counter
	staleUCs          metric.Int64Counter
	buildDuration     metric.Float64Histogram
	verifyDuration    metric.Float64Histogram
	quorumLatency     metric.Float64Histogram
	irDivergences     metric.Int64Counter
	recoveryStops     metric.Int64Counter
	pendingCatchUp    metric.Int64Gauge
	pendingCatchUpAge metric.Float64Gauge
}

// NewMetrics registers this package's instruments on meter. See
// docs/engine-api-adapter-plan.md C3.2 for what each one is for.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{}
	var err error

	if m.roundsCertified, err = meter.Int64Counter("shardnode.rounds.certified",
		metric.WithDescription("Rounds successfully certified (a UC arrived confirming what this node submitted)")); err != nil {
		return nil, fmt.Errorf("creating rounds.certified counter: %w", err)
	}
	if m.repeatUCs, err = meter.Int64Counter("shardnode.uc.repeat",
		metric.WithDescription("Repeat UCs received — each one is a round the root chain timed out waiting for quorum on")); err != nil {
		return nil, fmt.Errorf("creating uc.repeat counter: %w", err)
	}
	if m.staleUCs, err = meter.Int64Counter("shardnode.uc.stale",
		metric.WithDescription("Authentic certificates for rounds already passed — routine on a node subscribed to several root nodes, but a sharp rise means retransmission churn (#93)")); err != nil {
		return nil, fmt.Errorf("creating uc.stale counter: %w", err)
	}
	if m.buildDuration, err = meter.Float64Histogram("shardnode.build.duration",
		metric.WithDescription("Time from Build to Seal returning, leader rounds only"), metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5)); err != nil {
		return nil, fmt.Errorf("creating build.duration histogram: %w", err)
	}
	if m.verifyDuration, err = meter.Float64Histogram("shardnode.verify.duration",
		metric.WithDescription("Time spent in Executor.Verify, every round including self-verify"), metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5)); err != nil {
		return nil, fmt.Errorf("creating verify.duration histogram: %w", err)
	}
	if m.quorumLatency, err = meter.Float64Histogram("shardnode.quorum.latency",
		metric.WithDescription("Time from submitting a certification request to the confirming certificate arriving"), metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30)); err != nil {
		return nil, fmt.Errorf("creating quorum.latency histogram: %w", err)
	}
	if m.irDivergences, err = meter.Int64Counter("shardnode.ir.divergences",
		metric.WithDescription("Locally-detected InputRecord problems: a local ValidRequest mirror failure, or a reconcile that needed to run")); err != nil {
		return nil, fmt.Errorf("creating ir.divergences counter: %w", err)
	}
	if m.recoveryStops, err = meter.Int64Counter("shardnode.execution_recovery.stops",
		metric.WithDescription("Journal execution recovery entered an operator-visible stop state")); err != nil {
		return nil, fmt.Errorf("creating execution_recovery.stops counter: %w", err)
	}
	if m.pendingCatchUp, err = meter.Int64Gauge("shardnode.execution_recovery.pending_catch_up",
		metric.WithDescription("One while an authenticated certificate awaits peer catch-up before admission, zero otherwise")); err != nil {
		return nil, fmt.Errorf("creating execution_recovery.pending_catch_up gauge: %w", err)
	}
	if m.pendingCatchUpAge, err = meter.Float64Gauge("shardnode.execution_recovery.pending_catch_up_age",
		metric.WithDescription("Age in seconds of the pending authenticated certificate"), metric.WithUnit("s")); err != nil {
		return nil, fmt.Errorf("creating execution_recovery.pending_catch_up_age gauge: %w", err)
	}
	return m, nil
}

func (m *Metrics) recordRoundCertified(ctx context.Context) {
	if m == nil {
		return
	}
	m.roundsCertified.Add(ctx, 1)
}

func (m *Metrics) recordRepeatUC(ctx context.Context) {
	if m == nil {
		return
	}
	m.repeatUCs.Add(ctx, 1)
}

func (m *Metrics) recordStaleUC(ctx context.Context) {
	if m == nil {
		return
	}
	m.staleUCs.Add(ctx, 1)
}

func (m *Metrics) recordBuildDuration(ctx context.Context, d time.Duration) {
	if m == nil {
		return
	}
	m.buildDuration.Record(ctx, d.Seconds())
}

func (m *Metrics) recordVerifyDuration(ctx context.Context, d time.Duration, leader bool) {
	if m == nil {
		return
	}
	m.verifyDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.Bool("self_verify", leader)))
}

func (m *Metrics) recordQuorumLatency(ctx context.Context, d time.Duration) {
	if m == nil {
		return
	}
	m.quorumLatency.Record(ctx, d.Seconds())
}

func (m *Metrics) recordIRDivergence(ctx context.Context, reason string) {
	if m == nil {
		return
	}
	m.irDivergences.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

func (m *Metrics) recordRecoveryStop(ctx context.Context) {
	if m == nil {
		return
	}
	m.recoveryStops.Add(ctx, 1)
}

func (m *Metrics) recordPendingCatchUp(ctx context.Context, pending bool, age time.Duration) {
	if m == nil {
		return
	}
	if pending {
		m.pendingCatchUp.Record(ctx, 1)
		m.pendingCatchUpAge.Record(ctx, age.Seconds())
	} else {
		m.pendingCatchUp.Record(ctx, 0)
		m.pendingCatchUpAge.Record(ctx, 0)
	}
}
