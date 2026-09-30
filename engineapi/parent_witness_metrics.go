package engineapi

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ParentWitnessMetrics records bounded outcomes and acquisition latency for
// the journal-backed D2 parent-witness path. Outcome is a fixed low-cardinality label.
type ParentWitnessMetrics struct {
	verifications metric.Int64Counter
	duration      metric.Float64Histogram
}

func NewParentWitnessMetrics(meter metric.Meter) (*ParentWitnessMetrics, error) {
	m := &ParentWitnessMetrics{}
	var err error
	if m.verifications, err = meter.Int64Counter("engineapi.parent_witness.verification",
		metric.WithDescription("D2 parent-witness acquisitions by outcome")); err != nil {
		return nil, fmt.Errorf("creating parent-witness verification counter: %w", err)
	}
	if m.duration, err = meter.Float64Histogram("engineapi.parent_witness.verification.duration",
		metric.WithDescription("Time to acquire and verify the exact certified parent witness"), metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)); err != nil {
		return nil, fmt.Errorf("creating parent-witness verification histogram: %w", err)
	}
	return m, nil
}

func (m *ParentWitnessMetrics) record(ctx context.Context, outcome string, elapsed time.Duration) {
	if m == nil {
		return
	}
	m.verifications.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	m.duration.Record(ctx, elapsed.Seconds())
}
