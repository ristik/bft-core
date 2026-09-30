package recordwiring

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics reports the result and latency of witness verification performed
// while capturing certified records. Outcome values are a fixed, low-cardinality set.
type Metrics struct {
	witnessVerifications metric.Int64Counter
	witnessDuration      metric.Float64Histogram
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{}
	var err error
	if m.witnessVerifications, err = meter.Int64Counter("recordwiring.witness.verification",
		metric.WithDescription("Certified-record witness verification attempts by outcome")); err != nil {
		return nil, fmt.Errorf("creating witness verification counter: %w", err)
	}
	if m.witnessDuration, err = meter.Float64Histogram("recordwiring.witness.verification.duration",
		metric.WithDescription("Time to acquire and verify a certified-record registry witness"), metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)); err != nil {
		return nil, fmt.Errorf("creating witness verification duration histogram: %w", err)
	}
	return m, nil
}

func (m *Metrics) recordWitness(ctx context.Context, outcome string, elapsed time.Duration) {
	if m == nil {
		return
	}
	m.witnessVerifications.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	m.witnessDuration.Record(ctx, elapsed.Seconds())
}
