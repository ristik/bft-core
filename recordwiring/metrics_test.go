package recordwiring

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestWitnessMetricsRecordOutcomeAndLatency(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(ctx)) })
	m, err := NewMetrics(provider.Meter("witness-test"))
	require.NoError(t, err)
	m.recordWitness(ctx, "verified", 125*time.Millisecond)
	m.recordWitness(ctx, "unavailable", 2*time.Second)

	var data metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &data))
	foundCounter, foundHistogram := false, false
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			switch metric.Name {
			case "recordwiring.witness.verification":
				counter, ok := metric.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.Len(t, counter.DataPoints, 2)
				total := int64(0)
				for _, point := range counter.DataPoints {
					total += point.Value
				}
				require.EqualValues(t, 2, total)
				foundCounter = true
			case "recordwiring.witness.verification.duration":
				histogram, ok := metric.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				require.Len(t, histogram.DataPoints, 1)
				require.EqualValues(t, 2, histogram.DataPoints[0].Count)
				foundHistogram = true
			}
		}
	}
	require.True(t, foundCounter)
	require.True(t, foundHistogram)
}
