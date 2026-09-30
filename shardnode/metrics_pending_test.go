package shardnode

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestPendingCatchUpMetricShowsAgeAndClears(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(ctx)) })
	m, err := NewMetrics(provider.Meter("pending-catch-up-test"))
	require.NoError(t, err)
	read := func() (int64, float64) {
		var data metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(ctx, &data))
		var pending int64
		var age float64
		for _, scope := range data.ScopeMetrics {
			for _, metric := range scope.Metrics {
				switch metric.Name {
				case "shardnode.execution_recovery.pending_catch_up":
					gauge, ok := metric.Data.(metricdata.Gauge[int64])
					require.True(t, ok)
					pending = gauge.DataPoints[0].Value
				case "shardnode.execution_recovery.pending_catch_up_age":
					gauge, ok := metric.Data.(metricdata.Gauge[float64])
					require.True(t, ok)
					age = gauge.DataPoints[0].Value
				}
			}
		}
		return pending, age
	}
	m.recordPendingCatchUp(ctx, true, 12*time.Second)
	pending, age := read()
	require.EqualValues(t, 1, pending)
	require.Equal(t, float64(12), age)
	m.recordPendingCatchUp(ctx, false, 0)
	pending, age = read()
	require.Zero(t, pending)
	require.Zero(t, age)
}

func TestCertificationMetricsExposeEpochTransitionPauseTimestamps(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(ctx)) })
	m, err := NewMetrics(provider.Meter("certification-pause-test"))
	require.NoError(t, err)
	m.recordRoundCertified(ctx, 4)
	time.Sleep(time.Millisecond)
	m.recordRoundCertified(ctx, 5)

	var data metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &data))
	got := make(map[string]float64)
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			switch metric.Name {
			case "shardnode.certification.last_timestamp", "shardnode.certification.pause_start_timestamp", "shardnode.certification.pause_end_timestamp":
				gauge, ok := metric.Data.(metricdata.Gauge[float64])
				require.True(t, ok)
				got[metric.Name] = gauge.DataPoints[0].Value
			case "shardnode.certification.pause_duration":
				histogram, ok := metric.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				require.EqualValues(t, 1, histogram.DataPoints[0].Count)
				require.Greater(t, histogram.DataPoints[0].Sum, float64(0))
			}
		}
	}
	require.Greater(t, got["shardnode.certification.last_timestamp"], float64(0))
	require.Greater(t, got["shardnode.certification.pause_start_timestamp"], float64(0))
	require.Greater(t, got["shardnode.certification.pause_end_timestamp"], got["shardnode.certification.pause_start_timestamp"])
}
