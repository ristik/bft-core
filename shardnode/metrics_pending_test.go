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
