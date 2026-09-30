package engineapi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/unicitynetwork/bft-core/registrywitness"
)

func TestParentWitnessSourceMetricsIncludeVerifiedCacheAndMismatch(t *testing.T) {
	ctx := context.Background()
	chain, pins, parent := sourceFixture(t)
	server, _ := sourceServer(t, chain.Blocks[1].Hash, chain.Blocks[1].Evidence, nil)
	defer server.Close()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(ctx)) })
	metrics, err := NewParentWitnessMetrics(provider.Meter("engineapi-test"))
	require.NoError(t, err)
	source, err := NewParentWitnessSource(ctx, pins, registrywitness.NewHTTPCaller(server.URL, time.Second), DefaultParentWitnessBudget())
	require.NoError(t, err)
	source.metrics = metrics
	defer source.Close()

	_, _, err = source.AcquireWithProvenance(ctx, parent)
	require.NoError(t, err)
	_, _, err = source.AcquireWithProvenance(ctx, parent)
	require.NoError(t, err)
	wrong := parent
	wrong.StateRoot = make([]byte, len(parent.StateRoot))
	_, _, err = source.AcquireWithProvenance(ctx, wrong)
	require.ErrorIs(t, err, ErrParentWitnessMismatch)

	var gathered metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &gathered))
	var outcomes map[string]int64
	var durationCount uint64
	for _, scope := range gathered.ScopeMetrics {
		for _, metric := range scope.Metrics {
			switch metric.Name {
			case "engineapi.parent_witness.verification":
				counter, ok := metric.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				outcomes = make(map[string]int64)
				for _, point := range counter.DataPoints {
					value, ok := point.Attributes.Value(attribute.Key("outcome"))
					require.True(t, ok)
					outcomes[value.AsString()] = point.Value
				}
			case "engineapi.parent_witness.verification.duration":
				histogram, ok := metric.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				for _, point := range histogram.DataPoints {
					durationCount += point.Count
				}
			}
		}
	}
	require.Equal(t, map[string]int64{"verified": 1, "cache_hit": 1, "mismatch": 1}, outcomes)
	require.EqualValues(t, 3, durationCount)
}
