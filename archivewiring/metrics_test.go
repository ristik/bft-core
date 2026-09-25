package archivewiring

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestArchiveMetricsReportPendingAcknowledgedAndLagging(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(ctx)
	m, err := NewMetrics(provider.Meter("archive-test"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.set(Status{Pending: 5, Acknowledged: 3, Lagging: 2})
	var data metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &data); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"archive.pending_records": 5, "archive.acknowledged_records": 3, "archive.lagging_records": 2}
	for _, scope := range data.ScopeMetrics {
		for _, measured := range scope.Metrics {
			expected, ok := want[measured.Name]
			if !ok {
				continue
			}
			gauge, ok := measured.Data.(metricdata.Gauge[int64])
			if !ok || len(gauge.DataPoints) != 1 || gauge.DataPoints[0].Value != expected {
				t.Fatalf("%s: %#v", measured.Name, measured.Data)
			}
			delete(want, measured.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing archive gauges: %v", want)
	}
}
