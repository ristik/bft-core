package monitoring

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// value returns the value of the single unlabeled sample of name, and whether there is one.
func value(t *testing.T, reg *prometheus.Registry, name string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == name && len(mf.GetMetric()) > 0 {
			return mf.GetMetric()[0].GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func TestNilRegistryIsUsable(t *testing.T) {
	r := New(nil)
	r.Counter("unicity_x_total", "x").Inc()
	r.GaugeFunc("unicity_y", "y", func() float64 { return 1 })
	RegisterUpgrades(r, &UpgradeTracker{rules: map[[32]byte]UpgradeRule{}})
}

func TestUpgradeMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	tr := &UpgradeTracker{rules: map[[32]byte]UpgradeRule{}}
	RegisterUpgrades(New(reg), tr)
	v, ok := value(t, reg, "unicity_upgrade_required")
	require.True(t, ok)
	require.Zero(t, v)
	_, ok = value(t, reg, "unicity_upgrade_activation_epoch")
	require.False(t, ok)
	tr.Require(UpgradeRule{RuleID: [32]byte{1}, RootEpoch: 7})
	v, _ = value(t, reg, "unicity_upgrade_required")
	require.Equal(t, 1.0, v)
	v, ok = value(t, reg, "unicity_upgrade_activation_epoch")
	require.True(t, ok)
	require.Equal(t, 7.0, v)
	tr.Clear([32]byte{1})
	_, ok = value(t, reg, "unicity_upgrade_activation_epoch")
	require.False(t, ok)
}

func TestDiskMetrics(t *testing.T) {
	var buf bytes.Buffer
	reg := prometheus.NewRegistry()
	RegisterDisk(New(reg), slog.New(slog.NewTextHandler(&buf, nil)), Volume{Name: "tmp", Path: t.TempDir()})
	for _, n := range []string{"unicity_disk_free_bytes", "unicity_disk_free_ratio", "unicity_disk_total_bytes"} {
		_, ok := value(t, reg, n)
		require.True(t, ok, n)
	}
	// a volume that cannot be read is an error gauge, not zero free bytes
	reg2 := prometheus.NewRegistry()
	RegisterDisk(New(reg2), nil, Volume{Name: "gone", Path: "/nonexistent/vt12"})
	_, ok := value(t, reg2, "unicity_disk_free_bytes")
	require.False(t, ok)
	v, ok := value(t, reg2, "unicity_disk_stat_error")
	require.True(t, ok)
	require.Equal(t, 1.0, v)
	require.Equal(t, "vr.identity.parked", IdentityEvent("Parked"))
	require.Equal(t, "vr.identity.none", IdentityEvent("bogus"))
}
