package monitoring

import (
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Volume is a named directory whose filesystem is watched.
type Volume struct{ Name, Path string }

// DiskLowRatio is the free fraction below which the node logs the node.disk.low event (once per crossing); the alert rules use the
// same threshold (deploy/testnet/monitoring/validator-alerts.yml, UnicityDiskLow).
const DiskLowRatio = 0.10

// RegisterDisk registers unicity_disk_free_bytes, unicity_disk_total_bytes and unicity_disk_free_ratio per volume, read at scrape time,
// and unicity_disk_stat_errors_total. When log is not nil, a scrape that finds a volume below DiskLowRatio logs node.disk.low once, and
// node.disk.recovered when it is above again.
func RegisterDisk(r *Registry, log *slog.Logger, volumes ...Volume) {
	if len(volumes) == 0 {
		return
	}
	r.Collector(&diskCollector{volumes: volumes, log: log, low: map[string]bool{},
		free:  prometheus.NewDesc("unicity_disk_free_bytes", "Bytes available to the node's user on the volume's filesystem.", []string{"volume"}, nil),
		total: prometheus.NewDesc("unicity_disk_total_bytes", "Size of the volume's filesystem.", []string{"volume"}, nil),
		ratio: prometheus.NewDesc("unicity_disk_free_ratio", "Free fraction of the volume's filesystem (0..1).", []string{"volume"}, nil),
		errs:  prometheus.NewDesc("unicity_disk_stat_error", "1 when the volume's filesystem could not be read.", []string{"volume"}, nil)})
}

type diskCollector struct {
	volumes                  []Volume
	log                      *slog.Logger
	mu                       sync.Mutex
	low                      map[string]bool
	free, total, ratio, errs *prometheus.Desc
}

func (c *diskCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.free
	ch <- c.total
	ch <- c.ratio
	ch <- c.errs
}

func (c *diskCollector) Collect(ch chan<- prometheus.Metric) {
	for _, v := range c.volumes {
		free, total, err := statfs(v.Path)
		if err != nil || total == 0 {
			ch <- prometheus.MustNewConstMetric(c.errs, prometheus.GaugeValue, 1, v.Name)
			continue
		}
		ratio := float64(free) / float64(total)
		ch <- prometheus.MustNewConstMetric(c.errs, prometheus.GaugeValue, 0, v.Name)
		ch <- prometheus.MustNewConstMetric(c.free, prometheus.GaugeValue, float64(free), v.Name)
		ch <- prometheus.MustNewConstMetric(c.total, prometheus.GaugeValue, float64(total), v.Name)
		ch <- prometheus.MustNewConstMetric(c.ratio, prometheus.GaugeValue, ratio, v.Name)
		c.edge(v, ratio, free)
	}
}

func (c *diskCollector) edge(v Volume, ratio float64, free uint64) {
	if c.log == nil {
		return
	}
	c.mu.Lock()
	was := c.low[v.Name]
	now := ratio < DiskLowRatio
	c.low[v.Name] = now
	c.mu.Unlock()
	switch {
	case now && !was:
		c.log.Warn("disk space is low", "volume", v.Name, "path", v.Path, "freeBytes", free, "freeRatio", ratio, Event(EvDiskLow))
	case !now && was:
		c.log.Info("disk space recovered", "volume", v.Name, "path", v.Path, "freeBytes", free, "freeRatio", ratio, Event(EvDiskRecovered))
	}
}
