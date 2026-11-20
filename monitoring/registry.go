// Package monitoring is the VT-12 monitoring pack's code: the unicity_* Prometheus metrics registered next to the OpenTelemetry ones, the
// stable event names of the lifecycle log lines, and the node-level collectors (disk, peers). The names are an operator-facing
// compatibility promise, catalogued in docs/operations/monitoring/metrics-catalogue.md and events.md; a test keeps the code and the
// catalogues in step.
package monitoring

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Registry registers unicity_* metrics on a Prometheus registerer. A nil Registerer (the node runs without `--metrics prometheus`) is
// valid: every constructor then returns a working metric that nothing scrapes, so call sites never branch on it.
type Registry struct{ reg prometheus.Registerer }

// New returns a registry on reg (may be nil).
func New(reg prometheus.Registerer) *Registry { return &Registry{reg: reg} }

func (r *Registry) register(c prometheus.Collector) {
	if r == nil || r.reg == nil {
		return
	}
	if err := r.reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			return // the same node set up twice in one process (tests, an in-process epoch switch): the first registration stays
		}
		panic("monitoring: " + err.Error()) // a malformed metric is a programming error, caught by the catalogue test
	}
}

// GaugeFunc registers a gauge read at scrape time. constLabels are alternating name, value pairs.
func (r *Registry) GaugeFunc(name, help string, f func() float64, constLabels ...string) {
	r.register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: labels(constLabels)}, f))
}

// CounterFunc registers a counter read at scrape time (f must be monotonic).
func (r *Registry) CounterFunc(name, help string, f func() float64, constLabels ...string) {
	r.register(prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help, ConstLabels: labels(constLabels)}, f))
}

// Gauge registers a settable gauge.
func (r *Registry) Gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
	r.register(g)
	return g
}

// GaugeVec registers a settable gauge family.
func (r *Registry) GaugeVec(name, help string, labelNames ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labelNames)
	r.register(g)
	return g
}

// Counter registers a counter.
func (r *Registry) Counter(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
	r.register(c)
	return c
}

// CounterVec registers a counter family.
func (r *Registry) CounterVec(name, help string, labelNames ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labelNames)
	r.register(c)
	return c
}

// Collector registers a custom collector.
func (r *Registry) Collector(c prometheus.Collector) { r.register(c) }

func labels(kv []string) prometheus.Labels {
	if len(kv) == 0 {
		return nil
	}
	if len(kv)%2 != 0 {
		panic("monitoring: constant labels are name, value pairs")
	}
	l := prometheus.Labels{}
	for i := 0; i < len(kv); i += 2 {
		l[kv[i]] = kv[i+1]
	}
	return l
}
