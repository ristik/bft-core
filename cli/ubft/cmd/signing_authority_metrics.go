package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ainvaltin/httpsrv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/unicitynetwork/bft-core/monitoring"
	"github.com/unicitynetwork/bft-core/signingauthority"
)

// errAuthorityMetricsAddress is returned for a --metrics-address that is not a loopback address.
var errAuthorityMetricsAddress = errors.New("signing-authority: --metrics-address must be a loopback host:port")

// checkAuthorityMetricsAddress refuses anything but a loopback address: the endpoint is read-only and carries no key or request bytes, but
// the authority is the machine's most protected process and publishes nothing to the network.
func checkAuthorityMetricsAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %w", errAuthorityMetricsAddress, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w (got %q)", errAuthorityMetricsAddress, addr)
	}
	return nil
}

// authorityCollector exports the authority's diagnostic Status (never request or signature bytes) as unicity_authority_* gauges.
type authorityCollector struct {
	a *signingauthority.Authority
}

const (
	authoritySessionAgeHelp   = "Seconds since the current client session was issued; absent without a session."
	authoritySessionSignsHelp = "Certification signatures made in the current client session; absent without a session."
	authorityLastSignHelp     = "Seconds since the last certification signature in the current client session; absent before its first."
)

var authorityGauges = []struct{ name, help string }{
	{"unicity_authority_enrolled", "1 once the enrollment is complete (the shard configuration hash is bound)."},
	{"unicity_authority_faulted", "1 when the authority latched faulted (an inconsistency in its record): it signs nothing further until restarted."},
	{"unicity_authority_key_lost", "1 when the authority holds no signing key (it was closed)."},
	{"unicity_authority_retired", "1 when the authority latched retired (this validator was removed): it signs nothing further."},
	{"unicity_authority_session_issued", "1 when a client session was issued since the last scope change: the shard node has a session to sign through."},
	{"unicity_authority_has_reservation", "1 while a round is reserved."},
	{"unicity_authority_response_retained", "1 while a signed response is retained for replay."},
	{"unicity_authority_generation", "The client session generation; it advances on every replace-session."},
	{"unicity_authority_reserved_round", "The shard round currently reserved."},
	{"unicity_authority_root_epoch", "The root epoch the authority is enrolled for."},
	{"unicity_authority_shard_epoch", "The shard epoch the authority is enrolled for."},
	{"unicity_authority_lineage_pinned", "1 when the authority verifies its own epoch advances from a pinned genesis."},
	{"unicity_authority_lineage_epoch", "The last root epoch the authority's own lineage holds (0 without a pin)."},
}

func (c *authorityCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, g := range authorityGauges {
		ch <- prometheus.NewDesc(g.name, g.help, nil, nil)
	}
	ch <- prometheus.NewDesc("unicity_authority_signatures_total", "Signatures made in this authority lifetime.", nil, nil)
	ch <- prometheus.NewDesc("unicity_authority_last_signature_age_seconds", authorityLastSignHelp, nil, nil)
	ch <- prometheus.NewDesc("unicity_authority_session_age_seconds", authoritySessionAgeHelp, nil, nil)
	ch <- prometheus.NewDesc("unicity_authority_session_signatures", authoritySessionSignsHelp, nil, nil)
	ch <- prometheus.NewDesc("unicity_authority_up", "Always 1 while the authority process answers.", nil, nil)
}

func (c *authorityCollector) Collect(ch chan<- prometheus.Metric) {
	b := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}
	st := signingauthority.Activity(c.a)
	vals := []float64{b(st.Enrolled), b(st.Faulted), b(st.KeyLost), b(st.Retired), b(st.SessionIssued), b(st.HasReservation), b(st.ResponseRetained),
		float64(st.Generation), float64(st.ReservedRound), float64(st.RootEpoch), float64(st.ShardEpoch), b(st.LineagePinned), float64(st.LineageEpoch)}
	for i, g := range authorityGauges {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc(g.name, g.help, nil, nil), prometheus.GaugeValue, vals[i])
	}
	ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("unicity_authority_signatures_total", "Signatures made in this authority lifetime.", nil, nil), prometheus.CounterValue, float64(st.Signatures))
	if !st.SessionLastSign.IsZero() {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("unicity_authority_last_signature_age_seconds", authorityLastSignHelp, nil, nil),
			prometheus.GaugeValue, time.Since(st.SessionLastSign).Seconds())
	}
	if st.SessionIssued {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("unicity_authority_session_age_seconds", authoritySessionAgeHelp, nil, nil), prometheus.GaugeValue, time.Since(st.SessionIssuedAt).Seconds())
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("unicity_authority_session_signatures", authoritySessionSignsHelp, nil, nil), prometheus.GaugeValue, float64(st.SessionSignatures))
	}
	ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("unicity_authority_up", "Always 1 while the authority process answers.", nil, nil), prometheus.GaugeValue, 1)
}

// serveAuthorityMetrics serves GET /metrics (and /api/v1/metrics) on the loopback address until ctx ends.
func serveAuthorityMetrics(ctx context.Context, log *slog.Logger, addr string, a *signingauthority.Authority) error {
	if err := checkAuthorityMetricsAddress(addr); err != nil {
		return err
	}
	reg := prometheus.NewRegistry()
	mon := monitoring.New(reg)
	monitoring.RegisterBuildInfo(mon, "authority")
	mon.Collector(&authorityCollector{a: a})
	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{MaxRequestsInFlight: 1})
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h)
	mux.Handle("GET /api/v1/metrics", h)
	log.Info("signing authority metrics", "address", addr)
	return httpsrv.Run(ctx, &http.Server{Addr: addr, Handler: mux, ReadTimeout: 3 * time.Second, ReadHeaderTimeout: time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second})
}
