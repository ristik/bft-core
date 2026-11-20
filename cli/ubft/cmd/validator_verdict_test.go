package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient/vrfake"
)

// TestStatusExitCode: --exit-code turns the verdict into the exit status and --json carries the verdict and the numeric fields.
func TestStatusExitCode(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)

	out, err := runValidator(t, home, "status", "--json", "--exit-code")
	var rep validatorStatusReport
	require.NoError(t, json.Unmarshal([]byte(out), &rep), out)
	require.NotEmpty(t, rep.Verdict)
	want := map[string]int{"ok": ExitOK, "warning": ExitWarning, "critical": ExitCritical}[rep.Verdict]
	if want == ExitOK {
		require.NoError(t, err)
	} else {
		var coded *ExitCodeError
		require.True(t, errors.As(err, &coded), "%s: %v", rep.Verdict, err)
		require.Equal(t, want, coded.ExitCode())
		require.True(t, coded.Silent(), "a verdict has already been printed")
	}

	// a read that fails is "unknown", exit 3, with the error printed
	chain.With(func(c *vrfake.Chain) { c.FailSyncing = true })
	_, err = runValidator(t, home, "status", "--exit-code")
	var coded *ExitCodeError
	require.True(t, errors.As(err, &coded), "%v", err)
	require.GreaterOrEqual(t, coded.ExitCode(), ExitCritical) // critical findings beat unknown; the fake's old head may make it 2
	require.Contains(t, []int{ExitCritical, ExitUnknown}, coded.ExitCode())
	chain.With(func(c *vrfake.Chain) { c.FailSyncing = false })

	// without --exit-code the exit status is unchanged
	_, err = runValidator(t, home, "status")
	var c2 *ExitCodeError
	require.False(t, errors.As(err, &c2))
}

// TestJudge: the findings and the verdict they make.
func TestJudge(t *testing.T) {
	ok := func() *validatorStatusReport {
		return &validatorStatusReport{Health: "Healthy", PublicHead: ptrU(100), PublicHeadTime: uint64(time.Now().Unix()), LocalRPC: "x", LocalSync: "in sync"}
	}
	r := ok()
	r.judge(statusThresholds{})
	require.Equal(t, "ok", r.Verdict)
	require.Empty(t, r.Findings)

	cases := []struct {
		name    string
		mut     func(*validatorStatusReport)
		verdict string
		code    string
	}{
		{"module", func(r *validatorStatusReport) { r.Health = "Stalled" }, "critical", "module_unhealthy"},
		{"keys", func(r *validatorStatusReport) { r.LocalKeys = "other" }, "critical", "keys_mismatch"},
		{"stalled chain", func(r *validatorStatusReport) { r.PublicHeadTime = uint64(time.Now().Add(-10 * time.Minute).Unix()) }, "critical", "chain_stalled"},
		{"slow chain", func(r *validatorStatusReport) { r.PublicHeadTime = uint64(time.Now().Add(-90 * time.Second).Unix()) }, "warning", "chain_slow"},
		{"record lag", func(r *validatorStatusReport) { r.RecordCount, r.RecordCursor = 500, 100 }, "warning", "record_lag"},
		{"parked", func(r *validatorStatusReport) { r.PoaState = "Parked" }, "warning", "identity_parked"},
		{"local down", func(r *validatorStatusReport) { r.LocalSync = "unreachable: connection refused" }, "critical", "local_unreachable"},
		{"local behind", func(r *validatorStatusReport) {
			h := uint64(91)
			ph := uint64(100)
			r.PublicHead, r.LocalHead, r.LocalSync = &ph, &h, "behind by 9 blocks"
		}, "warning", "local_behind"},
		{"local far behind", func(r *validatorStatusReport) {
			h := uint64(20)
			ph := uint64(100)
			r.PublicHead, r.LocalHead, r.LocalSync = &ph, &h, "behind by 80 blocks"
		}, "critical", "local_behind"},
		{"syncing far behind is critical, not a warning", func(r *validatorStatusReport) {
			h := uint64(1)
			ph := uint64(1000)
			r.PublicHead, r.LocalHead, r.LocalSync = &ph, &h, "syncing (block 1 of 1000)"
		}, "critical", "local_behind"},
		{"syncing close behind", func(r *validatorStatusReport) {
			h := uint64(99)
			ph := uint64(100)
			r.PublicHead, r.LocalHead, r.LocalSync = &ph, &h, "syncing (block 99 of 100)"
		}, "warning", "local_syncing"},
		{"upgrade far", func(r *validatorStatusReport) {
			r.Epoch = 3
			r.UpgradeRequired = []statusUpgrade{{Rule: "r", Release: "x", RootEpoch: 9}}
		}, "warning", "upgrade_required"},
		{"upgrade imminent", func(r *validatorStatusReport) {
			r.Epoch = 8
			r.UpgradeRequired = []statusUpgrade{{Rule: "r", Release: "x", RootEpoch: 9}}
		}, "critical", "upgrade_imminent"},
		{"unknown", func(r *validatorStatusReport) { r.Unknown = []string{"identity: x"} }, "unknown", ""},
		{"critical beats unknown", func(r *validatorStatusReport) { r.Unknown = []string{"x"}; r.Health = "Faulted" }, "critical", "module_unhealthy"},
	}
	for _, c := range cases {
		r := ok()
		c.mut(r)
		r.judge(statusThresholds{})
		require.Equal(t, c.verdict, r.Verdict, c.name)
		if c.code != "" {
			found := false
			for _, f := range r.Findings {
				found = found || f.Code == c.code
			}
			require.True(t, found, "%s: %v", c.name, r.Findings)
		}
	}
}

// TestExporterMetrics: one polled status becomes the unicity_vr_* series, and a state change logs the identity event.
func TestExporterMetrics(t *testing.T) {
	var logs strings.Builder
	one, two := uint8(4), uint64(7)
	e := &validatorExporter{log: slog.New(slog.NewTextHandler(&logs, nil)), rep: &validatorStatusReport{Identity: "found", ID: 2, PoaState: "Active", PoaStateCode: &one, Member: true, Health: "Healthy",
		RecordCount: 40, RecordCursor: 30, CustodyCursor: &two, Verdict: "ok", Committee: []uint64{1, 2, 3}, PublicHead: ptrU(100), LocalRPC: "x", LocalHead: &two}, localMax: 7}
	reg := prometheus.NewRegistry()
	reg.MustRegister(e)
	seen := map[string]bool{}
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		seen[mf.GetName()] = true
		if mf.GetName() == "unicity_evm_head_lag_blocks" {
			require.Equal(t, 93.0, mf.GetMetric()[0].GetGauge().GetValue()) // public 100, local 7
		}
	}
	for _, n := range []string{"unicity_vr_record_application_lag", "unicity_vr_identity_state", "unicity_vr_custody_cursor_minus_vr_cursor", "unicity_evm_head_lag_blocks"} {
		require.True(t, seen[n], n)
	}
}

// TestHeadResponses: a null block or a header without its fields is an error, never height 0 at time 0; block 0 itself is a real answer.
func TestHeadResponses(t *testing.T) {
	answer := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":`+answer+`}`)
	}))
	defer srv.Close()
	c, err := dialBounded(context.Background(), srv.URL)
	require.NoError(t, err)
	defer c.Close()
	for _, bad := range []string{`null`, `{}`, `{"number":"0x5"}`, `{"timestamp":"0x5"}`} {
		answer = bad
		_, _, err := blockInfo(context.Background(), c, "latest")
		require.Error(t, err, bad)
	}
	answer = `{"number":"0x0","timestamp":"0x0"}`
	n, ts, err := blockInfo(context.Background(), c, "latest")
	require.NoError(t, err)
	require.Zero(t, n+ts)
}

// TestRPCResponseIsBounded: a response beyond the bound is refused, not read.
func TestRPCResponseIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"`)
		chunk := strings.Repeat("a", 1<<20)
		for i := 0; i < maxRPCBody>>20+2; i++ {
			_, _ = io.WriteString(w, chunk)
		}
		_, _ = io.WriteString(w, `"}`)
	}))
	defer srv.Close()
	c, err := dialBounded(context.Background(), srv.URL)
	require.NoError(t, err)
	defer c.Close()
	var out string
	require.Error(t, c.CallContext(context.Background(), &out, "eth_blockNumber"))
}

func TestParseCount(t *testing.T) {
	for in, want := range map[string]uint64{"0": 0, "12": 12, "1.2e+06": 1200000} {
		got, err := parseCount("m", in)
		require.NoError(t, err, in)
		require.Equal(t, want, got)
	}
	for _, bad := range []string{"NaN", "+Inf", "-1", "1.5", "1e300", "abc", ""} {
		_, err := parseCount("m", bad)
		require.Error(t, err, bad)
	}
}

func gather(t *testing.T, e *validatorExporter) map[string][]float64 {
	reg := prometheus.NewRegistry()
	reg.MustRegister(e)
	mfs, err := reg.Gather()
	require.NoError(t, err)
	out := map[string][]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			out[mf.GetName()] = append(out[mf.GetName()], m.GetGauge().GetValue())
		}
	}
	return out
}

// TestExporterUnknownIsAbsent: an unreachable local client that was never seen has no lag value; the root target and the upgrade series are absent
// when unknown, and the upgrade series follow the schedule (they clear when it no longer holds the rule).
func TestExporterUnknownIsAbsent(t *testing.T) {
	var logs strings.Builder
	rep := &validatorStatusReport{Identity: "found", Health: "Healthy", PublicHead: ptrU(100), LocalRPC: "x", Epoch: 3, Verdict: "ok"}
	e := &validatorExporter{log: slog.New(slog.NewTextHandler(&logs, nil)), rep: rep}
	m := gather(t, e)
	require.NotContains(t, m, "unicity_evm_head_lag_blocks", "no local head was ever observed")
	require.Equal(t, []float64{0}, m["unicity_evm_local_up"])
	require.NotContains(t, m, "unicity_vr_record_root_target")
	require.Equal(t, []float64{0}, m["unicity_upgrade_schedule_known"])
	require.NotContains(t, m, "unicity_upgrade_required", "an unreadable schedule is unknown, not 0")

	rep.ScheduleKnown = true
	rep.UpgradeRequired = []statusUpgrade{{Rule: "ab", Release: "cd", RootEpoch: 6, State: "Active"}}
	m = gather(t, e)
	require.Equal(t, []float64{1}, m["unicity_upgrade_required"])
	require.Equal(t, []float64{3}, m["unicity_upgrade_epochs_remaining"])
	rep.UpgradeRequired = nil // superseded or implemented: the next poll's schedule no longer holds it
	m = gather(t, e)
	require.Equal(t, []float64{0}, m["unicity_upgrade_required"])
	require.NotContains(t, m, "unicity_upgrade_epochs_remaining")

	// a head seen once, then the client stops: the lag is measured against the highest head it showed
	h := uint64(90)
	rep.LocalHead = &h
	e.localMax, e.localSeen = 90, true
	rep.LocalHead = nil
	m = gather(t, e)
	require.Equal(t, []float64{10}, m["unicity_evm_head_lag_blocks"])
}

func ptrU(v uint64) *uint64 { return &v }
