package cmd

import (
	"encoding/json"
	"errors"
	"log/slog"
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
		return &validatorStatusReport{Health: "Healthy", PublicHeadTime: uint64(time.Now().Unix()), LocalRPC: "x", LocalSync: "in sync"}
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
		{"local behind", func(r *validatorStatusReport) { r.LocalSync = "behind by 9 blocks" }, "warning", "local_behind"},
		{"local far behind", func(r *validatorStatusReport) { r.LocalSync = "behind by 80 blocks" }, "critical", "local_behind"},
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
		RecordCount: 40, RecordCursor: 30, CustodyCursor: &two, Verdict: "ok", Committee: []uint64{1, 2, 3}, PublicHead: 100, LocalRPC: "x", LocalHead: &two}, localMax: 7}
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
