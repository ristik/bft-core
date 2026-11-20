package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/vrclient"
)

// The exit codes of `validator status --exit-code`.
const (
	ExitOK       = 0
	ExitWarning  = 1
	ExitCritical = 2
	ExitUnknown  = 3
)

// ExitCodeError makes the process exit with Code; main reads it through ExitCode().
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit status %d", e.Code)
}
func (e *ExitCodeError) Unwrap() error { return e.Err }

// ExitCode is the process exit status.
func (e *ExitCodeError) ExitCode() int { return e.Code }

// Silent is true when the report already said everything (a verdict), so main prints no error line.
func (e *ExitCodeError) Silent() bool { return e.Err == nil }

// Finding is one thing status found wrong or worth knowing. Codes are stable (docs/operations/monitoring/runbooks.md names each).
type Finding struct {
	Severity string `json:"severity"` // "warning" or "critical"
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// statusThresholds are the limits status judges against. The defaults suit a testnet generation (a block about every 10 s, H = 16).
type statusThresholds struct {
	MaxHeadAge    time.Duration // the public chain produced no EVM block for longer than this: critical
	WarnHeadAge   time.Duration // ... warning
	MaxRecordLag  uint64        // VR has imported (SealRegistry) more records than it applied by this many: warning
	MaxLocalBlock uint64        // the local ureth trails the public head by more blocks than this: warning (critical: ten times it)
}

func (t *statusThresholds) add(cmd *cobra.Command) {
	cmd.Flags().DurationVar(&t.WarnHeadAge, "warn-head-age", 60*time.Second, "warning when the public head is older than this (no EVM block produced)")
	cmd.Flags().DurationVar(&t.MaxHeadAge, "max-head-age", 180*time.Second, "critical when the public head is older than this")
	cmd.Flags().Uint64Var(&t.MaxRecordLag, "max-record-lag", 128, "warning when SealRegistry's imported record count exceeds VR's cursor by more than this")
	cmd.Flags().Uint64Var(&t.MaxLocalBlock, "max-local-lag", 5, "warning when the local ureth trails the public head by more than this many blocks (critical at ten times)")
}

func (t statusThresholds) withDefaults() statusThresholds {
	if t.WarnHeadAge == 0 {
		t.WarnHeadAge = 60 * time.Second
	}
	if t.MaxHeadAge == 0 {
		t.MaxHeadAge = 180 * time.Second
	}
	if t.MaxRecordLag == 0 {
		t.MaxRecordLag = 128
	}
	if t.MaxLocalBlock == 0 {
		t.MaxLocalBlock = 5
	}
	return t
}

func (r *validatorStatusReport) find(sev, code, format string, args ...any) {
	r.Findings = append(r.Findings, Finding{Severity: sev, Code: code, Message: fmt.Sprintf(format, args...)})
}

// judge sets the verdict from what the report holds. A read that failed makes the verdict "unknown" unless something already critical was
// found; the finding codes are part of the monitoring compatibility promise.
func (r *validatorStatusReport) judge(t statusThresholds) {
	t = t.withDefaults()
	r.Findings = nil
	if r.Health != "Healthy" {
		r.find("critical", "module_unhealthy", "VR's active module reports %s", r.Health)
	}
	if r.LocalKeys == "other" {
		r.find("critical", "keys_mismatch", "the local keys do not match the binding in VR")
	}
	switch r.PoaState {
	case "Parked":
		r.find("warning", "identity_parked", "this identity is Parked: it is not electable until its owner or the governance acts")
	case "Exited":
		r.find("warning", "identity_exited", "this identity has exited")
	case "Active":
		if !r.Member {
			r.find("warning", "active_not_member", "PoA says Active but the identity is not in the committee (it joins at the next boundary)")
		}
	}
	if r.Staged != nil && r.LocalKeys == "staged" {
		r.find("warning", "staged_binding", "the keys match the STAGED binding: they sign only once it is installed")
	}
	if r.PublicHeadTime != 0 {
		age := time.Since(time.Unix(int64(r.PublicHeadTime), 0))
		switch {
		case age > t.MaxHeadAge:
			r.find("critical", "chain_stalled", "the public head is %s old: no EVM block was produced", age.Round(time.Second))
		case age > t.WarnHeadAge:
			r.find("warning", "chain_slow", "the public head is %s old", age.Round(time.Second))
		}
	}
	if r.RecordCount > r.RecordCursor && r.RecordCount-r.RecordCursor > t.MaxRecordLag {
		r.find("warning", "record_lag", "VR has applied %d of the %d imported root records (lag %d)", r.RecordCursor, r.RecordCount, r.RecordCount-r.RecordCursor)
	}
	if r.OpenOutput != nil && r.OpenOutput.ProgressLeft < 0 {
		r.find("warning", "output_expired", "the open output %s is past its expiry (progress %d)", r.OpenOutput.ID[:8], r.OpenOutput.ExpiresAtProgress)
	}
	switch {
	case r.LocalRPC == "":
	case strings.HasPrefix(r.LocalSync, "unreachable"):
		r.find("critical", "local_unreachable", "the local execution client does not answer: %s", r.LocalSync)
	case strings.HasPrefix(r.LocalSync, "behind by "):
		n, _ := strconv.ParseUint(strings.Fields(strings.TrimPrefix(r.LocalSync, "behind by "))[0], 10, 64)
		sev := "warning"
		if n > 10*t.MaxLocalBlock {
			sev = "critical"
		}
		if n > t.MaxLocalBlock {
			r.find(sev, "local_behind", "the local execution client is %d blocks behind the public head", n)
		}
	case strings.HasPrefix(r.LocalSync, "syncing"):
		r.find("warning", "local_syncing", "the local execution client is syncing: %s", r.LocalSync)
	}
	switch {
	case hasSeverity(r.Findings, "critical"):
		r.Verdict = "critical"
	case len(r.Unknown) > 0:
		r.Verdict = "unknown"
	case hasSeverity(r.Findings, "warning"):
		r.Verdict = "warning"
	default:
		r.Verdict = "ok"
	}
}

func hasSeverity(fs []Finding, sev string) bool {
	for _, f := range fs {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

// exitForVerdict turns a verdict into the exit status; the report was already printed, so a verdict that is not ok carries no error text.
func exitForVerdict(r *validatorStatusReport, err error) error {
	switch r.Verdict {
	case "ok":
		return nil
	case "warning":
		return &ExitCodeError{Code: ExitWarning}
	case "critical":
		return &ExitCodeError{Code: ExitCritical}
	}
	return &ExitCodeError{Code: ExitUnknown, Err: err}
}

var custodyABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"recordCursor","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]}]`))
	if err != nil {
		panic(err)
	}
	return a
}()

// readCounters reads the two counters VR's own clock does not hold: custody's cursor (--custody) and the root's projected-record count
// (--root-metrics), the first at the same pinned block as the rest. A failed read is listed in Unknown, never counted as zero.
func (r *validatorStatusReport) readCounters(ctx context.Context, f *validatorStatusFlags, vr *vrclient.Client) {
	if f.Custody != "" {
		if !common.IsHexAddress(f.Custody) {
			r.Unknown = append(r.Unknown, "custody cursor: --custody is not an address")
		} else if data, err := custodyABI.Pack("recordCursor"); err != nil {
			r.Unknown = append(r.Unknown, "custody cursor: "+err.Error())
		} else if ret, err := vr.CallRaw(ctx, common.HexToAddress(f.Custody), data); err != nil {
			r.Unknown = append(r.Unknown, "custody cursor: "+err.Error())
		} else if vals, err := custodyABI.Methods["recordCursor"].Outputs.Unpack(ret); err != nil || len(vals) != 1 {
			r.Unknown = append(r.Unknown, fmt.Sprintf("custody cursor: not a recordCursor() answer (%v)", err))
		} else {
			v := vals[0].(uint64)
			r.CustodyCursor = &v
		}
	}
	if f.RootMetrics != "" {
		v, err := fetchRootTarget(ctx, f.RootMetrics)
		if err != nil {
			r.Unknown = append(r.Unknown, "root target: "+err.Error())
		} else {
			r.RecordRootTarget = &v
		}
	}
}

// RootTargetMetric is the root's metric that holds the records it has projected (committed).
const RootTargetMetric = "unicity_root_records_projected"

// fetchRootTarget reads RootTargetMetric from a root's Prometheus text endpoint.
func fetchRootTarget(ctx context.Context, url string) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, RootTargetMetric+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err != nil || f < 0 {
				return 0, fmt.Errorf("%s: unreadable value %q", RootTargetMetric, rest)
			}
			return uint64(f), nil
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New(RootTargetMetric + " is not in the root's metrics")
}
