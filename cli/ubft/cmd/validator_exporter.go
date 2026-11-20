package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/monitoring"
)

// validatorExporter polls `validator status` and serves it as unicity_vr_* / unicity_evm_* metrics. The status read is the one place that
// knows how to read VR, so the CLI, its JSON, the exit code and the exporter cannot disagree. One poll is one pinned block: the record
// counters are sampled at the same point.
type validatorExporter struct {
	flags *validatorStatusFlags
	log   *slog.Logger

	mu        sync.Mutex
	rep       *validatorStatusReport
	lastOK    time.Time
	errs      uint64
	lastErr   string
	prevPoa   string
	prevHlth  string
	headSeen  uint64
	headMove  time.Time
	localMax  uint64 // the highest local head seen: a stopped ureth's lag keeps growing against it
	localSeen bool   // a local head was observed at least once (the lag is unknown before that)
}

func validatorExporterCmd(base *baseFlags) *cobra.Command {
	f := &validatorStatusFlags{validatorFlags: validatorFlags{baseFlags: base}}
	var listen string
	var disks []string
	var every time.Duration
	cmd := &cobra.Command{
		Use:   "exporter",
		Short: "Serve the validator's VR state, record counters and execution-client lag as Prometheus metrics (unicity_vr_*, unicity_evm_*)",
		Long: "Polls the same read as `validator status` (public RPC, optionally --local-rpc from the config, --custody and --root-metrics) every --interval and serves " +
			"it on --listen at /metrics. It logs vr.identity.* and vr.module.health_changed events when the validator's PoA state or the module's health changes. " +
			"Read-only: it holds no key and sends no transaction.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if every <= 0 {
				return fmt.Errorf("--interval must be positive, got %s", every)
			}
			f.NoKeys = true // the exporter reads public data only: no key file is opened
			log := slog.Default()
			if f.baseFlags != nil && f.observe != nil {
				log = f.observe.Logger()
			}
			if v, err := f.load(); err != nil {
				return err
			} else if f.ID == 0 && v.cfg.ID == 0 {
				return errors.New("the exporter needs the identity: set \"id\" in the validator config or pass --id (it does not scan logs for it)")
			}
			e := &validatorExporter{flags: f, log: log}
			reg := prometheus.NewRegistry()
			monitoring.RegisterBuildInfo(monitoring.New(reg), "vr-exporter")
			reg.MustRegister(e)
			var vols []monitoring.Volume
			for _, d := range disks {
				name, path, ok := strings.Cut(d, "=")
				if !ok || name == "" || path == "" {
					return fmt.Errorf("--disk-path %q: want name=path", d)
				}
				vols = append(vols, monitoring.Volume{Name: name, Path: path})
			}
			monitoring.RegisterDisk(monitoring.New(reg), log, vols...)
			mux := http.NewServeMux()
			mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
			if err := checkAuthorityMetricsAddress(listen); err != nil { // the same rule: a loopback address; Prometheus reaches it through a relay or a same-host scrape
				return fmt.Errorf("--listen: %w", err)
			}
			ctx := cmd.Context()
			go e.run(ctx, every)
			srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
			go func() { <-ctx.Done(); _ = srv.Close() }()
			log.Info("validator exporter", "listen", listen, "interval", every.String())
			if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
				return err
			}
			return nil
		},
	}
	f.validatorFlags.add(cmd)
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:9180", "loopback host:port to serve /metrics on")
	cmd.Flags().DurationVar(&every, "interval", 10*time.Second, "how often to read the chain")
	cmd.Flags().StringArrayVar(&disks, "disk-path", nil, "name=path of a directory whose filesystem to watch (unicity_disk_*{volume=name}); repeatable, for example the execution client's data directory")
	cmd.Flags().StringVar(&f.Custody, "custody", "", "PoS generation: the custody contract (holder 0), for the custody cursor")
	cmd.Flags().StringVar(&f.RootMetrics, "root-metrics", "", "the root's metrics URL, for the root target of the record counters")
	f.Thresholds.add(cmd)
	return cmd
}

func (e *validatorExporter) run(ctx context.Context, every time.Duration) {
	e.poll(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.poll(ctx)
		}
	}
}

func (e *validatorExporter) poll(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	r, err := validatorStatus(pctx, e.flags)
	e.mu.Lock()
	defer e.mu.Unlock()
	if r == nil {
		e.errs++
		e.lastErr = err.Error()
		e.rep = nil
		e.log.Warn("validator state could not be read", "error", err)
		return
	}
	if err != nil {
		e.errs++
		e.lastErr = err.Error()
	} else {
		e.lastErr = ""
		e.lastOK = time.Now()
	}
	if e.flags.ID == 0 && r.ID != 0 {
		e.flags.ID = r.ID // the identity is found once (a log scan); later polls read it directly
	}
	e.rep = r
	if r.LocalHead != nil && (!e.localSeen || *r.LocalHead > e.localMax) {
		e.localMax, e.localSeen = *r.LocalHead, true
	}
	if r.PublicHead != nil && (*r.PublicHead != e.headSeen || e.headMove.IsZero()) {
		e.headSeen, e.headMove = *r.PublicHead, time.Now()
	}
	state := r.PoaState
	if r.Identity == "none" {
		state = "None"
	}
	if r.Identity != "unknown" && state != e.prevPoa {
		e.log.Info("validator state changed", "id", r.ID, "state", state, "previous", e.prevPoa, "member", r.Member, "progress", r.Progress, monitoring.Event(monitoring.IdentityEvent(state)))
		e.prevPoa = state
	}
	if r.Health != e.prevHlth {
		lvl := slog.LevelInfo
		if r.Health != "Healthy" {
			lvl = slog.LevelWarn
		}
		e.log.Log(ctx, lvl, "VR module health changed", "health", r.Health, "previous", e.prevHlth, "module", r.Module, monitoring.Event(monitoring.EvVRModuleHealth))
		e.prevHlth = r.Health
	}
}

var (
	dUp       = prometheus.NewDesc("unicity_vr_up", "1 when the last read of VR through the public RPC succeeded completely.", nil, nil)
	dErrs     = prometheus.NewDesc("unicity_vr_read_errors_total", "Reads of VR that failed or were incomplete.", nil, nil)
	dLastOK   = prometheus.NewDesc("unicity_vr_last_success_timestamp_seconds", "Unix time of the last complete read.", nil, nil)
	dHealth   = prometheus.NewDesc("unicity_vr_module_health", "VR's active module health: 0 Healthy, 1 Faulted, 2 Stalled, 3 Inconsistent.", nil, nil)
	dBlock    = prometheus.NewDesc("unicity_vr_read_block", "The EVM block the counters were read at (one pinned block).", nil, nil)
	dEpoch    = prometheus.NewDesc("unicity_vr_root_epoch", "The root epoch VR knows.", nil, nil)
	dCommit   = prometheus.NewDesc("unicity_vr_committee_size", "Members of the committee VR holds.", nil, nil)
	dProgress = prometheus.NewDesc("unicity_vr_progress", "SealRegistry progress (VR's clock).", nil, nil)
	dToBound  = prometheus.NewDesc("unicity_vr_progress_to_next_boundary", "Progress units until the next election may be reserved (negative: past the epoch gap).", nil, nil)
	dOutState = prometheus.NewDesc("unicity_vr_open_output_state", "State of VR's open output: 0 none, 1 Reserved, 2 Published, 3 Invalidated, 4 Rejected, 5 Acknowledged, 6 Recovered, 7 Closed.", nil, nil)
	dOutLeft  = prometheus.NewDesc("unicity_vr_open_output_progress_left", "Progress units until the open output expires (negative: expired); absent without an open output.", nil, nil)
	dPending  = prometheus.NewDesc("unicity_vr_boundary_pending", "1 while an output is acknowledged and its Boundary record is awaited.", nil, nil)
	dTarget   = prometheus.NewDesc("unicity_vr_record_root_target", "Records the root has projected (root target).", nil, nil)
	dImported = prometheus.NewDesc("unicity_vr_record_imported", "Records the SealRegistry has imported (recordCount).", nil, nil)
	dVRCursor = prometheus.NewDesc("unicity_vr_record_cursor", "Records VR has applied (VR recordCursor).", nil, nil)
	dCustody  = prometheus.NewDesc("unicity_vr_custody_record_cursor", "Records custody has applied (custody recordCursor); PoS generations only.", nil, nil)
	dImpLag   = prometheus.NewDesc("unicity_vr_record_import_lag", "Root target minus imported count.", nil, nil)
	dAppLag   = prometheus.NewDesc("unicity_vr_record_application_lag", "Imported count minus VR cursor.", nil, nil)
	dCustDiff = prometheus.NewDesc("unicity_vr_custody_cursor_minus_vr_cursor", "Signed: custody cursor minus VR cursor (custody may legitimately lead; persistently negative is the problem).", nil, nil)
	dIdKnown  = prometheus.NewDesc("unicity_vr_identity_known", "1 when the exporter knows which VR identity it watches.", nil, nil)
	dIdState  = prometheus.NewDesc("unicity_vr_identity_state", "The watched identity's PoA state: 0 None, 1 Applied, 2 Admitted, 3 Joining, 4 Active, 5 ExitRequested, 6 Removing, 7 Leaving, 8 Exited, 9 Parked.", nil, nil)
	dIdInfo   = prometheus.NewDesc("unicity_vr_identity_info", "The watched identity (value 1).", []string{"id", "state"}, nil)
	dMember   = prometheus.NewDesc("unicity_vr_identity_member", "1 when the watched identity is in the committee.", nil, nil)
	dStaged   = prometheus.NewDesc("unicity_vr_identity_staged_binding", "1 when a binding is staged for the watched identity.", nil, nil)
	dTargetAt = prometheus.NewDesc("unicity_vr_record_root_target_sample_timestamp_seconds", "Unix time the root target was sampled from the root's metrics: a separate observation, not at the pinned EVM block.", nil, nil)
	dSchedule = prometheus.NewDesc("unicity_upgrade_schedule_known", "1 when VR's activation schedule was read at the last poll, 0 when it could not be (the upgrade series are then absent: unknown, not zero).", nil, nil)
	dUpReq    = prometheus.NewDesc("unicity_upgrade_required", "1 while VR's activation schedule holds an Active or Latched rule (rule, release) this binary does not implement; reconciled from the schedule at every poll, so it clears on supersession or when the binary implements the rule.", nil, nil)
	dUpLeft   = prometheus.NewDesc("unicity_upgrade_epochs_remaining", "Root epochs left before the earliest unsupported rule activates (negative: already past); absent while none is required.", nil, nil)
	dUpInfo   = prometheus.NewDesc("unicity_upgrade_rule_info", "A schedule rule this binary does not implement (value 1).", []string{"rule", "release", "activation_epoch", "state"}, nil)
	dActs     = prometheus.NewDesc("unicity_vr_activations", "Entries in VR's activation schedule.", nil, nil)
	dVerdict  = prometheus.NewDesc("unicity_vr_status_verdict", "validator status verdict: 0 ok, 1 warning, 2 critical, 3 unknown.", nil, nil)
	dPubHead  = prometheus.NewDesc("unicity_evm_public_head_number", "Block number of the public RPC's head.", nil, nil)
	dPubAge   = prometheus.NewDesc("unicity_evm_public_head_age_seconds", "Age of the public RPC's head block: the eligible-block cadence going wrong shows here.", nil, nil)
	dLocalUp  = prometheus.NewDesc("unicity_evm_local_up", "1 when the local execution client answers (needs localRpc in the config).", nil, nil)
	dLocalHd  = prometheus.NewDesc("unicity_evm_local_head_number", "Block number of the local execution client's head.", nil, nil)
	dLocalLag = prometheus.NewDesc("unicity_evm_head_lag_blocks", "Public head minus the local execution client's head; while it is unreachable, minus the highest head it showed.", nil, nil)
)

func (e *validatorExporter) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{dUp, dErrs, dLastOK, dHealth, dBlock, dEpoch, dCommit, dProgress, dToBound, dOutState, dOutLeft, dPending, dTarget, dImported, dVRCursor,
		dCustody, dImpLag, dAppLag, dCustDiff, dIdKnown, dIdState, dIdInfo, dMember, dStaged, dActs, dTargetAt, dSchedule, dUpReq, dUpLeft, dUpInfo, dVerdict, dPubHead, dPubAge, dLocalUp, dLocalHd, dLocalLag} {
		ch <- d
	}
}

func (e *validatorExporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	g := func(d *prometheus.Desc, v float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
	}
	b := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}
	ch <- prometheus.MustNewConstMetric(dErrs, prometheus.CounterValue, float64(e.errs))
	r := e.rep
	g(dUp, b(r != nil && e.lastErr == ""))
	if !e.lastOK.IsZero() {
		g(dLastOK, float64(e.lastOK.Unix()))
	}
	if r == nil {
		return
	}
	g(dHealth, float64(r.HealthCode))
	g(dBlock, float64(r.Block))
	g(dEpoch, float64(r.Epoch))
	g(dCommit, float64(len(r.Committee)))
	g(dProgress, float64(r.Progress))
	g(dToBound, float64(int64(r.EarliestBoundaryProgress)-int64(r.Progress)))
	if r.OpenOutput != nil {
		g(dOutState, float64(r.OpenOutput.StateCode))
		g(dOutLeft, float64(r.OpenOutput.ProgressLeft))
	} else {
		g(dOutState, 0)
	}
	g(dPending, b(r.PendingBoundary))
	g(dImported, float64(r.RecordCount))
	g(dVRCursor, float64(r.RecordCursor))
	g(dAppLag, float64(int64(r.RecordCount)-int64(r.RecordCursor)))
	if r.RecordRootTarget != nil {
		g(dTarget, float64(*r.RecordRootTarget))
		g(dTargetAt, float64(r.RecordRootTargetAt))
		g(dImpLag, float64(int64(*r.RecordRootTarget)-int64(r.RecordCount)))
	}
	if r.CustodyCursor != nil {
		g(dCustody, float64(*r.CustodyCursor))
		g(dCustDiff, float64(int64(*r.CustodyCursor)-int64(r.RecordCursor)))
	}
	g(dIdKnown, b(r.Identity == "found"))
	if r.PoaStateCode != nil {
		g(dIdState, float64(*r.PoaStateCode))
		g(dIdInfo, 1, fmt.Sprint(r.ID), r.PoaState)
	}
	g(dMember, b(r.Member))
	g(dStaged, b(r.Staged != nil))
	g(dActs, float64(len(r.Activations)))
	g(dSchedule, b(r.ScheduleKnown))
	if r.ScheduleKnown {
		g(dUpReq, b(len(r.UpgradeRequired) > 0))
		least, have := int64(0), false
		for _, u := range r.UpgradeRequired {
			ch <- prometheus.MustNewConstMetric(dUpInfo, prometheus.GaugeValue, 1, u.Rule, u.Release, fmt.Sprint(u.RootEpoch), u.State)
			if left := int64(u.RootEpoch) - int64(r.Epoch); !have || left < least {
				least, have = left, true
			}
		}
		if have {
			g(dUpLeft, float64(least))
		}
	}
	switch r.Verdict {
	case "ok":
		g(dVerdict, 0)
	case "warning":
		g(dVerdict, 1)
	case "critical":
		g(dVerdict, 2)
	default:
		g(dVerdict, 3)
	}
	if r.PublicHead != nil {
		g(dPubHead, float64(*r.PublicHead))
	}
	if r.PublicHeadTime != 0 {
		g(dPubAge, time.Since(time.Unix(int64(r.PublicHeadTime), 0)).Seconds())
	}
	if r.LocalRPC != "" {
		up := r.LocalHead != nil
		g(dLocalUp, b(up))
		ref, known := e.localMax, e.localSeen
		if up {
			g(dLocalHd, float64(*r.LocalHead))
			ref, known = *r.LocalHead, true
		}
		// the lag needs a local head to measure against: none was ever observed, so there is no lag value (not "the whole chain")
		if known && r.PublicHead != nil {
			if *r.PublicHead > ref {
				g(dLocalLag, float64(*r.PublicHead-ref))
			} else {
				g(dLocalLag, 0)
			}
		}
	}
}
