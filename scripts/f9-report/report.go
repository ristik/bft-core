package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/unicitynetwork/bft-core/archivewiring"
)

const (
	maxConfigBytes       = 1 << 20
	maxResponseBytes     = 4 << 20
	maxStatusBytes       = 1 << 20
	maxNodes             = 64
	maxSamples           = 1000
	maxTotalSamplingTime = 24 * time.Hour
	maxArchiveEntries    = 250_000
	defaultArchiveLimit  = 100_000
	maxConcurrentNodes   = 8
)

type nodeConfig struct {
	Name           string `json:"name"`
	StatusURL      string `json:"status_url"`
	MetricsURL     string `json:"metrics_url"`
	ArchiveDir     string `json:"archive_dir"`
	ProcessPIDFile string `json:"process_pid_file,omitempty"`
}

type config struct {
	Nodes             []nodeConfig `json:"nodes"`
	Samples           int          `json:"samples"`
	Interval          string       `json:"interval"`
	MaxArchiveEntries uint64       `json:"max_archive_entries,omitempty"`
}

type checkedConfig struct {
	Nodes             []nodeConfig
	Samples           int
	Interval          time.Duration
	MaxArchiveEntries uint64
}

type report struct {
	SchemaVersion int          `json:"schemaVersion"`
	StartedAt     time.Time    `json:"startedAt"`
	FinishedAt    time.Time    `json:"finishedAt"`
	Complete      bool         `json:"complete"`
	Nodes         []nodeReport `json:"nodes"`
}

type nodeReport struct {
	Name           string                     `json:"name"`
	StartedAt      time.Time                  `json:"startedAt"`
	FinishedAt     time.Time                  `json:"finishedAt"`
	Complete       bool                       `json:"complete"`
	Samples        int                        `json:"samples"`
	Errors         []string                   `json:"errors,omitempty"`
	ErrorsOmitted  uint64                     `json:"errorsOmitted,omitempty"`
	RootEpoch      uint64                     `json:"rootEpoch"`
	CertifiedTip   *archivewiring.BlockPin    `json:"certifiedTip,omitempty"`
	RestoreBase    *archivewiring.BlockPin    `json:"restoreBase,omitempty"`
	LatestLocalV2  *archivewiring.BlockPin    `json:"latestLocalV2Archive,omitempty"`
	PruneFrontier  *archivewiring.BlockPin    `json:"pruneFrontier,omitempty"`
	FrontierTipGap *uint64                    `json:"frontierTipGap,omitempty"`
	Journal        archivewiring.JournalUsage `json:"journal"`
	Archive        archiveUsage               `json:"archive"`
	Replicas       []replicaLag               `json:"replicas"`
	Process        processReport              `json:"process"`
	Witness        witnessReport              `json:"witnessVerification"`
	Certification  certificationReport        `json:"certification"`
}

type replicaLag struct {
	Peer                   string  `json:"peer"`
	LastAcknowledgedHeight uint64  `json:"lastAcknowledgedHeight"`
	LagBlocks              *uint64 `json:"lagBlocks,omitempty"`
	Error                  string  `json:"error,omitempty"`
}

type processReport struct {
	StartTimeUnix   *float64 `json:"startTimeUnix,omitempty"`
	CPUSecondsTotal *float64 `json:"cpuSecondsTotal,omitempty"`
	CPUPercent      *float64 `json:"cpuPercent,omitempty"`
	RSSBytes        *float64 `json:"rssBytes,omitempty"`
	OpenFDs         *float64 `json:"openFDs,omitempty"`
}

type witnessReport struct {
	Available  bool              `json:"available"`
	Count      uint64            `json:"count"`
	ByOutcome  map[string]uint64 `json:"byOutcome,omitempty"`
	P50Seconds *float64          `json:"p50Seconds,omitempty"`
	P99Seconds *float64          `json:"p99Seconds,omitempty"`
}

type certificationReport struct {
	EpochTransitionObserved bool     `json:"epochTransitionObserved"`
	PauseMetricsAvailable   bool     `json:"pauseMetricsAvailable"`
	LastCertifiedAt         *float64 `json:"lastCertifiedAtUnix,omitempty"`
	PauseStartAt            *float64 `json:"lastEpochTransitionPauseStartUnix,omitempty"`
	PauseEndAt              *float64 `json:"lastEpochTransitionPauseEndUnix,omitempty"`
	PauseDurationSeconds    *float64 `json:"lastEpochTransitionPauseSeconds,omitempty"`
}

type sample struct {
	at      time.Time
	status  archivewiring.OperatorStatus
	metrics map[string]*dto.MetricFamily
	process *processSnapshot
}

func loadConfig(path string) (checkedConfig, error) {
	var raw config
	info, err := os.Stat(path)
	if err != nil {
		return checkedConfig{}, err
	}
	if info.Size() < 0 || info.Size() > maxConfigBytes {
		return checkedConfig{}, fmt.Errorf("config file exceeds %d bytes", maxConfigBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return checkedConfig{}, err
	}
	defer f.Close()
	configBytes, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return checkedConfig{}, fmt.Errorf("reading config: %w", err)
	}
	if len(configBytes) > maxConfigBytes {
		return checkedConfig{}, fmt.Errorf("config file exceeds %d bytes", maxConfigBytes)
	}
	dec := json.NewDecoder(strings.NewReader(string(configBytes)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return checkedConfig{}, fmt.Errorf("decoding config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return checkedConfig{}, errors.New("config contains trailing JSON")
	}
	if len(raw.Nodes) == 0 || len(raw.Nodes) > maxNodes {
		return checkedConfig{}, fmt.Errorf("nodes must contain between 1 and %d entries", maxNodes)
	}
	if raw.Samples < 2 || raw.Samples > maxSamples {
		return checkedConfig{}, fmt.Errorf("samples must be between 2 and %d", maxSamples)
	}
	interval, err := time.ParseDuration(raw.Interval)
	if err != nil || interval < 0 {
		return checkedConfig{}, fmt.Errorf("interval must be a non-negative duration")
	}
	if interval > maxTotalSamplingTime/time.Duration(raw.Samples-1) {
		return checkedConfig{}, fmt.Errorf("sampling window exceeds %s", maxTotalSamplingTime)
	}
	limit := raw.MaxArchiveEntries
	if limit == 0 {
		limit = defaultArchiveLimit
	}
	if limit > maxArchiveEntries {
		return checkedConfig{}, fmt.Errorf("max_archive_entries exceeds %d", maxArchiveEntries)
	}
	seen := make(map[string]struct{}, len(raw.Nodes))
	for i := range raw.Nodes {
		n := &raw.Nodes[i]
		n.Name = strings.TrimSpace(n.Name)
		if n.Name == "" {
			return checkedConfig{}, fmt.Errorf("node %d has an empty name", i)
		}
		if _, ok := seen[n.Name]; ok {
			return checkedConfig{}, fmt.Errorf("duplicate node name %q", n.Name)
		}
		seen[n.Name] = struct{}{}
		if err := validateReadURL(n.StatusURL); err != nil {
			return checkedConfig{}, fmt.Errorf("node %q status_url: %w", n.Name, err)
		}
		if err := validateReadURL(n.MetricsURL); err != nil {
			return checkedConfig{}, fmt.Errorf("node %q metrics_url: %w", n.Name, err)
		}
		if strings.TrimSpace(n.ArchiveDir) == "" {
			return checkedConfig{}, fmt.Errorf("node %q archive_dir is required", n.Name)
		}
	}
	return checkedConfig{Nodes: raw.Nodes, Samples: raw.Samples, Interval: interval, MaxArchiveEntries: limit}, nil
}

func validateReadURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be an http(s) base URL with host, without credentials, path, query or fragment")
	}
	return nil
}

func collect(ctx context.Context, cfg checkedConfig, client *http.Client, now func() time.Time) report {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	out := report{SchemaVersion: 1, StartedAt: now(), Complete: true, Nodes: make([]nodeReport, len(cfg.Nodes))}
	sem := make(chan struct{}, maxConcurrentNodes)
	var wg sync.WaitGroup
	for i := range cfg.Nodes {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				node := nodeReport{Name: cfg.Nodes[i].Name, StartedAt: now(), Complete: true}
				node.addError(ctx.Err())
				node.Archive = measureArchive(cfg.Nodes[i].ArchiveDir, cfg.MaxArchiveEntries)
				if !node.Archive.Complete {
					node.addError(fmt.Errorf("archive measurement incomplete: %s", node.Archive.Error))
				}
				node.FinishedAt = now()
				out.Nodes[i] = node
				return
			}
			out.Nodes[i] = collectNode(ctx, cfg.Nodes[i], cfg, client, now)
		}()
	}
	wg.Wait()
	for _, node := range out.Nodes {
		if !node.Complete {
			out.Complete = false
		}
	}
	out.FinishedAt = now()
	return out
}

func collectNode(ctx context.Context, node nodeConfig, cfg checkedConfig, client *http.Client, now func() time.Time) nodeReport {
	out := nodeReport{Name: node.Name, StartedAt: now(), Complete: true}
	var firstSample, lastSample *sample
	sampleCount := 0
sampling:
	for i := 0; i < cfg.Samples; i++ {
		if i > 0 && cfg.Interval > 0 {
			t := time.NewTimer(cfg.Interval)
			select {
			case <-ctx.Done():
				t.Stop()
				out.addError(ctx.Err())
				break sampling
			case <-t.C:
			}
		}
		s, err := readSample(ctx, node, client, now())
		if err != nil {
			out.addError(fmt.Errorf("sample %d: %w", i+1, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if firstSample == nil {
			firstSample = &s
		}
		lastSample = &s
		sampleCount++
	}
	out.Samples = sampleCount
	if sampleCount == 0 {
		out.addError(errors.New("no complete status and metrics sample was collected"))
	} else {
		applyStatus(&out, lastSample.status)
		applyMetrics(&out, *firstSample, *lastSample, sampleCount)
	}
	out.Archive = measureArchive(node.ArchiveDir, cfg.MaxArchiveEntries)
	if !out.Archive.Complete {
		out.addError(fmt.Errorf("archive measurement incomplete: %s", out.Archive.Error))
	}
	out.FinishedAt = now()
	return out
}

func (r *nodeReport) addError(err error) {
	if err == nil {
		return
	}
	r.Complete = false
	if len(r.Errors) < 16 {
		r.Errors = append(r.Errors, err.Error())
	} else {
		r.ErrorsOmitted++
	}
}

func readSample(ctx context.Context, node nodeConfig, client *http.Client, at time.Time) (sample, error) {
	statusURL := strings.TrimRight(node.StatusURL, "/") + "/api/v1/operator/status"
	statusReq, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return sample{}, err
	}
	statusResp, err := client.Do(statusReq)
	if err != nil {
		return sample{}, fmt.Errorf("operator status request: %w", err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(statusResp.Body, 4096))
		return sample{}, fmt.Errorf("operator status returned %s: %s", statusResp.Status, strings.TrimSpace(string(body)))
	}
	statusBytes, err := io.ReadAll(io.LimitReader(statusResp.Body, maxStatusBytes+1))
	if err != nil {
		return sample{}, fmt.Errorf("reading operator status: %w", err)
	}
	if len(statusBytes) > maxStatusBytes {
		return sample{}, fmt.Errorf("operator status response exceeds %d bytes", maxStatusBytes)
	}
	var status archivewiring.OperatorStatus
	dec := json.NewDecoder(strings.NewReader(string(statusBytes)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&status); err != nil {
		return sample{}, fmt.Errorf("decoding operator status: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return sample{}, errors.New("operator status has trailing JSON")
	}
	metricsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(node.MetricsURL, "/")+"/api/v1/metrics", nil)
	if err != nil {
		return sample{}, err
	}
	metricsResp, err := client.Do(metricsReq)
	if err != nil {
		return sample{}, fmt.Errorf("metrics request: %w", err)
	}
	defer metricsResp.Body.Close()
	if metricsResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(metricsResp.Body, 4096))
		return sample{}, fmt.Errorf("metrics returned %s: %s", metricsResp.Status, strings.TrimSpace(string(body)))
	}
	metricBytes, err := io.ReadAll(io.LimitReader(metricsResp.Body, maxResponseBytes+1))
	if err != nil {
		return sample{}, fmt.Errorf("reading metrics: %w", err)
	}
	if len(metricBytes) > maxResponseBytes {
		return sample{}, fmt.Errorf("metrics response exceeds %d bytes", maxResponseBytes)
	}
	parser := &expfmt.TextParser{}
	families, err := parser.TextToMetricFamilies(strings.NewReader(string(metricBytes)))
	if err != nil {
		return sample{}, fmt.Errorf("parsing Prometheus metrics: %w", err)
	}
	var process *processSnapshot
	if node.ProcessPIDFile != "" {
		process, err = readProcessSnapshot(ctx, node.ProcessPIDFile)
		if err != nil {
			return sample{}, fmt.Errorf("reading local process metrics: %w", err)
		}
	}
	return sample{at: at, status: status, metrics: families, process: process}, nil
}

func applyStatus(out *nodeReport, status archivewiring.OperatorStatus) {
	out.RootEpoch = status.CurrentRootEpoch
	out.CertifiedTip = status.CertifiedTip
	out.RestoreBase = status.RestoreBase
	out.LatestLocalV2 = status.LatestLocalV2
	out.PruneFrontier = status.PruneFrontier
	out.Journal = status.Journal
	if status.CertifiedTip != nil && status.PruneFrontier != nil {
		gap := uint64(0)
		if status.CertifiedTip.Height > status.PruneFrontier.Height {
			gap = status.CertifiedTip.Height - status.PruneFrontier.Height
		}
		out.FrontierTipGap = &gap
	}
	for _, replica := range status.Replicas {
		var lag *uint64
		if status.CertifiedTip != nil {
			value := uint64(0)
			if status.CertifiedTip.Height > replica.LastAcknowledgedHeight {
				value = status.CertifiedTip.Height - replica.LastAcknowledgedHeight
			}
			lag = &value
		}
		out.Replicas = append(out.Replicas, replicaLag{Peer: replica.Replica,
			LastAcknowledgedHeight: replica.LastAcknowledgedHeight, LagBlocks: lag, Error: replica.Error})
	}
}

func applyMetrics(out *nodeReport, first, last sample, sampleCount int) {
	firstStart := metricScalar(first.metrics, "process_start_time_seconds")
	lastStart := metricScalar(last.metrics, "process_start_time_seconds")
	out.Process.StartTimeUnix = lastStart
	processRestarted := firstStart != nil && lastStart != nil && *firstStart != *lastStart
	if processRestarted {
		out.addError(errors.New("node process restarted during the sampling window"))
	}
	if cpu := metricScalar(last.metrics, "process_cpu_seconds_total"); cpu != nil {
		out.Process.CPUSecondsTotal = cpu
		if sampleCount > 1 && !processRestarted {
			before := metricScalar(first.metrics, "process_cpu_seconds_total")
			elapsed := last.at.Sub(first.at).Seconds()
			if before != nil && *cpu >= *before && elapsed > 0 {
				pct := (*cpu - *before) / elapsed * 100
				out.Process.CPUPercent = &pct
			}
		}
	}
	out.Process.RSSBytes = metricScalar(last.metrics, "process_resident_memory_bytes")
	out.Process.OpenFDs = metricScalar(last.metrics, "process_open_fds")
	if last.process != nil {
		if out.Process.CPUSecondsTotal == nil {
			cpu := last.process.CPUSeconds
			out.Process.CPUSecondsTotal = &cpu
			if first.process != nil && sampleCount > 1 && !processRestarted {
				elapsed := last.at.Sub(first.at).Seconds()
				if elapsed > 0 && cpu >= first.process.CPUSeconds {
					pct := (cpu - first.process.CPUSeconds) / elapsed * 100
					out.Process.CPUPercent = &pct
				}
			}
		}
		if out.Process.RSSBytes == nil {
			value := last.process.RSSBytes
			out.Process.RSSBytes = &value
		}
		if out.Process.OpenFDs == nil {
			value := float64(last.process.OpenFDs)
			out.Process.OpenFDs = &value
		}
	}
	out.Certification.LastCertifiedAt = metricScalar(last.metrics, "shardnode_certification_last_timestamp")
	out.Certification.PauseStartAt = metricScalar(last.metrics, "shardnode_certification_pause_start_timestamp")
	out.Certification.PauseEndAt = metricScalar(last.metrics, "shardnode_certification_pause_end_timestamp")
	out.Certification.PauseMetricsAvailable = out.Certification.PauseStartAt != nil || out.Certification.PauseEndAt != nil
	if start, end := out.Certification.PauseStartAt, out.Certification.PauseEndAt; start != nil && end != nil && *end >= *start {
		duration := *end - *start
		out.Certification.PauseDurationSeconds = &duration
		out.Certification.EpochTransitionObserved = true
	}

	firstCounter := metricCounterOutcomes(first.metrics)
	lastCounter := metricCounterOutcomes(last.metrics)
	if len(lastCounter) > 0 {
		out.Witness.Available = true
		out.Witness.ByOutcome = make(map[string]uint64, len(lastCounter))
		for name, value := range lastCounter {
			if before, ok := firstCounter[name]; ok && value >= before && sampleCount > 1 && !processRestarted {
				value -= before
			}
			count := uint64(value)
			out.Witness.ByOutcome[name] = count
			out.Witness.Count += count
		}
	}
	histLast, histOK := metricHistogram(last.metrics, "recordwiring_witness_verification_duration")
	if !histOK {
		histLast, histOK = metricHistogram(last.metrics, "engineapi_parent_witness_verification_duration")
	}
	if histOK {
		if sampleCount > 1 && !processRestarted {
			histFirst, firstOK := metricHistogram(first.metrics, "recordwiring_witness_verification_duration")
			if !firstOK {
				histFirst, firstOK = metricHistogram(first.metrics, "engineapi_parent_witness_verification_duration")
			}
			if firstOK && histLast.count >= histFirst.count {
				histLast = subtractHistogram(histLast, histFirst)
			}
		}
		out.Witness.P50Seconds = histogramQuantile(histLast, 0.50)
		out.Witness.P99Seconds = histogramQuantile(histLast, 0.99)
		out.Witness.Available = true
	}
	if out.Process.CPUSecondsTotal == nil {
		out.addError(errors.New("process CPU seconds metric is unavailable"))
	}
	if out.Process.CPUPercent == nil {
		out.addError(errors.New("process CPU percentage could not be calculated from the samples"))
	}
	if out.Process.RSSBytes == nil {
		out.addError(errors.New("process RSS metric is unavailable"))
	}
	if out.Process.OpenFDs == nil {
		out.addError(errors.New("process open file descriptor metric is unavailable"))
	}
	if !out.Witness.Available {
		out.addError(errors.New("witness verification metrics are unavailable"))
	}
	if out.Witness.P50Seconds == nil || out.Witness.P99Seconds == nil {
		out.addError(errors.New("witness latency quantiles are unavailable for the sampled interval"))
	}
}

func metricScalar(families map[string]*dto.MetricFamily, fragment string) *float64 {
	family := findFamily(families, fragment)
	if family == nil || len(family.Metric) == 0 {
		return nil
	}
	var sum float64
	for _, metric := range family.Metric {
		switch family.GetType() {
		case dto.MetricType_GAUGE:
			sum += metric.GetGauge().GetValue()
		case dto.MetricType_COUNTER:
			sum += metric.GetCounter().GetValue()
		case dto.MetricType_UNTYPED:
			sum += metric.GetUntyped().GetValue()
		}
	}
	return &sum
}

func findFamily(families map[string]*dto.MetricFamily, fragment string) *dto.MetricFamily {
	keys := make([]string, 0, len(families))
	for key := range families {
		if strings.Contains(key, fragment) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	return families[keys[0]]
}

func metricCounterOutcomes(families map[string]*dto.MetricFamily) map[string]float64 {
	var family *dto.MetricFamily
	for name, candidate := range families {
		if (strings.Contains(name, "recordwiring_witness_verification") || strings.Contains(name, "engineapi_parent_witness_verification")) && !strings.Contains(name, "duration") && candidate.GetType() == dto.MetricType_COUNTER {
			family = candidate
			break
		}
	}
	if family == nil {
		return nil
	}
	out := make(map[string]float64)
	for _, metric := range family.Metric {
		outcome := "unknown"
		for _, label := range metric.Label {
			if label.GetName() == "outcome" {
				outcome = label.GetValue()
			}
		}
		out[outcome] += metric.GetCounter().GetValue()
	}
	return out
}

type histogramData struct {
	count   uint64
	buckets map[float64]uint64
}

func metricHistogram(families map[string]*dto.MetricFamily, fragment string) (histogramData, bool) {
	family := findFamily(families, fragment)
	if family == nil || family.GetType() != dto.MetricType_HISTOGRAM {
		return histogramData{}, false
	}
	out := histogramData{buckets: make(map[float64]uint64)}
	for _, metric := range family.Metric {
		h := metric.GetHistogram()
		out.count += h.GetSampleCount()
		for _, bucket := range h.Bucket {
			out.buckets[bucket.GetUpperBound()] += bucket.GetCumulativeCount()
		}
	}
	return out, true
}

func subtractHistogram(after, before histogramData) histogramData {
	if after.count < before.count {
		return after
	}
	for bound, count := range after.buckets {
		if count < before.buckets[bound] {
			return after
		}
	}
	out := histogramData{buckets: make(map[float64]uint64)}
	out.count = after.count - before.count
	for bound, count := range after.buckets {
		if previous := before.buckets[bound]; count >= previous {
			out.buckets[bound] = count - previous
		}
	}
	return out
}

func histogramQuantile(hist histogramData, q float64) *float64 {
	if hist.count == 0 || len(hist.buckets) == 0 {
		return nil
	}
	boundaries := make([]float64, 0, len(hist.buckets))
	for bound := range hist.buckets {
		if math.IsInf(bound, 0) || math.IsNaN(bound) {
			continue
		}
		boundaries = append(boundaries, bound)
	}
	if len(boundaries) == 0 {
		return nil
	}
	sort.Float64s(boundaries)
	rank := uint64(float64(hist.count)*q + 0.999999999)
	if rank == 0 {
		rank = 1
	}
	for _, bound := range boundaries {
		if hist.buckets[bound] >= rank {
			return &bound
		}
	}
	last := boundaries[len(boundaries)-1]
	return &last
}
