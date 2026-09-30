package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archivewiring"
)

func TestLoadConfigRejectsUnknownAndUnboundedInputs(t *testing.T) {
	t.Parallel()
	for name, contents := range map[string]string{
		"unknown":     `{"nodes":[],"samples":2,"interval":"0s","surprise":true}`,
		"samples":     `{"nodes":[{"name":"n","status_url":"http://localhost","metrics_url":"http://localhost","archive_dir":"/tmp"}],"samples":1001,"interval":"0s"}`,
		"window":      `{"nodes":[{"name":"n","status_url":"http://localhost","metrics_url":"http://localhost","archive_dir":"/tmp"}],"samples":1000,"interval":"2h"}`,
		"scheme":      `{"nodes":[{"name":"n","status_url":"file:///tmp","metrics_url":"http://localhost","archive_dir":"/tmp"}],"samples":2,"interval":"0s"}`,
		"archive-cap": `{"nodes":[{"name":"n","status_url":"http://localhost","metrics_url":"http://localhost","archive_dir":"/tmp"}],"samples":2,"interval":"0s","max_archive_entries":250001}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
			_, err := loadConfig(path)
			require.Error(t, err)
		})
	}
}

func TestMeasureArchiveCountsBytesAndStopsAtDirectoryLimit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, name := range []string{strings.Repeat("a", 64), "v2-" + strings.Repeat("b", 64)} {
		dir := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest"), []byte("12345"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "chunk-00"), []byte("123"), 0600))
	}
	require.NoError(t, os.Mkdir(filepath.Join(root, "not-an-archive-record"), 0700))
	complete := measureArchive(root, 3)
	require.True(t, complete.Complete)
	require.Equal(t, uint64(2), complete.Records)
	require.Equal(t, uint64(16), complete.Bytes)
	bounded := measureArchive(root, 1)
	require.False(t, bounded.Complete)
	require.Equal(t, uint64(1), bounded.Records)
	require.Contains(t, bounded.Error, "limit")
}

func TestCollectBuildsFixtureReport(t *testing.T) {
	t.Parallel()
	archiveDir := t.TempDir()
	recordDir := filepath.Join(archiveDir, "v2-"+strings.Repeat("c", 64))
	require.NoError(t, os.Mkdir(recordDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(recordDir, "manifest"), []byte("archive"), 0600))
	var metricsRequest atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/operator/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"currentRootEpoch":3,"journal":{"candidatesUsed":4,"candidatesCap":8,"observationsUsed":2,"observationsCap":8,"bytesUsed":1024,"bytesCap":4096},"certifiedTip":{"height":12,"hash":"0x12"},"pruneFrontier":{"height":10,"hash":"0x10"},"replicas":[{"replica":"peer-a","lastAcknowledgedHeight":8},{"replica":"peer-b","lastAcknowledgedHeight":12,"error":"transient"}]}`)
		case "/api/v1/metrics":
			n := metricsRequest.Add(1)
			cpu, rss, fds, verifies, count, low, high, start, end := "2", "100", "5", "3", "3", "1", "3", "1000", "1000"
			if n > 1 {
				cpu, rss, fds, verifies, count, low, high, start, end = "3", "120", "7", "5", "5", "2", "5", "1001", "1004"
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = fmt.Fprintf(w, "# TYPE ab_recordwiring_witness_verification_total counter\n# TYPE ab_recordwiring_witness_verification_duration_seconds histogram\nprocess_start_time_seconds 50\nprocess_cpu_seconds_total %s\nprocess_resident_memory_bytes %s\nprocess_open_fds %s\nab_recordwiring_witness_verification_total{outcome=\"verified\"} %s\nab_recordwiring_witness_verification_duration_seconds_bucket{le=\"0.1\"} %s\nab_recordwiring_witness_verification_duration_seconds_bucket{le=\"0.5\"} %s\nab_recordwiring_witness_verification_duration_seconds_bucket{le=\"+Inf\"} %s\nab_recordwiring_witness_verification_duration_seconds_count %s\nab_shardnode_certification_last_timestamp_seconds %s\nab_shardnode_certification_pause_start_timestamp_seconds %s\nab_shardnode_certification_pause_end_timestamp_seconds %s\n", cpu, rss, fds, verifies, low, high, count, count, end, start, end)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := checkedConfig{
		Nodes:   []nodeConfig{{Name: "validator-a", StatusURL: server.URL, MetricsURL: server.URL, ArchiveDir: archiveDir}},
		Samples: 2, Interval: 5 * time.Millisecond, MaxArchiveEntries: 10,
	}
	result := collect(context.Background(), cfg, server.Client(), time.Now)
	require.True(t, result.Complete, "%+v", result.Nodes[0].Errors)
	require.Len(t, result.Nodes, 1)
	node := result.Nodes[0]
	require.True(t, node.Complete)
	require.Equal(t, 2, node.Samples)
	require.Equal(t, uint64(3), node.RootEpoch)
	require.Equal(t, uint64(2), *node.FrontierTipGap)
	require.Equal(t, 4, node.Journal.CandidatesUsed)
	require.Equal(t, uint64(4), *node.Replicas[0].LagBlocks)
	require.Equal(t, uint64(0), *node.Replicas[1].LagBlocks)
	require.Equal(t, uint64(1), node.Archive.Records)
	require.Equal(t, uint64(len("archive")), node.Archive.Bytes)
	require.NotNil(t, node.Process.CPUPercent)
	require.Equal(t, float64(120), *node.Process.RSSBytes)
	require.Equal(t, float64(50), *node.Process.StartTimeUnix)
	require.Equal(t, float64(7), *node.Process.OpenFDs)
	require.True(t, node.Witness.Available)
	require.Equal(t, uint64(2), node.Witness.Count)
	require.Equal(t, uint64(2), node.Witness.ByOutcome["verified"])
	require.Equal(t, float64(0.1), *node.Witness.P50Seconds)
	require.Equal(t, float64(0.5), *node.Witness.P99Seconds)
	require.Equal(t, float64(1004), *node.Certification.PauseEndAt)
	require.Equal(t, float64(3), *node.Certification.PauseDurationSeconds)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"witnessVerification"`)
}

func TestMeasureArchiveMissingPathIsUncovered(t *testing.T) {
	t.Parallel()
	got := measureArchive(filepath.Join(t.TempDir(), "missing"), 10)
	require.False(t, got.Complete)
	require.NotEmpty(t, got.Error)
}

func TestApplyStatusKeepsReplicaRowsWhenTipIsUnknown(t *testing.T) {
	t.Parallel()
	out := nodeReport{}
	applyStatus(&out, archivewiring.OperatorStatus{Replicas: []archivewiring.ReplicaReport{{
		Replica: "peer-a", LastAcknowledgedHeight: 8, Error: "timeout",
	}}})
	require.Len(t, out.Replicas, 1)
	require.Nil(t, out.Replicas[0].LagBlocks)
	require.Equal(t, "timeout", out.Replicas[0].Error)
}

func TestApplyMetricsMarksMissingRequiredMeasurementsIncomplete(t *testing.T) {
	t.Parallel()
	out := nodeReport{Complete: true}
	first := sample{at: time.Unix(1, 0)}
	last := sample{at: time.Unix(2, 0)}
	applyMetrics(&out, first, last, 2)
	require.False(t, out.Complete)
	require.NotEmpty(t, out.Errors)
}
