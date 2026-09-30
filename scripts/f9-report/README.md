# F9 node measurement report

`go run ./scripts/f9-report --config run.json --out report.json` collects a bounded read-only report from shard-node status and Prometheus endpoints. It only issues `GET` requests to `/api/v1/operator/status` and `/api/v1/metrics`.

Example config:

```json
{
  "nodes": [
    {
      "name": "validator-a",
      "status_url": "http://127.0.0.1:8081",
      "metrics_url": "http://127.0.0.1:8081",
      "archive_dir": "/var/lib/ubft/archive",
      "process_pid_file": "/var/lib/ubft/shard-node.pid"
    }
  ],
  "samples": 6,
  "interval": "5s",
  "max_archive_entries": 100000
}
```

The report includes process CPU time and sampled CPU percentage, RSS, open file descriptors, journal usage, record-directory and byte counts, certified-tip to prune-frontier distance, per-replica acknowledgement lag, witness verification outcomes and bucket-estimated p50/p99 latency, and old-epoch/new-epoch certification timestamps when a transition is observed. Witness outcomes include both the sampled-window delta (`byOutcome`) and latest cumulative counters (`cumulativeByOutcome`), so a brief malformed-proof event remains visible in a final sample. `process_pid_file` is optional; it lets the collector sample the local node process on hosts where the Prometheus process collector is unavailable (including macOS). It reads the PID file and uses bounded `ps` and `lsof` calls on macOS or `/proc` on Linux. A missing certified tip or metric remains absent; scan or endpoint failures mark the report incomplete, and the command exits nonzero after writing it.

Bounds: 64 nodes, 2–1000 samples, at most 24 hours of sampling, eight concurrent node collectors, five-second HTTP request timeout, 1 MiB status/config and 4 MiB metrics responses, and at most 250,000 archive record directories (100,000 by default). Local process commands have a two-second timeout and a 4 MiB output cap. Archive bytes are summed from regular files inside record directories; the scanner does not read or re-verify chunk contents. Missing required process, witness or latency-quantile measurements mark the report incomplete and make the command exit nonzero. Pause fields are absent when no transition gauge was recorded; `pauseMetricsAvailable` distinguishes that case from measured pause timestamps.

CPU percentage is derived from process CPU seconds over the sampled wall interval. The collector detects a process restart from `process_start_time_seconds` or a changed local PID and marks the report incomplete instead of treating reset counters as a valid interval. Histogram quantiles use the exported bucket upper bound, so they are approximate. Certification pause endpoints describe the last old-root-epoch to new-root-epoch transition, measured from the last certified round in the old epoch to the first certified round in the new epoch.

For all fields to be present, start each shard node with its read-only RPC/status server enabled and Prometheus metrics export configured. Legacy record-store nodes expose `recordwiring_*` witness metrics. Journal-backed D2 nodes expose `engineapi_parent_witness_*` metrics; the report accepts either source and marks missing measurements incomplete rather than treating them as zero.
