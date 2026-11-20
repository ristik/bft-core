# Metrics catalogue

Status: VT-12 (bft-core#1152). The `unicity_*` names are an operator-facing compatibility promise: they are not renamed or reused, only added.
`TestMetricsCatalogue` (monitoring package) fails when a `unicity_*` name in the code is missing here or listed here and gone from the code.

Where each metric is served:

| source | how to scrape | notes |
|---|---|---|
| root node | `ubft root-node run --metrics prometheus --rpc-server-address 127.0.0.1:P`, `GET /api/v1/metrics` | the operator listener is loopback only; the testnet package relays it (`metrics_relay.py`) |
| shard node | the same flags on `ubft shard-node run` | `unicity_shard_*`, `unicity_evm_head_*`, node-level metrics |
| signing authority | `ubft signing-authority run --metrics-address 127.0.0.1:P`, `GET /metrics` | off by default; loopback only; no key, request or response bytes |
| VR exporter | `ubft validator exporter --listen 127.0.0.1:P`, `GET /metrics` | reads VR and the public RPC at one pinned block; read-only, opens no key file, needs the identity id; every response is size-bounded |
| ureth | its own `--metrics` (reth's `reth_*` series); the head lag is exported by the VR exporter and by the shard node | no `unicity_*` series are added in ureth |

Labels `instance`, `job` and `validator` come from Prometheus' scrape configuration (`deploy/testnet/monitoring/prometheus-validator.yml`).

## Root node (`component=root`)

| metric | type | labels | meaning |
|---|---|---|---|
| `unicity_root_round` | gauge | | the root round this node is in |
| `unicity_root_epoch` | gauge | | the root epoch (trust base epoch) this node is in |
| `unicity_root_committed_round` | gauge | | round of the latest committed root block |
| `unicity_root_round_lag` | gauge | | round in progress minus committed round; about 3 when healthy, grows while rounds time out or the node is behind |
| `unicity_root_member` | gauge | | 1 while this root is in the epoch's committee, 0 for a follower |
| `unicity_root_committee_size` | gauge | | root nodes in the epoch's committee |
| `unicity_root_proposals_total` | counter | | proposals this root signed and sent as leader |
| `unicity_root_votes_missed_total` | counter | `reason` = `no_vote`, `timeout_only` | rounds a committee member ended without voting: `no_vote` signed nothing, `timeout_only` signed only a timeout vote |
| `unicity_root_round_timeouts_total` | counter | | rounds in which the local round timer fired, counted once per round; a follower root times out every round |
| `unicity_root_records_projected` | gauge | | records the committed root chain has projected (the root target of the catch-up counters); absent while the record store cannot be read |
| `unicity_peers_connected` | gauge | `network` | connected peers of the network (`root`, `shard`), this node excluded |
| `unicity_peers_expected` | gauge | `network` | peers the node should be connected to (the committee, the shard's validators) |
| `unicity_disk_free_bytes` | gauge | `volume` | bytes available on the volume's filesystem: `home` (the node's home) from the nodes, any `--disk-path name=path` (for example `ureth`, the execution client's data directory) from the VR exporter |
| `unicity_disk_total_bytes` | gauge | `volume` | filesystem size |
| `unicity_disk_free_ratio` | gauge | `volume` | free fraction, 0..1; the node logs `node.disk.low` below 0.10 |
| `unicity_disk_stat_error` | gauge | `volume` | 1 when the filesystem could not be read |
| `unicity_build_info` | gauge | `component`, `revision`, `go` | always 1 |

Upgrade metrics are not node-native: the schedule is the source of truth, so they are exported by the VR exporter (below), reconciled from VR's
activation schedule at every poll. VT-07 (#1228) additionally exposes the OpenTelemetry gauge `ab_unicity_upgrade_required{rule,epoch,state}` on
the roots (`state` is `pending`: a ScheduleActivation bound into the open VR output, or `effective`: in the committed schedule; `ab_` is the
exporter namespace). The alert pack watches both.

## Shard node (`component=shard`)

| metric | type | labels | meaning |
|---|---|---|---|
| `unicity_shard_executor_ok` | gauge | | 1 while the last Engine API call succeeded |
| `unicity_shard_certified_round` | gauge | | shard round of the latest certificate held |
| `unicity_shard_root_round` | gauge | | root round of the latest certificate held |
| `unicity_shard_submitted_round` | gauge | | shard round of the latest certification request |
| `unicity_shard_certified_lag_rounds` | gauge | | submitted minus certified; 1 is normal, a value that stays above a few means the roots are not certifying this shard |
| `unicity_shard_voting` | gauge | | 1 while the node contributes certification requests |
| `unicity_shard_active` | gauge | | 1 while the node's published role is active, 0 for a follower |
| `unicity_shard_health_age_seconds` | gauge | | seconds since the health state last changed |
| `unicity_shard_execution_ready` | gauge | | 0 while the execution recovery is catching the executor up |
| `unicity_evm_head_number` | gauge | | head block of the execution client as the shard node reads it |
| `unicity_evm_finalized_number` | gauge | | finalized block of the execution client |
| `unicity_evm_unfinalized_blocks` | gauge | | head minus finalized |
| `unicity_evm_head_stuck_seconds` | gauge | | seconds the head has not advanced (seen at scrapes) |
| `unicity_evm_unreachable` | gauge | | 1 when the execution client's head could not be read |

The node-level metrics of the root (`unicity_peers_*`, `unicity_disk_*`, `unicity_build_info`) are registered by the shard node
as well (`network="shard"` for the peers: the validators of the installed assignment).

## Signing authority (`component=authority`)

| metric | type | labels | meaning |
|---|---|---|---|
| `unicity_authority_up` | gauge | | 1 while the process answers |
| `unicity_authority_enrolled` | gauge | | 1 once the enrollment is complete |
| `unicity_authority_faulted` | gauge | | 1 when the authority latched faulted: it signs nothing further until restarted |
| `unicity_authority_key_lost` | gauge | | 1 when it holds no key |
| `unicity_authority_retired` | gauge | | 1 when the validator was removed: it signs nothing further |
| `unicity_authority_session_issued` | gauge | | 1 when a client session exists (the shard node can sign through it) |
| `unicity_authority_has_reservation` | gauge | | 1 while a round is reserved |
| `unicity_authority_response_retained` | gauge | | 1 while a signed response is retained |
| `unicity_authority_generation` | gauge | | session generation (advances on `replace-session`) |
| `unicity_authority_reserved_round` | gauge | | the reserved shard round |
| `unicity_authority_root_epoch` | gauge | | root epoch enrolled for |
| `unicity_authority_shard_epoch` | gauge | | shard epoch enrolled for |
| `unicity_authority_lineage_pinned` | gauge | | 1 when it verifies its own epoch advances |
| `unicity_authority_lineage_epoch` | gauge | | last root epoch its lineage holds |
| `unicity_authority_session_age_seconds` | gauge | | seconds since the current client session was first seen by the endpoint (a new generation restarts it); absent without a session |
| `unicity_authority_session_signatures` | gauge | | signatures since the current session was first seen; a session that stays at 0 never started signing |
| `unicity_authority_signatures_total` | counter | | signatures made in this lifetime |
| `unicity_authority_last_signature_age_seconds` | gauge | | seconds since the last signature; absent before the first |

## VR exporter (`ubft validator exporter`)

One poll is one pinned EVM block, so the four record counters belong to the same point. The exporter is the status read of
`ubft validator status`, served as metrics: the CLI, its JSON, its exit code and the exporter cannot disagree.

| metric | type | labels | meaning |
|---|---|---|---|
| `unicity_vr_up` | gauge | | 1 when the last read of VR was complete |
| `unicity_vr_read_errors_total` | counter | | reads that failed or were incomplete |
| `unicity_vr_last_success_timestamp_seconds` | gauge | | unix time of the last complete read |
| `unicity_vr_status_verdict` | gauge | | the `validator status` verdict: 0 ok, 1 warning, 2 critical, 3 unknown |
| `unicity_vr_module_health` | gauge | | active module health: 0 Healthy, 1 Faulted, 2 Stalled, 3 Inconsistent |
| `unicity_vr_read_block` | gauge | | the EVM block the counters were read at |
| `unicity_vr_root_epoch` | gauge | | the root epoch VR knows |
| `unicity_vr_committee_size` | gauge | | members of VR's committee |
| `unicity_vr_progress` | gauge | | SealRegistry progress, VR's clock |
| `unicity_vr_progress_to_next_boundary` | gauge | | progress left until an election may be reserved (negative: past the epoch gap) |
| `unicity_vr_open_output_state` | gauge | | 0 none, 1 Reserved, 2 Published, 3 Invalidated, 4 Rejected, 5 Acknowledged, 6 Recovered, 7 Closed |
| `unicity_vr_open_output_progress_left` | gauge | | progress left until the open output expires; absent without one |
| `unicity_vr_boundary_pending` | gauge | | 1 while an acknowledged output awaits its Boundary record |
| `unicity_vr_record_root_target` | gauge | | counter 1 of 4: records the root has projected (`--root-metrics`) |
| `unicity_vr_record_root_target_sample_timestamp_seconds` | gauge | | unix time the root target was sampled from the root's metrics (a separate observation, not at the pinned block) |
| `unicity_vr_record_imported` | gauge | | counter 2 of 4: SealRegistry's imported count (`recordCount`) |
| `unicity_vr_record_cursor` | gauge | | counter 3 of 4: VR's `recordCursor` |
| `unicity_vr_custody_record_cursor` | gauge | | counter 4 of 4: custody's `recordCursor` (`--custody`, PoS generations) |
| `unicity_vr_record_import_lag` | gauge | | root target minus imported count |
| `unicity_vr_record_application_lag` | gauge | | imported count minus VR cursor |
| `unicity_vr_custody_cursor_minus_vr_cursor` | gauge | | signed; custody may lead VR legitimately, persistently negative is the problem |
| `unicity_vr_identity_known` | gauge | | 1 when the exporter knows the identity it watches |
| `unicity_vr_identity_state` | gauge | | PoA state: 0 None, 1 Applied, 2 Admitted, 3 Joining, 4 Active, 5 ExitRequested, 6 Removing, 7 Leaving, 8 Exited, 9 Parked |
| `unicity_vr_identity_info` | gauge | `id`, `state` | the watched identity (value 1) |
| `unicity_vr_identity_member` | gauge | | 1 when the identity is in the committee |
| `unicity_vr_identity_staged_binding` | gauge | | 1 when a binding is staged |
| `unicity_vr_activations` | gauge | | entries in VR's activation schedule |
| `unicity_upgrade_schedule_known` | gauge | | 1 when VR's activation schedule was read at the last poll, 0 when it could not be (the upgrade series are then absent) |
| `unicity_upgrade_required` | gauge | | 1 while the schedule holds an Active or Latched rule (rule, release) this binary does not implement; reconciled every poll, so it clears on supersession or when the binary implements the rule (the exporter must be the node's release) |
| `unicity_upgrade_epochs_remaining` | gauge | | root epochs until the earliest unsupported rule activates (negative: past); absent while none |
| `unicity_upgrade_rule_info` | gauge | `rule`, `release`, `activation_epoch`, `state` | one series (value 1) per unsupported rule |
| `unicity_evm_public_head_number` | gauge | | head of the public RPC |
| `unicity_evm_public_head_age_seconds` | gauge | | age of that head block: the eligible-block cadence going wrong |
| `unicity_evm_local_up` | gauge | | 1 when the local execution client answers (`localRpc` in the validator config) |
| `unicity_evm_local_head_number` | gauge | | head of the local execution client |
| `unicity_evm_head_lag_blocks` | gauge | | public head minus local head; while the client is unreachable, minus the highest head it showed; absent until a local head was observed |

## Existing metrics (not changed by VT-12)

The OpenTelemetry instruments are exposed with the Prometheus namespace `ab_` (counters get `_total`, histograms `_seconds`). The alert pack uses the ones marked *.

| metric | source | meaning |
|---|---|---|
| `ab_round_total` | root | rounds started |
| `ab_round_duration_seconds` | root | round length histogram |
| `ab_round_leader_total` | root | rounds this node led |
| `ab_count_vote_total` | root | votes cast (`kind` per vote type) |
| `ab_qc_participated_total`, `ab_qc_vote_count_total` | root | QC participation |
| `ab_cert_req_consensus_time_seconds`, `ab_cert_rsp_ready_time_seconds` | root | shard request latency |
| `ab_shardnode_rounds_certified_total` | shard | certified rounds |
| `ab_shardnode_certification_last_timestamp_seconds` | shard | when the last round was certified |
| `ab_shardnode_certification_no_progress_age_seconds` * | shard | seconds without certification progress while work remains |
| `ab_shardnode_execution_recovery_pending_catch_up`, `..._age_seconds` | shard | execution catch-up in progress |
| `ab_shardnode_uc_repeat_total`, `ab_shardnode_uc_stale_total`, `ab_shardnode_ir_divergences_total` | shard | certificate anomalies |
| `ab_archive_pending_records`, `ab_archive_lagging_records` | shard | archive publication backlog |
| `libp2p_rcmgr_connections`, `go_*`, `process_*` | all | libp2p resource manager, Go runtime, process |

Not covered here: the aggregator (a separate repository outside ristik/*; its `/metrics` is scraped as is) and ureth's own `reth_*` series.

## Running the pack

- Nodes: start the root and shard node with `--metrics prometheus --rpc-server-address 127.0.0.1:PORT`, the authority with `--metrics-address 127.0.0.1:PORT`.
- Exporter (one per validator, next to its nodes): `ubft validator exporter --validator-config validator.json --listen 127.0.0.1:9180 --root-metrics http://127.0.0.1:PORT/api/v1/metrics [--custody 0x..] [--disk-path ureth=/data/ureth]`. The config needs `rpc` (the public endpoint), `localRpc` (this validator's own ureth, for the lag) and `id`.
- Prometheus: `deploy/testnet/monitoring/prometheus-validator.yml.tmpl` shows the scrape jobs and the `validator` label; `deploy/testnet/monitoring/validator-alerts.yml` is the alert pack (`promtool check rules`, `promtool test rules validator-alerts.test.yml`); `grafana-validator.json` is the one-validator dashboard.
- On a slot 0 development lane with authority signing and a certified VR genesis, start the lane with `MONITORING=1`. Run `MON_GRAFANA=1 scripts/vt12-monitoring.sh start`, then run `scripts/vt12-acceptance.sh` from the lane checkout. The launcher builds each exporter config from the corresponding root's genesis identity. The acceptance script stores scrape outputs, firing alerts and a dashboard PNG in `$EVID` (default `~/evidence/vt12/live`).
- To check the pending-upgrade alert against an active VT-07 development lane on the same host, set `VT12_VT07_PORT` to its metrics port and `VT12_VT07_VALIDATOR` to its validator label (default `4`). The acceptance script temporarily scrapes only its `ab_unicity_upgrade_required` samples. With no port supplied, the acceptance script serves a local fixture for the upgrade rules.
- Scripts and alerting: `ubft validator status --json --exit-code` (exit 0 ok, 1 warning, 2 critical, 3 unknown).
