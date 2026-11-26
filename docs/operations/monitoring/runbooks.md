# Validator runbooks (handbook draft)

Status: VT-12 (bft-core#1152), a draft for the validator handbook (VT-13). One section per alert of `deploy/testnet/monitoring/validator-alerts.yml`; the alert's `runbook` annotation links here. `TestAlertRunbooks` fails when an alert has no section.

Common first steps, for every alert:

1. `ubft validator status --json` (add `--exit-code` in scripts: 0 ok, 1 warning, 2 critical, 3 unknown) shows the validator's VR record, committee, record counters, sync state and its verdict with the findings.
2. `ubft validator doctor` checks the local setup.
3. Logs carry stable `event=` names (`events.md`); search for the event the alert names.
4. Metric names: `metrics-catalogue.md`. The thresholds below are the alert pack's defaults for a testnet generation (a block about every 10 s); tune them in the rule file.

Severity: *critical* pages the on-call operator; *warning* is for the next working window. Never delete a node database, a safety store (`vr-member.json`, the root and key stores) or an authority's state to clear an alert.

## UnicityTargetDown

Severity: critical.

**What it means.** Prometheus cannot scrape a validator process (root, shard node, authority or VR exporter): it is down, hung, or its metrics listener is unreachable.

**Confirm.** `up{job=...}` shows which target. Check the process (`ps`, the service manager or `docker compose ps`), its last log lines, and `curl` the metrics URL from the Prometheus host.

**Fix.** Restart the process. A root, shard node or authority that crashed leaves its reason in the last log lines: read them before restarting. NEVER restart a signing authority casually: it holds the key only in memory (see UnicityAuthorityFaulted). If only the exporter is down, `ubft validator exporter` is stateless and restarts freely.

**Escalate when.** Escalate when a root or authority is down and does not come back, or when more than one validator's targets are down (a network or host problem).

## UnicityRootStalled

Severity: critical.

**What it means.** This member has observed no new committed root block over three minutes, and that condition persisted for another minute. The committee may have lost quorum, or this node may be cut off from it.

**Confirm.** `unicity_root_committed_round` is flat on every root: a chain-wide stall. Flat only here: this node is isolated (`unicity_peers_connected{network="root"}`). Log: `event=root.round.timeout` every round, `event=root.recovery.triggered`.

**Fix.** Chain-wide: bring the missing roots back (quorum is more than two thirds); look for a recent handoff (`event=root.handoff.outcome`, `event=root.epoch.switch_failed`) and follow `docs/operations/root-handoff-abort.md`. Only this node: fix its network, then watch `unicity_root_round_lag` fall.

**Escalate when.** Escalate at once for a chain-wide stall that lasts more than 10 minutes, or any `root.epoch.switch_failed`.

## UnicityRootRoundLag

Severity: warning.

**What it means.** The current round runs more than 30 rounds ahead of the committed head: rounds time out without a commit, or this node lags the committee.

**Confirm.** Graph `unicity_root_round_lag` and `unicity_root_round_timeouts_total`. Healthy is about 3. Compare with the other roots.

**Fix.** A leader that is down costs a few timeouts per rotation and clears itself. Persistent lag on one node: check CPU and disk of the host and its peer count. Lag everywhere: see UnicityRootStalled.

**Escalate when.** Escalate when it persists for 15 minutes or grows.

## UnicityRootVotesMissed

Severity: warning.

**What it means.** A committee member ended more than 10 rounds in 5 minutes without signing any vote. It is not participating in consensus although it is in the committee.

**Confirm.** `increase(unicity_root_votes_missed_total[5m])` by `reason`; `no_vote` means it signed nothing, `timeout_only` only timeouts. Log: `event=root.vote.missed`, then the lines before it (signing errors, `failed to sign vote`, an authority or key problem).

**Fix.** Check the node's peers and clock, the host load, and that its key store is readable. A root that cannot sign because its store is full or read-only: free the disk (UnicityDiskLow) and restart. Do not delete the safety store.

**Escalate when.** Escalate when the root stays out of the quorum and the committee has no spare capacity (a second validator is also failing).

## UnicityRootRoundTimeouts

Severity: warning.

**What it means.** A committee root's round timer fired in more than 20 distinct rounds in 5 minutes (a follower root times out every round and is excluded): proposals do not arrive in time.

**Confirm.** `increase(unicity_root_round_timeouts_total[5m])` (counted once per round) on all roots, `event=root.round.timeout` in the log, `ab_round_duration_seconds`.

**Fix.** Find the leader(s) that fail to propose (the log names the leader per round), fix their host or network. Check clock skew (NTP) across the committee.

**Escalate when.** The rate is chain-wide and growing.

## UnicityRootNotMember

Severity: warning.

**What it means.** VR says the identity is Active, but the node's root is a follower, not in the committee, for more than 10 minutes.

**Confirm.** `unicity_vr_identity_state == 4` and `unicity_root_member == 0`. `ubft validator status` prints `member false` and the next boundary. An Active identity joins at the boundary after its election: a long gap means the boundary did not happen.

**Fix.** See the election runbooks: UnicityOutputExpired, UnicityVRModuleUnhealthy. If the boundary was applied but the root did not switch, read `event=root.epoch.switch` / `root.epoch.switch_failed` and restart the root once.

**Escalate when.** Escalate when a boundary is applied in VR and this root still follows after one restart.

## UnicityPeersLow

Severity: warning.

**What it means.** The node reaches fewer peers than the committee (root) or the shard's validators (shard).

**Confirm.** `unicity_peers_connected` against `unicity_peers_expected` per `network`; log `event=node.peers.low` names the counts. Check firewalls, the peers' own health, and DNS.

**Fix.** Restore the connection to the missing peers (a restarted peer reconnects within a minute; a changed address needs the bootnode list updated). A committee change legitimately changes the expected count for a moment.

**Escalate when.** Escalate when the missing peers are healthy and the node cannot reach them (a routing or firewall problem you cannot fix), or when the count falls below quorum.

## UnicityNoPeers

Severity: critical.

**What it means.** The node is isolated: no peer of the network is connected.

**Confirm.** `unicity_peers_connected == 0`; `ss -tn` to the peers' ports; the node's own network.

**Fix.** Fix the host's network, firewall and DNS; check the node's listen and announce addresses. Restart the node only after the network is fixed.

**Escalate when.** Escalate immediately if the host network is fine.

## UnicityShardNotCertifying

Severity: critical.

**What it means.** The shard node submits certification requests that the roots do not certify.

**Confirm.** `unicity_shard_certified_lag_rounds` and `ab_shardnode_certification_no_progress_age_seconds`; log `event=shard.certification.stalled`. Compare `unicity_shard_root_round` with the roots' `unicity_root_round`.

**Fix.** If the roots are stalled see UnicityRootStalled. If only this shard node: check its link to the roots (`unicity_peers_connected`), that its role is active (`unicity_shard_active`), and its executor (`unicity_shard_executor_ok`, UnicityEvmUnreachable).

**Escalate when.** Escalate when the roots are healthy and the shard node does not recover after a restart.

## UnicityShardNotVoting

Severity: critical.

**What it means.** The shard node withholds its certification requests (`voting 0`: for example a restored process waiting for its gate) or its Engine API calls fail.

**Confirm.** `GET /api/v1/health` on the shard node: `voting`, `nonVotingReason`, `executorError`.

**Fix.** Follow `nonVotingReason`: a restore or recovery gate clears when the execution catch-up finishes (UnicityShardExecutionCatchUp). An executor error means ureth is down or its JWT/Engine endpoint changed (UnicityEvmUnreachable).

**Escalate when.** Escalate when `nonVotingReason` names a safety refusal.

## UnicityShardExecutionCatchUp

Severity: warning.

**What it means.** Execution recovery has been catching the executor up for more than 10 minutes.

**Confirm.** `unicity_shard_execution_ready == 0`, `ab_shardnode_execution_recovery_pending_catch_up`, the shard node's log for the recovery progress, `unicity_evm_head_number` against `unicity_evm_public_head_number`.

**Fix.** Let it run if the head advances; if it does not, check the archive replicas and the peers it fetches blocks from. A restore from an archive is documented in `docs/single-epoch-archive-restore.md`.

**Escalate when.** Escalate when the head does not advance for 15 minutes.

## UnicityEvmHeadLag

Severity: warning.

**What it means.** The local execution client (ureth) trails the public head by more than 5 blocks.

**Confirm.** `unicity_evm_head_lag_blocks`; `ubft validator status` prints `behind by N blocks` or `syncing`. Compare `unicity_evm_local_head_number` with `unicity_evm_public_head_number`. ureth's `reth_*` series show its sync stages and peers.

**Fix.** A restarted ureth catches up by itself: wait and watch the lag fall. If it does not, check its peers, disk (UnicityDiskLow) and CPU. A validator whose ureth is behind may withhold signing; the shard node log says so.

**Escalate when.** Escalate when the lag grows for 10 minutes or ureth restarts in a loop.

## UnicityEvmUnreachable

Severity: critical.

**What it means.** The local execution client does not answer the VR exporter, or the shard node cannot read its head.

**Confirm.** `unicity_evm_local_up == 0` or `unicity_evm_unreachable == 1`. Check the ureth process and its RPC and Engine ports; the shard node's `executorError`.

**Fix.** Start ureth. Check its log for a database or genesis error; do not delete its datadir to "fix" it. After the restart the lag alert may fire until it has caught up.

**Escalate when.** Escalate when ureth fails to start with a database error.

## UnicityChainStalled

Severity: critical.

**What it means.** The public head is more than 2 minutes old: no EVM block is being produced (eligible-block cadence lost).

**Confirm.** `unicity_evm_public_head_age_seconds`; `ubft validator status` prints the head's age and the verdict `chain_stalled`. Check the roots (UnicityRootStalled) and the shard nodes (UnicityShardNotCertifying).

**Fix.** Fix the layer that stalled: roots, shard certification, or the block producer. The chain resumes by itself when the quorum is back.

**Escalate when.** Escalate at once; this is a network-wide incident.

## UnicityBlockCadenceLow

Severity: warning.

**What it means.** Fewer than 3 EVM blocks per minute over 5 minutes (plan: about 6 at a 10 s interval). Missed or frozen blocks provide no record service.

**Confirm.** `rate(unicity_evm_public_head_number[5m])`, the round timeouts, and `docs/operations/vr-record-catch-up.md` for why cadence matters to the record limit.

**Fix.** As UnicityChainStalled, less severe: find why blocks are slow (timeouts, a slow shard leader, load).

**Escalate when.** Escalate when it persists for 30 minutes.

## UnicityDiskLow

Severity: warning.

**What it means.** Less than 10 percent of the volume is free.

**Confirm.** `unicity_disk_free_ratio` by `volume`; `df -h` on the host; `event=node.disk.low`.

**Fix.** Free space: rotate or delete old logs and evidence, prune the archive within its policy, grow the volume. Do NOT delete node databases, the safety store or `vr-member.json`.

**Escalate when.** Escalate when you cannot free space within a day, or the ratio falls below 3 percent (UnicityDiskCritical).

## UnicityDiskCritical

Severity: critical.

**What it means.** Less than 3 percent of the volume is free, or its filesystem cannot be read: the node is about to fail to write its state.

**Confirm.** As UnicityDiskLow. A full disk makes a root refuse to vote and ureth fail its database writes.

**Fix.** Free space now (logs first). If a node already refused to sign because it could not store its vote, restart it after freeing space; it re-sends what it persisted.

**Escalate when.** Escalate immediately if space cannot be freed in minutes.

## UnicityAuthorityFaulted

Severity: critical.

**What it means.** The signing authority latched faulted (an inconsistency in its record) or lost its key. It signs nothing further in this lifetime, and its key lives only in memory.

**Confirm.** `unicity_authority_faulted`, `unicity_authority_key_lost`; `ubft signing-authority status` over the operator socket; the authority's log.

**Fix.** A faulted authority never recovers by itself: the validator needs a new authority enrollment (`docs/operations/m2-runbook.md`, replacement and recovery). Do not restart it expecting the same key back: the key is gone with the process.

**Escalate when.** Escalate at once: the validator is not signing and its recovery needs the operator procedure.

## UnicityAuthorityRetired

Severity: warning.

**What it means.** The installed assignment excluded the validator or changed its key. The authority is fenced from signing and issuing sessions.

**Confirm.** `unicity_authority_retired == 1` after a committed exit or removal (`unicity_vr_identity_state` in 6 to 8).

**Fix.** After an acknowledged exit, follow the validator retirement procedure. If an unacknowledged primary excluded the validator and a verified recovery K restores its original key, advance the authority with both activation proofs in order. For unexpected removal, use `ubft validator status` to identify the governance change.

**Escalate when.** Escalate if it was not an exit you requested.

## UnicityAuthorityNoSession

Severity: critical.

**What it means.** The authority is enrolled and not retired, but no client session is issued: the shard node has nothing to sign through. (A retired authority legitimately has no session and does not alert here.)

**Confirm.** `unicity_authority_enrolled == 1`, `unicity_authority_retired == 0`, `unicity_authority_session_issued == 0`, `unicity_authority_generation`.

**Fix.** Issue a session with `ubft signing-authority replace-session` (operator socket and credential) and restart the shard node if it does not pick it up. See `docs/operations/m2-runbook.md`.

**Escalate when.** `replace-session` is refused: if the authority is retired the validator was removed, which is not an incident to fix by a session.

## UnicityAuthoritySigningStalled

Severity: critical.

**What it means.** A client session is issued, the authority is not retired and the shard node is active, but the authority signs nothing: either the session never made a first signature (`unicity_authority_session_signatures == 0` for 3 minutes) or the last certification signature in this session is more than 2 minutes old. Either condition must persist for another 2 minutes.

**Confirm.** `unicity_authority_session_age_seconds`, `unicity_authority_session_signatures`, `unicity_authority_last_signature_age_seconds`, `unicity_shard_certified_lag_rounds`; the shard node log for authority errors.

**Fix.** Check the client socket and that the shard node uses the issued session's credential (a session issued but never used means the shard node holds an old credential: restart it). A quiet shard certifies empty rounds, so a healthy signer signs continuously. Restart the shard node, not the authority.

**Escalate when.** Signing does not start or resume after the shard node restart.

## UnicityVRModuleUnhealthy

Severity: critical.

**What it means.** VR reports its active election module as Faulted, Stalled or Inconsistent: elections do not run.

**Confirm.** `unicity_vr_module_health` (1 Faulted, 2 Stalled, 3 Inconsistent); `ubft validator status`; `event=vr.module.health_changed`.

**Fix.** Stalled: the records hook is not applying (UnicityRecordCursorStuck). Faulted or Inconsistent: a governance action (a module change or recovery) is needed; see the VR design's health states.

**Escalate when.** Escalate at once to the governance signers.

## UnicityVRExporterDown

Severity: warning.

**What it means.** The VR exporter cannot read VR (`unicity_vr_up == 0`), or its last complete read is more than 2 minutes old (`unicity_vr_last_success_timestamp_seconds`): the exporter answers its scrape but serves a stale snapshot.

**Confirm.** `unicity_vr_read_errors_total`; the exporter log (`validator state could not be read`); `ubft validator status` from the same host. A dead exporter is UnicityTargetDown instead.

**Fix.** Check the public RPC the exporter uses (is its ureth up, UnicityEvmUnreachable) and the validator config. The exporter holds no state: restart it.

**Escalate when.** The public RPC is up and the exporter still fails.

## UnicityRecordApplicationLag

Severity: warning.

**What it means.** VR has imported more records than it applied by more than 128, for 5 minutes: not back to zero after a burst.

**Confirm.** `unicity_vr_record_application_lag` and `unicity_vr_record_imported` against `unicity_vr_record_cursor`; `docs/operations/vr-record-catch-up.md` for the limit and drain times.

**Fix.** Check the block cadence (UnicityBlockCadenceLow) and that no record-producing operation is running in bulk. Pace discretionary operations (exits, joins, closures). Do not pause the hooks.

**Escalate when.** Escalate when the lag keeps growing.

## UnicityRecordImportLag

Severity: warning.

**What it means.** The SealRegistry imports root records slower than the root projects them (root target minus imported count above 128 for 5 minutes).

**Confirm.** `unicity_vr_record_import_lag`, `unicity_vr_record_root_target`, `unicity_vr_record_imported`.

**Fix.** At most 32 records import per EVM block: a burst drains in a few blocks. Persistent lag with a normal cadence means imports are failing: read the shard node log around the import.

**Escalate when.** Escalate when the lag does not shrink after 15 minutes.

## UnicityRecordCursorStuck

Severity: critical.

**What it means.** VR's record cursor has been flat for 10 minutes, and the flat cursor and application lag persisted for another 5 minutes. Check whether the records hook is running.

**Confirm.** `changes(unicity_vr_record_cursor[10m])`, `unicity_vr_record_application_lag`, `unicity_vr_module_health`.

**Fix.** The hook runs in the EVM block's system calls: check that blocks are produced (UnicityChainStalled) and that VR's module is Healthy. A faulted module needs governance.

**Escalate when.** Escalate at once.

## UnicityCustodyBehind

Severity: warning.

**What it means.** Custody's record cursor is persistently below VR's (a custody lead alone is legitimate and does not alert).

**Confirm.** `unicity_vr_custody_cursor_minus_vr_cursor` below zero for 5 minutes, `unicity_vr_custody_record_cursor`.

**Fix.** Anyone can apply imported records to custody; run `applyRootRecords` on custody or wait for the hook. See `docs/operations/vr-record-catch-up.md`.

**Escalate when.** Escalate when it persists for an hour.

## UnicityRecordArrivalLimit

Severity: warning.

**What it means.** Root records arrive faster than the published limit (72 per ten eligible blocks plus one burst of 32).

**Confirm.** `increase(unicity_vr_record_root_target[5m])` against the blocks produced.

**Fix.** Pace record-producing operations (exits, retirements, joins, closures): spread them, do not batch them into one root block.

**Escalate when.** Escalate when a lag alert follows.

## UnicityOutputExpired

Severity: warning.

**What it means.** VR's open output is past its expiry and has not been replaced: the election is stuck.

**Confirm.** `unicity_vr_open_output_progress_left < 0`, `unicity_vr_open_output_state`, `ubft validator status` (next boundary), `event=vr.handoff.*`.

**Fix.** No operator step rejects it: every VR-mode root builds RejectResult v2 (Expired) from certified VR state once VR's progress reaches `expiresAtProgress`, and orders it at the next quiet proposal (root log `election result due for rejection` with `registry=true`; then VR's output state moves to Rejected and Closed once the EVM imports `OutputRejected` and `SessionClosed`). The module then re-reserves when it has work; check module health and record lag first. An output still open well past its expiry with no such root log is a root defect (bft-core#1311). A Published output whose handoff does not commit before its expiry: see `event=root.handoff.outcome` and `docs/operations/root-handoff-abort.md`.

**Escalate when.** Escalate when no new output is reserved within an hour.

## UnicityIdentityParked

Severity: warning.

**What it means.** The validator identity is Parked: it is not electable.

**Confirm.** `unicity_vr_identity_state == 9`; `event=vr.identity.parked`; `ubft validator status`.

**Fix.** The owner or the governance unparks it (see the validator lifecycle in the handbook). Check why it was parked (missed duties, key problems) before unparking.

**Escalate when.** Escalate to the governance signers if you did not cause it.

## UnicityUpgradeRequired

Severity: warning.

**What it means.** VR's activation schedule holds an Active or Latched rule (rule, release) that this binary does not implement (`unicity_upgrade_required`, reconciled from the schedule by the exporter at every poll, or VT-07's `ab_unicity_upgrade_required{state="effective"}`). The node signs no readiness for a handoff that needs it and refuses to run past the activation.

**Confirm.** `unicity_upgrade_rule_info` names the rule and release, `unicity_upgrade_epochs_remaining` the epochs left on this validator, `event=upgrade.required` and `ubft validator status` (finding `upgrade_required`).

**Fix.** Install the release that implements the rule (its digest is in the rule info) and restart the node; the series clears at the next poll once the binary implements the rule or the schedule supersedes it. The exporter must be of the node's release, or it judges by the wrong binary.

**Escalate when.** The release is not available, or fewer than 2 epochs remain (UnicityUpgradeImminent).

## UnicityUpgradePending

Severity: warning.

**What it means.** A ScheduleActivation change is bound into VR's open output (not yet committed in the schedule) and names a rule this binary does not implement (`ab_unicity_upgrade_required{state="pending"}`, VT-07). The warning arrives before the rule is latched, so there is time to upgrade.

**Confirm.** The rule and epoch are in the metric's `rule` and `epoch` labels and in the `event=upgrade.required state=pending` log line; `ubft validator upgrade` shows the schedule, the release digest each rule needs and whether this binary supports it.

**Fix.** Install the release whose digest the rule names and restart the node before the epoch; the metric clears once the binary implements the rule. `event=activation.latched` and `event=activation.active` mark the later stages.

**Escalate when.** The release is not available, or the epoch is near and the node is not upgraded (UnicityUpgradeImminent).

## UnicityUpgradeImminent

Severity: critical.

**What it means.** An unsupported rule activates within two root epochs of THIS validator's current epoch (`unicity_upgrade_epochs_remaining <= 2`).

**Confirm.** As UnicityUpgradeRequired.

**Fix.** Upgrade now. A node that is not upgraded at the activation refuses to continue and drops out of the signers.

**Escalate when.** You cannot upgrade before the activation.

## UnicityVRSeriesMissing

Severity: warning.

**What it means.** A VR exporter target answers its scrape (`up == 1`) but does not carry `unicity_vr_up`: an old or wrong binary, or a broken exporter.

**Confirm.** `curl` the exporter's /metrics and look for `unicity_vr_*`.

**Fix.** Run `ubft validator exporter` from the node's release; restart it.

**Escalate when.** The binary is right and the series stays missing.

## UnicityScrapeTargetsAbsent

Severity: critical.

**What it means.** Prometheus has no target at all for the job `vrexporter`, `root` or `shard`: the validators are not monitored (a missing scrape configuration or service discovery, not a down target).

**Confirm.** `up{job=...}` in Prometheus' targets page; the scrape configuration.

**Fix.** Restore the scrape configuration or discovery (see `prometheus-validator.yml.tmpl`).

**Escalate when.** The configuration is correct and the targets do not appear.

## UnicityUpgradeScheduleUnknown

Severity: warning.

**What it means.** The exporter could not read VR's activation schedule for 10 minutes (`unicity_upgrade_schedule_known == 0`): whether an upgrade is required is unknown, not "no". The upgrade series are absent meanwhile.

**Confirm.** `unicity_vr_up`, `unicity_vr_read_errors_total`, the exporter log, `ubft validator status` (the `Activations` read).

**Fix.** As UnicityVRExporterDown: the public RPC or VR read is failing. An `activationCount` above the schema's bound of 64 is refused by design and means the contract is not the expected VR.

**Escalate when.** The read keeps failing with a healthy RPC.
