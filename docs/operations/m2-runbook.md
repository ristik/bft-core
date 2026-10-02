# M2 operations runbook: handoff, restore, and restart

**Status:** rehearsal draft. The M2a recovery-core lane has passed, while the M2
and H6 gates remain open. Every procedure still needs an evidence run led by an
operator other than the implementer; this document is not production approval.
Cross-epoch full-disk restore and archive-replica maintenance are specifically
pending. Do not use the test harness against production data.

This runbook uses commands and observations present in the merged `ubft` CLIs,
paired-devnet scripts, and F9 report tool. Replace every `REPLACE_*` value before
running a command. The H4 and D2C scripts operate on `test-nodes/`, stop processes,
and in the H4 restore stage delete test datadirs. Use only a disposable, isolated
checkout. For a live lane, obtain the devnet lock first; these instructions do not
grant it.

## Shared preflight and evidence

For every change, save the current source and execution-client pins with the change
record. The lane prints these values at startup; these are the same commands:

```sh
git rev-parse HEAD
shasum -a 256 REPLACE_URETH_BINARY
shasum -a 256 registrygenesis/seal-registry-v1.json
```

For each external signing authority, capture a status document before and after the
operation. `status` is read-only and exposes the enrollment, root/shard epochs,
generation, high-water round, retained response, and fault/lost-key flags.

```sh
build/ubft signing-authority status \
  --operator-socket REPLACE_AUTHORITY_OPERATOR_SOCKET \
  --operator-credential REPLACE_AUTHORITY_OPERATOR_CREDENTIAL \
  > REPLACE_EVIDENCE_DIR/authority-before.json
jq '{authorityId,nodeId,rootEpoch,shardEpoch,enrollmentComplete,shardConfHash,generation,reservedRound,responseRetained,faulted,keyLost}' \
  REPLACE_EVIDENCE_DIR/authority-before.json
```

For journal-enabled shards, the read-only status endpoint is available when the
node is started with `--rpc-server-address HOST:PORT`. Capture its JSON snapshot
alongside the authority status:

```sh
build/ubft shard-node status --url REPLACE_SHARD_RPC_BASE_URL \
  > REPLACE_EVIDENCE_DIR/node-status-before.json
jq '{currentRootEpoch,activatedHandoffs,journal,pruneFrontier,restoreBase,latestLocalV2Archive,replicas,authority}' \
  REPLACE_EVIDENCE_DIR/node-status-before.json
build/ubft shard-node certified-parent --url REPLACE_SHARD_RPC_BASE_URL \
  > REPLACE_EVIDENCE_DIR/certified-parent-before.txt
```

`shard-node certified-parent` is a read-only `GET` of the same #300
`/api/v1/operator/status` endpoint and prints only the certified-tip block hash;
its height, root epoch and root round are written to stderr. The endpoint is
served only when the shard node has `--rpc-server-address`. Bind it to a trusted
operator network and restrict access at the host/network boundary; the endpoint
does not implement authentication.

## Supported-version matrix

This matrix is a conservative deployment rule, not a rolling-upgrade guarantee.
The available evidence is pinned to exact artifacts: the final M2a run used BFT
script tree `6e300cc1` and Ureth `055a314f759f78f045d55ceddfeb7e14b3b6a2f7`;
this H6 implementation is based on BFT integration
`dc8dd9aaa37e21e7c00a33819cb1110f24e9a58b`. `urethPinVerifyBinary` checks the
Ureth executable against its chosen commit before launch.

| Component | Compatibility rule supported by code/evidence | Deployment rule | Gap |
|---|---|---|---|
| BFT root nodes, shard nodes and `ubft` operators | Profile-2 and the operator commands are implemented in the BFT source tree; no mixed-BFT-version negotiation or rolling-upgrade acceptance is established. | Run one approved BFT commit across all participating root/shard processes and operator commands; record its full SHA. | Mixed-version compatibility, rollback and restoring new-format state with an older binary are unverified. |
| Ureth execution client | The paired launcher verifies the executable's reported commit; the final M2a evidence names the exact Ureth pin above. | Pin and verify the same approved Ureth build on each EVM validator; record binary SHA-256 as well as commit. | A supported range of Ureth commits and mixed-version Engine API behavior have not been tested. |
| Signing-authority operator/client protocol | The local protocol is version 1; the service and client reject a different version with `signing-unsupported-version`, with no negotiation (`signingauthority/service/wire.go`, `exchange.go`, `server.go`). | Use the matching `ubft` release for authority and shard node. An incompatible client must remain stopped. | No cross-release protocol compatibility matrix or upgrade negotiation exists. |
| Authority session and persisted signing record | `replace-session` advances generation and fences the old client while retaining the signing record; `advance-epoch` also fences the session. | Replace/reconnect only with the live authority and the operator procedure below. | Authority process/key failover and a supported downgrade path are not implemented. |

There is no release-level mixed-version promise beyond these exact-pin rules.
Before an upgrade, record the old and new BFT/Ureth SHAs, binary hashes, trust
bases and restore inputs, then rehearse the exact pair on disposable state. Do not
roll back a node with newer journal, checkpoint or signing-record state unless a
separately tested reader path exists.

The exact successful shard log records used by the lane are:

```text
msg="certificate admitted" block=<64 lowercase hex> height=<n> round=<n> rootRound=<n> rootEpoch=<n>
msg="handoff activated" rootEpoch=<n>
msg="execution journal restored" block=<64 lowercase hex> height=<n> round=<n> rootRound=<n>
msg="certification request signed" round=<n> ...
```

Before continuing, verify that the log belongs to the current process/run and that
the block hash, height, partition round, root round, and root epoch move forward.
Stop on an absent or conflicting record, a changed genesis/full-shard-conf hash,
authority `faulted=true` or `keyLost=true`, or any signing refusal. Never infer
success from a process merely remaining alive.

## 1. Planned root-key rotation

**Evidence:** the profile-2 lane replaces root validators and checks commit,
activation, and paid execution. The `signing-authority advance-epoch` CLI exists,
but the merged lane does not advance each EVM validator authority. Independent
operator evidence is pending.

### Before

1. Confirm the outgoing root quorum, all EVM validators, and both archive replicas
   are healthy. Save the authority status above for every EVM validator. Verify the
   old and proposed trust bases:

```sh
build/ubft trust-base verify \
  --trust-base REPLACE_PREVIOUS_TRUST_BASE_JSON \
  --trust-base REPLACE_NEXT_TRUST_BASE_JSON
```

2. Record the successor root node infos. The lane creates a replacement root key
   in a fresh home, builds the next trust base from the remaining old node infos
   plus the replacement, and signs that trust base with each included root key.
   The command forms are:

```sh
build/ubft root-node init --home REPLACE_NEW_ROOT_HOME -g
build/ubft trust-base generate --home REPLACE_WORK_DIR \
  --network-id REPLACE_NETWORK_ID --epoch REPLACE_NEXT_ROOT_EPOCH \
  --epoch-start REPLACE_ACTIVATION_ROOT_ROUND \
  --previous-trust-base REPLACE_PREVIOUS_TRUST_BASE_JSON \
  --output-file-name REPLACE_NEXT_TRUST_BASE_FILENAME \
  --node-info REPLACE_RETAINED_ROOT_NODE_INFO_1 \
  --node-info REPLACE_RETAINED_ROOT_NODE_INFO_2 \
  --node-info REPLACE_REPLACEMENT_ROOT_NODE_INFO
build/ubft trust-base sign --home REPLACE_RETAINED_ROOT_HOME_1 \
  --trust-base REPLACE_NEXT_TRUST_BASE_JSON
build/ubft trust-base sign --home REPLACE_RETAINED_ROOT_HOME_2 \
  --trust-base REPLACE_NEXT_TRUST_BASE_JSON
build/ubft trust-base sign --home REPLACE_NEW_ROOT_HOME \
  --trust-base REPLACE_NEXT_TRUST_BASE_JSON
```

The lane's actual `trust-base generate` also fixes `--epoch-start` and includes
the previous trust-base hash. Use the production activation round approved for
this deployment; do not copy the lane's synthetic epoch arithmetic.

### Propose, endorse, and commit

The proposal command is `root handoff propose`. It asks the first old root
RPC to build and endorse the plan, sends that plan to the other old root RPCs for
endorsement, and returns after a quorum response. Root consensus commits or aborts
the attempt. There is no separate CLI `endorse` or `commit` command.

`propose` names no EVM parent: it plans the handoff, the root orders a Prepare (which freezes the EVM and binds the
frozen parent) and only then are the endorsements collected, over the Prepare-bound parent. There is nothing to sample or pin before
the call, and `--frozen-parent` / `--certified-parent-status-url` no longer exist. Record the Prepare-bound parent from the root log
(`root handoff outcome` / the committed record) for the evidence.

```sh
build/ubft root handoff propose \
  --next-trust-base REPLACE_NEXT_TRUST_BASE_JSON \
  --root-rpc REPLACE_OLD_ROOT_RPC_1,REPLACE_OLD_ROOT_RPC_2,REPLACE_OLD_ROOT_RPC_3
```

Wait for the committed outcome on the outgoing roots and then activation on **every**
EVM validator. These are the exact lane checks (use the right log paths and epoch):

```sh
grep -E 'msg="root handoff outcome" .*phase=committed .*attempt=REPLACE_ATTEMPT .*rootEpoch=REPLACE_OLD_EPOCH([[:space:]]|$)' \
  REPLACE_OLD_ROOT_DEBUG_LOG
grep -E 'msg="handoff activated" rootEpoch=REPLACE_NEXT_ROOT_EPOCH([[:space:]]|$)' \
  REPLACE_EVM_VALIDATOR_DEBUG_LOG
```

The lane sees the root handoff outcome as
`msg="root handoff outcome" phase=committed attempt=<n> rootEpoch=<old> rootRound=<n>`;
an abort is the same line with `phase=aborted`. Check every validator log, not just
the first. Also require a later `certificate admitted` line under the new
`rootEpoch` and the receipt-success / registry-epoch checks in
`scripts/m2-profile2-handoffs.sh`.

### Advance each surviving signing authority

After the committed handoff and shard activation are confirmed, advance each
surviving EVM authority to the new root trust. If its shard assignment and key are
unchanged, pass the same full shard configuration; otherwise pass the separately
approved successor configuration that still names that authority's key.

```sh
build/ubft signing-authority advance-epoch \
  --operator-socket REPLACE_AUTHORITY_OPERATOR_SOCKET \
  --operator-credential REPLACE_AUTHORITY_OPERATOR_CREDENTIAL \
  --shard-conf REPLACE_SUCCESSOR_FULL_SHARD_CONF_JSON \
  --trust-base REPLACE_NEXT_TRUST_BASE_JSON
```

`advance-epoch` retains the authority's signing high-water record and fences its
current client session. A transient socket failure alone does not require a new
session: the BFT authority client keeps its connection and retries once after a
dead cached connection (`signingauthority/service/exchange.go`). For a planned
session replacement, write the replacement credential and reconnect the shard
node as follows:

```sh
build/ubft signing-authority replace-session \
  --operator-socket REPLACE_AUTHORITY_OPERATOR_SOCKET \
  --operator-credential REPLACE_AUTHORITY_OPERATOR_CREDENTIAL \
  --out REPLACE_AUTHORITY_CLIENT_CREDENTIAL
```

After the deployment's shard restart/reconnect, repeat the read-only authority
status command and require the new `rootEpoch`, a higher `generation`, unchanged
key fingerprint, no fault/lost-key state, and `reservedRound` not below its saved
high-water. Require a subsequent `certification request signed` and new-epoch
`certificate admitted` record before declaring the validator ready.

`replace-session` fences the old credential as soon as the authority accepts the
operation. It cannot be recovered from the authority; the command writes the new
credential once with restrictive file permissions. If that output file cannot be
written or is lost, run `replace-session` again and use only the newest credential.
`shard-node run` reads its credential at startup (`cli/ubft/cmd/shard_node_signing.go`),
so restart only the shard-node service with the new path; do not restart the
signing-authority process. For a systemd-managed deployment, the service action is:

```sh
sudo systemctl stop REPLACE_SHARD_NODE_UNIT
# Update only its --signing-authority-credential path to the new file.
sudo systemctl start REPLACE_SHARD_NODE_UNIT
sudo systemctl is-active REPLACE_SHARD_NODE_UNIT
```

Then inspect the node and authority statuses and wait for a later
`certification request signed` and `certificate admitted` record. For a normal
process/network reconnect using the same credential, the authority must remain
alive; check `signing-authority status`, the shard-node `/api/v1/health` endpoint,
and shard logs before rotating anything. The authority's signing key is
process-local; stopping/restarting that process loses the key and is not a
reconnect procedure. If status reports `keyLost`, `faulted`, a changed signing
fingerprint, or an unexpected generation, stop and preserve logs rather than
retrying with another credential.

**STOP:** do not advance authorities before the root handoff commits. If any advance
fails, do not restart that shard with the old client credential or manually edit
trust/config files. Keep enough unadvanced validators to preserve service and use
the escalation path under Gaps.

## 2. Aborted or stuck handoff: commit Abort before retrying

**Evidence:** the protocol supports automatic abort, and `root handoff abort`
provides an operator-triggered old-quorum abort for an exact prepared/endorsed
attempt (#301). H6 live operator evidence is pending.

First inspect every old root log. A retry is allowed only after an exact committed
Abort or an observed protocol-produced `phase=aborted` outcome for the current
attempt. A CLI failure from `root handoff propose` by itself is not evidence of an
abort:

```sh
grep -E 'msg="root handoff outcome" .*phase=aborted .*attempt=REPLACE_CURRENT_ATTEMPT .*rootEpoch=REPLACE_OLD_EPOCH([[:space:]]|$)' \
  REPLACE_OLD_ROOT_DEBUG_LOG
```

If this reports the current attempt as aborted, do not submit another abort
request. If no terminal outcome is present, do not infer the control state from
the missing log line. Submit the operator command from `root-handoff-abort.md`
only for the exact authenticated network, old epoch, predecessor, attempt, and
successor body IDs. The command accepts only prepared/endorsed control, refuses
an idle or mismatched target, and returns `too late` if H has already committed:

```sh
build/ubft root handoff abort \
  --network REPLACE_NETWORK_ID \
  --old-epoch REPLACE_OLD_EPOCH \
  --predecessor-body-id REPLACE_PREDECESSOR_BODY_ID \
  --attempt REPLACE_CURRENT_ATTEMPT \
  --next-body-id REPLACE_NEXT_BODY_ID \
  --root-rpc REPLACE_ROOT1_LOOPBACK_URL,REPLACE_ROOT2_LOOPBACK_URL,REPLACE_ROOT3_LOOPBACK_URL \
  --timeout 2m
```

Retain the CLI's committed Abort record ID and ordered round with the exact
target. A timeout is pending/unknown. A `too late` response means H committed;
stop and do not retry. After observing committed Abort, retry the same network
and predecessor at `attempt+1`, with new approvals and the same successor trust
base. Run `propose` again; the root binds the frozen parent anew at the next Prepare:

```sh
build/ubft root handoff propose \
  --next-trust-base REPLACE_NEXT_TRUST_BASE_JSON \
  --root-rpc REPLACE_OLD_ROOT_RPC_1,REPLACE_OLD_ROOT_RPC_2,REPLACE_OLD_ROOT_RPC_3
```

Then repeat the committed/activated/new-epoch checks in procedure 1. Record the
new attempt number and the newly bound frozen parent.

**STOP:** if the attempt remains prepared/endorsed, if no terminal `phase=aborted`
record appears, if validators disagree about the outcome, or if no fresh certified
parent is available. Do not submit a second proposal over an unresolved attempt.

## 3. Replace a validator after complete disk loss

**Evidence:** `h4-restore-probe.sh` wipes a disposable BFT/EL setup, pins an archive
tip, restores with a surviving external authority, and has `d1-monitor.py` compare
the restored block/state/receipt roots and authority high-water. A post-handoff,
cross-epoch H6 evidence run led by another operator is pending.

### Before loss/replacement

Keep the validator's external signing authority running outside the lost BFT/EL
disk domain. Its key is volatile and is not backed up. Save its PID, fingerprint,
session generation, reserved round and response-retained state. If the authority
was also lost, stop: this procedure cannot recover that key. A replacement key
requires a separately authorized configuration and committed handoff.

Use the helper against a configured archive replica and the deployment's current
trust base. It writes the latest valid archived UC/TR pair by certificate round
and prints its block height/hash/state root/receipts root plus the trust-base
BodyID. The restore command independently authenticates the pin.

```sh
go run ./scripts/h4-restore-pin \
  REPLACE_ARCHIVE_REPLICA_LOCAL_ARCHIVE_DIR \
  REPLACE_GENESIS_TRUST_BASE_JSON \
  REPLACE_EVIDENCE_DIR/latest
```

Check the printed `round=`, `height=`, `blockHash=`, `stateRoot=`,
`receiptsRoot=`, and `bodyID=` fields. Confirm the chosen archive is the intended
deployment/partition and that its latest certified tip includes every committed
handoff acknowledgement. `h4-restore-pin` scans archived v2 UC/TR/header records;
it does not by itself prove the replica is current or authenticate the UC. If the
archive lineage, subject, or tip is ambiguous, stop.

Start the pinned execution client on a **new empty datadir** with the finalized
genesis and the same Engine API/HTTP profile as the paired lane. The lane's client
command shape uses the real `urethPinUnicityFlags` helper from the lane. Source the
helper, set the binary's verified commit and fee beneficiary, and then run:

```sh
. scripts/lib/reth-pin.sh
URETH_PIN_COMMIT=REPLACE_URETH_COMMIT
URETH_PIN_FEE_COLLECTOR=REPLACE_FEE_COLLECTOR_ADDRESS
URETH_BIN=REPLACE_URETH_BINARY
urethPinVerifyBinary "$URETH_BIN" "$URETH_PIN_COMMIT"
"$URETH_BIN" node --chain REPLACE_FINALIZED_GENESIS_JSON \
  --datadir REPLACE_NEW_EMPTY_EL_DATADIR \
  --authrpc.jwtsecret REPLACE_SURVIVING_JWT_FILE \
  --authrpc.addr REPLACE_ENGINE_API_HOST --authrpc.port REPLACE_ENGINE_API_PORT \
  --http --http.addr REPLACE_ETH_RPC_HOST --http.port REPLACE_ETH_RPC_PORT \
  --http.api eth,net,web3,admin,debug --rpc.eth-proof-window 64 \
  --port REPLACE_EL_P2P_PORT --disable-discovery --ipcdisable \
  --engine.persistence-threshold REPLACE_PERSISTENCE_THRESHOLD \
  --builder.gaslimit 30000000 $(urethPinUnicityFlags)
```

The command verifies that the binary reports the supplied pinned commit, then uses
the same `--unicity.fee-collector` flag as the lane. Do not use generic EL sync as
a substitute for paired restore.

Run `shard-node restore` with empty BFT/journal/archive paths, the saved genesis
and full shard configuration, the pinned latest UC/TR/body ID, two configured
archive replicas, and the surviving authority. Enable `--trust-history-profile-2`
when the pin follows one or more root handoffs.

**STOP.** `--trust-base` must be the trust base at the genesis root epoch, never
the current one. Restore replays from block 1 and verifies each missed handoff
forward from that anchor; a later-epoch trust base is refused before anything is
built or written (`restore trust anchor is not the genesis root epoch`, naming
both epochs). The current BodyID stays mandatory in `--trust-body-id`.

```sh
build/ubft shard-node restore --home REPLACE_NEW_EMPTY_NODE_HOME --executor engine-api \
  --address REPLACE_SHARD_P2P_MULTIADDRESS --bootnodes REPLACE_CURRENT_ROOT_AND_SHARD_BOOTNODES \
  --trust-base REPLACE_GENESIS_TRUST_BASE_JSON \
  --full-shard-conf REPLACE_FINALIZED_FULL_SHARD_CONF_JSON \
  --genesis REPLACE_FINALIZED_GENESIS_JSON \
  --engine-url REPLACE_ENGINE_API_URL --eth-url REPLACE_ETH_RPC_URL \
  --jwt-secret REPLACE_SURVIVING_JWT_FILE \
  --engine-fee-collector REPLACE_FEE_COLLECTOR_ADDRESS \
  --execution-journal REPLACE_NEW_EMPTY_EXECUTION_JOURNAL \
  --archive-store REPLACE_NEW_EMPTY_LOCAL_ARCHIVE --archive-prune \
  --journal-candidates 16 \
  --archive-replica REPLACE_ARCHIVE_REPLICA_PEER_ID_1 \
  --archive-replica REPLACE_ARCHIVE_REPLICA_PEER_ID_2 \
  --signing-authority-socket REPLACE_SURVIVING_AUTHORITY_CLIENT_SOCKET \
  --signing-authority-credential REPLACE_SURVIVING_AUTHORITY_CLIENT_CREDENTIAL \
  --tip-uc REPLACE_EVIDENCE_DIR/latest.uc.cbor \
  --tip-tr REPLACE_EVIDENCE_DIR/latest.tr.cbor \
  --trust-body-id REPLACE_PRINTED_TRUST_BODY_ID \
  --trust-history-profile-2 --log-format text --log-level info
```

### After restore

Require a live restore process and these records after its start boundary:

```sh
grep -E 'msg="(execution journal restored|certification request signed|certificate admitted)"' \
  REPLACE_EVIDENCE_DIR/restore.log
build/ubft signing-authority status \
  --operator-socket REPLACE_SURVIVING_AUTHORITY_OPERATOR_SOCKET \
  --operator-credential REPLACE_SURVIVING_AUTHORITY_OPERATOR_CREDENTIAL \
  > REPLACE_EVIDENCE_DIR/authority-after.json
jq '{signingKeyFingerprint,generation,rootEpoch,reservedRound,responseRetained,faulted,keyLost}' \
  REPLACE_EVIDENCE_DIR/authority-after.json
```

At the pin height, compare the restored client's block hash, state root, and
receipts root against an independent surviving validator. These are the RPC calls
used by `d1-monitor.py` (`REPLACE_HEIGHT_HEX` must be the printed pin height):

```sh
curl -fsS REPLACE_RESTORED_ETH_RPC_URL \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["REPLACE_HEIGHT_HEX",false]}' \
  | jq -r '.result | [.hash,.stateRoot,.receiptsRoot] | @tsv'
curl -fsS REPLACE_SURVIVING_VALIDATOR_ETH_RPC_URL \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["REPLACE_HEIGHT_HEX",false]}' \
  | jq -r '.result | [.hash,.stateRoot,.receiptsRoot] | @tsv'
```

Require exact equality for all three values, `execution journal restored`, a later
`certification request signed`, a later positive-height `certificate admitted`,
the same authority PID and key fingerprint, and `reservedRound` strictly greater
than the saved high-water. Keep the existing authority and client credential; do
not restart the authority. Signing resumes only after the restore replay and the
authority high-water gate both pass.

Capture the shared status command before and after restore. Require the reported
root epoch and activated handoffs to match the committed history; compare journal
occupancy, restore base, prune frontier, and latest local v2 record with the
restore evidence.

**STOP:** restore exits; the pinned block/state/receipt roots differ; the status
shows another authority lifetime, changed key fingerprint, `keyLost` or `faulted`;
the reserved round did not increase; or no certificate under the current epoch is
admitted. A failed restore may have written partial journal state: restart with new
empty BFT and archive paths.

### A validator behind the pruned hot-journal window

A validator whose latest local height is below the cluster's prune frontier cannot catch up from peers: the peers have
pruned the early certificates and bodies, and an unrestored node audits coverage from height one (by design: there is exactly one supported recovery route, archive restore with paired-seal replay; generic EL sync is refused).
It stays unready ("candidate lacks its retained authorizing or resulting certificate"; replicas answer "no certified
association") and must be recovered with the archive restore procedure above, with fresh BFT and archive paths. Detect it
with the status command on the lagging node and on a healthy peer: if the peer's `pruneFrontier.height` is above the
lagging node's `latestLocalV2Archive.height` (its latest local archive record), the gap is past the window; a node still inside the window
(frontier gap zero or negative) catches up by itself.

```sh
build/ubft shard-node status --url REPLACE_LAGGING_RPC | jq '{latestLocalV2Archive,pruneFrontier}'
build/ubft shard-node status --url REPLACE_HEALTHY_PEER_RPC | jq '{pruneFrontier}'
```

A validator that only misses its first handshake no longer falls behind this way: the client re-sends the handshake every
2 s (backing off to the inactivity timeout) until its first certificate (`--startup-handshake-interval`).

## 4. Archive-replica maintenance

**Evidence:** the publisher requires acknowledgements from both configured
replicas before the frontier worker can prune. An archive replica is a shard-node
process with a local archive store and the peer-gated archive server registered
on its libp2p host; there is no separate `ubft archive-replica` daemon or
service-manager command (`cli/ubft/cmd/shard_node_run.go`,
`archivewiring/transport.go`). The deployment's process manager owns each
replica-node service. The #300 status endpoint and #316 bounded F9 report give
read-only acknowledgement/backlog measurements; independent operator evidence
remains pending.

Before taking a replica out, inspect the affected shard node's status. It must
have been started with `--rpc-server-address HOST:PORT`:

```sh
build/ubft shard-node status --url REPLACE_SHARD_RPC_BASE_URL \
  > REPLACE_EVIDENCE_DIR/operator-status-before.json
jq '{currentRootEpoch,pruneFrontier,replicas}' \
  REPLACE_EVIDENCE_DIR/operator-status-before.json
```

Require a non-null prune frontier and both configured replicas' acknowledged
heights at or above that frontier, with no reported replica error. A command
failure or missing frontier is a STOP condition. This is a read-only snapshot;
it does not authorize taking a replica offline.

Check the actual service and process logs on the host running the selected
replica. These are systemd examples; substitute the deployment's service manager
and exact unit. Confirm only one of the two replica units will be stopped:

```sh
sudo systemctl status REPLACE_REPLICA_UNIT
sudo systemctl is-active REPLACE_REPLICA_UNIT
sudo journalctl -u REPLACE_REPLICA_UNIT --since '30 minutes ago' --no-pager
curl -fsS REPLACE_REPLICA_STATUS_URL/api/v1/health
```

For an approved one-replica maintenance window, preserve its home, peer key,
journal, archive and service arguments. Stop and start that unit through the
deployment service manager, then confirm the process is active and inspect its
log before checking the sender again:

```sh
sudo systemctl stop REPLACE_REPLICA_UNIT
sudo systemctl is-active REPLACE_REPLICA_UNIT   # must report inactive
sudo systemctl start REPLACE_REPLICA_UNIT
sudo systemctl is-active REPLACE_REPLICA_UNIT   # must report active
sudo journalctl -u REPLACE_REPLICA_UNIT -f
```

The replica's own `/api/v1/health` is a process health check, not proof that the
sender has caught it up. Repeat `shard-node status` on each sender that names this
peer and require its acknowledgement height to reach the current frontier with
no transfer error. Do not stop the second peer until those checks pass.

The Prometheus endpoint is an additional backlog cross-check:
The node must have been started with `--metrics prometheus` and
`--rpc-server-address HOST:PORT` for `/api/v1/metrics` to exist. The publisher
exports these exact instrument names (Prometheus form):

```sh
curl -fsS REPLACE_SHARD_RPC_BASE_URL/api/v1/metrics \
  | grep -E '^ab_archive_(pending|acknowledged|lagging)_records([ {]|$)'
```

The Prometheus exporter is configured with namespace `ab`, so these series are
`ab_archive_pending_records`, `ab_archive_acknowledged_records`, and
`ab_archive_lagging_records`. An empty grep result means the metric name did not
match or the exporter is unavailable; it does **not** mean the backlog is zero.
Confirm `/api/v1/metrics` is enabled and inspect the full response before proceeding.

For bounded multi-sample evidence, #316's report collector reads only the
`GET /api/v1/operator/status` and `GET /api/v1/metrics` endpoints. Configure every
measured shard node with `status_url`, `metrics_url`, and its local `archive_dir`;
use at least two samples. The report writes incomplete evidence and exits
nonzero if required metrics or status fields are absent:

```sh
go run ./scripts/f9-report --config REPLACE_F9_REPORT_CONFIG.json \
  --out REPLACE_EVIDENCE_DIR/f9-replica-status.json
```

Before and after any maintenance, preserve the output and inspect the replica
process log for these exact wait diagnostics:

```sh
grep -E 'msg="(archive publication waiting|archive replica waiting|certified frontier waiting)"' \
  REPLACE_SHARD_DEBUG_LOG
```

Do not take a second replica out while one is unavailable. Do not continue when
`archive_pending_records` or `archive_lagging_records` is nonzero, when the two
replicas do not both acknowledge a recent certified record, or when
`certified frontier waiting` reports an error. After maintenance, repeat the
status and metrics checks before touching the other replica. The status endpoint
reports the last acknowledged heights and publisher's latest per-peer transfer
error; it does not prove a replica process is healthy between read attempts.
There is no platform-independent operator-safe replica restart command. Use the
deployment-owned service manager only after the acknowledgement/frontier checks;
see Gaps for the remaining product and live-rehearsal limits.

### Replacing a configured archive replica (`--archive-replica`)

After a validator-set change retires one configured replica, a retained validator
can switch to a replacement replica by changing its `--archive-replica` pair and
restarting. Both configured replicas are checked against the installed (verified)
validator set after replay (catch-up on restore), not against genesis.

Rules. Each one is refused at startup with `frontier.ErrContext` ("frontier: wrong
context or configured replicas") if broken:

- Replace **exactly one** replica per restart. Keep the other one, which must be one
  of the replicas that acknowledged the last durable frontier.
- Do **not** replace both replicas at once.
- Do **not** reorder an unchanged pair. Keep the configured order exactly.

What happens on the restart:

- The durable frontier position and the already-pruned floor stay valid. Two
  replicas acknowledged them when they were written.
- The retired replica's acknowledgment is dropped. The node logs one WARN: "archive
  replica pair changed; durable frontier position kept, retired acknowledgments
  dropped, pruning waits for the new pair to acknowledge beyond it".
- Pruning resumes only after **both** configured replicas acknowledge beyond that
  position. Until then the hot journal grows. Watch `pruneFrontier` and the
  `replicas` acknowledgment heights with `shard-node status`, as above.

To move off both old replicas, do it in two steps. Replace one replica, wait until
`shard-node status` shows a new durable frontier acknowledged by the new pair, then
replace the second. Never delete or discard the journal or the frontier record to
get past a refusal. That would discard the evidence the frontier protects.

## 5. Shard-node restart after handoffs

**Evidence:** the D2C helper restarts the shard process while retaining its local
journal, execution client, authority process, and authority session. The M2
profile-2 lane can be combined with that probe. Independent operator evidence is
pending.

The merged rehearsal command is:

```sh
M2_PROFILE2=1 D2C_RESTART_PROBE=1 SIGNING=authority \
  ./scripts/reth-paired-devnet.sh 4 10
```

Use only in the isolated lane environment after the devnet lock is available. The
script performs two profile-2 handoffs, then `d1-monitor.py` calls
`scripts/d2c-restart-validator.sh`; that helper stops and restarts only one shard
process. Before restart, save authority status. After restart, the D1 monitor
requires `execution journal restored`, later certificate admissions, the same
reth/authority PIDs, the same signing-key fingerprint and session generation, and
a greater reserved round with a retained response. The exact boundary marker is
`D2C_RESTART_BOUNDARY old=<pid>` in the shard debug log.

For manual inspection, run the lane helper only in its `test-nodes/` fixture:

```sh
bash scripts/d2c-restart-validator.sh REPLACE_VALIDATOR_INDEX
```

Then inspect the marker and recovery/admission records:

```sh
grep -E 'D2C_RESTART_BOUNDARY|msg="(execution journal restored|certification request signed|certificate admitted)"' \
  test-nodes/evmREPLACE_VALIDATOR_INDEX/debug.log
```

Do not apply that helper to production homes: it invokes the lane's `helper.sh`
process ownership and fixed test topology. Production process-manager restart
commands are deployment-specific and are not present in the merged scripts.

## 6. Checks and stop conditions

Before every procedure, capture source/client pins, health, current trust base,
latest admitted block and each authority status. After every procedure, capture the
same outputs and compare root epoch, certified height/hash, state/receipt roots,
authority key fingerprint, generation and reserved round. Keep root/shard logs,
the archive pin output, and the exact commands in a dated evidence directory.
Also capture the shared `shard-node status` JSON before and after each journaled
operation; treat an unavailable or invalid status response as a STOP condition.

Stop and do not resume signing on any of these conditions:

- the trust-base verification or root handoff outcome is missing, aborted, or
  disagrees across roots;
- any EVM validator lacks `handoff activated` for the successor root epoch;
- an authority is faulted, lost its key, changed fingerprint unexpectedly, or
  does not retain a response above its old high-water round;
- archive replica acknowledgements are lagging or the certified frontier cannot
  be independently read and matched to both replicas;
- restored block hash, state root, or receipts root differs from a survivor;
- a command would require reusing non-empty restore disks, bypassing the archive,
  editing trust files by hand, or restarting an authority process.

## Gaps

There are four concrete gaps; until closed, this document is a rehearsal guide,
not a complete recovery authority:

1. **Frozen-parent selection:** closed by the Prepare-first order. The root binds the frozen parent at the Prepare record and
   `root handoff propose` names none; the `shard-node certified-parent` query remains a read-only status tool for evidence.

2. **Authority advancement evidence:** `signing-authority advance-epoch` is a
   real command, but the merged profile-2 lane does not call it for each EVM
   authority or rehearse its session replacement and shard reconnect sequence.
   The code-verified steps are documented in procedure 1, but live/private H6
   acceptance remains pending.
3. **Replica lifecycle:** `shard-node status`, `/api/v1/health`, Prometheus and
   the #316 report are read-only. Actual stop/start uses the deployment-owned
   service manager; no `ubft` command can safely take a replica offline, check
   the other peer's service, or gate a restart on frontier acknowledgements.
   Validate the systemd example against the deployment unit and rehearse it
   independently before production use.
4. **Execution-version compatibility:** the matrix records a conservative
   same-release/exact-pin deployment rule. There is no rolling version activation,
   mixed-version compatibility table, downgrade guarantee, or recovery authority
   for incompatible persisted state. These require separate version-pair tests
   before operators can widen the supported set.

An operator who did not author this document must execute each supported rehearsal
procedure in an isolated environment, record the above evidence, and review these
gaps with the M2a owners before H6 can be considered closed.
