# M2 operations runbook: handoff, restore, and restart

**Status:** rehearsal draft. M2a is still being closed. All five procedures below
still need an evidence run led by an operator other than the implementer; none is
production approval. Cross-epoch full-disk restore and archive-replica maintenance
are specifically pending. Do not use the test harness against production data.

This runbook is limited to commands and observations present in the merged paired
devnet scripts and `ubft` CLIs. Replace every `REPLACE_*` value before running a
command. The H4 and D2C scripts operate on `test-nodes/`, stop processes, and in the
H4 restore stage delete test datadirs. Use only a disposable, isolated checkout.
For a live lane, obtain the devnet lock first; these instructions do not grant it.

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

The only operator command is `root handoff propose`. It asks the first old root
RPC to build and endorse the plan, sends that plan to the other old root RPCs for
endorsement, and returns after a quorum response. Root consensus commits or aborts
the attempt. There is no separate CLI `endorse` or `commit` command.

```sh
build/ubft root handoff propose \
  --next-trust-base REPLACE_NEXT_TRUST_BASE_JSON \
  --frozen-parent REPLACE_CERTIFIED_EVM_PARENT_HASH \
  --root-rpc REPLACE_OLD_ROOT_RPC_1,REPLACE_OLD_ROOT_RPC_2,REPLACE_OLD_ROOT_RPC_3
```

Wait for the committed outcome on the outgoing roots and then activation on **every**
EVM validator. These are the exact lane checks (use the right log paths and epoch):

```sh
grep -E 'msg="root handoff outcome" .*phase=committed .*rootEpoch=REPLACE_OLD_EPOCH([[:space:]]|$)' \
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
current client session. Issue a new session credential, then restart/reconnect the
shard node with that credential before expecting it to sign:

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

**STOP:** do not advance authorities before the root handoff commits. If any advance
fails, do not restart that shard with the old client credential or manually edit
trust/config files. Keep enough unadvanced validators to preserve service and use
the escalation path under Gaps.

## 2. Aborted or stuck handoff: retry only after an observed abort

**Evidence:** `m2-profile2-handoffs.sh` retries after a protocol-produced abort
using a newly sampled certified parent. It does not provide an operator abort
command. Independent operator evidence is pending.

First inspect every old root log. Retry only if the current attempt has an exact
`msg="root handoff outcome" ... phase=aborted ... rootEpoch=<old>` record. A CLI
failure from `root handoff propose` by itself is not evidence of an abort. The lane
reuses the same successor trust base and selects a fresh frozen parent for its next
attempt:

```sh
grep -E 'msg="root handoff outcome" .*phase=aborted .*rootEpoch=REPLACE_OLD_EPOCH([[:space:]]|$)' \
  REPLACE_OLD_ROOT_DEBUG_LOG
build/ubft root handoff propose \
  --next-trust-base REPLACE_NEXT_TRUST_BASE_JSON \
  --frozen-parent REPLACE_NEW_CERTIFIED_EVM_PARENT_HASH \
  --root-rpc REPLACE_OLD_ROOT_RPC_1,REPLACE_OLD_ROOT_RPC_2,REPLACE_OLD_ROOT_RPC_3
```

Then repeat the committed/activated/new-epoch checks in procedure 1. Record the
new attempt number and frozen parent; do not reuse the parent from the aborted
attempt.

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
  --journal-candidates 8 \
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

**STOP:** restore exits; the pinned block/state/receipt roots differ; the status
shows another authority lifetime, changed key fingerprint, `keyLost` or `faulted`;
the reserved round did not increase; or no certificate under the current epoch is
admitted. A failed restore may have written partial journal state: restart with new
empty BFT and archive paths.

## 4. Archive-replica maintenance

**Evidence:** the publisher requires acknowledgements from both configured
replicas before the frontier worker can prune. The merged scripts do not contain
a one-replica-at-a-time maintenance/restart procedure. Per-replica acknowledgement
and frontier inspection are pending; see Gaps.

Before taking a replica out, scrape the affected shard node's Prometheus endpoint.
The node must have been started with `--metrics prometheus` and
`--rpc-server-address HOST:PORT` for `/api/v1/metrics` to exist. The publisher
exports these exact instrument names (Prometheus form):

```sh
curl -fsS REPLACE_SHARD_RPC_BASE_URL/api/v1/metrics \
  | grep -E '^archive_(pending|acknowledged|lagging)_records([ {]|$)'
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
`certified frontier waiting` reports an error. The aggregate metrics do not name
which replica acknowledged a record, and there is no CLI to read the committed
frontier height/sequence. Without independent per-replica and frontier evidence,
stop before restarting any replica.

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

There are five concrete gaps; until closed, this document is a rehearsal guide,
not a complete recovery authority:

1. **Frozen-parent selection:** `root handoff propose` requires a certified EVM
   parent, but there is no stable read-only CLI to return it. The M2 lane parses
   `sending CertificationResponse` from `root1/debug.log` with inline Python.
   Obtain an approved operator query before a human production run; do not guess
   or copy an old hash.
2. **Abort of an unresolved handoff:** there is no operator abort/cancel CLI. The
   lane retries only after the protocol records `phase=aborted`. A prepared or
   endorsed attempt with no terminal outcome has no documented recovery command.
3. **Authority advancement evidence:** `signing-authority advance-epoch` is a
   real command, but the merged profile-2 lane does not call it for each EVM
   authority or rehearse its session replacement and shard reconnect sequence.
   The operator sequence in procedure 1 remains pending live/private acceptance.
4. **Replica/frontier visibility and lifecycle:** metrics provide aggregate
   acknowledged/lagging counts but not peer identity; no CLI reads the durable
   frontier or safely restarts one archive replica. The lane's process helpers
   are topology-specific and not an operator service manager.
5. **Execution-version activation/support policy:** the lane prints source/client
   pins and exercises current binaries, but there is no rolling version activation
   command, supported-version matrix, rollback procedure, or defined recovery
   authority for an incompatible upgrade.

An operator who did not author this document must execute each supported rehearsal
procedure in an isolated environment, record the above evidence, and review these
gaps with the M2a owners before H6 can be considered closed.
